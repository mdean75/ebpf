// Package protopulsepoller monitors TCP connection health using the nethealth
// library's /proc/net/tcp polling approach and applies state transitions to the
// balancer. This provides a third detection mode alongside eBPF (kernel events)
// and baseline (heartbeat-only).
package protopulsepoller

import (
	"log"
	"time"

	"github.com/mdean75/ebpf-grpc-experiment/service-a/internal/balancer"
	"github.com/mdean75/ebpf-grpc-experiment/service-a/internal/metrics"
	"github.com/mdean75/ebpf-grpc-experiment/service-a/internal/nethealth"
)

// StreamClient is the subset of stream.Client that the poller needs.
type StreamClient interface {
	Address() string
	ConnectionInfo() (localPort int, remoteIP string, remotePort int, ok bool)
}

// Poller monitors TCP connections via /proc/net/tcp and updates the balancer
// when degradation is detected.
type Poller struct {
	bal          *balancer.Balancer
	clients      []StreamClient
	monitor      *nethealth.Monitor
	pollInterval time.Duration
	stopCh       chan struct{}
	doneCh       chan struct{}
}

// New creates a Poller. clients must match the VM addresses in the balancer.
func New(bal *balancer.Balancer, clients []StreamClient, pollInterval time.Duration) *Poller {
	if pollInterval <= 0 {
		pollInterval = 200 * time.Millisecond
	}

	cfg := nethealth.DefaultMonitorConfig()
	cfg.PollInterval = pollInterval
	cfg.AlertPolicy = nethealth.AlertPolicy{
		CooldownSeconds: 0, // fire on every transition for fast detection
	}
	// Use default balanced thresholds and EMA smoothing.
	// Hysteresis: 3 consecutive confirmations before escalation/recovery.

	mon := nethealth.NewMonitor(cfg, 64)

	// Track one socket per VM address.
	for _, c := range clients {
		mon.Track(nethealth.SocketMeta{
			ID:     c.Address(),
			Labels: map[string]string{"addr": c.Address()},
		})
	}

	return &Poller{
		bal:          bal,
		clients:      clients,
		monitor:      mon,
		pollInterval: pollInterval,
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}
}

// Start begins polling and applying health transitions. Run in a goroutine.
func (p *Poller) Start() {
	defer close(p.doneCh)

	// Register alert callback to map nethealth ActionLevel to balancer health.
	p.monitor.OnAlert(func(evt nethealth.AlertEvent) {
		addr := evt.Meta.ID
		if p.bal.Mode() != balancer.ModeProtopulse {
			return
		}

		current := p.bal.GetHealth(addr)
		switch {
		case evt.To != nethealth.ActionHealthy && current == balancer.Healthy:
			log.Printf("protopulse signal: %s action=%s risk=%.1f — marking degraded",
				addr, evt.To, evt.Report.RiskScore)
			p.bal.SetHealth(addr, balancer.Degraded, "protopulse_signal")
			metrics.StreamHealth.WithLabelValues(addr).Set(1)
			metrics.Reroutes.WithLabelValues(addr, "protopulse_signal").Inc()
		case evt.To == nethealth.ActionHealthy && current == balancer.Degraded:
			log.Printf("protopulse signal: %s action=%s risk=%.1f — marking healthy",
				addr, evt.To, evt.Report.RiskScore)
			p.bal.SetHealth(addr, balancer.Healthy, "protopulse_recovery")
			metrics.StreamHealth.WithLabelValues(addr).Set(0)
		}
	})

	// Build the metrics collector that samples /proc/net/tcp for each stream.
	collector := nethealth.NewTCPMetricsCollector(nethealth.TCPCollectorConfig{
		IdleThreshold: 2 * time.Second,
		Iterate: func(yield func(nethealth.TCPCollectorSample) bool) {
			for _, c := range p.clients {
				localPort, remoteIP, remotePort, ok := c.ConnectionInfo()
				if !ok {
					continue
				}
				if !yield(nethealth.TCPCollectorSample{
					SocketID:           c.Address(),
					LocalPort:          localPort,
					RemoteIP:           remoteIP,
					RemotePort:         remotePort,
					LastMessageAtNanos: time.Now().UnixNano(), // treat as active while connected
					Active:             true,
				}) {
					return
				}
			}
		},
	})

	log.Printf("protopulse poller: starting (interval=%s, streams=%d)",
		p.pollInterval, len(p.clients))

	if err := p.monitor.StartPolling(collector); err != nil {
		log.Printf("protopulse poller: failed to start polling: %v", err)
		return
	}

	// Block until Stop() is called.
	<-p.stopCh
	p.monitor.StopPolling()
	log.Printf("protopulse poller: stopped")
}

// Stop signals the poller to shut down and waits for completion.
func (p *Poller) Stop() {
	select {
	case <-p.stopCh:
		return // already stopped
	default:
		close(p.stopCh)
	}
	<-p.doneCh
}
