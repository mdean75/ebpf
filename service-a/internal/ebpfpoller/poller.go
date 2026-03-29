package ebpfpoller

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/mdean75/ebpf-grpc-experiment/service-a/internal/balancer"
	"github.com/mdean75/ebpf-grpc-experiment/service-a/internal/metrics"
)

const pollInterval = 100 * time.Millisecond

// ConnHealth is the JSON shape returned by the eBPF agent's /health/all endpoint.
type ConnHealth struct {
	Conn struct {
		Saddr string `json:"saddr"`
		Daddr string `json:"daddr"`
		Dport uint16 `json:"dport"`
	} `json:"conn"`
	Score     float64 `json:"score"`
	Status    string  `json:"status"` // "healthy" or "degraded"
	LastEvent string  `json:"last_event"`
	UpdatedAt string  `json:"updated_at"`
}

// Poller polls the eBPF agent's /health/all endpoint and applies signals
// to the balancer. Only active in ModeEBPF.
type Poller struct {
	agentAddr string
	bal       *balancer.Balancer
	// vmAddrs maps VM IP to its dial address (ip:port) so we can match
	// eBPF connection keys (daddr) back to balancer keys.
	vmAddrs map[string]string
	client  *http.Client
	stopCh  chan struct{}
}

func New(agentAddr string, bal *balancer.Balancer, vmAddresses []string) *Poller {
	// Build a map from bare IP to full address for balancer lookups.
	// VM addresses are "ip:port"; we match on IP portion.
	vmAddrs := make(map[string]string, len(vmAddresses))
	for _, addr := range vmAddresses {
		ip := addr
		for i, ch := range addr {
			if ch == ':' {
				ip = addr[:i]
				break
			}
		}
		vmAddrs[ip] = addr
	}
	return &Poller{
		agentAddr: agentAddr,
		bal:       bal,
		vmAddrs:   vmAddrs,
		client:    &http.Client{Timeout: 500 * time.Millisecond},
		stopCh:    make(chan struct{}),
	}
}

// Start polls the agent until Stop is called. Should be run in a goroutine.
func (p *Poller) Start() {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	url := fmt.Sprintf("http://%s/health/all", p.agentAddr)

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			if p.bal.Mode() != balancer.ModeEBPF {
				continue
			}
			p.poll(url)
		}
	}
}

func (p *Poller) Stop() {
	close(p.stopCh)
}

func (p *Poller) poll(url string) {
	resp, err := p.client.Get(url)
	if err != nil {
		// Agent not reachable — don't change stream health based on absence of data.
		return
	}
	defer resp.Body.Close()

	var conns []ConnHealth
	if err := json.NewDecoder(resp.Body).Decode(&conns); err != nil {
		log.Printf("ebpf poller: decode error: %v", err)
		return
	}

	// Aggregate per VM IP: degraded beats healthy.
	// Multiple conn_keys can exist for the same VM (e.g. stale entries from
	// prior source ports that haven't been evicted yet). Taking the worst
	// status ensures a degraded entry always wins over a healthy one.
	type vmState struct {
		status string
		score  float64
	}
	best := make(map[string]vmState, len(p.vmAddrs))
	for _, ch := range conns {
		balAddr, ok := p.vmAddrs[ch.Conn.Daddr]
		if !ok {
			continue
		}
		prev, exists := best[balAddr]
		if !exists || (ch.Status == "degraded" && prev.status != "degraded") ||
			(ch.Status == prev.status && ch.Score > prev.score) {
			best[balAddr] = vmState{status: ch.Status, score: ch.Score}
		}
	}

	for balAddr, state := range best {
		current := p.bal.GetHealth(balAddr)
		switch {
		case state.status == "degraded" && current == balancer.Healthy:
			log.Printf("ebpf signal: %s score=%.2f — marking degraded", balAddr, state.score)
			p.bal.SetHealth(balAddr, balancer.Degraded, "ebpf_signal")
			metrics.StreamHealth.WithLabelValues(balAddr).Set(1)
			metrics.Reroutes.WithLabelValues(balAddr, "ebpf_signal").Inc()
		case state.status == "healthy" && current == balancer.Degraded:
			log.Printf("ebpf signal: %s score=%.2f — marking healthy", balAddr, state.score)
			p.bal.SetHealth(balAddr, balancer.Healthy, "ebpf_recovery")
			metrics.StreamHealth.WithLabelValues(balAddr).Set(0)
		}
	}
}
