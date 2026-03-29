// Package ebpfpoller connects to the eBPF agent's gRPC health stream and
// applies state transitions to the balancer immediately on receipt.
package ebpfpoller

import (
	"context"
	"log"
	"time"

	"github.com/mdean75/ebpf-grpc-experiment/service-a/internal/balancer"
	"github.com/mdean75/ebpf-grpc-experiment/service-a/internal/metrics"
	pb "github.com/mdean75/ebpf-grpc-experiment/proto/health"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Watcher holds an open gRPC stream to the eBPF agent and applies health
// state transitions to the balancer as they arrive.
type Watcher struct {
	agentAddr string
	bal       *balancer.Balancer
	// vmAddrs maps VM IP (bare, no port) to the full balancer key (ip:port).
	vmAddrs map[string]string
	ctx     context.Context
	cancel  context.CancelFunc
}

// New creates a Watcher. vmAddresses is the same slice passed to balancer.New.
func New(agentAddr string, bal *balancer.Balancer, vmAddresses []string) *Watcher {
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
	ctx, cancel := context.WithCancel(context.Background())
	return &Watcher{
		agentAddr: agentAddr,
		bal:       bal,
		vmAddrs:   vmAddrs,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start connects to the agent and streams events until Stop is called.
// On disconnect it reconnects with a 2-second backoff. Run in a goroutine.
func (w *Watcher) Start() {
	for {
		if err := w.watch(); err != nil {
			if w.ctx.Err() != nil {
				return // Stop() was called
			}
			log.Printf("ebpf watcher: %v — reconnecting in 2s", err)
			select {
			case <-time.After(2 * time.Second):
			case <-w.ctx.Done():
				return
			}
		}
	}
}

func (w *Watcher) watch() error {
	//nolint:staticcheck // grpc.Dial is deprecated but matches the rest of the codebase
	conn, err := grpc.Dial(w.agentAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()

	stream, err := pb.NewHealthWatcherClient(conn).Watch(w.ctx, &pb.WatchRequest{})
	if err != nil {
		return err
	}

	log.Printf("ebpf watcher: connected to %s", w.agentAddr)
	for {
		ev, err := stream.Recv()
		if err != nil {
			return err
		}
		w.apply(ev)
	}
}

func (w *Watcher) apply(ev *pb.HealthEvent) {
	balAddr, ok := w.vmAddrs[ev.Daddr]
	if !ok {
		return
	}
	if w.bal.Mode() != balancer.ModeEBPF {
		return
	}
	current := w.bal.GetHealth(balAddr)
	switch {
	case ev.Status == "degraded" && current == balancer.Healthy:
		log.Printf("ebpf signal: %s score=%.2f — marking degraded", balAddr, ev.Score)
		w.bal.SetHealth(balAddr, balancer.Degraded, "ebpf_signal")
		metrics.StreamHealth.WithLabelValues(balAddr).Set(1)
		metrics.Reroutes.WithLabelValues(balAddr, "ebpf_signal").Inc()
	case ev.Status == "healthy" && current == balancer.Degraded:
		log.Printf("ebpf signal: %s score=%.2f — marking healthy", balAddr, ev.Score)
		w.bal.SetHealth(balAddr, balancer.Healthy, "ebpf_recovery")
		metrics.StreamHealth.WithLabelValues(balAddr).Set(0)
	}
}

// Stop cancels the context, closing the active stream and preventing reconnects.
func (w *Watcher) Stop() {
	w.cancel()
}
