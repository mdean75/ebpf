package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mdean75/ebpf-grpc-experiment/service-a/config"
	"github.com/mdean75/ebpf-grpc-experiment/service-a/internal/balancer"
	"github.com/mdean75/ebpf-grpc-experiment/service-a/internal/ebpfpoller"
	"github.com/mdean75/ebpf-grpc-experiment/service-a/internal/metrics"
	"github.com/mdean75/ebpf-grpc-experiment/service-a/internal/protopulsepoller"
	sstream "github.com/mdean75/ebpf-grpc-experiment/service-a/internal/stream"
	pb "github.com/mdean75/ebpf-grpc-experiment/proto/stream"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	cfg := config.Load()

	if len(cfg.VMAddresses) == 0 {
		log.Fatal("VM_ADDRESSES is required (comma-separated list of host:port)")
	}
	if cfg.LBMode != "ebpf" && cfg.LBMode != "baseline" && cfg.LBMode != "protopulse" {
		log.Fatalf("LB_MODE must be 'ebpf', 'baseline', or 'protopulse', got %q", cfg.LBMode)
	}
	if cfg.DeadDetection != "heartbeat" && cfg.DeadDetection != "keepalive" {
		log.Fatalf("DEAD_DETECTION must be 'heartbeat' or 'keepalive', got %q", cfg.DeadDetection)
	}

	mode := balancer.Mode(cfg.LBMode)
	bal := balancer.New(cfg.VMAddresses, mode)
	log.Printf("starting service-a: %d VMs, mode=%s, dead-detection=%s, rate=%d msg/s",
		len(cfg.VMAddresses), mode, cfg.DeadDetection, cfg.MessagesPerSecond)

	keepaliveMode := cfg.DeadDetection == "keepalive"

	// One stream client per VM
	clients := make([]*sstream.Client, len(cfg.VMAddresses))
	for i, addr := range cfg.VMAddresses {
		clients[i] = sstream.NewClient(addr, bal,
			cfg.HeartbeatInterval, cfg.HeartbeatTimeout, cfg.TLSCACert,
			keepaliveMode, cfg.KeepaliveTime, cfg.KeepaliveTimeout)
		go clients[i].Start()
	}

	// eBPF agent health watcher — push-based gRPC stream
	// (only acts in ebpf mode, but always connected so mode switches take effect immediately)
	ebpfWatcher := ebpfpoller.New(cfg.EBPFAgentGRPCAddr, bal, cfg.VMAddresses)
	go ebpfWatcher.Start()

	// Protopulse poller — /proc/net/tcp polling with EMA scoring
	// (only acts in protopulse mode; uses same routing rules as eBPF)
	ppClients := make([]protopulsepoller.StreamClient, len(clients))
	for i, c := range clients {
		ppClients[i] = c
	}
	ppPoller := protopulsepoller.New(bal, ppClients, cfg.ProtopulsePollInterval)
	go ppPoller.Start()

	// Message generator: produce MessagesPerSecond across healthy streams
	go messageGenerator(bal, clients, cfg)

	// Prometheus metrics
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		addr := ":2112"
		log.Printf("metrics on %s/metrics", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Printf("metrics server: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")

	ebpfWatcher.Stop()
	ppPoller.Stop()
	for _, c := range clients {
		c.Stop()
	}
}

func messageGenerator(bal *balancer.Balancer, clients []*sstream.Client, cfg config.Config) {
	if cfg.MessagesPerSecond <= 0 {
		return
	}
	interval := time.Second / time.Duration(cfg.MessagesPerSecond)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Index clients by address for O(1) lookup
	clientByAddr := make(map[string]*sstream.Client, len(clients))
	for _, c := range clients {
		clientByAddr[c.Address()] = c
	}

	payload := make([]byte, 256) // fixed 256-byte payload

	for range ticker.C {
		addr, skipped := bal.Next()
		if addr == "" {
			metrics.MessagesDropped.Inc()
			continue
		}
		for _, s := range skipped {
			metrics.MessagesRerouted.WithLabelValues(s).Inc()
		}
		c := clientByAddr[addr]
		c.Send(&pb.Message{
			Id:        c.NextID(),
			Timestamp: time.Now().UnixNano(),
			Payload:   payload,
		})
	}
}

