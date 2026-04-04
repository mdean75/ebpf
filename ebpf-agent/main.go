package main

import (
	"log"
	"net"
	"net/http"
	"os"
	ossignal "os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/healthstream"
	"github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/loader"
	agentmetrics "github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/metrics"
	"github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/signal"
	"github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/tracker"
	pb "github.com/mdean75/ebpf-grpc-experiment/proto/health"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	cfg := loadConfig()
	log.Printf("ebpf-agent starting: target_port=%d cgroup=%s", cfg.TargetPort, cfg.CgroupPath)

	if err := loader.VerifyCgroupV2(cfg.CgroupPath); err != nil {
		log.Fatalf("cgroup check: %v", err)
	}

	progs, err := loader.Load(cfg)
	if err != nil {
		log.Fatalf("load eBPF programs: %v", err)
	}
	defer progs.Close()

	t := tracker.New(loadTrackerConfig())

	// Stale pruning + inactivity decay + Prometheus sync every 100ms
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			t.Prune()
			for _, h := range t.All() {
				agentmetrics.ConnectionScore.WithLabelValues(connLabels(h.Key)...).Set(h.RiskScore)
			}
		}
	}()

	// Platform-specific ring buffer readers (linux: real; other: no-op)
	startRingBufferReaders(progs, t)

	// HTTP signal API on :9090 (kept for manual inspection/debugging)
	signalSrv := signal.New(t, ":9090")
	go func() {
		log.Println("signal API on :9090")
		if err := signalSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("signal server: %v", err)
		}
	}()

	// gRPC health stream on :9092 — push-based state change notifications
	grpcLis, err := net.Listen("tcp", ":9092")
	if err != nil {
		log.Fatalf("grpc listen: %v", err)
	}
	grpcSrv := grpc.NewServer()
	pb.RegisterHealthWatcherServer(grpcSrv, healthstream.New(t))
	go func() {
		log.Println("health stream gRPC on :9092")
		if err := grpcSrv.Serve(grpcLis); err != nil {
			log.Printf("grpc server: %v", err)
		}
	}()

	// Prometheus metrics on :9091
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		log.Println("Prometheus metrics on :9091/metrics")
		if err := http.ListenAndServe(":9091", mux); err != nil {
			log.Printf("metrics server: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	ossignal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
}

func loadConfig() loader.Config {
	port := uint16(443)
	if v := os.Getenv("TARGET_PORT"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 16); err == nil {
			port = uint16(n)
		}
	}
	mult := uint16(3)
	if v := os.Getenv("RTT_MULTIPLIER"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 16); err == nil {
			mult = uint16(n)
		}
	}
	thresh := uint16(5)
	if v := os.Getenv("UNACKED_THRESHOLD"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 16); err == nil {
			thresh = uint16(n)
		}
	}
	return loader.Config{
		TargetPort:       port,
		RTTMultiplier:    mult,
		UnackedThreshold: thresh,
		CgroupPath:       detectCgroupPath(),
	}
}

// loadTrackerConfig builds a TrackerConfig from environment variables,
// falling back to defaults that mirror nethealth's DefaultThresholds.
//
// Preset: TRACKER_PRESET=default|conservative|high_throughput loads a bundle.
// Individual vars override the preset (all optional).
//
// Threshold vars (float): UNACKED_SOFT, UNACKED_HARD, RETRANS_SOFT, RETRANS_HARD,
//
//	SPIKES_SOFT, SPIKES_HARD, RTO_SOFT, RTO_HARD
//
// Weight vars (float, must sum to 1.0): WEIGHT_UNACKED, WEIGHT_RETRANS, WEIGHT_SPIKES, WEIGHT_RTO
// EMA alpha vars (float 0-1): ALPHA_UNACKED, ALPHA_RETRANS, ALPHA_SPIKES, ALPHA_RTO
// Hysteresis vars (int): ESCALATE_AFTER, RECOVER_AFTER
// Decay vars (float): INACTIVITY_SECONDS, DECAY_FACTOR
// Band vars (float): WARN_ABOVE, SICK_ABOVE, CRIT_ABOVE
func loadTrackerConfig() tracker.TrackerConfig {
	cfg := tracker.DefaultTrackerConfig()

	switch os.Getenv("TRACKER_PRESET") {
	case "conservative":
		cfg.Unacked = tracker.MetricThreshold{Soft: 3, Hard: 10}
		cfg.Retrans = tracker.MetricThreshold{Soft: 1, Hard: 5}
		cfg.Spikes = tracker.MetricThreshold{Soft: 1, Hard: 3}
		cfg.RTO = tracker.MetricThreshold{Soft: 1, Hard: 2}
	case "high_throughput":
		cfg.Unacked = tracker.MetricThreshold{Soft: 20, Hard: 100}
		cfg.Retrans = tracker.MetricThreshold{Soft: 5, Hard: 50}
		cfg.Spikes = tracker.MetricThreshold{Soft: 3, Hard: 10}
		cfg.RTO = tracker.MetricThreshold{Soft: 2, Hard: 8}
	}

	overrideFloat := func(dst *float64, env string) {
		if v := os.Getenv(env); v != "" {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				*dst = f
			}
		}
	}
	overrideInt := func(dst *int, env string) {
		if v := os.Getenv(env); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				*dst = n
			}
		}
	}

	overrideFloat(&cfg.Unacked.Soft, "UNACKED_SOFT")
	overrideFloat(&cfg.Unacked.Hard, "UNACKED_HARD")
	overrideFloat(&cfg.Retrans.Soft, "RETRANS_SOFT")
	overrideFloat(&cfg.Retrans.Hard, "RETRANS_HARD")
	overrideFloat(&cfg.Spikes.Soft, "SPIKES_SOFT")
	overrideFloat(&cfg.Spikes.Hard, "SPIKES_HARD")
	overrideFloat(&cfg.RTO.Soft, "RTO_SOFT")
	overrideFloat(&cfg.RTO.Hard, "RTO_HARD")

	overrideFloat(&cfg.UnackedWeight, "WEIGHT_UNACKED")
	overrideFloat(&cfg.RetransWeight, "WEIGHT_RETRANS")
	overrideFloat(&cfg.SpikesWeight, "WEIGHT_SPIKES")
	overrideFloat(&cfg.RTOWeight, "WEIGHT_RTO")

	overrideFloat(&cfg.AlphaUnacked, "ALPHA_UNACKED")
	overrideFloat(&cfg.AlphaRetrans, "ALPHA_RETRANS")
	overrideFloat(&cfg.AlphaSpikes, "ALPHA_SPIKES")
	overrideFloat(&cfg.AlphaRTO, "ALPHA_RTO")

	overrideInt(&cfg.EscalateAfter, "ESCALATE_AFTER")
	overrideInt(&cfg.RecoverAfter, "RECOVER_AFTER")

	overrideFloat(&cfg.InactivitySeconds, "INACTIVITY_SECONDS")
	overrideFloat(&cfg.DecayFactor, "DECAY_FACTOR")

	overrideFloat(&cfg.WarnAbove, "WARN_ABOVE")
	overrideFloat(&cfg.SickAbove, "SICK_ABOVE")
	overrideFloat(&cfg.CritAbove, "CRIT_ABOVE")

	return cfg
}

// detectCgroupPath returns the cgroupv2 path for sockops attachment.
//
// When running inside a Docker container, auto-detects the container's own
// cgroup path so that sockops covers service-a (which shares the container
// cgroup). On a VM with systemd, returns the root cgroup "/sys/fs/cgroup"
// which covers all processes including the separate service-a unit.
// CGROUP_PATH env var overrides all auto-detection.
func detectCgroupPath() string {
	if p := os.Getenv("CGROUP_PATH"); p != "" {
		return p
	}
	// Detect Docker container via /.dockerenv marker.
	if _, err := os.Stat("/.dockerenv"); err == nil {
		data, err := os.ReadFile("/proc/self/cgroup")
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				parts := strings.SplitN(line, ":", 3)
				// cgroupv2 unified hierarchy has hierarchy id "0"
				if len(parts) == 3 && parts[0] == "0" {
					rel := strings.TrimSpace(parts[2])
					if rel != "" && rel != "/" {
						return filepath.Join("/sys/fs/cgroup", rel)
					}
				}
			}
		}
	}
	return "/sys/fs/cgroup"
}
