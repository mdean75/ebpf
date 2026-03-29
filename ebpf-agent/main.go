package main

import (
	"log"
	"net/http"
	"os"
	ossignal "os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/loader"
	agentmetrics "github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/metrics"
	"github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/signal"
	"github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/tracker"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
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

	t := tracker.New()

	// Score decay + Prometheus sync every 100ms
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			t.Decay()
			for _, h := range t.All() {
				agentmetrics.ConnectionScore.WithLabelValues(connLabels(h.Key)...).Set(h.Score)
			}
		}
	}()

	// Platform-specific ring buffer readers (linux: real; other: no-op)
	startRingBufferReaders(progs, t)

	// HTTP signal API on :9090
	signalSrv := signal.New(t, ":9090")
	go func() {
		log.Println("signal API on :9090")
		if err := signalSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("signal server: %v", err)
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
	return loader.Config{
		TargetPort:    port,
		RTTMultiplier: mult,
		CgroupPath:    detectCgroupPath(),
	}
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
