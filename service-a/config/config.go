package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	VMAddresses        []string
	MessagesPerSecond  int
	HeartbeatInterval  time.Duration
	HeartbeatTimeout   time.Duration
	LBMode             string // "ebpf", "baseline", or "protopulse"
	EBPFAgentAddr      string // HTTP signal API (kept for debugging)
	EBPFAgentGRPCAddr  string // gRPC health stream
	TLSCACert          string
	ProtopulsePollInterval time.Duration
}

func Load() Config {
	return Config{
		VMAddresses:            splitCSV(os.Getenv("VM_ADDRESSES")),
		MessagesPerSecond:      getInt("MESSAGES_PER_SECOND", 200),
		HeartbeatInterval:      getDuration("HEARTBEAT_INTERVAL", 500*time.Millisecond),
		HeartbeatTimeout:       getDuration("HEARTBEAT_TIMEOUT", 2*time.Second),
		LBMode:                 getEnv("LB_MODE", "ebpf"),
		EBPFAgentAddr:          getEnv("EBPF_AGENT_ADDR", "localhost:9090"),
		EBPFAgentGRPCAddr:      getEnv("EBPF_AGENT_GRPC_ADDR", "localhost:9092"),
		TLSCACert:              os.Getenv("TLS_CA_CERT"),
		ProtopulsePollInterval: getDuration("PROTOPULSE_POLL_INTERVAL", 200*time.Millisecond),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func getInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return fallback
	}
	return n
}

func getDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
