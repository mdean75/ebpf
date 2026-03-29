package config

import (
	"os"
	"time"
)

type Config struct {
	GRPCPort        string
	HealthPort      string
	ProcessingDelay time.Duration
}

func Load() Config {
	return Config{
		GRPCPort:        getEnv("GRPC_PORT", "50051"),
		HealthPort:      getEnv("HEALTH_PORT", "8080"),
		ProcessingDelay: getDuration("PROCESSING_DELAY", time.Millisecond),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
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
