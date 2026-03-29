//go:build !linux

package main

import (
	"log"

	"github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/loader"
	"github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/tracker"
)

func startRingBufferReaders(_ *loader.Programs, _ *tracker.Tracker) {
	log.Println("ring buffer readers: no-op on non-Linux platform")
}

func connLabels(_ tracker.ConnKey) []string {
	return []string{"", "", ""}
}
