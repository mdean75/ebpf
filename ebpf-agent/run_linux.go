//go:build linux

package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/loader"
	agentmetrics "github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/metrics"
	"github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/tracker"
)

func startRingBufferReaders(progs *loader.Programs, t *tracker.Tracker) {
	go readRingBuffer(progs.RingBuffer(), t)

	rttRB, err := progs.RTTRingBuffer()
	if err != nil {
		log.Fatalf("rtt ring buffer: %v", err)
	}
	go readRingBuffer(rttRB, t)

	soRB, err := progs.SockopsRingBuffer()
	if err != nil {
		log.Fatalf("sockops ring buffer: %v", err)
	}
	go readRingBuffer(soRB, t)

	unackedRB, err := progs.UnackedRingBuffer()
	if err != nil {
		log.Fatalf("unacked ring buffer: %v", err)
	}
	go readRingBuffer(unackedRB, t)
}

func readRingBuffer(rb *ringbuf.Reader, t *tracker.Tracker) {
	for {
		rec, err := rb.Read()
		if err != nil {
			log.Printf("ring buffer read: %v", err)
			return
		}
		ev, err := tracker.ParseEvent(rec.RawSample)
		if err != nil {
			log.Printf("parse event: %v", err)
			continue
		}
		t.Record(ev)

		labels := connLabels(ev.Key)
		switch ev.EventType {
		case tracker.EventRetransmit:
			agentmetrics.RetransmitsTotal.WithLabelValues(labels...).Inc()
		case tracker.EventRTO:
			agentmetrics.RTOTotal.WithLabelValues(labels...).Inc()
		case tracker.EventRTTSpike:
			agentmetrics.RTTSpikeTotal.WithLabelValues(labels...).Inc()
		case tracker.EventUnacked:
			agentmetrics.UnackedTotal.WithLabelValues(labels...).Inc()
		}
	}
}

func connLabels(k tracker.ConnKey) []string {
	return []string{
		k.SaddrIP(),
		k.DaddrIP(),
		fmt.Sprintf("%d", k.Dport),
	}
}
