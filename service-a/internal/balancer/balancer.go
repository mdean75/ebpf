package balancer

import (
	"log"
	"sync"
	"time"
)

type StreamHealth int

const (
	Healthy  StreamHealth = iota
	Degraded              // eBPF agent signals degradation; stream still alive
	Dead                  // stream closed or heartbeat timeout
)

func (h StreamHealth) String() string {
	switch h {
	case Healthy:
		return "healthy"
	case Degraded:
		return "degraded"
	case Dead:
		return "dead"
	default:
		return "unknown"
	}
}

type Mode string

const (
	ModeEBPF     Mode = "ebpf"
	ModeBaseline Mode = "baseline"
)

type StreamState struct {
	Address   string
	Health    StreamHealth
	Reason    string // "ebpf_signal", "heartbeat_timeout", "send_error"
	UpdatedAt time.Time
}

// Balancer maintains per-stream health state and performs round-robin selection.
//
// In ebpf mode: Degraded streams are skipped when routing.
// In baseline mode: only Dead streams are skipped; Degraded streams still receive traffic.
type Balancer struct {
	mu      sync.Mutex
	streams map[string]*StreamState
	keys    []string // ordered for stable round-robin
	idx     int
	mode    Mode
}

func New(addresses []string, mode Mode) *Balancer {
	streams := make(map[string]*StreamState, len(addresses))
	keys := make([]string, len(addresses))
	for i, addr := range addresses {
		streams[addr] = &StreamState{
			Address:   addr,
			Health:    Healthy,
			UpdatedAt: time.Now(),
		}
		keys[i] = addr
	}
	return &Balancer{
		streams: streams,
		keys:    keys,
		mode:    mode,
	}
}

// Next returns the next routable address in round-robin order, skipping streams
// that are not routable in the current mode. Returns "" if all streams are down.
func (b *Balancer) Next() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	n := len(b.keys)
	for range n {
		addr := b.keys[b.idx%n]
		b.idx++
		s := b.streams[addr]
		if b.routable(s.Health) {
			return addr
		}
	}
	return ""
}

func (b *Balancer) routable(h StreamHealth) bool {
	switch h {
	case Healthy:
		return true
	case Degraded:
		// In baseline mode we still route to degraded streams — only the
		// heartbeat timeout will eventually mark them Dead.
		return b.mode == ModeBaseline
	default:
		return false
	}
}

// SetHealth updates the health of a stream and logs the transition.
func (b *Balancer) SetHealth(addr string, health StreamHealth, reason string) {
	b.mu.Lock()
	s, ok := b.streams[addr]
	if !ok {
		b.mu.Unlock()
		return
	}
	prev := s.Health
	s.Health = health
	s.Reason = reason
	s.UpdatedAt = time.Now()
	b.mu.Unlock()

	if prev != health {
		log.Printf("stream %s: %s -> %s (reason=%s)", addr, prev, health, reason)
	}
}

func (b *Balancer) GetHealth(addr string) StreamHealth {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s, ok := b.streams[addr]; ok {
		return s.Health
	}
	return Dead
}

func (b *Balancer) SetMode(mode Mode) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mode = mode
	log.Printf("balancer mode set to %s", mode)
}

func (b *Balancer) Mode() Mode {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.mode
}

// All returns a snapshot of all stream states.
func (b *Balancer) All() []StreamState {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]StreamState, 0, len(b.streams))
	for _, s := range b.streams {
		out = append(out, *s)
	}
	return out
}
