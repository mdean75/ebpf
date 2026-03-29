// Package tracker maintains per-connection health state derived from eBPF events.
package tracker

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// EventType mirrors the C constants in common.h.
type EventType uint8

const (
	EventRetransmit EventType = 1
	EventRTO        EventType = 2
	EventRTTSpike   EventType = 3
	EventUnacked    EventType = 4
)

// ConnKey is the Go equivalent of struct conn_key in common.h.
// Addresses and ports are in network byte order as received from the kernel.
type ConnKey struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
}

func (k ConnKey) String() string {
	src := fmt.Sprintf("%s:%d", uint32ToIP(k.Saddr), networkToHost16(k.Sport))
	dst := fmt.Sprintf("%s:%d", uint32ToIP(k.Daddr), networkToHost16(k.Dport))
	return src + "->" + dst
}

// SaddrIP returns the source IP as a string.
func (k ConnKey) SaddrIP() string {
	return uint32ToIP(k.Saddr)
}

// DaddrIP returns the destination IP as a string (for matching against VM addresses).
func (k ConnKey) DaddrIP() string {
	return uint32ToIP(k.Daddr)
}

// ConnEvent is the Go equivalent of struct conn_event in common.h.
type ConnEvent struct {
	Key          ConnKey
	TimestampNS  uint64
	EventType    EventType
	SrttUs       uint32
	RetransCount uint8
}

// ConnectionHealth tracks the inferred health state of one TCP connection.
type ConnectionHealth struct {
	Key             ConnKey
	RetransmitCount uint32
	LastRetransmit  time.Time
	LastRTO         time.Time
	RTTSpikeCount   uint32
	Score           float64 // 0.0 (healthy) → 1.0 (dead)
	// Degraded uses hysteresis: set when Score crosses above 0.5,
	// cleared only when Score falls below 0.25. This prevents rapid
	// healthy↔degraded oscillation when the score hovers near the threshold.
	Degraded  bool
	UpdatedAt time.Time
}

func (h *ConnectionHealth) Status() string {
	if h.Degraded {
		return "degraded"
	}
	return "healthy"
}

// Tracker maintains per-connection health state and applies score decay.
type Tracker struct {
	mu    sync.RWMutex
	conns map[ConnKey]*ConnectionHealth

	// Score weights, configurable for testing
	retransmitWeight float64 // added per retransmit event
	rtoWeight        float64 // added per RTO event
	rttSpikeWeight   float64 // added per RTT spike event
	unackedWeight    float64 // added per unacked threshold crossing

	lastDecay time.Time
}

// New returns a Tracker with the default score weights from the plan:
//   - retransmit: +0.1
//   - RTO: +0.3
//   - RTT spike: +0.1
//   - unacked threshold crossing: +0.6 (single event immediately crosses the
//     0.5 degraded threshold — the BPF program fires at most once per crossing
//     so this weight is intentionally high)
func New() *Tracker {
	return &Tracker{
		conns:            make(map[ConnKey]*ConnectionHealth),
		retransmitWeight: 0.1,
		rtoWeight:        0.3,
		rttSpikeWeight:   0.1,
		unackedWeight:    0.6,
		lastDecay:        time.Now(),
	}
}

// Record ingests a conn_event and updates the connection's score.
func (t *Tracker) Record(ev ConnEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()

	h := t.getOrCreate(ev.Key)
	h.UpdatedAt = time.Now()

	switch ev.EventType {
	case EventRetransmit:
		h.RetransmitCount++
		h.LastRetransmit = h.UpdatedAt
		h.Score = clamp(h.Score+t.retransmitWeight, 0, 1)
	case EventRTO:
		h.LastRTO = h.UpdatedAt
		h.Score = clamp(h.Score+t.rtoWeight, 0, 1)
	case EventRTTSpike:
		h.RTTSpikeCount++
		h.Score = clamp(h.Score+t.rttSpikeWeight, 0, 1)
	case EventUnacked:
		h.Score = clamp(h.Score+t.unackedWeight, 0, 1)
	}
	// Hysteresis: enter degraded at >0.5, only exit at <0.25 (in Decay).
	if !h.Degraded && h.Score > 0.5 {
		h.Degraded = true
	}
}

// Decay applies time-based score decay to all connections.
// Must be called periodically (e.g. every 100ms).
//
// Decay rates (from the plan):
//   - retransmit contribution: 0.05/second
//   - RTO contribution: 0.1/second
//
// We apply a single composite decay of 0.05/second to the total score.
// This is a simplification; individual event decay is handled by the score
// weight system rather than per-event tracking.
func (t *Tracker) Decay() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(t.lastDecay).Seconds()
	t.lastDecay = now

	const decayPerSecond = 0.05
	decay := decayPerSecond * elapsed

	// Prune stale entries: connections not updated in >15s have closed.
	// 15s is safe at 200 msg/s (events arrive every few ms on an active stream).
	// Without pruning, old entries from prior runs with the same VM IP but a
	// different source port linger and cause false positives when service-a
	// restarts and the poller matches on destination IP across all entries.
	const staleThreshold = 15 * time.Second

	for key, h := range t.conns {
		if now.Sub(h.UpdatedAt) > staleThreshold {
			delete(t.conns, key)
			continue
		}
		if h.Score > 0 {
			h.Score = clamp(h.Score-decay, 0, 1)
		}
		// Clear degraded only when score falls well below the entry threshold (0.5).
		// The 0.25 gap prevents re-oscillation when score hovers near 0.5.
		if h.Degraded && h.Score < 0.25 {
			h.Degraded = false
		}
		// Prune fully-recovered entries immediately — no need to retain a
		// score=0 healthy entry; if the connection re-appears it starts fresh.
		if h.Score == 0 && !h.Degraded {
			delete(t.conns, key)
		}
	}
}

// All returns a snapshot of all tracked connections.
func (t *Tracker) All() []ConnectionHealth {
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]ConnectionHealth, 0, len(t.conns))
	for _, h := range t.conns {
		out = append(out, *h)
	}
	return out
}

// Get returns the health for a specific connection, or nil if not tracked.
func (t *Tracker) Get(key ConnKey) *ConnectionHealth {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if h, ok := t.conns[key]; ok {
		copy := *h
		return &copy
	}
	return nil
}

func (t *Tracker) getOrCreate(key ConnKey) *ConnectionHealth {
	if h, ok := t.conns[key]; ok {
		return h
	}
	h := &ConnectionHealth{
		Key:       key,
		UpdatedAt: time.Now(),
	}
	t.conns[key] = h
	return h
}

// ParseEvent parses a raw ring buffer record into a ConnEvent.
// The layout matches struct conn_event in common.h (little-endian).
func ParseEvent(data []byte) (ConnEvent, error) {
	// conn_key: 4+4+2+2+4 = 16 bytes
	// conn_event: 16 + 8 + 1 + 4 + 1 = 30 bytes (with padding may be 32)
	if len(data) < 30 {
		return ConnEvent{}, fmt.Errorf("short record: %d bytes", len(data))
	}
	var ev ConnEvent
	ev.Key.Saddr = binary.LittleEndian.Uint32(data[0:4])
	ev.Key.Daddr = binary.LittleEndian.Uint32(data[4:8])
	ev.Key.Sport = binary.LittleEndian.Uint16(data[8:10])
	ev.Key.Dport = binary.LittleEndian.Uint16(data[10:12])
	// pad[4] at bytes 12:16
	ev.TimestampNS = binary.LittleEndian.Uint64(data[16:24])
	ev.EventType = EventType(data[24])
	// 3 bytes padding to align srtt_us
	ev.SrttUs = binary.LittleEndian.Uint32(data[28:32])
	if len(data) >= 33 {
		ev.RetransCount = data[32]
	}
	return ev, nil
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// uint32ToIP converts a kernel IPv4 address to a dotted-decimal string.
// The kernel stores IPv4 addresses in network byte order; on a little-endian
// host (x86_64), reading skc_daddr as uint32 gives bytes in reverse order.
// e.g. 192.168.122.10 → kernel uint32 = 0x0A7AA8C0 → "192.168.122.10"
func uint32ToIP(n uint32) string {
	return net.IP{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}.String()
}

func networkToHost16(n uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return binary.LittleEndian.Uint16(b)
}
