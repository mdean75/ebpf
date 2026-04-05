// Package tracker maintains per-connection health state derived from eBPF events.
package tracker

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sync"
	"time"
)

// HealthTransition is emitted when a connection's health state changes.
// Sent on the channel returned by Tracker.Events().
type HealthTransition struct {
	DaddrIP     string
	Score       float64
	Status      string      // "healthy" or "degraded" — backward compat for service-a
	ActionLevel ActionLevel // HEALTHY/WARNING/SICK/CRITICAL/DEAD
}

// ActionLevel mirrors nethealth's ActionLevel type for like-for-like comparison.
type ActionLevel string

const (
	ActionHealthy  ActionLevel = "HEALTHY"
	ActionWarning  ActionLevel = "WARNING"
	ActionSick     ActionLevel = "SICK"
	ActionCritical ActionLevel = "CRITICAL"
	ActionDead     ActionLevel = "DEAD"
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

// MetricThreshold defines soft and hard boundaries for a metric,
// matching nethealth's MetricThreshold type.
type MetricThreshold struct {
	Soft float64
	Hard float64
}

// TrackerConfig holds all configurable scoring parameters, aligned with
// nethealth's MonitorConfig shape to enable like-for-like comparison.
type TrackerConfig struct {
	// Soft/hard thresholds for each signal.
	// Unacked uses packet counts (packets_out from kernel), unlike nethealth's bytes.
	Unacked MetricThreshold // packets_out; default {Soft:5, Hard:20}
	Retrans MetricThreshold // cumulative retransmit count; default {Soft:2, Hard:10}
	Spikes  MetricThreshold // cumulative RTT spike count; default {Soft:1, Hard:5}
	RTO     MetricThreshold // cumulative RTO count; default {Soft:1, Hard:3}

	// Metric weights — must sum to 1.0.
	// No SendQ or TCP-state signal in eBPF agent; weight redistributed to RTT/RTO.
	UnackedWeight float64 // default 0.35
	RetransWeight float64 // default 0.35
	SpikesWeight  float64 // default 0.20
	RTOWeight     float64 // default 0.10

	// EMA smoothing alphas — higher = faster response to new data.
	AlphaUnacked float64 // default 0.4
	AlphaRetrans float64 // default 0.5
	AlphaSpikes  float64 // default 0.4
	AlphaRTO     float64 // default 0.4

	// Hysteresis: consecutive worsening/improving observations to change action level.
	EscalateAfter int // default 3
	RecoverAfter  int // default 3

	// Inactivity decay: after InactivitySeconds idle, risk is multiplied by
	// DecayFactor for each InactivitySeconds interval elapsed.
	InactivitySeconds float64 // default 10
	DecayFactor       float64 // default 0.90

	// Action band boundaries on the 0-100 risk scale (matches nethealth defaults).
	WarnAbove float64 // default 20
	SickAbove float64 // default 50
	CritAbove float64 // default 80
}

// DefaultTrackerConfig returns a TrackerConfig with defaults that mirror
// nethealth's DefaultThresholds for the signals that overlap.
func DefaultTrackerConfig() TrackerConfig {
	return TrackerConfig{
		Unacked: MetricThreshold{Soft: 3, Hard: 20},
		Retrans: MetricThreshold{Soft: 0, Hard: 3}, // matches protopulse: fires on first retransmit
		Spikes:  MetricThreshold{Soft: 1, Hard: 5},
		RTO:     MetricThreshold{Soft: 1, Hard: 3},

		UnackedWeight: 0.35,
		RetransWeight: 0.35,
		SpikesWeight:  0.20,
		RTOWeight:     0.10,

		AlphaUnacked: 0.4,
		AlphaRetrans: 0.8, // matches protopulse: fast EMA response to retransmits
		AlphaSpikes:  0.4,
		AlphaRTO:     0.4,

		EscalateAfter: 1, // matches protopulse: escalate on first threshold crossing
		RecoverAfter:  3,

		InactivitySeconds: 10,
		DecayFactor:       0.90,

		WarnAbove: 20,
		SickAbove: 50,
		CritAbove: 80,
	}
}

// ConnectionHealth tracks the inferred health state of one TCP connection.
type ConnectionHealth struct {
	Key ConnKey

	// Raw metric values — latest snapshot or accumulated count.
	PacketsOut   float64 // latest packets_out from EVENT_UNACKED (reused retrans_count field)
	RetransCount float64 // accumulated EVENT_RETRANSMIT events
	SpikeCount   float64 // accumulated EVENT_RTT_SPIKE events
	RTOCount     float64 // accumulated EVENT_RTO events

	// EMA-smoothed values (updated on every recomputeScore call).
	EMAUnacked float64
	EMARetrans float64
	EMASpikes  float64
	EMARTO     float64

	// Scoring state.
	RiskScore      float64     // 0-100; higher = worse (matches nethealth's RiskScore scale)
	Action         ActionLevel // current action level post-hysteresis
	EscalateStreak int         // consecutive worsening observations
	RecoverStreak  int         // consecutive improving observations

	// Timing.
	LastActivity time.Time
	UpdatedAt    time.Time

	firstObs bool // true until first recomputeScore call; seeds EMA from raw values
}

// Status returns "healthy" or "degraded" for backward compatibility
// with service-a's HealthEvent consumer.
func (h *ConnectionHealth) Status() string {
	if h.Action == ActionHealthy {
		return "healthy"
	}
	return "degraded"
}

// Tracker maintains per-connection health state.
type Tracker struct {
	mu     sync.RWMutex
	conns  map[ConnKey]*ConnectionHealth
	cfg    TrackerConfig
	events chan HealthTransition
}

// New returns a Tracker using the provided configuration.
func New(cfg TrackerConfig) *Tracker {
	return &Tracker{
		conns:  make(map[ConnKey]*ConnectionHealth),
		cfg:    cfg,
		events: make(chan HealthTransition, 64),
	}
}

// Events returns the channel on which health state transitions are published.
// Each send is non-blocking; events are dropped if the consumer is too slow.
func (t *Tracker) Events() <-chan HealthTransition {
	return t.events
}

// Record ingests a conn_event, updates the connection's raw metrics,
// and recomputes its health score.
func (t *Tracker) Record(ev ConnEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	h := t.getOrCreate(ev.Key)
	h.UpdatedAt = now

	switch ev.EventType {
	case EventUnacked:
		// unacked.c repurposes the retrans_count field to carry packets_out (capped at 255).
		h.PacketsOut = float64(ev.RetransCount)
		h.LastActivity = now
	case EventRetransmit:
		h.RetransCount++
		h.LastActivity = now
	case EventRTTSpike:
		h.SpikeCount++
		h.LastActivity = now
	case EventRTO:
		h.RTOCount++
		h.LastActivity = now
	}

	t.recomputeAndNotify(h, now)
}

// Prune removes stale connections and recomputes scores for idle connections
// so inactivity decay can drive recovery. Call periodically from a ticker goroutine.
func (t *Tracker) Prune() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	const staleThreshold = 15 * time.Second

	for key, h := range t.conns {
		if now.Sub(h.UpdatedAt) > staleThreshold {
			delete(t.conns, key)
			continue
		}
		// Recompute on each tick to apply inactivity decay and catch recovery
		// transitions even when no new events arrive.
		t.recomputeAndNotify(h, now)
		if h.RiskScore == 0 && h.Action == ActionHealthy {
			delete(t.conns, key)
		}
	}
}

// recomputeAndNotify recomputes the connection's score and emits a HealthTransition
// if the ActionLevel has changed. Must be called with t.mu held.
func (t *Tracker) recomputeAndNotify(h *ConnectionHealth, now time.Time) {
	prev := h.Action
	h.recomputeScore(t.cfg, now)
	if h.Action == prev {
		return
	}
	status := "degraded"
	if h.Action == ActionHealthy {
		status = "healthy"
	}
	select {
	case t.events <- HealthTransition{
		DaddrIP:     h.Key.DaddrIP(),
		Score:       h.RiskScore,
		Status:      status,
		ActionLevel: h.Action,
	}:
	default:
	}
}

// recomputeScore applies the nethealth-aligned scoring pipeline:
// EMA smoothing → normalize → weighted sum → inactivity decay → action bands → hysteresis.
func (h *ConnectionHealth) recomputeScore(cfg TrackerConfig, now time.Time) {
	// Seed EMA from raw values on first call so the initial observation registers
	// immediately rather than being damped by a zero-initialized EMA.
	if h.firstObs {
		h.EMAUnacked = h.PacketsOut
		h.EMARetrans = h.RetransCount
		h.EMASpikes = h.SpikeCount
		h.EMARTO = h.RTOCount
		h.firstObs = false
	} else {
		h.EMAUnacked = cfg.AlphaUnacked*h.PacketsOut + (1-cfg.AlphaUnacked)*h.EMAUnacked
		h.EMARetrans = cfg.AlphaRetrans*h.RetransCount + (1-cfg.AlphaRetrans)*h.EMARetrans
		h.EMASpikes = cfg.AlphaSpikes*h.SpikeCount + (1-cfg.AlphaSpikes)*h.EMASpikes
		h.EMARTO = cfg.AlphaRTO*h.RTOCount + (1-cfg.AlphaRTO)*h.EMARTO
	}

	// Normalize each EMA-smoothed metric to [0, 100] via a linear soft/hard ramp.
	nUnacked := normalizeRamp(h.EMAUnacked, cfg.Unacked.Soft, cfg.Unacked.Hard)
	nRetrans := normalizeRamp(h.EMARetrans, cfg.Retrans.Soft, cfg.Retrans.Hard)
	nSpikes := normalizeRamp(h.EMASpikes, cfg.Spikes.Soft, cfg.Spikes.Hard)
	nRTO := normalizeRamp(h.EMARTO, cfg.RTO.Soft, cfg.RTO.Hard)

	// Weighted sum → raw risk [0, 100].
	raw := cfg.UnackedWeight*nUnacked +
		cfg.RetransWeight*nRetrans +
		cfg.SpikesWeight*nSpikes +
		cfg.RTOWeight*nRTO

	// Inactivity decay: reduce risk when the connection has been quiet.
	// Mirrors nethealth's StabilityConfig.InactivityDecayFactor logic.
	if !h.LastActivity.IsZero() {
		idle := now.Sub(h.LastActivity).Seconds()
		if idle >= cfg.InactivitySeconds {
			raw *= math.Pow(cfg.DecayFactor, idle/cfg.InactivitySeconds)
		}
	}

	h.RiskScore = clamp(raw, 0, 100)

	target := actionFromRisk(h.RiskScore, cfg)
	h.applyHysteresis(target, cfg)
}

// normalizeRamp maps value to [0, 100] using a linear ramp between soft and hard.
// Mirrors nethealth's normalizeRamp function exactly.
func normalizeRamp(value, soft, hard float64) float64 {
	if hard <= soft {
		if value > hard {
			return 100
		}
		return 0
	}
	return clamp(100*(value-soft)/(hard-soft), 0, 100)
}

// actionFromRisk maps a risk score to an ActionLevel using the configured band boundaries.
func actionFromRisk(risk float64, cfg TrackerConfig) ActionLevel {
	switch {
	case risk >= 100:
		return ActionDead
	case risk > cfg.CritAbove:
		return ActionCritical
	case risk > cfg.SickAbove:
		return ActionSick
	case risk > cfg.WarnAbove:
		return ActionWarning
	default:
		return ActionHealthy
	}
}

// applyHysteresis updates h.Action using consecutive-observation streak counters.
// Mirrors nethealth's stability gate logic exactly.
func (h *ConnectionHealth) applyHysteresis(target ActionLevel, cfg TrackerConfig) {
	current := actionSeverity(h.Action)
	tgt := actionSeverity(target)

	switch {
	case tgt > current:
		h.EscalateStreak++
		h.RecoverStreak = 0
		if h.EscalateStreak >= cfg.EscalateAfter {
			h.Action = target
			h.EscalateStreak = 0
		}
	case tgt < current:
		h.RecoverStreak++
		h.EscalateStreak = 0
		if h.RecoverStreak >= cfg.RecoverAfter {
			h.Action = target
			h.RecoverStreak = 0
		}
	default:
		h.EscalateStreak = 0
		h.RecoverStreak = 0
		h.Action = target
	}
}

// actionSeverity returns a numeric severity for streak comparison.
func actionSeverity(a ActionLevel) int {
	switch a {
	case ActionDead:
		return 4
	case ActionCritical:
		return 3
	case ActionSick:
		return 2
	case ActionWarning:
		return 1
	default:
		return 0
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
		Action:    ActionHealthy,
		firstObs:  true,
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
