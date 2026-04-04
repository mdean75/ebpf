package tracker

import (
	"testing"
	"time"
)

var testKey = ConnKey{Saddr: 0x0101010a, Daddr: 0x0a010101, Sport: 12345, Dport: 443}

// cfg returns a TrackerConfig with tight thresholds for deterministic testing.
// EscalateAfter=1 so a single worsening observation triggers a state change immediately.
func testCfg() TrackerConfig {
	cfg := DefaultTrackerConfig()
	cfg.EscalateAfter = 1
	cfg.RecoverAfter = 1
	return cfg
}

func TestRecord_Retransmit_UpdatesCount(t *testing.T) {
	tr := New(testCfg())
	tr.Record(ConnEvent{Key: testKey, EventType: EventRetransmit})

	h := tr.Get(testKey)
	if h == nil {
		t.Fatal("expected connection to be tracked")
	}
	if h.RetransCount != 1 {
		t.Errorf("expected RetransCount=1, got %.0f", h.RetransCount)
	}
}

func TestRecord_Unacked_SetsPacketsOut(t *testing.T) {
	tr := New(testCfg())
	tr.Record(ConnEvent{Key: testKey, EventType: EventUnacked, RetransCount: 10})

	h := tr.Get(testKey)
	if h == nil {
		t.Fatal("expected connection to be tracked")
	}
	if h.PacketsOut != 10 {
		t.Errorf("expected PacketsOut=10, got %.0f", h.PacketsOut)
	}
}

func TestRecord_RTO_UpdatesCount(t *testing.T) {
	tr := New(testCfg())
	tr.Record(ConnEvent{Key: testKey, EventType: EventRTO})

	h := tr.Get(testKey)
	if h.RTOCount != 1 {
		t.Errorf("expected RTOCount=1, got %.0f", h.RTOCount)
	}
}

func TestRecord_RTTSpike_UpdatesCount(t *testing.T) {
	tr := New(testCfg())
	tr.Record(ConnEvent{Key: testKey, EventType: EventRTTSpike})

	h := tr.Get(testKey)
	if h.SpikeCount != 1 {
		t.Errorf("expected SpikeCount=1, got %.0f", h.SpikeCount)
	}
}

func TestRiskScore_BelowSoftThreshold_StaysHealthy(t *testing.T) {
	tr := New(testCfg())
	// Retrans soft=2: one retransmit (count=1) stays below soft — score stays low.
	tr.Record(ConnEvent{Key: testKey, EventType: EventRetransmit})

	h := tr.Get(testKey)
	if h.Action != ActionHealthy {
		t.Errorf("expected HEALTHY with retrans=1 (below soft=2), got %s (risk=%.1f)", h.Action, h.RiskScore)
	}
}

func TestRiskScore_AboveHardThreshold_DegradesFast(t *testing.T) {
	cfg := testCfg()
	// Unacked hard=20: fire enough unacked events to saturate the metric.
	tr := New(cfg)
	for range 5 {
		tr.Record(ConnEvent{Key: testKey, EventType: EventUnacked, RetransCount: 25}) // > hard threshold
	}

	h := tr.Get(testKey)
	if h.Action == ActionHealthy {
		t.Errorf("expected degraded with packets_out=25 (above hard=20), got HEALTHY (risk=%.1f)", h.RiskScore)
	}
}

func TestStatus_BackwardCompat(t *testing.T) {
	h := &ConnectionHealth{Action: ActionHealthy}
	if h.Status() != "healthy" {
		t.Errorf("expected 'healthy', got %q", h.Status())
	}
	h.Action = ActionSick
	if h.Status() != "degraded" {
		t.Errorf("expected 'degraded' for SICK, got %q", h.Status())
	}
	h.Action = ActionWarning
	if h.Status() != "degraded" {
		t.Errorf("expected 'degraded' for WARNING, got %q", h.Status())
	}
}

func TestHysteresis_EscalateAfter3(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cfg.EscalateAfter = 3 // explicit: test streak behavior independent of default
	tr := New(cfg)

	// Saturate unacked well above hard threshold on every event.
	// With EscalateAfter=3, need 3 consecutive worsening observations.
	for i := range 3 {
		tr.Record(ConnEvent{Key: testKey, EventType: EventUnacked, RetransCount: 255})
		h := tr.Get(testKey)
		if i < 2 && h.Action != ActionHealthy {
			t.Errorf("observation %d: expected HEALTHY (streak not yet met), got %s", i+1, h.Action)
		}
	}
	h := tr.Get(testKey)
	if h.Action == ActionHealthy {
		t.Errorf("after 3 worsening observations, expected escalation past HEALTHY, got %s", h.Action)
	}
}

func TestHysteresis_RecoveryAfter3(t *testing.T) {
	cfg := DefaultTrackerConfig() // RecoverAfter=3
	// EscalateAfter=1 to quickly enter degraded; AlphaUnacked=1.0 so EMA tracks raw
	// value immediately — isolates the hysteresis streak logic from EMA lag.
	cfg.EscalateAfter = 1
	cfg.AlphaUnacked = 1.0
	tr := New(cfg)

	// Push into degraded state.
	tr.Record(ConnEvent{Key: testKey, EventType: EventUnacked, RetransCount: 255})
	h := tr.Get(testKey)
	if h.Action == ActionHealthy {
		t.Fatal("expected degraded state after saturated unacked event")
	}

	// Send 3 observations with packets_out=0 — EMA drops immediately to 0.
	// Streak must reach RecoverAfter=3 before action changes.
	for i := range 3 {
		tr.Record(ConnEvent{Key: testKey, EventType: EventUnacked, RetransCount: 0})
		h = tr.Get(testKey)
		if i < 2 && h.Action == ActionHealthy {
			t.Errorf("observation %d: recovered too early (RecoverAfter=3)", i+1)
		}
	}
	h = tr.Get(testKey)
	if h.Action != ActionHealthy {
		t.Errorf("after 3 improving observations, expected HEALTHY, got %s (risk=%.1f)", h.Action, h.RiskScore)
	}
}

func TestInactivityDecay_ReducesRisk(t *testing.T) {
	cfg := testCfg()
	cfg.InactivitySeconds = 1 // 1s for fast test
	cfg.DecayFactor = 0.50    // 50% per interval
	tr := New(cfg)

	// Push some risk in.
	tr.Record(ConnEvent{Key: testKey, EventType: EventUnacked, RetransCount: 25})
	h := tr.Get(testKey)
	riskBefore := h.RiskScore

	// Manually backdating LastActivity simulates idle time.
	tr.mu.Lock()
	conn := tr.conns[testKey]
	conn.LastActivity = time.Now().Add(-5 * time.Second)
	tr.mu.Unlock()

	tr.Prune()
	h = tr.Get(testKey)
	if h == nil {
		// Entry may have been pruned if risk hit zero — that's also valid decay behavior.
		return
	}
	if h.RiskScore >= riskBefore {
		t.Errorf("expected risk to decrease via inactivity decay: before=%.1f after=%.1f", riskBefore, h.RiskScore)
	}
}

func TestPrune_RemovesStaleConnections(t *testing.T) {
	tr := New(testCfg())
	tr.Record(ConnEvent{Key: testKey, EventType: EventRetransmit})

	// Backdate UpdatedAt past the 15s stale threshold.
	tr.mu.Lock()
	tr.conns[testKey].UpdatedAt = time.Now().Add(-20 * time.Second)
	tr.mu.Unlock()

	tr.Prune()

	h := tr.Get(testKey)
	if h != nil {
		t.Error("expected stale connection to be pruned")
	}
}

func TestAll_ReturnsSnapshot(t *testing.T) {
	tr := New(testCfg())
	k1 := ConnKey{Saddr: 1, Daddr: 2, Sport: 100, Dport: 443}
	k2 := ConnKey{Saddr: 3, Daddr: 4, Sport: 200, Dport: 443}

	tr.Record(ConnEvent{Key: k1, EventType: EventRetransmit})
	tr.Record(ConnEvent{Key: k2, EventType: EventRTO})

	all := tr.All()
	if len(all) != 2 {
		t.Errorf("expected 2 connections, got %d", len(all))
	}
}

func TestNormalizeRamp(t *testing.T) {
	cases := []struct {
		value, soft, hard float64
		want              float64
	}{
		{0, 5, 20, 0},    // below soft
		{5, 5, 20, 0},    // at soft
		{12.5, 5, 20, 50}, // midpoint → 50
		{20, 5, 20, 100}, // at hard
		{30, 5, 20, 100}, // above hard → clamped
	}
	for _, c := range cases {
		got := normalizeRamp(c.value, c.soft, c.hard)
		if got != c.want {
			t.Errorf("normalizeRamp(%.1f, %.1f, %.1f) = %.1f, want %.1f", c.value, c.soft, c.hard, got, c.want)
		}
	}
}

func TestActionFromRisk(t *testing.T) {
	cfg := DefaultTrackerConfig()
	cases := []struct {
		risk float64
		want ActionLevel
	}{
		{0, ActionHealthy},
		{20, ActionHealthy},
		{21, ActionWarning},
		{50, ActionWarning},
		{51, ActionSick},
		{80, ActionSick},
		{81, ActionCritical},
		{99, ActionCritical},
		{100, ActionDead},
	}
	for _, c := range cases {
		got := actionFromRisk(c.risk, cfg)
		if got != c.want {
			t.Errorf("actionFromRisk(%.0f) = %s, want %s", c.risk, got, c.want)
		}
	}
}

func TestHealthTransition_EmittedOnActionChange(t *testing.T) {
	cfg := testCfg() // EscalateAfter=1 for immediate escalation
	tr := New(cfg)

	// Fire enough unacked events to trigger degradation.
	for range 3 {
		tr.Record(ConnEvent{Key: testKey, EventType: EventUnacked, RetransCount: 255})
	}

	select {
	case ev := <-tr.Events():
		if ev.Status == "healthy" {
			t.Errorf("expected degraded transition, got status=%q action=%s", ev.Status, ev.ActionLevel)
		}
		if ev.ActionLevel == "" {
			t.Error("ActionLevel should be populated in HealthTransition")
		}
	default:
		t.Error("expected a HealthTransition event on the channel")
	}
}

func TestParseEvent_ValidData(t *testing.T) {
	// Construct a 33-byte record matching struct conn_event layout
	data := make([]byte, 33)
	// saddr = 0x0a000001 (10.0.0.1)
	data[0], data[1], data[2], data[3] = 0x01, 0x00, 0x00, 0x0a
	// daddr = 0x0a000002 (10.0.0.2)
	data[4], data[5], data[6], data[7] = 0x02, 0x00, 0x00, 0x0a
	// sport = 12345
	data[8], data[9] = 0x39, 0x30
	// dport = 443
	data[10], data[11] = 0xbb, 0x01
	// pad[4] = 0
	// timestamp = 1000 ns
	data[16] = 0xe8
	data[17], data[18], data[19] = 0x03, 0, 0
	// event_type = EVENT_RETRANSMIT
	data[24] = 1
	// 3 bytes padding
	// srtt_us = 500
	data[28], data[29] = 0xf4, 0x01
	// retrans_count = 1
	data[32] = 1

	ev, err := ParseEvent(data)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	if ev.EventType != EventRetransmit {
		t.Errorf("expected EventRetransmit, got %d", ev.EventType)
	}
	if ev.RetransCount != 1 {
		t.Errorf("expected RetransCount=1, got %d", ev.RetransCount)
	}
}

func TestParseEvent_TooShort(t *testing.T) {
	_, err := ParseEvent(make([]byte, 10))
	if err == nil {
		t.Error("expected error for short record")
	}
}

func TestConnKey_DaddrIP(t *testing.T) {
	// daddr = 192.168.122.10 in big-endian: 0xc0a87a0a
	k := ConnKey{Daddr: 0x0a7aa8c0}
	ip := k.DaddrIP()
	if ip != "192.168.122.10" {
		t.Errorf("expected 192.168.122.10, got %q", ip)
	}
}
