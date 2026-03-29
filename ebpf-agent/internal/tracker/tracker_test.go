package tracker

import (
	"testing"
	"time"
)

var testKey = ConnKey{Saddr: 0x0101010a, Daddr: 0x0a010101, Sport: 12345, Dport: 443}

func TestRecord_Retransmit_IncrementsScore(t *testing.T) {
	tr := New()
	tr.Record(ConnEvent{Key: testKey, EventType: EventRetransmit})

	h := tr.Get(testKey)
	if h == nil {
		t.Fatal("expected connection to be tracked")
	}
	if h.Score != 0.1 {
		t.Errorf("expected score=0.1 after one retransmit, got %.3f", h.Score)
	}
	if h.RetransmitCount != 1 {
		t.Errorf("expected RetransmitCount=1, got %d", h.RetransmitCount)
	}
}

func TestRecord_RTO_IncrementsScore(t *testing.T) {
	tr := New()
	tr.Record(ConnEvent{Key: testKey, EventType: EventRTO})

	h := tr.Get(testKey)
	if h.Score != 0.3 {
		t.Errorf("expected score=0.3 after one RTO, got %.3f", h.Score)
	}
}

func TestRecord_RTTSpike_IncrementsScore(t *testing.T) {
	tr := New()
	tr.Record(ConnEvent{Key: testKey, EventType: EventRTTSpike})

	h := tr.Get(testKey)
	if h.Score != 0.1 {
		t.Errorf("expected score=0.1 after one RTT spike, got %.3f", h.Score)
	}
	if h.RTTSpikeCount != 1 {
		t.Errorf("expected RTTSpikeCount=1, got %d", h.RTTSpikeCount)
	}
}

func TestRecord_ScoreClampedAt1(t *testing.T) {
	tr := New()
	// 4 RTOs = 4 * 0.3 = 1.2 → clamped to 1.0
	for range 4 {
		tr.Record(ConnEvent{Key: testKey, EventType: EventRTO})
	}
	h := tr.Get(testKey)
	if h.Score != 1.0 {
		t.Errorf("expected score clamped at 1.0, got %.3f", h.Score)
	}
}

func TestRecord_ScoreNotBelowZero(t *testing.T) {
	tr := New()
	// Score starts at 0; decay should not go negative
	tr.Decay()
	tr.Decay()
	all := tr.All()
	for _, h := range all {
		if h.Score < 0 {
			t.Errorf("score went negative: %.3f", h.Score)
		}
	}
}

func TestStatus_DegradedAbove0_5(t *testing.T) {
	tr := New()
	// 2 RTOs = 0.6 > 0.5 → degraded
	tr.Record(ConnEvent{Key: testKey, EventType: EventRTO})
	tr.Record(ConnEvent{Key: testKey, EventType: EventRTO})

	h := tr.Get(testKey)
	if h.Status() != "degraded" {
		t.Errorf("expected 'degraded' with score=%.2f, got %q", h.Score, h.Status())
	}
}

func TestStatus_HealthyBelow0_5(t *testing.T) {
	tr := New()
	tr.Record(ConnEvent{Key: testKey, EventType: EventRetransmit}) // score = 0.1

	h := tr.Get(testKey)
	if h.Status() != "healthy" {
		t.Errorf("expected 'healthy' with score=%.2f, got %q", h.Score, h.Status())
	}
}

func TestDecay_ReducesScore(t *testing.T) {
	tr := New()
	tr.Record(ConnEvent{Key: testKey, EventType: EventRTO}) // score = 0.3

	// Force a non-trivial elapsed time by manipulating lastDecay
	tr.lastDecay = time.Now().Add(-2 * time.Second) // 2s ago
	tr.Decay()

	h := tr.Get(testKey)
	// After 2s decay at 0.05/s: 0.3 - 0.10 = 0.20 (approximately)
	if h.Score >= 0.3 {
		t.Errorf("expected score to decrease from 0.3, got %.3f", h.Score)
	}
	if h.Score < 0 {
		t.Errorf("score went negative: %.3f", h.Score)
	}
}

func TestDecay_ScoreReachesZero(t *testing.T) {
	tr := New()
	tr.Record(ConnEvent{Key: testKey, EventType: EventRetransmit}) // score = 0.1

	// Simulate 10s of decay — score should reach 0
	tr.lastDecay = time.Now().Add(-10 * time.Second)
	tr.Decay()

	h := tr.Get(testKey)
	if h.Score != 0 {
		t.Errorf("expected score=0 after sufficient decay, got %.3f", h.Score)
	}
}

func TestAll_ReturnsSnapshot(t *testing.T) {
	tr := New()
	k1 := ConnKey{Saddr: 1, Daddr: 2, Sport: 100, Dport: 443}
	k2 := ConnKey{Saddr: 3, Daddr: 4, Sport: 200, Dport: 443}

	tr.Record(ConnEvent{Key: k1, EventType: EventRetransmit})
	tr.Record(ConnEvent{Key: k2, EventType: EventRTO})

	all := tr.All()
	if len(all) != 2 {
		t.Errorf("expected 2 connections, got %d", len(all))
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
