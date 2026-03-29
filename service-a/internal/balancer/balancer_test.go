package balancer

import (
	"testing"
)

func TestNext_SkipsDeadStreams(t *testing.T) {
	b := New([]string{"a:443", "b:443", "c:443"}, ModeBaseline)
	b.SetHealth("b:443", Dead, "test")

	seen := map[string]int{}
	for range 30 {
		addr, _ := b.Next()
		if addr == "" {
			t.Fatal("Next() returned empty with healthy streams available")
		}
		seen[addr]++
	}
	if seen["b:443"] > 0 {
		t.Errorf("dead stream b:443 was selected %d times", seen["b:443"])
	}
}

func TestNext_AllDead(t *testing.T) {
	b := New([]string{"a:443", "b:443"}, ModeBaseline)
	b.SetHealth("a:443", Dead, "test")
	b.SetHealth("b:443", Dead, "test")

	addr, skipped := b.Next()
	if addr != "" {
		t.Errorf("expected empty string with all streams dead, got %q", addr)
	}
	if skipped != nil {
		t.Errorf("expected nil skipped when all dead, got %v", skipped)
	}
}

func TestEBPFMode_SkipsDegradedStreams(t *testing.T) {
	b := New([]string{"a:443", "b:443"}, ModeEBPF)
	b.SetHealth("b:443", Degraded, "ebpf_signal")

	seen := map[string]int{}
	skippedCount := 0
	for range 20 {
		addr, skipped := b.Next()
		seen[addr]++
		skippedCount += len(skipped)
	}
	if seen["b:443"] > 0 {
		t.Errorf("ebpf mode: degraded stream b:443 was selected %d times", seen["b:443"])
	}
	if seen["a:443"] == 0 {
		t.Error("ebpf mode: healthy stream a:443 was never selected")
	}
	if skippedCount == 0 {
		t.Error("ebpf mode: expected skipped list to be non-empty when routing away from degraded stream")
	}
}

func TestBaselineMode_RoutesDegradedStreams(t *testing.T) {
	b := New([]string{"a:443", "b:443"}, ModeBaseline)
	b.SetHealth("b:443", Degraded, "ebpf_signal")

	seen := map[string]int{}
	skippedCount := 0
	for range 20 {
		addr, skipped := b.Next()
		seen[addr]++
		skippedCount += len(skipped)
	}
	if seen["b:443"] == 0 {
		t.Error("baseline mode: degraded stream b:443 should still receive traffic")
	}
	if skippedCount > 0 {
		t.Errorf("baseline mode: degraded stream should not appear in skipped list, got %d skips", skippedCount)
	}
}

func TestSetMode_SwitchesAtRuntime(t *testing.T) {
	b := New([]string{"a:443", "b:443"}, ModeBaseline)
	b.SetHealth("b:443", Degraded, "ebpf_signal")

	// In baseline mode, degraded stream is routable
	b.SetMode(ModeBaseline)
	seen := map[string]bool{}
	for range 20 {
		addr, _ := b.Next()
		seen[addr] = true
	}
	if !seen["b:443"] {
		t.Error("baseline mode: expected b:443 to be selected")
	}

	// Switch to ebpf mode — degraded stream should be skipped
	b.SetMode(ModeEBPF)
	seen = map[string]bool{}
	for range 20 {
		addr, _ := b.Next()
		seen[addr] = true
	}
	if seen["b:443"] {
		t.Error("ebpf mode after switch: b:443 should not be selected while degraded")
	}
}

func TestSetHealth_LogsTransitions(t *testing.T) {
	b := New([]string{"x:443"}, ModeEBPF)

	// Idempotent — no panic on repeated transitions
	b.SetHealth("x:443", Degraded, "test")
	b.SetHealth("x:443", Degraded, "test")
	b.SetHealth("x:443", Dead, "test")
	b.SetHealth("x:443", Healthy, "test")

	if h := b.GetHealth("x:443"); h != Healthy {
		t.Errorf("expected Healthy, got %v", h)
	}
}

func TestGetHealth_UnknownAddr(t *testing.T) {
	b := New([]string{"a:443"}, ModeEBPF)
	if h := b.GetHealth("unknown:443"); h != Dead {
		t.Errorf("expected Dead for unknown address, got %v", h)
	}
}

func TestRoundRobin(t *testing.T) {
	b := New([]string{"a:443", "b:443", "c:443"}, ModeEBPF)

	first, _ := b.Next()
	second, _ := b.Next()
	third, _ := b.Next()
	fourth, _ := b.Next()

	if first == second || second == third {
		t.Errorf("round-robin should cycle: got %s, %s, %s", first, second, third)
	}
	if first != fourth {
		t.Errorf("round-robin should wrap: first=%s fourth=%s", first, fourth)
	}
}

func TestNext_SkippedList_EBPFMode(t *testing.T) {
	b := New([]string{"a:443", "b:443", "c:443"}, ModeEBPF)
	b.SetHealth("a:443", Degraded, "test")

	// First call: a:443 is first in round-robin but degraded, so it should be skipped.
	addr, skipped := b.Next()
	if addr == "a:443" {
		t.Error("degraded stream a:443 should not be returned")
	}
	if len(skipped) == 0 {
		t.Fatal("expected a:443 in skipped list")
	}
	if skipped[0] != "a:443" {
		t.Errorf("expected skipped[0]=a:443, got %q", skipped[0])
	}
	_ = addr
}

func TestNext_SkippedList_BaselineMode(t *testing.T) {
	b := New([]string{"a:443", "b:443"}, ModeBaseline)
	b.SetHealth("a:443", Degraded, "test")

	// In baseline mode degraded is routable — skipped list should be empty.
	_, skipped := b.Next()
	if len(skipped) > 0 {
		t.Errorf("baseline mode: expected empty skipped list, got %v", skipped)
	}
}
