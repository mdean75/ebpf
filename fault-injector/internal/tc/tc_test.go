package tc

import (
	"strings"
	"testing"
)

func TestValidate_PacketLoss(t *testing.T) {
	p := InjectParams{Iface: "virbr0", TargetIP: "192.168.122.10", Mode: ModePacketLoss, LossRate: 5.0}
	if err := p.Validate(); err != nil {
		t.Errorf("expected valid, got: %v", err)
	}
}

func TestValidate_Latency(t *testing.T) {
	p := InjectParams{Iface: "virbr0", TargetIP: "192.168.122.10", Mode: ModeLatency, Delay: "200ms"}
	if err := p.Validate(); err != nil {
		t.Errorf("expected valid, got: %v", err)
	}
}

func TestValidate_Disconnect(t *testing.T) {
	p := InjectParams{Iface: "virbr0", TargetIP: "192.168.122.10", Mode: ModeDisconnect}
	if err := p.Validate(); err != nil {
		t.Errorf("expected valid, got: %v", err)
	}
}

func TestValidate_MissingIface(t *testing.T) {
	p := InjectParams{TargetIP: "192.168.122.10", Mode: ModeDisconnect}
	if err := p.Validate(); err == nil {
		t.Error("expected error for missing iface")
	}
}

func TestValidate_MissingTarget(t *testing.T) {
	p := InjectParams{Iface: "virbr0", Mode: ModeDisconnect}
	if err := p.Validate(); err == nil {
		t.Error("expected error for missing target IP")
	}
}

func TestValidate_InvalidLossRate(t *testing.T) {
	p := InjectParams{Iface: "virbr0", TargetIP: "192.168.122.10", Mode: ModePacketLoss, LossRate: 0}
	if err := p.Validate(); err == nil {
		t.Error("expected error for loss rate=0")
	}
	p.LossRate = 101
	if err := p.Validate(); err == nil {
		t.Error("expected error for loss rate=101")
	}
}

func TestValidate_LatencyMissingDelay(t *testing.T) {
	p := InjectParams{Iface: "virbr0", TargetIP: "192.168.122.10", Mode: ModeLatency}
	if err := p.Validate(); err == nil {
		t.Error("expected error for latency mode with no delay")
	}
}

func TestCommands_PacketLoss(t *testing.T) {
	p := InjectParams{
		Iface:    "virbr0",
		TargetIP: "192.168.122.10",
		Mode:     ModePacketLoss,
		LossRate: 5.0,
	}
	cmds, err := Commands(p)
	if err != nil {
		t.Fatalf("Commands: %v", err)
	}
	if len(cmds) == 0 {
		t.Fatal("expected at least one command")
	}
	// netem command should contain "loss 5.0%"
	netemCmd := strings.Join(cmds[1], " ")
	if !strings.Contains(netemCmd, "loss") || !strings.Contains(netemCmd, "5.0%") {
		t.Errorf("expected netem loss 5.0%% in %q", netemCmd)
	}
}

func TestCommands_Latency(t *testing.T) {
	p := InjectParams{
		Iface:    "virbr0",
		TargetIP: "192.168.122.10",
		Mode:     ModeLatency,
		Delay:    "200ms",
		Jitter:   "50ms",
	}
	cmds, err := Commands(p)
	if err != nil {
		t.Fatalf("Commands: %v", err)
	}
	netemCmd := strings.Join(cmds[1], " ")
	if !strings.Contains(netemCmd, "delay") || !strings.Contains(netemCmd, "200ms") {
		t.Errorf("expected 'delay 200ms' in %q", netemCmd)
	}
	if !strings.Contains(netemCmd, "50ms") {
		t.Errorf("expected jitter 50ms in %q", netemCmd)
	}
}

func TestCommands_Disconnect(t *testing.T) {
	p := InjectParams{
		Iface:    "virbr0",
		TargetIP: "192.168.122.10",
		Mode:     ModeDisconnect,
	}
	cmds, err := Commands(p)
	if err != nil {
		t.Fatalf("Commands: %v", err)
	}
	netemCmd := strings.Join(cmds[1], " ")
	if !strings.Contains(netemCmd, "loss 100%") {
		t.Errorf("expected 'loss 100%%' in %q", netemCmd)
	}
}

func TestCommands_ContainsFilterWithTargetIP(t *testing.T) {
	p := InjectParams{
		Iface:    "virbr0",
		TargetIP: "10.0.0.1",
		Mode:     ModeDisconnect,
	}
	cmds, err := Commands(p)
	if err != nil {
		t.Fatalf("Commands: %v", err)
	}
	filterCmd := strings.Join(cmds[2], " ")
	if !strings.Contains(filterCmd, "10.0.0.1") {
		t.Errorf("expected target IP in filter command: %q", filterCmd)
	}
}

func TestIPToHex(t *testing.T) {
	cases := []struct {
		ip  string
		hex string
	}{
		{"192.168.122.10", "0xc0a87a0a"},
		{"10.0.0.1", "0x0a000001"},
		{"127.0.0.1", "0x7f000001"},
	}
	for _, tc := range cases {
		got, err := ipToHex(tc.ip)
		if err != nil {
			t.Errorf("ipToHex(%q): %v", tc.ip, err)
			continue
		}
		if got != tc.hex {
			t.Errorf("ipToHex(%q) = %q, want %q", tc.ip, got, tc.hex)
		}
	}
}

func TestIPToHex_Invalid(t *testing.T) {
	if _, err := ipToHex("not-an-ip"); err == nil {
		t.Error("expected error for invalid IP")
	}
	if _, err := ipToHex("999.0.0.1"); err == nil {
		t.Error("expected error for out-of-range octet")
	}
}
