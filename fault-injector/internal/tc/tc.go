// Package tc wraps the tc (traffic control) command to inject and clear
// per-IP network faults on a bridge interface using netem qdiscs.
//
// Architecture of the tc rules created:
//
//	root prio qdisc (handle 1:)
//	  band 1:1 — matched by u32 filter on dst IP → netem (handle 10:)
//	  band 1:2 — unmatched traffic passes through unaffected
//	  band 1:3
//
// The prio qdisc is shared across all injected targets on the same interface.
// Each target IP gets its own u32 filter and netem child qdisc under band 1:1.
// Inject is idempotent: calling it twice on the same target replaces the rule.
package tc

import (
	"fmt"
	"os/exec"
	"strings"
)

// Mode describes the type of fault to inject.
type Mode string

const (
	ModePacketLoss Mode = "packet-loss"
	ModeLatency    Mode = "latency"
	ModeDisconnect Mode = "disconnect"
)

// InjectParams holds the parameters for a fault injection.
type InjectParams struct {
	Iface    string
	TargetIP string
	Mode     Mode

	// packet-loss
	LossRate float64 // percent, e.g. 5.0

	// latency
	Delay  string // e.g. "200ms"
	Jitter string // e.g. "50ms"
}

// Validate returns an error if the parameters are missing or inconsistent.
func (p InjectParams) Validate() error {
	if p.Iface == "" {
		return fmt.Errorf("iface is required")
	}
	if p.TargetIP == "" {
		return fmt.Errorf("target IP is required")
	}
	switch p.Mode {
	case ModePacketLoss:
		if p.LossRate <= 0 || p.LossRate > 100 {
			return fmt.Errorf("loss rate must be between 0 and 100, got %.1f", p.LossRate)
		}
	case ModeLatency:
		if p.Delay == "" {
			return fmt.Errorf("delay is required for latency mode")
		}
	case ModeDisconnect:
		// no extra params needed
	default:
		return fmt.Errorf("unknown mode %q", p.Mode)
	}
	return nil
}

// Inject applies a fault to the given target IP on the interface.
// It is idempotent: if a rule for the target already exists it is replaced.
func Inject(p InjectParams) error {
	if err := p.Validate(); err != nil {
		return err
	}

	// Ensure prio root qdisc exists. Try to add; ignore "already exists" error.
	if err := ensurePrioQdisc(p.Iface); err != nil {
		return fmt.Errorf("ensure prio qdisc: %w", err)
	}

	// Remove any existing rule for this target (idempotency)
	_ = Clear(p.Iface, p.TargetIP)

	// Add netem qdisc on band 1:1
	netemArgs := buildNetemArgs(p)
	if err := run("tc", append([]string{
		"qdisc", "add", "dev", p.Iface,
		"parent", "1:1", "handle", "10:", "netem",
	}, netemArgs...)...); err != nil {
		return fmt.Errorf("add netem qdisc: %w", err)
	}

	// Add u32 filter matching dst IP, directing matched traffic to band 1:1
	ipHex, err := ipToHex(p.TargetIP)
	if err != nil {
		return fmt.Errorf("convert IP: %w", err)
	}
	if err := run("tc",
		"filter", "add", "dev", p.Iface,
		"parent", "1:0", "protocol", "ip",
		"prio", "1", "u32",
		"match", "ip", "dst", p.TargetIP+"/32",
		"match", "u32", ipHex, "0xffffffff", "at", "16",
		"flowid", "1:1",
	); err != nil {
		return fmt.Errorf("add filter: %w", err)
	}

	return nil
}

// Clear removes the netem qdisc and u32 filter for the target IP.
// Returns nil if no rule exists (idempotent).
func Clear(iface, targetIP string) error {
	if iface == "" || targetIP == "" {
		return fmt.Errorf("iface and targetIP are required")
	}

	// Delete filter first (filter references the qdisc)
	// Ignore errors — rule may not exist
	_ = run("tc", "filter", "del", "dev", iface, "parent", "1:0",
		"protocol", "ip", "prio", "1")

	// Delete netem child qdisc
	_ = run("tc", "qdisc", "del", "dev", iface, "parent", "1:1", "handle", "10:")

	return nil
}

// Status prints the current tc state on the interface to stdout via tc show.
func Status(iface string) error {
	if iface == "" {
		return fmt.Errorf("iface is required")
	}
	if err := runPrint("tc", "qdisc", "show", "dev", iface); err != nil {
		return err
	}
	return runPrint("tc", "filter", "show", "dev", iface)
}

// Commands returns the list of tc shell commands that Inject would execute,
// without running them. Useful for testing and dry-runs.
func Commands(p InjectParams) ([][]string, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	netemArgs := buildNetemArgs(p)
	cmds := [][]string{
		{"tc", "qdisc", "add", "dev", p.Iface, "root", "handle", "1:", "prio"},
		append([]string{"tc", "qdisc", "add", "dev", p.Iface, "parent", "1:1", "handle", "10:", "netem"}, netemArgs...),
		{
			"tc", "filter", "add", "dev", p.Iface,
			"parent", "1:0", "protocol", "ip",
			"prio", "1", "u32",
			"match", "ip", "dst", p.TargetIP + "/32",
			"flowid", "1:1",
		},
	}
	return cmds, nil
}

func buildNetemArgs(p InjectParams) []string {
	switch p.Mode {
	case ModePacketLoss:
		return []string{"loss", fmt.Sprintf("%.1f%%", p.LossRate)}
	case ModeLatency:
		args := []string{"delay", p.Delay}
		if p.Jitter != "" {
			args = append(args, p.Jitter, "distribution", "normal")
		}
		return args
	case ModeDisconnect:
		return []string{"loss", "100%"}
	default:
		return nil
	}
}

func ensurePrioQdisc(iface string) error {
	// Use "replace" rather than "add" so that:
	//   - if no root qdisc exists: acts like add
	//   - if the same prio qdisc already exists: no-op
	//   - if Docker's default "noqueue" qdisc exists: replaces it regardless
	//     of the exclusivity flag ("Exclusivity flag on, cannot modify")
	return run("tc", "qdisc", "replace", "dev", iface, "root", "handle", "1:", "prio")
}

// ipToHex converts a dotted-decimal IP to a 0x-prefixed 8-digit hex string
// for use in tc u32 filters.
func ipToHex(ip string) (string, error) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid IP: %s", ip)
	}
	var b [4]uint64
	for i, p := range parts {
		var n uint64
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n > 255 {
			return "", fmt.Errorf("invalid IP octet %q in %s", p, ip)
		}
		b[i] = n
	}
	return fmt.Sprintf("0x%02x%02x%02x%02x", b[0], b[1], b[2], b[3]), nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w — %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runPrint(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil // let it inherit stdout
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w — %s", name, err, strings.TrimSpace(string(out)))
	}
	fmt.Print(string(out))
	return nil
}
