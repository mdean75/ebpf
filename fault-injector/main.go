package main

import (
	"fmt"
	"os"

	"github.com/mdean75/ebpf-grpc-experiment/fault-injector/internal/tc"
	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "fault",
		Short: "Inject and clear network faults on a bridge interface using tc netem",
	}
	root.AddCommand(injectCmd(), clearCmd(), statusCmd())
	return root
}

func injectCmd() *cobra.Command {
	var (
		iface    string
		target   string
		mode     string
		lossRate float64
		delay    string
		jitter   string
	)

	cmd := &cobra.Command{
		Use:   "inject",
		Short: "Inject a network fault targeting a specific VM IP",
		Example: `  fault inject --iface virbr0 --target 192.168.122.10 --mode packet-loss --rate 5
  fault inject --iface virbr0 --target 192.168.122.10 --mode latency --delay 200ms --jitter 50ms
  fault inject --iface virbr0 --target 192.168.122.10 --mode disconnect`,
		RunE: func(cmd *cobra.Command, args []string) error {
			p := tc.InjectParams{
				Iface:    iface,
				TargetIP: target,
				Mode:     tc.Mode(mode),
				LossRate: lossRate,
				Delay:    delay,
				Jitter:   jitter,
			}
			if err := p.Validate(); err != nil {
				return err
			}
			fmt.Printf("injecting %s fault on %s → %s\n", mode, iface, target)
			return tc.Inject(p)
		},
	}

	cmd.Flags().StringVar(&iface, "iface", "", "Bridge interface name (required)")
	cmd.Flags().StringVar(&target, "target", "", "Target VM IP address (required)")
	cmd.Flags().StringVar(&mode, "mode", "", "Fault mode: packet-loss, latency, or disconnect (required)")
	cmd.Flags().Float64Var(&lossRate, "rate", 5.0, "Packet loss percentage (packet-loss mode)")
	cmd.Flags().StringVar(&delay, "delay", "200ms", "Base delay (latency mode)")
	cmd.Flags().StringVar(&jitter, "jitter", "50ms", "Jitter (latency mode)")

	cmd.MarkFlagRequired("iface")
	cmd.MarkFlagRequired("target")
	cmd.MarkFlagRequired("mode")

	return cmd
}

func clearCmd() *cobra.Command {
	var iface, target string

	cmd := &cobra.Command{
		Use:     "clear",
		Short:   "Remove the fault rule for a target IP",
		Example: `  fault clear --iface virbr0 --target 192.168.122.10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("clearing fault on %s → %s\n", iface, target)
			return tc.Clear(iface, target)
		},
	}

	cmd.Flags().StringVar(&iface, "iface", "", "Bridge interface name (required)")
	cmd.Flags().StringVar(&target, "target", "", "Target VM IP address (required)")
	cmd.MarkFlagRequired("iface")
	cmd.MarkFlagRequired("target")

	return cmd
}

func statusCmd() *cobra.Command {
	var iface string

	cmd := &cobra.Command{
		Use:     "status",
		Short:   "Show current tc qdisc and filter state on the interface",
		Example: `  fault status --iface virbr0`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return tc.Status(iface)
		},
	}

	cmd.Flags().StringVar(&iface, "iface", "", "Bridge interface name (required)")
	cmd.MarkFlagRequired("iface")

	return cmd
}
