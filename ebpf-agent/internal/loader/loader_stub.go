//go:build !linux

// Package loader stubs out eBPF program loading for non-Linux platforms.
// On Linux, loader_linux.go is used instead.
package loader

import "fmt"

type Programs struct{}
type Config struct {
	TargetPort    uint16
	RTTMultiplier uint16
	CgroupPath    string
}

func Load(_ Config) (*Programs, error) {
	return nil, fmt.Errorf("eBPF is only supported on Linux")
}

func (p *Programs) Close() {}

func VerifyCgroupV2(_ string) error {
	return fmt.Errorf("eBPF is only supported on Linux")
}
