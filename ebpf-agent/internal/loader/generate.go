package loader

// Code generation for eBPF programs.
// Run via: make generate  (requires clang + bpf2go on Linux)
//
// Each directive produces:
//   <Name>_bpfel.go / <Name>_bpfeb.go — Go bindings with embedded ELF
//
// The generated types referenced in loader_linux.go:
//   retransmitObjects  / loadRetransmitObjects()
//   rttObjects         / loadRttObjects()
//   sockopsObjects     / loadSockopsObjects()

// BPF_EXTRA_INCLUDES is expanded by go generate. On macOS set it to the
// Homebrew include path, e.g. -I/opt/homebrew/include (see make deps-mac).
// On Linux with libbpf-dev installed it can be left empty.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" Retransmit ../../bpf/retransmit.c -- -I../../bpf/headers $BPF_EXTRA_INCLUDES
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" Rtt ../../bpf/rtt.c -- -I../../bpf/headers $BPF_EXTRA_INCLUDES
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" Sockops ../../bpf/sockops.c -- -I../../bpf/headers $BPF_EXTRA_INCLUDES
