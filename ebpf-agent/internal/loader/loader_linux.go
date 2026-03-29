//go:build linux

package loader

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Programs holds the loaded eBPF program handles and their attach links.
// Call Close() on shutdown.
type Programs struct {
	retransmitObjs RetransmitObjects
	rttObjs        RttObjects
	sockopsObjs    SockopsObjects
	unackedObjs    UnackedObjects

	links []link.Link
	rb    *ringbuf.Reader
}

// Config is provided by the Go agent at load time.
type Config struct {
	// TargetPort is the destination port to filter on (nginx TLS port, typically 443).
	TargetPort uint16
	// RTTMultiplier is the spike detection threshold. Default 3.
	RTTMultiplier uint16
	// UnackedThreshold is the tcp_sock.packets_out value at which an
	// EVENT_UNACKED is emitted. On a healthy LAN connection packets_out is
	// 0–1; a threshold of 5 detects a black hole in ~25 ms at 200 msg/s.
	// Default 5.
	UnackedThreshold uint16
	// CgroupPath is the cgroupv2 root. Default "/sys/fs/cgroup".
	CgroupPath string
}

func (c *Config) setDefaults() {
	if c.RTTMultiplier == 0 {
		c.RTTMultiplier = 3
	}
	if c.UnackedThreshold == 0 {
		c.UnackedThreshold = 5
	}
	if c.CgroupPath == "" {
		c.CgroupPath = "/sys/fs/cgroup"
	}
}

// Load compiles and attaches all three eBPF programs and returns a Programs
// handle whose RingBuffer() can be read for events.
func Load(cfg Config) (*Programs, error) {
	cfg.setDefaults()

	p := &Programs{}

	// --- retransmit.c ---
	if err := LoadRetransmitObjects(&p.retransmitObjs, nil); err != nil {
		return nil, fmt.Errorf("load retransmit: %w", err)
	}
	if err := setPortFilter(p.retransmitObjs.PortConfig, cfg.TargetPort); err != nil {
		p.Close()
		return nil, fmt.Errorf("set retransmit port filter: %w", err)
	}
	tp, err := link.Tracepoint("tcp", "tcp_retransmit_skb", p.retransmitObjs.TracepointTcpTcpRetransmitSkb, nil)
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("attach retransmit tracepoint: %w", err)
	}
	p.links = append(p.links, tp)
	log.Println("eBPF: retransmit tracepoint attached")

	// --- rtt.c ---
	if err := LoadRttObjects(&p.rttObjs, nil); err != nil {
		p.Close()
		return nil, fmt.Errorf("load rtt: %w", err)
	}
	if err := setPortFilter(p.rttObjs.PortConfig, cfg.TargetPort); err != nil {
		p.Close()
		return nil, fmt.Errorf("set rtt port filter: %w", err)
	}
	if err := setRTTMultiplier(p.rttObjs.PortConfig, cfg.RTTMultiplier); err != nil {
		p.Close()
		return nil, fmt.Errorf("set rtt multiplier: %w", err)
	}
	fe, err := link.AttachTracing(link.TracingOptions{
		Program: p.rttObjs.FentryTcpRcvEstablished,
	})
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("attach rtt fentry: %w (check /sys/kernel/btf/vmlinux exists)", err)
	}
	p.links = append(p.links, fe)
	log.Println("eBPF: rtt fentry attached")

	// --- sockops.c ---
	if err := LoadSockopsObjects(&p.sockopsObjs, nil); err != nil {
		p.Close()
		return nil, fmt.Errorf("load sockops: %w", err)
	}
	if err := setPortFilter(p.sockopsObjs.PortConfig, cfg.TargetPort); err != nil {
		p.Close()
		return nil, fmt.Errorf("set sockops port filter: %w", err)
	}
	cgroupFD, err := openCgroupFD(cfg.CgroupPath)
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("open cgroup: %w", err)
	}
	defer cgroupFD.Close()

	so, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cfg.CgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: p.sockopsObjs.SockOpsHandler,
	})
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("attach sockops: %w", err)
	}
	p.links = append(p.links, so)
	log.Println("eBPF: sockops attached to cgroup", cfg.CgroupPath)

	// --- unacked.c ---
	if err := LoadUnackedObjects(&p.unackedObjs, nil); err != nil {
		p.Close()
		return nil, fmt.Errorf("load unacked: %w", err)
	}
	if err := setPortFilter(p.unackedObjs.PortConfig, cfg.TargetPort); err != nil {
		p.Close()
		return nil, fmt.Errorf("set unacked port filter: %w", err)
	}
	if err := setUnackedThreshold(p.unackedObjs.PortConfig, cfg.UnackedThreshold); err != nil {
		p.Close()
		return nil, fmt.Errorf("set unacked threshold: %w", err)
	}
	uf, err := link.AttachTracing(link.TracingOptions{
		Program: p.unackedObjs.TcpSendmsgUnacked,
	})
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("attach unacked fentry: %w (check /sys/kernel/btf/vmlinux exists)", err)
	}
	p.links = append(p.links, uf)
	log.Printf("eBPF: unacked fentry attached (threshold=%d packets)", cfg.UnackedThreshold)

	// Open ring buffer reader on the retransmit program's ring buffer.
	// (All four programs emit to their own ring buffers; we read from each.)
	rb, err := ringbuf.NewReader(p.retransmitObjs.Events)
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("open retransmit ring buffer: %w", err)
	}
	p.rb = rb

	return p, nil
}

// RingBuffer returns the ring buffer reader for retransmit events.
// For rtt and sockops ring buffers, use RingBufferRTT and RingBufferSockops.
func (p *Programs) RingBuffer() *ringbuf.Reader { return p.rb }

// RTTRingBuffer returns the ring buffer for rtt events.
func (p *Programs) RTTRingBuffer() (*ringbuf.Reader, error) {
	return ringbuf.NewReader(p.rttObjs.Events)
}

// SockopsRingBuffer returns the ring buffer for sockops events.
func (p *Programs) SockopsRingBuffer() (*ringbuf.Reader, error) {
	return ringbuf.NewReader(p.sockopsObjs.Events)
}

// UnackedRingBuffer returns the ring buffer for unacked events.
func (p *Programs) UnackedRingBuffer() (*ringbuf.Reader, error) {
	return ringbuf.NewReader(p.unackedObjs.Events)
}

func (p *Programs) Close() {
	for _, l := range p.links {
		l.Close()
	}
	if p.rb != nil {
		p.rb.Close()
	}
	p.retransmitObjs.Close()
	p.rttObjs.Close()
	p.sockopsObjs.Close()
	p.unackedObjs.Close()
}

// setPortFilter writes the target port (network byte order) to config map key 0.
func setPortFilter(configMap *ebpf.Map, port uint16) error {
	key := uint32(0)
	val := port
	return configMap.Put(&key, &val)
}

// setRTTMultiplier writes the spike multiplier to config map key 1.
func setRTTMultiplier(configMap *ebpf.Map, multiplier uint16) error {
	key := uint32(1)
	val := multiplier
	return configMap.Put(&key, &val)
}

// setUnackedThreshold writes the packets_out threshold to config map key 1
// of the unacked program's config map (CFG_KEY_UNACKED_THRESHOLD = 1).
func setUnackedThreshold(configMap *ebpf.Map, threshold uint16) error {
	key := uint32(1)
	val := threshold
	return configMap.Put(&key, &val)
}

// portToNetwork converts a host-byte-order port to network byte order.
func portToNetwork(port uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, port)
	return binary.LittleEndian.Uint16(b)
}

func openCgroupFD(cgroupPath string) (*os.File, error) {
	f, err := os.Open(cgroupPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", cgroupPath, err)
	}
	return f, nil
}

// VerifyCgroupV2 checks that the given path is a cgroupv2 mount.
// Returns an error with remediation hint if it is not.
func VerifyCgroupV2(cgroupPath string) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(cgroupPath, &stat); err != nil {
		return fmt.Errorf("statfs %s: %w", cgroupPath, err)
	}
	const cgroup2Magic = 0x63677270
	if stat.Type != cgroup2Magic {
		return fmt.Errorf("%s is not a cgroupv2 mount (type=0x%x); "+
			"try /sys/fs/cgroup/unified for hybrid cgroupv1/v2 hosts", cgroupPath, stat.Type)
	}
	return nil
}

