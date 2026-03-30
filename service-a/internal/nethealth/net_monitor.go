package nethealth

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type tcpEntry struct {
	flow     SocketFlow
	sndQueue int64
	retrans  int64
}

type NetHealthMonitor struct {
	isLinux               bool
	classifier            SocketClassifier
	metadataRegistry      *SocketMetadataRegistry
	discoverSocketInodes  func() map[int]string
	parseProcNetTCPSource func() map[string]tcpEntry
}

func NewNetHealthMonitor() *NetHealthMonitor {
	return NewNetHealthMonitorWithDeps(NewSocketClassifierFromRules("4222=nats,ephemeral=stream,*=other"), NewSocketMetadataRegistry())
}

func NewNetHealthMonitorWithDeps(classifier SocketClassifier, metadataRegistry *SocketMetadataRegistry) *NetHealthMonitor {
	monitor := &NetHealthMonitor{
		isLinux:          runtime.GOOS == "linux",
		classifier:       classifier,
		metadataRegistry: metadataRegistry,
	}
	monitor.discoverSocketInodes = monitor.discoverSocketInodesDefault
	monitor.parseProcNetTCPSource = monitor.parseProcNetTCPDefault
	return monitor
}

func (m *NetHealthMonitor) Sample() []SocketSnapshot {
	snapshots := []SocketSnapshot{}
	tcpEntries := m.parseProcNetTCPSource()

	for fd, inode := range m.discoverSocketInodes() {
		entry, ok := tcpEntries[inode]
		if !ok {
			entry = tcpEntry{flow: SocketFlow{LocalIP: "0.0.0.0", RemoteIP: "0.0.0.0"}}
		}

		classification := m.classifier.Classify(entry.flow.LocalPort, entry.flow.RemotePort)
		metadata := m.metadataRegistry.Resolve(inode, entry.flow)
		description := fmt.Sprintf("class=%s inode=%s flow=%s", classification, inode, entry.flow.AsDisplay())
		if len(metadata) > 0 {
			description += fmt.Sprintf(" metadata=%v", metadata)
		}

		for _, connectionID := range parseStreamCorrIDs(metadata, fd) {
			snapshots = append(snapshots, SocketSnapshot{
				ConnectionID: connectionID,
				Description:  description,
				Inflight:     entry.sndQueue,
				Failures:     entry.retrans,
				QueuedBytes:  entry.sndQueue,
				Connected:    true,
			})
		}
	}

	return snapshots
}

func parseStreamCorrIDs(metadata map[string]string, fd int) []string {
	if csv := strings.TrimSpace(metadata["streamCorrIDs"]); csv != "" {
		out := []string{}
		for _, token := range strings.Split(csv, ",") {
			trimmed := strings.TrimSpace(token)
			if trimmed != "" {
				out = append(out, trimmed)
			}
		}
		if len(out) > 0 {
			return out
		}
	}

	if single := strings.TrimSpace(metadata["streamCorrID"]); single != "" {
		return []string{single}
	}
	if single := strings.TrimSpace(metadata["streamId"]); single != "" {
		return []string{single}
	}

	return []string{fmt.Sprintf("fd-%d", fd)}
}

func (m *NetHealthMonitor) discoverSocketInodesDefault() map[int]string {
	fds := map[int]string{}
	if !m.isLinux {
		return fds
	}

	fdDir := filepath.Join("/proc", strconv.Itoa(os.Getpid()), "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return fds
	}

	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fds[fd] = strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
	}

	return fds
}

func (m *NetHealthMonitor) parseProcNetTCPDefault() map[string]tcpEntry {
	inodeMap := map[string]tcpEntry{}
	if !m.isLinux {
		return inodeMap
	}

	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 10 {
				continue
			}
			localParts := strings.Split(fields[1], ":")
			remoteParts := strings.Split(fields[2], ":")
			queueParts := strings.Split(fields[4], ":")
			if len(localParts) != 2 || len(remoteParts) != 2 || len(queueParts) != 2 {
				continue
			}

			localPort, err1 := strconv.ParseInt(localParts[1], 16, 32)
			remotePort, err2 := strconv.ParseInt(remoteParts[1], 16, 32)
			sndQueue, err3 := strconv.ParseInt(queueParts[0], 16, 64)
			retrans, err4 := strconv.ParseInt(fields[6], 16, 64)
			if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
				continue
			}

			inode := fields[9]
			inodeMap[inode] = tcpEntry{
				flow: SocketFlow{
					LocalIP:    HexToIP(localParts[0]),
					LocalPort:  int(localPort),
					RemoteIP:   HexToIP(remoteParts[0]),
					RemotePort: int(remotePort),
				},
				sndQueue: sndQueue,
				retrans:  retrans,
			}
		}
	}

	return inodeMap
}

// HexToIP converts a /proc/net/tcp hex-encoded IP address (little-endian IPv4
// or IPv6) to a dotted-decimal string.
func HexToIP(hexIP string) string {
	if len(hexIP) == 8 {
		return hexToIPv4LittleEndian(hexIP)
	}
	if len(hexIP) == 32 && strings.HasPrefix(hexIP, "0000000000000000FFFF0000") {
		return hexToIPv4LittleEndian(hexIP[24:])
	}
	return "0.0.0.0"
}

func hexToIPv4LittleEndian(hexIP string) string {
	if len(hexIP) != 8 {
		return "0.0.0.0"
	}
	bytes := [4]int{}
	for i := 0; i < 4; i++ {
		part := hexIP[i*2 : i*2+2]
		value, err := strconv.ParseInt(part, 16, 32)
		if err != nil {
			return "0.0.0.0"
		}
		bytes[i] = int(value)
	}
	return fmt.Sprintf("%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0])
}
