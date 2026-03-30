package nethealth

import (
	"net"
	"os"
	"strconv"
	"strings"
)

// ParseHostPort splits a "host:port" or "[host]:port" address string into its
// host and port components. Returns ("", 0) on parse error.
func ParseHostPort(addr string) (string, int) {
	host, portRaw, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", 0
	}
	host = strings.Trim(host, "[]")
	if zone := strings.Index(host, "%"); zone >= 0 {
		host = host[:zone]
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		return host, 0
	}
	return host, port
}

// IPEqual returns true if two IP address strings represent the same network
// address, handling IPv4/IPv6 equivalences (e.g. "::ffff:1.2.3.4" vs "1.2.3.4").
func IPEqual(a, b string) bool {
	if a == b {
		return true
	}
	left := net.ParseIP(strings.TrimSpace(a))
	right := net.ParseIP(strings.TrimSpace(b))
	if left == nil || right == nil {
		return false
	}
	return left.Equal(right)
}

// MaxInt64 returns the larger of a and b.
func MaxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// SampleFlowMetrics reads /proc/net/tcp and /proc/net/tcp6 to find the socket
// whose (localPort, remoteIP, remotePort) matches the given arguments and
// returns its send-queue depth, retransmit count, and TCP unacknowledged byte
// count. Returns (-1, -1, -1) when no matching entry is found or when running
// on a non-Linux platform.
func SampleFlowMetrics(localPort int, remoteIP string, remotePort int) (sndQueue, retrans, tcpUnacked int64) {
	if localPort <= 0 || remotePort <= 0 || strings.TrimSpace(remoteIP) == "" {
		return -1, -1, -1
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
			entryLocalPort, err1 := strconv.ParseInt(localParts[1], 16, 32)
			entryRemotePort, err2 := strconv.ParseInt(remoteParts[1], 16, 32)
			if err1 != nil || err2 != nil {
				continue
			}
			entryRemoteIP := HexToIP(remoteParts[0])
			if int(entryLocalPort) != localPort || int(entryRemotePort) != remotePort || !IPEqual(entryRemoteIP, remoteIP) {
				continue
			}
			sq, e1 := strconv.ParseInt(queueParts[0], 16, 64)
			ua, e2 := strconv.ParseInt(queueParts[1], 16, 64)
			rt, _ := strconv.ParseInt(fields[6], 16, 64)
			if e1 != nil {
				sq = -1
			}
			if e2 != nil {
				ua = -1
			}
			return sq, rt, ua
		}
	}
	return -1, -1, -1
}
