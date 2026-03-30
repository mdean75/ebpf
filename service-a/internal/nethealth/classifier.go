package nethealth

import "strconv"

const (
	minEphemeralPort = 10000
	maxPort          = 65535
)

type SocketClassifier struct {
	exactPortLabels map[int]string
	ephemeralLabel  string
	defaultLabel    string
}

func NewSocketClassifierFromRules(rules string) SocketClassifier {
	exact := map[int]string{}
	ephemeral := "stream"
	fallback := "other"

	for _, token := range splitCSV(rules) {
		parts := splitKV(token)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}
		key := lower(parts[0])
		val := parts[1]

		switch key {
		case "ephemeral":
			ephemeral = val
		case "*", "default":
			fallback = val
		default:
			port, err := strconv.Atoi(key)
			if err != nil || port <= 0 || port > maxPort {
				continue
			}
			exact[port] = val
		}
	}

	return SocketClassifier{
		exactPortLabels: exact,
		ephemeralLabel:  ephemeral,
		defaultLabel:    fallback,
	}
}

func (c SocketClassifier) Classify(localPort, remotePort int) string {
	if label, ok := c.exactPortLabels[remotePort]; ok {
		return label
	}
	if label, ok := c.exactPortLabels[localPort]; ok {
		return label
	}
	if isEphemeral(localPort) || isEphemeral(remotePort) {
		return c.ephemeralLabel
	}
	return c.defaultLabel
}

func isEphemeral(port int) bool {
	return port >= minEphemeralPort && port <= maxPort
}
