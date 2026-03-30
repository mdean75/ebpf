package nethealth

import "strings"

func splitCSV(value string) []string {
	raw := strings.Split(value, ",")
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func splitKV(value string) []string {
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 {
		return nil
	}
	return []string{strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])}
}

func lower(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
