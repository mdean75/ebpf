package nethealth

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

type SocketMetadataRegistry struct {
	mu            sync.RWMutex
	metadataInode map[string]map[string]string
	metadataFlow  map[string]map[string]string
	streamIDsFlow map[string]map[string]struct{}
}

func NewSocketMetadataRegistry() *SocketMetadataRegistry {
	return &SocketMetadataRegistry{
		metadataInode: map[string]map[string]string{},
		metadataFlow:  map[string]map[string]string{},
		streamIDsFlow: map[string]map[string]struct{}{},
	}
}

func NewSocketMetadataRegistryFromPropertiesFile(path string) (*SocketMetadataRegistry, error) {
	registry := NewSocketMetadataRegistry()
	if path == "" {
		return registry, nil
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return registry, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if strings.HasPrefix(name, "inode.") {
			rest := strings.TrimPrefix(name, "inode.")
			i := strings.LastIndex(rest, ".")
			if i <= 0 || i == len(rest)-1 {
				continue
			}
			registry.PutForInode(rest[:i], rest[i+1:], value)
			continue
		}

		if strings.HasPrefix(name, "flow.") {
			rest := strings.TrimPrefix(name, "flow.")
			i := strings.LastIndex(rest, ".")
			if i <= 0 || i == len(rest)-1 {
				continue
			}
			registry.PutForFlow(rest[:i], rest[i+1:], value)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return registry, nil
}

func (r *SocketMetadataRegistry) PutForInode(inode, key, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.metadataInode[inode]; !ok {
		r.metadataInode[inode] = map[string]string{}
	}
	r.metadataInode[inode][key] = value
}

func (r *SocketMetadataRegistry) PutForFlow(flowKey, key, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.metadataFlow[flowKey]; !ok {
		r.metadataFlow[flowKey] = map[string]string{}
	}
	r.metadataFlow[flowKey][key] = value
}

func (r *SocketMetadataRegistry) AddStreamCorrIDForFlow(flowKey, streamCorrID string) {
	if strings.TrimSpace(flowKey) == "" || strings.TrimSpace(streamCorrID) == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.streamIDsFlow[flowKey]; !ok {
		r.streamIDsFlow[flowKey] = map[string]struct{}{}
	}
	r.streamIDsFlow[flowKey][streamCorrID] = struct{}{}
}

func (r *SocketMetadataRegistry) Resolve(inode string, flow SocketFlow) map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	merged := map[string]string{}
	if inodeMap, ok := r.metadataInode[inode]; ok {
		for key, value := range inodeMap {
			merged[key] = value
		}
	}
	if flowMap, ok := r.metadataFlow[flow.ToFlowKey()]; ok {
		for key, value := range flowMap {
			merged[key] = value
		}
	}

	if ids, ok := r.streamIDsFlow[flow.ToFlowKey()]; ok && len(ids) > 0 {
		all := make([]string, 0, len(ids))
		for id := range ids {
			all = append(all, id)
		}
		merged["streamCorrIDs"] = strings.Join(all, ",")
	}

	if len(merged) == 0 {
		return map[string]string{}
	}
	return merged
}
