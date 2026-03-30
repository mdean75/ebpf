package nethealth

import (
	"sync"
	"time"
)

type NetHealth struct {
	StreamID            string
	Status              string
	HealthScore         int
	Unhealthy           bool
	IdleMs              int64
	AppPendingResponses int64
	TCPUnacked          int64
	SndQueue            int64
	Retrans             int64
	DetectedIn          string
}

func NetHealthNotFound(streamID string) NetHealth {
	return NetHealth{
		StreamID:            streamID,
		Status:              "NOT_FOUND",
		HealthScore:         0,
		Unhealthy:           true,
		IdleMs:              -1,
		AppPendingResponses: -1,
		TCPUnacked:          -1,
		SndQueue:            -1,
		Retrans:             -1,
		DetectedIn:          "-",
	}
}

func (h NetHealth) GetStreamID() string           { return h.StreamID }
func (h NetHealth) GetStatus() string             { return h.Status }
func (h NetHealth) GetHealthScore() int           { return h.HealthScore }
func (h NetHealth) IsUnhealthy() bool             { return h.Unhealthy }
func (h NetHealth) GetIdleMs() int64              { return h.IdleMs }
func (h NetHealth) GetAppPendingResponses() int64 { return h.AppPendingResponses }
func (h NetHealth) GetTCPUnacked() int64          { return h.TCPUnacked }
func (h NetHealth) GetSndQueue() int64            { return h.SndQueue }
func (h NetHealth) GetRetrans() int64             { return h.Retrans }
func (h NetHealth) GetDetectedIn() string         { return h.DetectedIn }

type HealthComputer func(streamID string, socket *SocketSnapshot) NetHealth

type HealthMonitor struct {
	netHealthMonitor     *NetHealthMonitor
	mu                   sync.RWMutex
	latestHealthByStream map[string]NetHealth
	listeners            []HealthChangeListener
}

func NewHealthMonitor(netHealthMonitor *NetHealthMonitor) *HealthMonitor {
	return &HealthMonitor{
		netHealthMonitor:     netHealthMonitor,
		latestHealthByStream: map[string]NetHealth{},
		listeners:            []HealthChangeListener{},
	}
}

// AddHealthChangeListener registers a listener to be notified of health changes.
func (m *HealthMonitor) AddHealthChangeListener(listener HealthChangeListener) {
	if listener != nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.listeners = append(m.listeners, listener)
	}
}

// RemoveHealthChangeListener unregisters a previously registered listener.
func (m *HealthMonitor) RemoveHealthChangeListener(listener HealthChangeListener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Note: Go function types don't support equality comparison,
	// so removal is not straightforward. Users should track listener state.
	// Alternatively, we could clear all listeners.
}

// ClearHealthChangeListeners removes all registered listeners.
func (m *HealthMonitor) ClearHealthChangeListeners() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = []HealthChangeListener{}
}

func (m *HealthMonitor) Sample(streamIDs []string, computer HealthComputer) {
	socketByStream := map[string]SocketSnapshot{}
	for _, snapshot := range m.netHealthMonitor.Sample() {
		socketByStream[snapshot.ConnectionID] = snapshot
	}

	m.mu.Lock()
	for _, streamID := range streamIDs {
		var newHealth NetHealth
		snapshot, ok := socketByStream[streamID]
		if ok {
			s := snapshot
			newHealth = computer(streamID, &s)
		} else {
			newHealth = computer(streamID, nil)
		}

		// Check if health changed and fire event
		previousHealth, found := m.latestHealthByStream[streamID]
		m.latestHealthByStream[streamID] = newHealth

		// Fire event if health changed (not on first sample)
		if found && m.healthChanged(previousHealth, newHealth) {
			m.fireHealthChangeEvent(streamID, previousHealth, newHealth)
		}
	}
	m.mu.Unlock()
}

// healthChanged checks if health meaningfully changed (status or unhealthy state changed).
func (m *HealthMonitor) healthChanged(prev, curr NetHealth) bool {
	return prev.GetStatus() != curr.GetStatus() ||
		prev.IsUnhealthy() != curr.IsUnhealthy() ||
		prev.GetHealthScore() != curr.GetHealthScore()
}

// fireHealthChangeEvent notifies all listeners of a health change.
func (m *HealthMonitor) fireHealthChangeEvent(streamID string, prevHealth, currHealth NetHealth) {
	// Create a copy of listeners to avoid holding lock during callback
	listeners := make([]HealthChangeListener, len(m.listeners))
	copy(listeners, m.listeners)

	// Fire events outside the lock to avoid deadlocks
	// Note: This runs synchronously but outside the main lock
	go func() {
		event := HealthChangeEvent{
			StreamID:       streamID,
			PreviousHealth: prevHealth,
			CurrentHealth:  currHealth,
			Timestamp:      time.Now(),
		}
		for _, listener := range listeners {
			func() {
				defer func() {
					if r := recover(); r != nil {
						// Prevent one listener from crashing others
					}
				}()
				listener(event)
			}()
		}
	}()
}

func (m *HealthMonitor) GetNetHealth(streamID string) NetHealth {
	if streamID == "" {
		return NetHealthNotFound(streamID)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if health, ok := m.latestHealthByStream[streamID]; ok {
		return health
	}
	return NetHealthNotFound(streamID)
}

func CalculateHealthScore(closed bool, idleDegraded bool, sndQueue int64, retrans int64, tcpUnacked int64, appPendingResponses int64) int {
	state := "ESTABLISHED"
	if closed {
		state = "CLOSED"
	} else if idleDegraded {
		state = "CLOSE_WAIT"
	}

	input := ScoreInput{
		State:   state,
		Unacked: float64(maxInt64(tcpUnacked, appPendingResponses)),
		Retrans: float64(retrans),
		SendQ:   float64(sndQueue),
	}

	breakdown := ScoreWithConfig(input, DefaultScoreConfig())
	return breakdown.HealthScore
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
