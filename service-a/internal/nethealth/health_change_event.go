package nethealth

import "time"

// HealthChangeEvent represents a change in stream health status.
type HealthChangeEvent struct {
	StreamID       string
	PreviousHealth NetHealth
	CurrentHealth  NetHealth
	Timestamp      time.Time
}

// StatusChanged returns true if the health status (not just score) changed.
func (e HealthChangeEvent) StatusChanged() bool {
	return e.PreviousHealth.GetStatus() != e.CurrentHealth.GetStatus()
}

// HealthinessChanged returns true if the health unhealthy state changed.
func (e HealthChangeEvent) HealthinessChanged() bool {
	return e.PreviousHealth.IsUnhealthy() != e.CurrentHealth.IsUnhealthy()
}

// HealthChangeListener is called when a stream's health changes.
type HealthChangeListener func(event HealthChangeEvent)
