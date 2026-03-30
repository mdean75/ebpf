package nethealth

import (
	"errors"
	"sync"
	"time"
)

// Errors returned by Monitor methods.
var (
	ErrPollingAlreadyActive = errors.New("polling is already active")
)

// SocketMeta identifies and describes a socket being monitored.
// Clients associate arbitrary key/value labels to sockets so they can later
// query health by label (e.g. service, region, tier, pod).
type SocketMeta struct {
	// ID is the unique identifier for this socket or stream.
	// It must be non-empty and stable for the lifetime of the connection.
	ID string

	// Labels are arbitrary user-defined key/value pairs.
	// Examples: {"service": "payments", "region": "us-east", "tier": "critical"}
	Labels map[string]string
}

// HealthReport is returned by pull queries and included in push alerts.
type HealthReport struct {
	// Meta is the socket metadata as registered via Track().
	Meta SocketMeta

	// Action is the current health action level: HEALTHY, WARNING, SICK, CRITICAL, DEAD.
	Action ActionLevel

	// RiskScore is the smoothed raw risk value (0–100). Higher = more risk.
	// This is the effective post-decay, post-EMA value used to derive Action.
	RiskScore float64

	// HealthScore is the inverse: 100 - RiskScore, clamped to [0, 100].
	// Higher = healthier. Suitable for dashboards.
	HealthScore int

	// Breakdown contains the detailed intermediate scoring values (per-metric
	// normalized scores, EMA-smoothed inputs, state component). Useful for
	// debugging and observability tooling.
	Breakdown ScoreBreakdown

	// Timestamp is when this report was computed.
	Timestamp time.Time
}

// AlertEvent is delivered via push (OnAlert or AlertChan) whenever a socket's
// action level changes and the AlertPolicy conditions are met.
type AlertEvent struct {
	// Meta is the socket metadata.
	Meta SocketMeta

	// From is the previous ActionLevel before the transition.
	From ActionLevel

	// To is the new ActionLevel after the transition.
	To ActionLevel

	// Report is the full HealthReport at the moment the alert fired.
	Report HealthReport
}

// AlertPolicy controls when and how push alerts are sent.
// An alert fires when a socket's ActionLevel changes AND all policy conditions
// are satisfied.
type AlertPolicy struct {
	// OnActions limits which destination ActionLevels trigger an alert.
	// An empty slice means "fire on any action change".
	// Example: []ActionLevel{ActionWarning, ActionSick, ActionCritical, ActionDead}
	OnActions []ActionLevel

	// CooldownSeconds is the minimum interval between consecutive alerts for
	// the same socket. 0 means no cooldown (alert every time the action changes).
	CooldownSeconds int
}

// MonitorConfig is the top-level configuration for a Monitor.
// All scoring parameters live in Scoring; push notification policy in AlertPolicy.
type MonitorConfig struct {
	// Scoring controls the weighted risk model, thresholds, EMA smoothing,
	// hysteresis, inactivity decay, and action band boundaries.
	//
	// Use DefaultScoreConfig() as a starting point, then override only the
	// fields relevant to your deployment:
	//
	//   cfg := nethealth.DefaultMonitorConfig()
	//   cfg.Scoring.Thresholds = nethealth.ConservativeThresholds()
	//   cfg.Scoring.Bands = nethealth.ActionBands{WarnAbove: 10, SickAbove: 40, CritAbove: 70, DeadAt: 95}
	Scoring ScoreConfig

	// AlertPolicy controls push notifications (OnAlert / AlertChan).
	AlertPolicy AlertPolicy

	// PollInterval is the interval at which StartPolling will sample metrics.
	// If zero or negative, defaults to 200 milliseconds when StartPolling is called.
	PollInterval time.Duration
}

// DefaultMonitorConfig returns a ready-to-use MonitorConfig with balanced
// thresholds and push alerts enabled for WARNING and above with a 30-second
// cooldown.
func DefaultMonitorConfig() MonitorConfig {
	return MonitorConfig{
		Scoring: DefaultScoreConfig(),
		AlertPolicy: AlertPolicy{
			OnActions:       []ActionLevel{ActionWarning, ActionSick, ActionCritical, ActionDead},
			CooldownSeconds: 30,
		},
	}
}

// socketEntry is internal state for a single tracked socket.
type socketEntry struct {
	meta       SocketMeta
	engine     *ScoreEngine
	latest     HealthReport
	lastAlert  time.Time
	prevAction ActionLevel
}

// MetricsPoint represents the current metrics snapshot for a single socket.
// Returned by a MetricsCollector function during polling.
type MetricsPoint struct {
	// SocketID identifies which socket these metrics belong to.
	SocketID string

	// Input contains the raw TCP/application metrics (unacked, retrans, sendQ, state).
	Input ScoreInput

	// Active indicates whether the socket has had recent activity (controls inactivity decay).
	Active bool
}

// MetricsCollector is a function that samples metrics for all monitored sockets.
// Called by StartPolling at each poll interval. Return a slice of MetricsPoints
// for sockets to be scored. Update only returns metrics for sockets you want scored
// (e.g., only connected sockets); the library will call Observe for each point.
//
// Example for gRPC server:
//
//	collector := func() []nethealth.MetricsPoint {
//	    var points []nethealth.MetricsPoint
//	    hub.states.Range(func(_, v any) bool {
//	        state := v.(*streamState)
//	        sq, rt, ua := nethealth.SampleFlowMetrics(...)
//	        points = append(points, nethealth.MetricsPoint{
//	            SocketID: state.id,
//	            Input: nethealth.ScoreInput{
//	                State: "ESTABLISHED",
//	                Unacked: float64(ua),
//	                Retrans: float64(rt),
//	                SendQ: float64(sq),
//	            },
//	            Active: !state.closed,
//	        })
//	        return true
//	    })
//	    return points
//	}
//	mon.StartPolling(collector)
type MetricsCollector func() []MetricsPoint

// Monitor is the high-level facade for socket health monitoring.
//
// It manages one ScoreEngine per tracked socket (maintaining per-socket EMA
// history and hysteresis state), exposes a pull API for querying current
// health, and a push API for receiving alerts when health changes.
//
// Usage — pull model:
//
//	m := nethealth.NewMonitor(nethealth.DefaultMonitorConfig(), 0)
//	m.Track(nethealth.SocketMeta{ID: "conn-1", Labels: map[string]string{"service": "api"}})
//	// feed metrics each poll interval:
//	m.Observe("conn-1", nethealth.ScoreInput{State: "ESTABLISHED", Unacked: 30}, time.Now(), true)
//	report, _ := m.Health("conn-1")
//	fmt.Println(report.Action, report.HealthScore)
//
// Usage — push model:
//
//	m.OnAlert(func(evt nethealth.AlertEvent) {
//	    log.Printf("socket %s transitioned %s → %s", evt.Meta.ID, evt.From, evt.To)
//	})
//	// or use the channel:
//	go func() {
//	    for evt := range m.AlertChan() {
//	        log.Printf("alert: %s is now %s", evt.Meta.ID, evt.To)
//	    }
//	}()
type Monitor struct {
	cfg       MonitorConfig
	mu        sync.RWMutex
	sockets   map[string]*socketEntry
	callbacks []func(AlertEvent)
	alertCh   chan AlertEvent

	// Polling state
	pollingMu     sync.Mutex
	pollingActive bool
	pollingStop   chan struct{}
	pollingDone   sync.WaitGroup
}

// NewMonitor creates a new Monitor.
//
// alertBufferSize sets the capacity of the push channel returned by AlertChan.
// Use 0 for the default (64). Alerts are dropped (not blocked) when the
// channel is full, so size this appropriately for your processing rate.
func NewMonitor(cfg MonitorConfig, alertBufferSize int) *Monitor {
	if alertBufferSize <= 0 {
		alertBufferSize = 64
	}
	return &Monitor{
		cfg:     cfg,
		sockets: make(map[string]*socketEntry),
		alertCh: make(chan AlertEvent, alertBufferSize),
	}
}

// Track registers a socket for monitoring with its metadata. Safe to call
// multiple times for the same ID — subsequent calls update the Labels without
// resetting the engine's EMA or hysteresis state.
func (m *Monitor) Track(meta SocketMeta) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, exists := m.sockets[meta.ID]; exists {
		// Update metadata only; preserve in-flight engine state.
		entry.meta = meta
		entry.latest.Meta = meta
		return
	}
	m.sockets[meta.ID] = &socketEntry{
		meta:       meta,
		engine:     NewScoreEngine(m.cfg.Scoring),
		prevAction: ActionHealthy,
	}
}

// Untrack removes a socket from monitoring and discards its engine state.
func (m *Monitor) Untrack(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sockets, id)
}

// Observe feeds a new metric reading for a tracked socket and returns the
// updated HealthReport. If the socket has not been registered via Track, it
// is auto-registered with an empty Labels map.
//
// Parameters:
//   - id: socket identifier (must match the ID used in Track)
//   - input: current raw TCP/application metrics
//   - now: wall-clock time of this observation (use time.Now() or a test clock)
//   - active: true if the connection has had activity since the last observation
//     (controls inactivity-decay)
//
// This is the main injection point for the scoring pipeline. Call it once per
// polling interval per socket.
func (m *Monitor) Observe(id string, input ScoreInput, now time.Time, active bool) HealthReport {
	if now.IsZero() {
		now = time.Now()
	}

	m.mu.Lock()
	entry, exists := m.sockets[id]
	if !exists {
		entry = &socketEntry{
			meta:       SocketMeta{ID: id},
			engine:     NewScoreEngine(m.cfg.Scoring),
			prevAction: ActionHealthy,
		}
		m.sockets[id] = entry
	}

	breakdown := entry.engine.Observe(input, now, active)
	report := HealthReport{
		Meta:        entry.meta,
		Action:      breakdown.Action,
		RiskScore:   breakdown.EffectiveRaw,
		HealthScore: breakdown.HealthScore,
		Breakdown:   breakdown,
		Timestamp:   now,
	}
	entry.latest = report

	var alertToFire *AlertEvent
	if breakdown.Action != entry.prevAction {
		evt := AlertEvent{
			Meta:   entry.meta,
			From:   entry.prevAction,
			To:     breakdown.Action,
			Report: report,
		}
		if m.shouldAlert(entry, breakdown.Action, now) {
			alertToFire = &evt
			entry.lastAlert = now
		}
		entry.prevAction = breakdown.Action
	}

	// Capture callbacks under lock, fire outside to prevent deadlock.
	callbacks := m.callbacks
	m.mu.Unlock()

	if alertToFire != nil {
		m.fire(*alertToFire, callbacks)
	}

	return report
}

// Health returns the most recent HealthReport for the given socket ID.
// Returns (report, true) if the socket is known; (zero-value, false) if not.
func (m *Monitor) Health(id string) (HealthReport, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.sockets[id]
	if !ok {
		return HealthReport{}, false
	}
	return entry.latest, true
}

// HealthByLabel returns the latest HealthReport for every tracked socket whose
// Labels contain ALL of the given key/value pairs. Useful for querying all
// sockets belonging to a service, region, or tier.
//
// Example:
//
//	reports := m.HealthByLabel(map[string]string{"service": "payments"})
func (m *Monitor) HealthByLabel(labels map[string]string) []HealthReport {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var results []HealthReport
	for _, entry := range m.sockets {
		if labelsMatch(entry.meta.Labels, labels) {
			results = append(results, entry.latest)
		}
	}
	return results
}

// AllHealth returns the current HealthReport for every tracked socket.
// Order is not guaranteed.
func (m *Monitor) AllHealth() []HealthReport {
	m.mu.RLock()
	defer m.mu.RUnlock()
	results := make([]HealthReport, 0, len(m.sockets))
	for _, entry := range m.sockets {
		results = append(results, entry.latest)
	}
	return results
}

// OnAlert registers a callback that is called synchronously whenever an alert
// fires. Multiple callbacks can be registered; they are called in registration
// order. Keep callbacks fast — they run inside Observe.
//
// This is the push model callback variant:
//
//	m.OnAlert(func(evt nethealth.AlertEvent) {
//	    metrics.Increment("socket.health.alert", evt.To)
//	    if evt.To == nethealth.ActionDead {
//	        notifier.Send("connection lost: " + evt.Meta.ID)
//	    }
//	})
func (m *Monitor) OnAlert(fn func(AlertEvent)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks = append(m.callbacks, fn)
}

// AlertChan returns a read-only channel of AlertEvents (push model — channel
// variant). The channel is buffered (capacity set at NewMonitor). When full,
// events are silently dropped rather than blocking Observe.
//
// The channel is never closed; consume it in a goroutine until the Monitor is
// no longer needed.
//
//	go func() {
//	    for evt := range m.AlertChan() {
//	        log.Printf("[alert] %s: %s → %s (risk=%.1f)", evt.Meta.ID, evt.From, evt.To, evt.Report.RiskScore)
//	    }
//	}()
func (m *Monitor) AlertChan() <-chan AlertEvent {
	return m.alertCh
}

// TrackedCount returns the number of sockets currently tracked.
func (m *Monitor) TrackedCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sockets)
}

// shouldAlert returns true if an alert should fire for the given entry and
// incoming action, applying the configured policy and per-socket cooldown.
func (m *Monitor) shouldAlert(entry *socketEntry, action ActionLevel, now time.Time) bool {
	policy := m.cfg.AlertPolicy

	// Filter by target action if a whitelist is configured.
	if len(policy.OnActions) > 0 {
		found := false
		for _, a := range policy.OnActions {
			if a == action {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Respect per-socket cooldown.
	if policy.CooldownSeconds > 0 && !entry.lastAlert.IsZero() {
		elapsed := now.Sub(entry.lastAlert).Seconds()
		if elapsed < float64(policy.CooldownSeconds) {
			return false
		}
	}

	return true
}

// fire dispatches an alert to all registered callbacks and the alert channel.
func (m *Monitor) fire(alert AlertEvent, callbacks []func(AlertEvent)) {
	for _, cb := range callbacks {
		cb(alert)
	}
	select {
	case m.alertCh <- alert:
	default:
		// Channel full; drop to avoid blocking Observe.
	}
}

// StartPolling begins automatic periodic polling of socket metrics.
// The provided collector function is called at each poll interval to sample
// current metrics for all active sockets. For each MetricsPoint returned,
// Observe() is called to score and evaluate health.
//
// If polling is already active, StartPolling returns an error without changes.
// Multiple callers should serialize their calls or use this once.
//
// The poll interval is taken from cfg.PollInterval. If zero or negative,
// defaults to 200 milliseconds.
//
// Polling runs in a background goroutine and continues until StopPolling is called.
// StopPolling must be called to clean up the polling goroutine.
//
// Example:
//
//	mon := nethealth.NewMonitor(cfg, 0)
//	collector := func() []nethealth.MetricsPoint {
//	    // Return current metrics for all active sockets
//	}
//	if err := mon.StartPolling(collector); err != nil {
//	    log.Fatal(err)
//	}
//	defer mon.StopPolling()
//	// mon is now auto-scoring at each poll interval
func (m *Monitor) StartPolling(collector MetricsCollector) error {
	m.pollingMu.Lock()
	defer m.pollingMu.Unlock()

	if m.pollingActive {
		return ErrPollingAlreadyActive
	}

	interval := m.cfg.PollInterval
	if interval <= 0 {
		interval = 200 * time.Millisecond
	}

	m.pollingActive = true
	m.pollingStop = make(chan struct{})
	m.pollingDone.Add(1)

	go func() {
		defer m.pollingDone.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-m.pollingStop:
				return
			case <-ticker.C:
				points := collector()
				now := time.Now()
				for _, point := range points {
					m.Observe(point.SocketID, point.Input, now, point.Active)
				}
			}
		}
	}()

	return nil
}

// StopPolling stops automatic polling and waits for the polling goroutine to exit.
// Safe to call even if polling is not active.
//
// After StopPolling returns, no more calls to the collector will be made.
func (m *Monitor) StopPolling() error {
	m.pollingMu.Lock()
	if !m.pollingActive {
		m.pollingMu.Unlock()
		return nil
	}
	m.pollingActive = false
	close(m.pollingStop)
	m.pollingMu.Unlock()

	m.pollingDone.Wait()
	return nil
}

// labelsMatch returns true when all key/value pairs in query exist in socket.
func labelsMatch(socketLabels, query map[string]string) bool {
	for k, v := range query {
		if socketLabels[k] != v {
			return false
		}
	}
	return true
}
