package nethealth

type AggregateAppMetrics struct {
	Sent         int64
	Acked        int64
	Errors       int64
	Pending      int64
	MaxPending   int64
	OpenConns    int64
	PayloadBytes int64
}

type AggregateTCPCollectorConfig struct {
	SocketID         string
	SocketCollector  MetricsCollector
	AppMetrics       func() AggregateAppMetrics
	OnRawMetrics     func(unacked, retrans, sendQ int64)
	ShouldMarkClosed func(app AggregateAppMetrics) bool
}

func DefaultShouldMarkClosed(app AggregateAppMetrics) bool {
	if app.OpenConns > 0 || app.Errors == 0 || app.Pending > 0 {
		return false
	}
	return app.Sent == 0 || app.Acked < app.Sent/2
}

func NewAggregateTCPMetricsCollector(cfg AggregateTCPCollectorConfig) MetricsCollector {
	return func() []MetricsPoint {
		if cfg.AppMetrics == nil {
			return nil
		}

		app := cfg.AppMetrics()
		pending := app.Pending
		if pending < 0 {
			pending = 0
		}
		maxPending := app.MaxPending
		if maxPending < pending {
			maxPending = pending
		}

		unacked := MaxInt64(maxPending, app.Sent-app.Acked)
		retrans := app.Errors
		sendQ := unacked * app.PayloadBytes

		if cfg.SocketCollector != nil {
			for _, point := range cfg.SocketCollector() {
				unacked = MaxInt64(unacked, int64(point.Input.Unacked))
				retrans = MaxInt64(retrans, int64(point.Input.Retrans))
				sendQ = MaxInt64(sendQ, int64(point.Input.SendQ))
			}
		}

		if cfg.OnRawMetrics != nil {
			cfg.OnRawMetrics(unacked, retrans, sendQ)
		}

		shouldMarkClosed := DefaultShouldMarkClosed(app)
		if cfg.ShouldMarkClosed != nil {
			shouldMarkClosed = cfg.ShouldMarkClosed(app)
		}

		tcpState := "ESTABLISHED"
		if shouldMarkClosed {
			tcpState = "CLOSED"
		}

		socketID := cfg.SocketID
		if socketID == "" {
			socketID = "aggregate"
		}

		return []MetricsPoint{{
			SocketID: socketID,
			Input: ScoreInput{
				State:   tcpState,
				Unacked: float64(unacked),
				Retrans: float64(retrans),
				SendQ:   float64(sendQ),
			},
			Active: app.OpenConns > 0,
		}}
	}
}
