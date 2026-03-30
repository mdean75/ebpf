package nethealth

import "time"

type TCPCollectorSample struct {
	SocketID           string
	LocalPort          int
	RemoteIP           string
	RemotePort         int
	LastMessageAtNanos int64
	Received           int64
	Acked              int64
	Active             bool
	OnIdleDetected     func(nowNanos int64)
}

type TCPCollectorConfig struct {
	IdleThreshold time.Duration
	Iterate       func(yield func(TCPCollectorSample) bool)
}

func NewTCPMetricsCollector(cfg TCPCollectorConfig) MetricsCollector {
	return func() []MetricsPoint {
		if cfg.Iterate == nil {
			return nil
		}

		points := make([]MetricsPoint, 0, 256)
		nowNanos := time.Now().UnixNano()

		cfg.Iterate(func(sample TCPCollectorSample) bool {
			sndQueue, retrans, tcpUnacked := SampleFlowMetrics(sample.LocalPort, sample.RemoteIP, sample.RemotePort)

			idleDegraded := false
			if sample.LastMessageAtNanos > 0 {
				idleDegraded = time.Duration(nowNanos-sample.LastMessageAtNanos) > cfg.IdleThreshold
			}
			if idleDegraded && sample.OnIdleDetected != nil {
				sample.OnIdleDetected(nowNanos)
			}

			appPending := MaxInt64(0, sample.Acked-sample.Received)
			tcpUnackedInput := MaxInt64(appPending, MaxInt64(0, tcpUnacked))

			tcpState := "ESTABLISHED"
			if idleDegraded {
				tcpState = "CLOSE_WAIT"
			}

			points = append(points, MetricsPoint{
				SocketID: sample.SocketID,
				Input: ScoreInput{
					State:   tcpState,
					Unacked: float64(tcpUnackedInput),
					Retrans: float64(MaxInt64(0, retrans)),
					SendQ:   float64(MaxInt64(0, sndQueue)),
				},
				Active: sample.Active,
			})

			return true
		})

		return points
	}
}
