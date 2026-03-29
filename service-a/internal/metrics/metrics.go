package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	MessagesSent = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "service_a_messages_sent_total",
		Help: "Total messages sent per stream.",
	}, []string{"addr"})

	MessagesLost = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "service_a_messages_lost_total",
		Help: "Messages sent with no response within the deadline, per stream.",
	}, []string{"addr"})

	ResponseLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "service_a_response_latency_seconds",
		Help:    "Round-trip latency from message send to response receipt.",
		Buckets: prometheus.DefBuckets,
	}, []string{"addr"})

	StreamHealth = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "service_a_stream_health",
		Help: "Current stream health: 0=healthy, 1=degraded, 2=dead.",
	}, []string{"addr"})

	Reroutes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "service_a_reroutes_total",
		Help: "Number of times a message was rerouted away from a stream.",
	}, []string{"addr", "reason"})
)
