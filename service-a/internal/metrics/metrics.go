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

	// MessagesLost counts messages that were never successfully delivered.
	// reason: "timeout"    — no response within lossDeadline (3s)
	//         "queue_full" — send queue saturated, message dropped before send
	//         "abandoned"  — message was in-flight when stream disconnected
	MessagesLost = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "service_a_messages_lost_total",
		Help: "Messages lost per stream, by reason (timeout|queue_full|abandoned).",
	}, []string{"addr", "reason"})

	// MessagesRerouted counts messages routed to an alternate stream because
	// the round-robin candidate was degraded or dead. Labeled by the skipped
	// stream so you can see how many messages were diverted away from each VM.
	MessagesRerouted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "service_a_messages_rerouted_total",
		Help: "Messages sent to an alternate stream because the primary was degraded/dead.",
	}, []string{"skipped_addr"})

	// MessagesDropped counts messages that were not sent because every stream
	// was simultaneously dead (Next() returned "").
	MessagesDropped = promauto.NewCounter(prometheus.CounterOpts{
		Name: "service_a_messages_dropped_total",
		Help: "Messages discarded because all streams were unavailable.",
	})

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
		Help: "Number of stream state transitions to degraded/dead, per stream.",
	}, []string{"addr", "reason"})
)
