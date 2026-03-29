package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	RetransmitsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_retransmits_total",
		Help: "Total TCP retransmit events observed per connection.",
	}, []string{"saddr", "daddr", "dport"})

	RTOTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_rto_total",
		Help: "Total RTO events observed per connection.",
	}, []string{"saddr", "daddr", "dport"})

	RTTSpikeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_rtt_spike_total",
		Help: "Total RTT spike events observed per connection.",
	}, []string{"saddr", "daddr", "dport"})

	ConnectionScore = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_connection_score",
		Help: "Current health score per connection (0=healthy, 1=dead).",
	}, []string{"saddr", "daddr", "dport"})
)
