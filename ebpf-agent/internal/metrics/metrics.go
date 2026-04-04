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

	UnackedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_unacked_total",
		Help: "Total unacked-threshold-crossing events per connection (each count is one black-hole detection).",
	}, []string{"saddr", "daddr", "dport"})

	ConnectionScore = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_connection_score",
		Help: "Current risk score per connection (0=healthy, 100=dead). Matches nethealth's RiskScore scale.",
	}, []string{"saddr", "daddr", "dport"})
)
