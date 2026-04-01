# Results-9 Analysis: eBPF vs Protopulse vs Baseline — Detection Latency Comparison

**Date:** 2026-04-01
**Branch:** feature/protopulse-integration
**Test environment:** KVM VMs — service-a → nginx TLS → service-b ×2 at 200 msg/s (256-byte messages, 60s runs)

## Overview

This report covers a full six-way comparison of load-balancer health-detection modes:

| Dimension | Values |
|-----------|--------|
| LB mode | `baseline`, `ebpf`, `protopulse` |
| Dead-detection | `heartbeat` (500ms interval, 2s timeout), `keepalive` (10s interval, 5s timeout) |

**Key change from previous run (results-8):** Protopulse `/proc/net/tcp` polling thresholds were re-tuned to enable faster detection:

| Parameter | results-8 (default) | results-9 (tuned) |
|-----------|--------------------|--------------------|
| Retrans soft / hard | 2 / 10 | **0 / 3** |
| SendQ soft / hard | 64 KB / 256 KB | **2 KB / 16 KB** |
| AlphaRetrans (EMA) | 0.5 | **0.8** |
| EscalateAfter | 3 | **1** |

The previous defaults required ~7 retransmits before a WARNING fired, which takes ~25 s via TCP exponential backoff — far too slow to compete with the 2.4 s heartbeat. The new thresholds target detection at the 2nd retransmit (~600 ms after a disconnect).

---

## Configuration Reference

### Heartbeat dead-detection
- Interval: `500ms`, Timeout: `2s`
- Sends application-level ping messages on the gRPC stream; marks stream dead if no echo within timeout

### Keepalive dead-detection
- Time: `10s`, Timeout: `5s`, `PermitWithoutStream: true`
- Uses gRPC HTTP/2 PING frames; worst-case disconnect detection: 15 s
- In practice, HTTP/2 flow-control window exhaustion (~5 s) triggers connection close before the keepalive PING fires

### Protopulse poller
- Poll interval: `200ms`
- Reads `/proc/net/tcp` per connection; computes EMA-smoothed risk score from retransmit counter, send queue depth, and unacked segments
- WARNING fires when `rawRisk > 20`; alert cooldown: `0s`

---

## Run 1 — No Fault (Baseline)

All 6 mode/detection combinations: **0 lost, 0 rerouted, 0 dropped**. All streams healthy throughout.

---

## Run 2 — 5% Packet Loss on VM1

| Mode | Dead-detection | Detection time | Lost | Rerouted | Signal source |
|------|---------------|----------------|------|---------|---------------|
| baseline | heartbeat | not detected | 0 | 0 | — |
| baseline | keepalive | not detected | 0 | 0 | — |
| **eBPF** | heartbeat | **0.38 s** | 0 | 7,516 | kernel TCP event |
| **eBPF** | keepalive | **0.39 s** | 0 | 6,860 | kernel TCP event |
| **protopulse** | heartbeat | **5.82 s** | 0 | 120 | `protopulse_signal` ← first ever |
| protopulse | keepalive | not detected | 0 | 0 | — |

**Notes:**
- 5% loss is too gentle to consistently fail a 2 s heartbeat response. Neither baseline mode detects it.
- Protopulse now fires for the first time on 5% packet loss (risk=20.1, just at threshold), but only in heartbeat mode. The signal immediately recovers 600 ms later — only 120 messages rerouted. In keepalive mode the sendQ pattern doesn't cross the threshold.
- eBPF is the only reliable detector at this loss level, firing within ~400 ms via kernel TCP congestion events.

> **Script anomaly:** `run2-packetloss-baseline/heartbeat` ran ~130 s instead of 70 s due to a timing issue, resulting in 25,709 messages sent (vs ~13,000 for all other runs). No detection occurred regardless.

---

## Run 3 — 200ms Latency on VM1

| Mode | Dead-detection | Detection time | Lost | Rerouted | Signal source |
|------|---------------|----------------|------|---------|---------------|
| baseline | heartbeat | not detected | 0 | 0 | — |
| baseline | keepalive | not detected | 0 | 0 | — |
| **eBPF** | heartbeat | **0.086 s** | 0 | 10,292 | kernel TCP event |
| **eBPF** | keepalive | **0.074 s** | 0 | 6,943 | kernel TCP event |
| protopulse | heartbeat | not detected | 0 | 0 | — |
| **protopulse** | keepalive | **3.45 s** | 0 | 120 | `protopulse_signal` |

**Notes:**
- 200ms latency (400ms RTT) is well under the 2 s heartbeat timeout, so baseline/heartbeat sees the stream as healthy even though throughput is degraded.
- Protopulse/keepalive detected at 3.45 s (risk=23.2), immediately recovered 600 ms later. Only 120 messages rerouted during the degraded window. The same scenario in protopulse/heartbeat mode produced no signal — heartbeat send traffic slightly changes TCP window dynamics, keeping the sendQ just below the 2 KB threshold. This is a fragile, boundary-case detection.
- eBPF detects via kernel push event within 80–90 ms regardless of dead-detection mode, rerouting 10,000+ messages with zero loss.

---

## Run 4 — Hard Disconnect VM1

| Mode | Dead-detection | Detection time | Lost | Rerouted | Signal source |
|------|---------------|----------------|------|---------|---------------|
| baseline | heartbeat | 2.47 s | 242 | 9,809 | heartbeat timeout |
| baseline | keepalive | 5.33 s | 423 | 5,836 | HTTP/2 flow ctrl exhaustion |
| **eBPF** | heartbeat | **0.091 s** | 6 | 10,291 | kernel TCP event |
| **eBPF** | keepalive | **0.090 s** | 6 | 10,352 | kernel TCP event |
| **protopulse** | heartbeat | **0.798 s** | 76 | 10,164 | `protopulse_signal` |
| **protopulse** | keepalive | **0.613 s** | 59 | 6,041 | `protopulse_signal` |

**vs results-8 (before threshold tuning):**

| Mode | results-8 lost | results-9 lost | Reduction |
|------|---------------|---------------|-----------|
| protopulse/heartbeat | 244 | 76 | **−69%** |
| protopulse/keepalive | 425 | 59 | **−86%** |

**Notes:**
- Protopulse now detects hard disconnects in sub-second time. It fires first (risk=34.2 and 20.2 respectively), marks the stream degraded and starts rerouting immediately. The heartbeat then confirms fully dead at ~2.4 s.
- In keepalive mode, the stream errors via HTTP/2 flow-control exhaustion at ~5 s, long after protopulse has already rerouted traffic.
- eBPF remains the fastest at ~90 ms with only 6 messages lost, independent of dead-detection mode.

**Detection time ranking (disconnect):** eBPF (90 ms) → protopulse (0.6–0.8 s) → baseline/heartbeat (2.5 s) → baseline/keepalive (5.3 s)

---

## Run 5 — VM2 Scenarios (eBPF & protopulse only)

### 5% Packet Loss — VM2

| Mode | Dead-detection | Detection time | Lost | Rerouted |
|------|---------------|----------------|------|---------|
| eBPF | heartbeat | 0.44 s | 0 | 7,254 |
| eBPF | keepalive | 0.55 s | 0 | 6,388 |
| protopulse | heartbeat | not detected | 0 | 0 |
| protopulse | keepalive | not detected | 0 | 0 |

### 200ms Latency — VM2

| Mode | Dead-detection | Detection time | Lost | Rerouted |
|------|---------------|----------------|------|---------|
| **eBPF** | heartbeat | **0.088 s** | 0 | 10,366 |
| **eBPF** | keepalive | **0.087 s** | 0 | 7,041 |
| **protopulse** | heartbeat | **6.16 s** | 0 | 280 |
| protopulse | keepalive | not detected | 0 | 0 |

Protopulse detected latency on VM2 in heartbeat mode (6.16 s, 2 transitions) but not in keepalive mode — consistent with the boundary-case, mode-dependent behavior observed on VM1.

### Hard Disconnect — VM2

| Mode | Dead-detection | Detection time | Lost | Rerouted |
|------|---------------|----------------|------|---------|
| **eBPF** | heartbeat | **0.083 s** | 6 | 10,293 |
| **eBPF** | keepalive | **0.090 s** | 6 | 10,372 |
| **protopulse** | heartbeat | **0.754 s** | 73 | 10,189 |
| **protopulse** | keepalive | **0.753 s** | 73 | 6,088 |

Disconnect detection is consistent across both VMs: protopulse fires at ~750 ms in both heartbeat and keepalive modes.

---

## Run 6 — 30% Heavy Packet Loss on VM1

| Mode | Dead-detection | Detection time | Lost | Rerouted | Transitions |
|------|---------------|----------------|------|---------|------------|
| baseline | heartbeat | ~12.4 s* | 21 | 7,799 | — |
| baseline | keepalive | not detected | 386 | 0 | — |
| **eBPF** | heartbeat | **0.31 s** | 0 | 10,249 | 1 |
| **eBPF** | keepalive | **0.13 s** | 0 | 10,277 | 1 |
| **protopulse** | heartbeat | **0.83 s** | 0 | 2,675 | **17** |
| **protopulse** | keepalive | **1.62 s** | 67 | 3,834 | **12** |

\* Baseline/heartbeat detection time is non-deterministic with stochastic 30% loss (5.95 s in results-8, 12.4 s here). The 21-message loss count is low because TCP retransmits successfully delivered most messages — just slowly.

**Notes:**
- Protopulse detects heavy packet loss quickly (0.83 s / 1.62 s), but the **17 and 12 state transition counts reveal an oscillation problem.** The stochastic nature of 30% loss causes the risk score to repeatedly hover near the 20 WARNING threshold, triggering rapid healthy ↔ degraded flips every ~600 ms. With `EscalateAfter=1` and zero hysteresis, every marginal poll sample causes a state change.
- This oscillation explains why protopulse achieves 0 lost (traffic is always being evaluated) but only 2,675 rerouted — far fewer than eBPF's 10,249. Some traffic continues reaching the degraded VM between degraded windows.
- **Recommendation:** Raise `EscalateAfter` back to 2 or 3 to dampen oscillation under stochastic loss, while keeping fast detection for deterministic failures (disconnects).
- Baseline/keepalive does not detect 30% packet loss at all (some ACKs still flow, flow-control window never exhausts), resulting in 386 messages lost to the 3 s `lossDeadline`.

---

## Summary: Detection Latency Across All Scenarios

```
Scenario            eBPF/hb   eBPF/ka   proto/hb   proto/ka   base/hb    base/ka
──────────────────  ────────  ────────  ─────────  ─────────  ─────────  ───────
5% packet loss      ~0.4 s    ~0.4 s    5.8 s*     none       none       none
200ms latency       ~0.09 s   ~0.08 s   ~6 s*      3.45 s*    none       none
Hard disconnect     ~0.09 s   ~0.09 s   ~0.8 s     ~0.6 s     ~2.5 s     ~5.3 s
30% packet loss     ~0.3 s    ~0.1 s    ~0.8 s†    ~1.6 s†    5–12 s     none
```

\* Inconsistent — these detections are boundary-case and vary between runs
† Detected but oscillates (12–17 state transitions); traffic not fully rerouted

---

## Key Findings

### 1. Threshold tuning significantly improved protopulse disconnect detection

Sub-second detection (0.6–0.8 s) for hard disconnects is now achieved, reducing message loss by 69–86% compared to results-8. The retransmit counter rises quickly once TCP begins backing off after a disconnect, which the lowered thresholds now catch at the 2nd retransmit.

### 2. Soft-fault detection (5% loss, 200ms latency) remains inconsistent

The risk score hovers near the 20 WARNING boundary. Whether it crosses depends on exact TCP window state at poll time, whether heartbeat traffic is in-flight, and run-to-run timing variance. These detections are not reliable enough to depend on in production.

### 3. Oscillation is a new problem under stochastic loss

Removing all hysteresis (`EscalateAfter=1`) enables fast detection for clean failures but causes rapid state flipping under stochastic conditions. Raising `EscalateAfter` to 2–3 is recommended to balance responsiveness against stability.

### 4. eBPF is unmatched across all scenarios

~80–550 ms detection, zero message loss, single clean state transition, consistent across both VMs and both dead-detection modes. The kernel push-event model means it sees TCP-level signals (retransmits, RTT spikes, connection close) before any application-level mechanism can react.

### 5. Heartbeat outperforms keepalive for dead-detection

| Scenario | Heartbeat lost | Keepalive lost |
|----------|---------------|---------------|
| Disconnect | 242 | 423 |
| 30% packet loss | 21 | 386 |
| 200ms latency | 0 | 0* |

\* Baseline/keepalive produces 0 lost for latency only because the stream continues to function; messages are delayed but not dropped at the TCP level.

gRPC keepalive (10 s + 5 s = 15 s worst case) is far too slow for sub-second fault response. In disconnect scenarios, HTTP/2 flow-control exhaustion (~5 s) is what actually terminates the connection — the keepalive PING never fires. Heartbeat's 500 ms interval + 2 s timeout is substantially more responsive.

### 6. Dead-detection mode is irrelevant when eBPF is active

eBPF/heartbeat and eBPF/keepalive produce nearly identical results (≤2 message difference) because the kernel push event fires long before either application-layer mechanism would trigger.

---

## CPU and Memory Overhead

The `service-a-metrics.prom` snapshots captured at end-of-run include process-level metrics. No significant difference was observed between modes:

| Metric | Range across all runs |
|--------|----------------------|
| RSS memory | 14–19 MB |
| CPU (cumulative, ~70 s run) | 15–18 CPU-seconds (~21–26% of one core) |

**Caveats:** These are single end-of-run snapshots, not time-series data. They cover service-a only — there is no measurement of eBPF agent overhead at the kernel level or service-b VM resource usage. To properly characterize eBPF agent cost, time-series `pidstat` or `perf stat` sampling during runs would be needed.

---

## Recommended Next Steps

1. **Raise `EscalateAfter` to 2 or 3** in the protopulse poller to suppress oscillation under stochastic packet loss while retaining fast disconnect detection.
2. **Instrument CPU/memory time-series** per run (e.g. `pidstat -p <pid> 1` sampled during the run window) to properly compare overhead between modes, especially eBPF agent kernel cost.
3. **Consider a hybrid protopulse+eBPF signal** — protopulse's `/proc/net/tcp` polling could serve as a local fallback on hosts where the eBPF agent is unavailable, without replacing the kernel-event path.
