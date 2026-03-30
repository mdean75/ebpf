package nethealth

import (
	"math"
	"strings"
	"time"
)

type ActionLevel string

const (
	ActionHealthy  ActionLevel = "HEALTHY"
	ActionWarning  ActionLevel = "WARNING"
	ActionSick     ActionLevel = "SICK"
	ActionCritical ActionLevel = "CRITICAL"
	ActionDead     ActionLevel = "DEAD"
)

type MetricThreshold struct {
	Soft float64
	Hard float64
}

type ScoreThresholds struct {
	Unacked MetricThreshold
	Retrans MetricThreshold
	SendQ   MetricThreshold
}

type ScoreWeights struct {
	State   float64
	Retrans float64
	Unacked float64
	SendQ   float64
}

type EmaConfig struct {
	AlphaUnacked float64
	AlphaRetrans float64
	AlphaSendQ   float64
}

type StabilityConfig struct {
	EscalateAfter         int
	RecoverAfter          int
	InactivitySeconds     int
	InactivityDecayFactor float64
}

// ActionBands defines the raw-risk boundary values that map a risk score
// (0-100) to an ActionLevel. Override to tune sensitivity per deployment.
type ActionBands struct {
	// Risk scores <= WarnAbove are HEALTHY. Default 20.
	WarnAbove float64
	// Risk scores <= SickAbove are WARNING. Default 50.
	SickAbove float64
	// Risk scores <= CritAbove are SICK. Default 80.
	CritAbove float64
	// Risk scores >= DeadAt are DEAD. Default 100.
	DeadAt float64
}

// DefaultActionBands returns the standard band boundaries.
func DefaultActionBands() ActionBands {
	return ActionBands{WarnAbove: 20, SickAbove: 50, CritAbove: 80, DeadAt: 100}
}

type ScoreConfig struct {
	Weights    ScoreWeights
	Thresholds ScoreThresholds
	EMA        EmaConfig
	Stability  StabilityConfig
	// Bands controls how raw-risk values map to ActionLevel labels.
	// Leave as zero-value to use DefaultActionBands.
	Bands ActionBands
}

func DefaultScoreConfig() ScoreConfig {
	return ScoreConfig{
		Weights: ScoreWeights{State: 0.30, Retrans: 0.35, Unacked: 0.25, SendQ: 0.15},
		Thresholds: ScoreThresholds{
			Unacked: MetricThreshold{Soft: 50, Hard: 200},
			Retrans: MetricThreshold{Soft: 2, Hard: 10},
			SendQ:   MetricThreshold{Soft: 64 * 1024, Hard: 256 * 1024},
		},
		EMA:       EmaConfig{AlphaUnacked: 0.4, AlphaRetrans: 0.5, AlphaSendQ: 0.4},
		Stability: StabilityConfig{EscalateAfter: 3, RecoverAfter: 3, InactivitySeconds: 10, InactivityDecayFactor: 0.90},
		Bands:     DefaultActionBands(),
	}
}

func ConservativeThresholds() ScoreThresholds {
	return ScoreThresholds{
		Unacked: MetricThreshold{Soft: 20, Hard: 80},
		Retrans: MetricThreshold{Soft: 1, Hard: 5},
		SendQ:   MetricThreshold{Soft: 16 * 1024, Hard: 64 * 1024},
	}
}

func BalancedThresholds() ScoreThresholds {
	return ScoreThresholds{
		Unacked: MetricThreshold{Soft: 50, Hard: 200},
		Retrans: MetricThreshold{Soft: 2, Hard: 10},
		SendQ:   MetricThreshold{Soft: 64 * 1024, Hard: 256 * 1024},
	}
}

func HighThroughputThresholds() ScoreThresholds {
	return ScoreThresholds{
		Unacked: MetricThreshold{Soft: 200, Hard: 1000},
		Retrans: MetricThreshold{Soft: 5, Hard: 50},
		SendQ:   MetricThreshold{Soft: 256 * 1024, Hard: 1024 * 1024},
	}
}

type ScoreInput struct {
	State   string
	Unacked float64
	Retrans float64
	SendQ   float64
}

type ScoreBreakdown struct {
	StateScore   float64
	NormRetrans  float64
	NormUnacked  float64
	NormSendQ    float64
	RawRisk      float64
	HealthScore  int
	NHS          float64
	Action       ActionLevel
	EffectiveRaw float64
}

type emaState struct {
	initialized bool
	unacked     float64
	retrans     float64
	sendQ       float64
}

type ScoreEngine struct {
	cfg              ScoreConfig
	ema              emaState
	currentAction    ActionLevel
	escalateStreak   int
	recoveryStreak   int
	lastActivityTime time.Time
}

func NewScoreEngine(cfg ScoreConfig) *ScoreEngine {
	cfg = normalizeScoreConfig(cfg)
	return &ScoreEngine{cfg: cfg, currentAction: ActionHealthy}
}

func (e *ScoreEngine) Observe(input ScoreInput, now time.Time, active bool) ScoreBreakdown {
	if now.IsZero() {
		now = time.Now()
	}

	emaInput := input
	if !e.ema.initialized {
		e.ema = emaState{initialized: true, unacked: input.Unacked, retrans: input.Retrans, sendQ: input.SendQ}
	} else {
		e.ema.unacked = emaUpdate(e.cfg.EMA.AlphaUnacked, input.Unacked, e.ema.unacked)
		e.ema.retrans = emaUpdate(e.cfg.EMA.AlphaRetrans, input.Retrans, e.ema.retrans)
		e.ema.sendQ = emaUpdate(e.cfg.EMA.AlphaSendQ, input.SendQ, e.ema.sendQ)
	}
	if active {
		e.lastActivityTime = now
	}

	emaInput.Unacked = e.ema.unacked
	emaInput.Retrans = e.ema.retrans
	emaInput.SendQ = e.ema.sendQ

	breakdown := ScoreWithConfig(emaInput, e.cfg)
	raw := breakdown.RawRisk

	if !e.lastActivityTime.IsZero() && e.cfg.Stability.InactivitySeconds > 0 && e.cfg.Stability.InactivityDecayFactor > 0 && e.cfg.Stability.InactivityDecayFactor < 1 {
		idleSeconds := now.Sub(e.lastActivityTime).Seconds()
		if idleSeconds >= float64(e.cfg.Stability.InactivitySeconds) {
			steps := int(idleSeconds / float64(e.cfg.Stability.InactivitySeconds))
			raw = raw * math.Pow(e.cfg.Stability.InactivityDecayFactor, float64(steps))
		}
	}

	target := actionFromRiskBanded(raw, e.cfg.Bands)
	effective := target

	if actionSeverity(target) > actionSeverity(e.currentAction) {
		e.escalateStreak++
		e.recoveryStreak = 0
		if e.escalateStreak >= e.cfg.Stability.EscalateAfter {
			e.currentAction = target
			e.escalateStreak = 0
		}
		effective = e.currentAction
	} else if actionSeverity(target) < actionSeverity(e.currentAction) {
		e.recoveryStreak++
		e.escalateStreak = 0
		if e.recoveryStreak >= e.cfg.Stability.RecoverAfter {
			e.currentAction = target
			e.recoveryStreak = 0
		}
		effective = e.currentAction
	} else {
		e.escalateStreak = 0
		e.recoveryStreak = 0
		e.currentAction = target
		effective = target
	}

	breakdown.EffectiveRaw = raw
	breakdown.Action = effective
	breakdown.HealthScore = int(math.Round(clamp(100-raw, 0, 100)))
	breakdown.NHS = clamp((100-raw)/100, 0, 1)
	return breakdown
}

func ScoreWithConfig(input ScoreInput, cfg ScoreConfig) ScoreBreakdown {
	cfg = normalizeScoreConfig(cfg)

	stateScore := stateScore(input.State)
	normRetrans := normalizeRamp(input.Retrans, cfg.Thresholds.Retrans)
	normUnacked := normalizeRamp(input.Unacked, cfg.Thresholds.Unacked)
	normSendQ := normalizeRamp(input.SendQ, cfg.Thresholds.SendQ)

	raw := cfg.Weights.State*stateScore +
		cfg.Weights.Retrans*normRetrans +
		cfg.Weights.Unacked*normUnacked +
		cfg.Weights.SendQ*normSendQ
	raw = clamp(raw, 0, 100)

	health := int(math.Round(100 - raw))
	if health < 0 {
		health = 0
	}

	return ScoreBreakdown{
		StateScore:  stateScore,
		NormRetrans: normRetrans,
		NormUnacked: normUnacked,
		NormSendQ:   normSendQ,
		RawRisk:     raw,
		HealthScore: health,
		NHS:         clamp((100-raw)/100, 0, 1),
		Action:      actionFromRiskBanded(raw, cfg.Bands),
	}
}

// ActionFromRisk maps a raw risk score (0-100) to an ActionLevel using the
// default band boundaries. Use actionFromRiskBanded for custom bands.
func ActionFromRisk(rawRisk float64) ActionLevel {
	return actionFromRiskBanded(rawRisk, DefaultActionBands())
}

// ParseAction validates and normalizes a string into an ActionLevel.
// The input is trimmed and uppercased before matching.
// Returns the matching ActionLevel and true if valid; returns ("", false) otherwise.
func ParseAction(s string) (ActionLevel, bool) {
	switch ActionLevel(strings.ToUpper(strings.TrimSpace(s))) {
	case ActionHealthy, ActionWarning, ActionSick, ActionCritical, ActionDead:
		return ActionLevel(strings.ToUpper(strings.TrimSpace(s))), true
	default:
		return "", false
	}
}

// Score returns a representative health score (0–100) for this action level.
// The value sits at approximately the midpoint of its band and is suitable
// for display or override scenarios when a precise score is unavailable.
func (a ActionLevel) Score() int {
	switch a {
	case ActionHealthy:
		return 95
	case ActionWarning:
		return 65
	case ActionSick:
		return 30
	case ActionCritical:
		return 10
	case ActionDead:
		return 0
	default:
		return 100
	}
}

// Colorize wraps the action level string in ANSI terminal color codes.
// When enabled is false the plain uppercase action name is returned unchanged.
//
// Color mapping:
//
//	HEALTHY  → green
//	WARNING  → yellow
//	SICK     → red
//	CRITICAL → magenta
//	DEAD     → magenta
func (a ActionLevel) Colorize(enabled bool) string {
	base := string(a)
	if !enabled {
		return base
	}
	const (
		green   = "\x1b[32m"
		yellow  = "\x1b[33m"
		red     = "\x1b[31m"
		magenta = "\x1b[35m"
		reset   = "\x1b[0m"
	)
	switch a {
	case ActionHealthy:
		return green + base + reset
	case ActionWarning:
		return yellow + base + reset
	case ActionSick:
		return red + base + reset
	case ActionCritical, ActionDead:
		return magenta + base + reset
	default:
		return base
	}
}

func actionFromRiskBanded(rawRisk float64, bands ActionBands) ActionLevel {
	risk := clamp(rawRisk, 0, 100)
	switch {
	case risk >= bands.DeadAt:
		return ActionDead
	case risk > bands.CritAbove:
		return ActionCritical
	case risk > bands.SickAbove:
		return ActionSick
	case risk > bands.WarnAbove:
		return ActionWarning
	default:
		return ActionHealthy
	}
}

func stateScore(state string) float64 {
	s := strings.ToUpper(strings.TrimSpace(state))
	switch s {
	case "CLOSED", "TIME_WAIT", "LAST_ACK", "LISTEN":
		return 100
	case "CLOSE_WAIT", "FIN_WAIT_1", "FIN_WAIT_2", "CLOSING":
		return 80
	default:
		return 0
	}
}

func normalizeRamp(value float64, threshold MetricThreshold) float64 {
	if threshold.Hard <= threshold.Soft {
		if value > threshold.Hard {
			return 100
		}
		return 0
	}
	scaled := 100 * (value - threshold.Soft) / (threshold.Hard - threshold.Soft)
	return clamp(scaled, 0, 100)
}

func normalizeScoreConfig(cfg ScoreConfig) ScoreConfig {
	if cfg.Thresholds.Unacked.Hard == 0 && cfg.Thresholds.Retrans.Hard == 0 && cfg.Thresholds.SendQ.Hard == 0 {
		cfg = DefaultScoreConfig()
	}

	if cfg.EMA.AlphaUnacked <= 0 || cfg.EMA.AlphaUnacked > 1 {
		cfg.EMA.AlphaUnacked = 0.4
	}
	if cfg.EMA.AlphaRetrans <= 0 || cfg.EMA.AlphaRetrans > 1 {
		cfg.EMA.AlphaRetrans = 0.5
	}
	if cfg.EMA.AlphaSendQ <= 0 || cfg.EMA.AlphaSendQ > 1 {
		cfg.EMA.AlphaSendQ = 0.4
	}

	if cfg.Stability.EscalateAfter < 1 {
		cfg.Stability.EscalateAfter = 3
	}
	if cfg.Stability.RecoverAfter < 1 {
		cfg.Stability.RecoverAfter = 3
	}

	weightSum := cfg.Weights.State + cfg.Weights.Retrans + cfg.Weights.Unacked + cfg.Weights.SendQ
	if weightSum <= 0 {
		cfg.Weights = DefaultScoreConfig().Weights
		weightSum = cfg.Weights.State + cfg.Weights.Retrans + cfg.Weights.Unacked + cfg.Weights.SendQ
	}
	cfg.Weights.State /= weightSum
	cfg.Weights.Retrans /= weightSum
	cfg.Weights.Unacked /= weightSum
	cfg.Weights.SendQ /= weightSum

	// Default band boundaries if not explicitly configured.
	if cfg.Bands.DeadAt == 0 && cfg.Bands.CritAbove == 0 && cfg.Bands.SickAbove == 0 && cfg.Bands.WarnAbove == 0 {
		cfg.Bands = DefaultActionBands()
	}

	return cfg
}

func emaUpdate(alpha, value, prev float64) float64 {
	return alpha*value + (1-alpha)*prev
}

func actionSeverity(action ActionLevel) int {
	switch action {
	case ActionDead:
		return 4
	case ActionCritical:
		return 3
	case ActionSick:
		return 2
	case ActionWarning:
		return 1
	default:
		return 0
	}
}

func clamp(v, low, high float64) float64 {
	if v < low {
		return low
	}
	if v > high {
		return high
	}
	return v
}
