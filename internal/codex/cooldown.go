package codex

import (
	"fmt"
	"sync"
	"time"
)

// CooldownGate 共享链路冷却控制器。
// 当连续失败次数超过阈值时，触发全局冷却暂停，所有 worker 等待冷却结束。
// 成功一次即重置连续失败计数和冷却状态。
type CooldownGate struct {
	mu                  sync.Mutex
	consecutiveFailures int
	cooldownUntil       time.Time
	threshold           int           // 连续失败多少次触发冷却
	cooldownDuration    time.Duration // 冷却持续时间
	failureStageCounts  map[string]int
	failureDetailCounts map[string]string
}

type CooldownSnapshot struct {
	IsCoolingDown        bool      `json:"is_cooling_down"`
	ConsecutiveFailures  int       `json:"consecutive_failures"`
	CooldownUntil        time.Time `json:"-"`
	CooldownUntilDisplay string    `json:"cooldown_until,omitempty"`
}

// NewCooldownGate 创建冷却控制器。
func NewCooldownGate(threshold int, cooldownDuration time.Duration) *CooldownGate {
	if threshold < 1 {
		threshold = 5
	}
	if cooldownDuration < time.Second {
		cooldownDuration = 45 * time.Second
	}
	return &CooldownGate{
		threshold:           threshold,
		cooldownDuration:    cooldownDuration,
		failureStageCounts:  make(map[string]int),
		failureDetailCounts: make(map[string]string),
	}
}

// WaitForAvailability 阻塞等待冷却结束。如果不在冷却期则立即返回。
// ctx 用于检查取消（但 CooldownGate 本身不带 context，由调用方控制）。
func (g *CooldownGate) WaitForAvailability() {
	for {
		g.mu.Lock()
		until := g.cooldownUntil
		failures := g.consecutiveFailures
		g.mu.Unlock()

		if until.IsZero() || time.Now().After(until) {
			return
		}

		waitSec := time.Until(until).Seconds()
		if waitSec < 0 {
			return
		}
		// 最多等 5 秒再检查一次（避免长时间阻塞）
		sleepDur := time.Duration(waitSec * float64(time.Second))
		if sleepDur > 5*time.Second {
			sleepDur = 5 * time.Second
		}
		fmt.Printf("  ⏸️ 共享链路处于冷却期，等待 %.1fs 后重试（连续失败=%d）\n", waitSec, failures)
		time.Sleep(sleepDur)
	}
}

// NoteSuccess 成功后重置冷却状态。
func (g *CooldownGate) NoteSuccess() {
	g.mu.Lock()
	g.consecutiveFailures = 0
	g.cooldownUntil = time.Time{}
	g.mu.Unlock()
}

// NoteFailure 失败后累加计数，超过阈值触发冷却。
// 返回是否触发了冷却。
func (g *CooldownGate) NoteFailure(stage, email, detail string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.consecutiveFailures++
	count := g.consecutiveFailures
	stageKey := stage
	if stageKey == "" {
		stageKey = "unknown"
	}
	g.failureStageCounts[stageKey]++
	if detail != "" {
		g.failureDetailCounts[stageKey] = detail
	}

	if count >= g.threshold {
		newUntil := time.Now().Add(g.cooldownDuration)
		if newUntil.After(g.cooldownUntil) {
			g.cooldownUntil = newUntil
		}
		fmt.Printf("  🧊 失败归类: stage=%s email=%s consecutive=%d/%d | 进入冷却至 %s\n",
			stageKey, email, count, g.threshold, g.cooldownUntil.Format("15:04:05"))
		return true
	}

	fmt.Printf("  ⚠️ 失败归类: stage=%s email=%s consecutive=%d/%d\n",
		stageKey, email, count, g.threshold)
	return false
}

// IsCoolingDown 返回当前是否在冷却期。
func (g *CooldownGate) IsCoolingDown() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.cooldownUntil.IsZero() && time.Now().Before(g.cooldownUntil)
}

// FailureStats 返回失败统计快照。
func (g *CooldownGate) FailureStats() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	cp := make(map[string]int, len(g.failureStageCounts))
	for k, v := range g.failureStageCounts {
		cp[k] = v
	}
	return cp
}

func (g *CooldownGate) Snapshot() CooldownSnapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	snap := CooldownSnapshot{
		IsCoolingDown:       !g.cooldownUntil.IsZero() && time.Now().Before(g.cooldownUntil),
		ConsecutiveFailures: g.consecutiveFailures,
		CooldownUntil:       g.cooldownUntil,
	}
	if !g.cooldownUntil.IsZero() {
		snap.CooldownUntilDisplay = g.cooldownUntil.Format("15:04:05")
	}
	return snap
}

// Reset 重置冷却状态。
func (g *CooldownGate) Reset() {
	g.mu.Lock()
	g.consecutiveFailures = 0
	g.cooldownUntil = time.Time{}
	g.failureStageCounts = make(map[string]int)
	g.failureDetailCounts = make(map[string]string)
	g.mu.Unlock()
}
