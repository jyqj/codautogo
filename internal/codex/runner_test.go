package codex

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunMaintainOnceWithoutCPAConfig(t *testing.T) {
	cfg := newTestConfig(t)
	runner := NewRunner(cfg)

	runner.RunMaintainOnce(context.Background())

	snap := runner.MaintainStateSnapshot()
	if !strings.Contains(snap.Message, "CPA 未配置") {
		t.Fatalf("expected missing CPA message, got %q", snap.Message)
	}
	if snap.CandidatesCount != 0 || snap.CompletedCount != 0 || snap.TotalTarget != 0 {
		t.Fatalf("unexpected maintain snapshot: %+v", snap)
	}
	if snap.OauthPoolActive {
		t.Fatalf("oauth pool should be inactive: %+v", snap)
	}
}

func TestRunMaintainLoopStopsAfterCancel(t *testing.T) {
	cfg := newTestConfig(t)
	runner := NewRunner(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runner.RunMaintainLoop(ctx)
	}()

	waitForCondition(t, 2*time.Second, func() bool {
		snap := runner.MaintainStateSnapshot()
		return snap.LoopRound >= 1 && strings.Contains(snap.Message, "后开始下一轮巡检")
	})

	cancel()
	waitForCondition(t, 2*time.Second, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	})

	snap := runner.MaintainStateSnapshot()
	if snap.LoopRound < 1 {
		t.Fatalf("expected loop round >= 1, got %+v", snap)
	}
	if snap.Message != "循环维护已停止" {
		t.Fatalf("expected stop message, got %q", snap.Message)
	}
	if snap.OauthPoolActive {
		t.Fatalf("oauth pool should be inactive after stop: %+v", snap)
	}
	if snap.NextCheckAfter != 0 {
		t.Fatalf("expected countdown cleared after stop, got %+v", snap)
	}
}
