package codex

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandleStatusIncludesMaintainPayload(t *testing.T) {
	cfg := newTestConfig(t)
	runner := NewRunner(cfg)
	runner.maintainState = MaintainState{
		OauthPoolActive: true,
		CandidatesCount: 42,
		MinCandidates:   50,
		PendingCount:    5,
		LastCheckTime:   time.Now(),
		NextCheckAfter:  30 * time.Second,
		LoopRound:       3,
		CompletedCount:  8,
		TotalTarget:     12,
		Message:         "库存不足 (42 < 50)，正在补号...",
	}
	runner.cooldown.NoteFailure("oauth", "tester@example.com", "timeout")

	stats := NewStatsCollector()
	stats.RecordTiming(AccountTiming{Email: "a@example.com", RegSeconds: 12.3, OAuthSeconds: 8.5, TotalSeconds: 20.8, Timestamp: NowLocalString()})
	stats.RecordTiming(AccountTiming{Email: "b@example.com", RegSeconds: 10.0, OAuthSeconds: 6.0, TotalSeconds: 16.0, Timestamp: NowLocalString()})

	broadcaster := NewLogBroadcaster(10)
	broadcaster.Broadcast("📊 巡检: CPA candidates=42")

	srv := &Server{
		cfg:         &ServerConfig{AdminToken: "secret"},
		runner:      runner,
		codexCfg:    cfg,
		stats:       stats,
		broadcaster: broadcaster,
		running:     true,
		runMode:     "loop",
		phase:       "running",
	}

	req := httptest.NewRequest("GET", "/api/runtime/status", nil)
	req.Header.Set("X-Admin-Token", "secret")
	rr := httptest.NewRecorder()
	srv.withAuth(srv.handleStatus)(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	maintain, ok := payload["maintain"].(map[string]any)
	if !ok {
		t.Fatalf("expected maintain payload, got %#v", payload["maintain"])
	}

	if got := int(maintain["available_candidates"].(float64)); got != 42 {
		t.Fatalf("expected candidates 42, got %d", got)
	}
	if got := int(maintain["pending_count"].(float64)); got != 5 {
		t.Fatalf("expected pending 5, got %d", got)
	}
	if got := int(maintain["loop_round"].(float64)); got != 3 {
		t.Fatalf("expected loop round 3, got %d", got)
	}
	if got := int(maintain["percent"].(float64)); got != 67 {
		t.Fatalf("expected rounded percent 67, got %d", got)
	}
	if got := maintain["message"].(string); !strings.Contains(got, "库存不足") {
		t.Fatalf("unexpected maintain message %q", got)
	}

	cooldown, ok := maintain["cooldown"].(map[string]any)
	if !ok || int(cooldown["consecutive_failures"].(float64)) != 1 {
		t.Fatalf("unexpected cooldown payload %#v", maintain["cooldown"])
	}

	timing, ok := maintain["single_account_timing"].(map[string]any)
	if !ok {
		t.Fatalf("missing timing payload: %#v", maintain["single_account_timing"])
	}
	if got := int(timing["sample_size"].(float64)); got != 2 {
		t.Fatalf("expected timing sample size 2, got %d", got)
	}
	if timing["latest_total_seconds"] == nil {
		t.Fatalf("expected latest total timing, got %#v", timing)
	}
}
