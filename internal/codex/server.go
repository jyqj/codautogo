package codex

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ──────────────── Server Config ────────────────

type ServerConfig struct {
	Host       string
	Port       int
	AdminToken string
	DataDir    string
	ConfigPath string
	LogsDir    string
}

// ──────────────── Log Broadcaster ────────────────

type LogBroadcaster struct {
	mu      sync.RWMutex
	clients map[chan string]struct{}
	buffer  []string
	maxBuf  int
}

func NewLogBroadcaster(maxBuf int) *LogBroadcaster {
	if maxBuf <= 0 {
		maxBuf = 500
	}
	return &LogBroadcaster{
		clients: make(map[chan string]struct{}),
		maxBuf:  maxBuf,
	}
}

func (lb *LogBroadcaster) Broadcast(line string) {
	lb.mu.Lock()
	if len(lb.buffer) >= lb.maxBuf {
		lb.buffer = lb.buffer[1:]
	}
	lb.buffer = append(lb.buffer, line)
	for ch := range lb.clients {
		select {
		case ch <- line:
		default:
		}
	}
	lb.mu.Unlock()
}

func (lb *LogBroadcaster) Subscribe() (chan string, []string) {
	ch := make(chan string, 64)
	lb.mu.Lock()
	snapshot := make([]string, len(lb.buffer))
	copy(snapshot, lb.buffer)
	lb.clients[ch] = struct{}{}
	lb.mu.Unlock()
	return ch, snapshot
}

func (lb *LogBroadcaster) Unsubscribe(ch chan string) {
	lb.mu.Lock()
	delete(lb.clients, ch)
	lb.mu.Unlock()
	close(ch)
}

func (lb *LogBroadcaster) RecentLines(n int) []string {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	if n <= 0 || n >= len(lb.buffer) {
		result := make([]string, len(lb.buffer))
		copy(result, lb.buffer)
		return result
	}
	start := len(lb.buffer) - n
	result := make([]string, n)
	copy(result, lb.buffer[start:])
	return result
}

// ──────────────── Log Writer (tee stdout + broadcast) ────────────────

type LogWriter struct {
	original    *os.File
	broadcaster *LogBroadcaster
}

func (w *LogWriter) Write(p []byte) (int, error) {
	n, err := w.original.Write(p)
	lines := strings.Split(string(p), "\n")
	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed != "" {
			w.broadcaster.Broadcast(trimmed)
		}
	}
	return n, err
}

// ──────────────── Server ────────────────

type Server struct {
	cfg         *ServerConfig
	runner      *Runner
	codexCfg    *Config
	stats       *StatsCollector
	broadcaster *LogBroadcaster

	mu        sync.Mutex
	running   bool
	runMode   string // "", "once", "loop"
	runCancel context.CancelFunc
	phase     string // idle, running, completed, failed
	lastError string

	mux *http.ServeMux
}

func NewServer(cfg *ServerConfig) *Server {
	broadcaster := NewLogBroadcaster(500)
	stats := NewStatsCollector()
	srv := &Server{
		cfg:         cfg,
		stats:       stats,
		broadcaster: broadcaster,
		phase:       "idle",
		mux:         http.NewServeMux(),
	}
	srv.registerRoutes()

	// tee stdout to broadcaster
	pr, pw, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = pw
	go func() {
		scanner := bufio.NewScanner(pr)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			_, _ = origStdout.Write([]byte(line + "\n"))
			broadcaster.Broadcast(line)
		}
	}()

	return srv
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/config", s.withAuth(s.handleConfig))
	s.mux.HandleFunc("/api/runtime/status", s.withAuth(s.handleStatus))
	s.mux.HandleFunc("/api/runtime/start", s.withAuth(s.handleStart))
	s.mux.HandleFunc("/api/runtime/start-loop", s.withAuth(s.handleStartLoop))
	s.mux.HandleFunc("/api/runtime/stop", s.withAuth(s.handleStop))
	s.mux.HandleFunc("/api/stats", s.withAuth(s.handleStats))
	s.mux.HandleFunc("/api/logs/stream", s.withAuth(s.handleLogsSSE))
	s.mux.HandleFunc("/api/auth/verify", s.handleVerifyToken)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// ──────────────── Auth ────────────────

func (s *Server) withAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Admin-Token")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token != s.cfg.AdminToken {
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

// ──────────────── Handlers ────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{"status": "ok", "time": NowLocalString()})
}

func (s *Server) handleVerifyToken(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Admin-Token")
	if token == s.cfg.AdminToken {
		jsonOK(w, map[string]any{"valid": true})
	} else {
		jsonError(w, "invalid token", http.StatusForbidden)
	}
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		raw, err := LoadConfigRaw(s.cfg.ConfigPath)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		MaskSensitiveFields(raw)
		jsonOK(w, raw)
	case "POST":
		var incoming map[string]any
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		current, err := LoadConfigRaw(s.cfg.ConfigPath)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		merged := MergeConfigPreserveSensitive(current, incoming)
		if err := SaveConfigRaw(s.cfg.ConfigPath, merged); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]any{"status": "saved"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func buildSingleAccountTiming(stats StatsSnapshot) map[string]any {
	var latestReg any
	var latestOAuth any
	var latestTotal any
	var recentAvgReg any
	var recentAvgOAuth any
	var recentAvgTotal any

	if n := len(stats.RecentTimings); n > 0 {
		last := stats.RecentTimings[n-1]
		if last.RegSeconds > 0 {
			latestReg = last.RegSeconds
		}
		if last.OAuthSeconds > 0 {
			latestOAuth = last.OAuthSeconds
		}
		if last.TotalSeconds > 0 {
			latestTotal = last.TotalSeconds
		}
	}
	if stats.AvgRegSeconds > 0 {
		recentAvgReg = stats.AvgRegSeconds
	}
	if stats.AvgOAuthSec > 0 {
		recentAvgOAuth = stats.AvgOAuthSec
	}
	if stats.AvgTotalSec > 0 {
		recentAvgTotal = stats.AvgTotalSec
	}

	recentSlowCount := 0
	if stats.AvgTotalSec > 0 {
		threshold := stats.AvgTotalSec * 1.25
		for _, item := range stats.RecentTimings {
			if item.TotalSeconds >= threshold {
				recentSlowCount++
			}
		}
	}

	return map[string]any{
		"latest_reg_seconds":       latestReg,
		"latest_oauth_seconds":     latestOAuth,
		"latest_total_seconds":     latestTotal,
		"recent_avg_reg_seconds":   recentAvgReg,
		"recent_avg_oauth_seconds": recentAvgOAuth,
		"recent_avg_total_seconds": recentAvgTotal,
		"recent_slow_count":        recentSlowCount,
		"sample_size":              len(stats.RecentTimings),
	}
}

func buildMaintainPayload(runner *Runner, minCandidates int, stats StatsSnapshot) map[string]any {
	singleTiming := buildSingleAccountTiming(stats)
	payload := map[string]any{
		"available_candidates":       0,
		"pending_count":              0,
		"oauth_pool_active":          false,
		"min_candidates":             maxInt(0, minCandidates),
		"loop_round":                 0,
		"loop_next_check_in_seconds": 0,
		"completed":                  0,
		"total":                      0,
		"percent":                    0,
		"message":                    "等待维护任务启动",
		"cooldown":                   map[string]any{"is_cooling_down": false, "consecutive_failures": 0},
		"single_account_timing":      singleTiming,
	}
	if runner == nil {
		return payload
	}

	snap := runner.MaintainStateSnapshot()
	percent := 0
	if snap.TotalTarget > 0 {
		percent = int(math.Round((float64(snap.CompletedCount) / float64(snap.TotalTarget)) * 100))
		if percent < 0 {
			percent = 0
		}
		if percent > 100 {
			percent = 100
		}
	}

	nextCheck := 0
	if snap.NextCheckAfter > 0 && !snap.LastCheckTime.IsZero() {
		remaining := time.Until(snap.LastCheckTime.Add(snap.NextCheckAfter))
		if remaining > 0 {
			nextCheck = int(math.Ceil(remaining.Seconds()))
		}
	}

	cooldownPayload := map[string]any{
		"is_cooling_down":      false,
		"consecutive_failures": 0,
	}
	if runner.cooldown != nil {
		cooldown := runner.cooldown.Snapshot()
		cooldownPayload["is_cooling_down"] = cooldown.IsCoolingDown
		cooldownPayload["consecutive_failures"] = cooldown.ConsecutiveFailures
	}

	payload["available_candidates"] = snap.CandidatesCount
	payload["pending_count"] = snap.PendingCount
	payload["oauth_pool_active"] = snap.OauthPoolActive
	payload["min_candidates"] = snap.MinCandidates
	payload["loop_round"] = snap.LoopRound
	payload["loop_next_check_in_seconds"] = nextCheck
	payload["completed"] = snap.CompletedCount
	payload["total"] = snap.TotalTarget
	payload["percent"] = percent
	if strings.TrimSpace(snap.Message) != "" {
		payload["message"] = snap.Message
	}
	payload["cooldown"] = cooldownPayload
	payload["single_account_timing"] = singleTiming
	return payload
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	runner := s.runner
	minCandidates := 0
	if s.codexCfg != nil {
		minCandidates = s.codexCfg.MinCandidates
	}
	stats := s.stats.Snapshot()
	status := map[string]any{
		"running":  s.running,
		"mode":     s.runMode,
		"phase":    s.phase,
		"error":    s.lastError,
		"stats":    stats,
		"logs":     s.broadcaster.RecentLines(120),
		"maintain": buildMaintainPayload(runner, minCandidates, stats),
	}
	s.mu.Unlock()
	jsonOK(w, status)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, s.stats.Snapshot())
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		jsonError(w, "already running", http.StatusConflict)
		return
	}

	cfg, err := LoadConfig(s.cfg.DataDir)
	if err != nil {
		s.mu.Unlock()
		jsonError(w, "load config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.codexCfg = cfg
	s.stats.Reset()
	runner := NewRunner(cfg)
	runner.SetStats(s.stats)
	s.runner = runner
	s.running = true
	s.runMode = "once"
	s.phase = "running"
	s.lastError = ""

	ctx, cancel := context.WithCancel(context.Background())
	s.runCancel = cancel
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			s.running = false
			s.runMode = ""
			if s.phase == "running" {
				s.phase = "completed"
			}
			s.mu.Unlock()
		}()
		runner.RunMaintainOnce(ctx)
	}()

	jsonOK(w, map[string]any{"status": "started", "mode": "once", "message": "已启动单次维护"})
}

func (s *Server) handleStartLoop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		jsonError(w, "already running", http.StatusConflict)
		return
	}

	cfg, err := LoadConfig(s.cfg.DataDir)
	if err != nil {
		s.mu.Unlock()
		jsonError(w, "load config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.codexCfg = cfg
	s.stats.Reset()
	runner := NewRunner(cfg)
	runner.SetStats(s.stats)
	s.runner = runner
	s.running = true
	s.runMode = "loop"
	s.phase = "running"
	s.lastError = ""

	ctx, cancel := context.WithCancel(context.Background())
	s.runCancel = cancel
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			s.running = false
			s.runMode = ""
			if s.phase == "running" {
				s.phase = "completed"
			}
			s.mu.Unlock()
		}()
		runner.RunMaintainLoop(ctx)
	}()

	jsonOK(w, map[string]any{"status": "started", "mode": "loop", "message": "已启动循环维护"})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		jsonError(w, "not running", http.StatusConflict)
		return
	}
	if s.runCancel != nil {
		s.runCancel()
	}
	s.phase = "stopped"
	s.mu.Unlock()
	jsonOK(w, map[string]any{"status": "stopping"})
}

func (s *Server) handleLogsSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonError(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch, history := s.broadcaster.Subscribe()
	defer s.broadcaster.Unsubscribe(ch)

	for _, line := range history {
		fmt.Fprintf(w, "data: %s\n\n", line)
	}
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", line)
			flusher.Flush()
		}
	}
}

// ──────────────── Config Raw Operations ────────────────

func LoadConfigRaw(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return data, nil
}

func SaveConfigRaw(path string, data map[string]any) error {
	raw, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

const maskedValue = "__MASKED__"

var sensitiveTopLevel = []string{
	"cf_admin_password",
}

var sensitiveNested = map[string][]string{
	"clean": {"token"},
}

func MaskSensitiveFields(data map[string]any) {
	for _, key := range sensitiveTopLevel {
		if v, ok := data[key]; ok && v != nil && fmt.Sprint(v) != "" {
			data[key] = maskedValue
		}
	}
	for section, keys := range sensitiveNested {
		if sub, ok := data[section].(map[string]any); ok {
			for _, key := range keys {
				if v, ok := sub[key]; ok && v != nil && fmt.Sprint(v) != "" {
					sub[key] = maskedValue
				}
			}
		}
	}
	if cfConfigs, ok := data["cf_mail_configs"].([]any); ok {
		for _, item := range cfConfigs {
			if m, ok := item.(map[string]any); ok {
				if v, ok := m["admin_password"]; ok && v != nil && fmt.Sprint(v) != "" {
					m["admin_password"] = maskedValue
				}
			}
		}
	}
}

func MergeConfigPreserveSensitive(current, incoming map[string]any) map[string]any {
	for _, key := range sensitiveTopLevel {
		if fmt.Sprint(incoming[key]) == maskedValue {
			incoming[key] = current[key]
		}
	}
	for section, keys := range sensitiveNested {
		inSub, inOK := incoming[section].(map[string]any)
		curSub, curOK := current[section].(map[string]any)
		if inOK && curOK {
			for _, key := range keys {
				if fmt.Sprint(inSub[key]) == maskedValue {
					inSub[key] = curSub[key]
				}
			}
		}
	}
	inConfigs, inOK := incoming["cf_mail_configs"].([]any)
	curConfigs, curOK := current["cf_mail_configs"].([]any)
	if inOK && curOK {
		for idx, item := range inConfigs {
			if m, ok := item.(map[string]any); ok {
				if fmt.Sprint(m["admin_password"]) == maskedValue && idx < len(curConfigs) {
					if cm, ok := curConfigs[idx].(map[string]any); ok {
						m["admin_password"] = cm["admin_password"]
					}
				}
			}
		}
	}
	return incoming
}

// ──────────────── Admin Token ────────────────

func ResolveAdminToken(dataDir string) string {
	if token := os.Getenv("APP_ADMIN_TOKEN"); token != "" {
		return token
	}
	tokenFile := filepath.Join(dataDir, "admin_token.txt")
	if raw, err := os.ReadFile(tokenFile); err == nil {
		token := strings.TrimSpace(string(raw))
		if token != "" {
			return token
		}
	}
	token := generateRandomToken()
	_ = os.WriteFile(tokenFile, []byte(token+"\n"), 0o600)
	fmt.Printf("Generated admin token: %s\n", token)
	fmt.Printf("Saved to: %s\n", tokenFile)
	return token
}

func generateRandomToken() string {
	buf := make([]byte, 24)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// ──────────────── JSON helpers ────────────────

func jsonOK(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Admin-Token")
	_ = json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Admin-Token")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ──────────────── Unused import guard ────────────────
var _ io.Reader
var _ = time.Now
