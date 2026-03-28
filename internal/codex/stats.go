package codex

import (
	"sync"
	"time"
)

type FailureCategory string

const (
	FailMailCreate    FailureCategory = "mail_create_error"
	FailRegister      FailureCategory = "register_error"
	FailOTPTimeout    FailureCategory = "otp_timeout"
	FailPhoneRequired FailureCategory = "phone_required"
	FailNetworkError  FailureCategory = "network_error"
	FailAccountBanned FailureCategory = "account_banned"
	FailCPAUpload     FailureCategory = "cpa_upload_error"
	FailOAuthError    FailureCategory = "oauth_error"
	FailUnknown       FailureCategory = "unknown_error"
)

const maxTimingSamples = 50

type AccountTiming struct {
	Email        string  `json:"email"`
	RegSeconds   float64 `json:"reg_seconds"`
	OAuthSeconds float64 `json:"oauth_seconds"`
	TotalSeconds float64 `json:"total_seconds"`
	Timestamp    string  `json:"timestamp"`
}

type StatsSnapshot struct {
	StartTime      string                  `json:"start_time"`
	UptimeSeconds  float64                 `json:"uptime_seconds"`
	RegOK          int                     `json:"reg_ok"`
	RegFail        int                     `json:"reg_fail"`
	OAuthOK        int                     `json:"oauth_ok"`
	OAuthFail      int                     `json:"oauth_fail"`
	TotalProcessed int                     `json:"total_processed"`
	Failures       map[FailureCategory]int `json:"failures"`
	RecentTimings  []AccountTiming         `json:"recent_timings"`
	AvgRegSeconds  float64                 `json:"avg_reg_seconds"`
	AvgOAuthSec    float64                 `json:"avg_oauth_seconds"`
	AvgTotalSec    float64                 `json:"avg_total_seconds"`
	Throughput     float64                 `json:"throughput_per_account"`
}

type StatsCollector struct {
	mu            sync.RWMutex
	startTime     time.Time
	regOK         int
	regFail       int
	oauthOK       int
	oauthFail     int
	failures      map[FailureCategory]int
	recentTimings []AccountTiming
}

func NewStatsCollector() *StatsCollector {
	return &StatsCollector{
		startTime: time.Now(),
		failures:  make(map[FailureCategory]int),
	}
}

func (s *StatsCollector) RecordRegSuccess() {
	s.mu.Lock()
	s.regOK++
	s.mu.Unlock()
}

func (s *StatsCollector) RecordRegFailure(cat FailureCategory) {
	s.mu.Lock()
	s.regFail++
	s.failures[cat]++
	s.mu.Unlock()
}

func (s *StatsCollector) RecordOAuthSuccess() {
	s.mu.Lock()
	s.oauthOK++
	s.mu.Unlock()
}

func (s *StatsCollector) RecordOAuthFailure(cat FailureCategory) {
	s.mu.Lock()
	s.oauthFail++
	s.failures[cat]++
	s.mu.Unlock()
}

func (s *StatsCollector) RecordTiming(t AccountTiming) {
	s.mu.Lock()
	if len(s.recentTimings) >= maxTimingSamples {
		s.recentTimings = s.recentTimings[1:]
	}
	s.recentTimings = append(s.recentTimings, t)
	s.mu.Unlock()
}

func (s *StatsCollector) Snapshot() StatsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snap := StatsSnapshot{
		StartTime:      s.startTime.Format("2006-01-02 15:04:05"),
		UptimeSeconds:  time.Since(s.startTime).Seconds(),
		RegOK:          s.regOK,
		RegFail:        s.regFail,
		OAuthOK:        s.oauthOK,
		OAuthFail:      s.oauthFail,
		TotalProcessed: s.regOK + s.regFail,
		Failures:       make(map[FailureCategory]int, len(s.failures)),
		RecentTimings:  make([]AccountTiming, len(s.recentTimings)),
	}
	for k, v := range s.failures {
		snap.Failures[k] = v
	}
	copy(snap.RecentTimings, s.recentTimings)

	if n := len(snap.RecentTimings); n > 0 {
		var sumReg, sumOAuth, sumTotal float64
		for _, t := range snap.RecentTimings {
			sumReg += t.RegSeconds
			sumOAuth += t.OAuthSeconds
			sumTotal += t.TotalSeconds
		}
		snap.AvgRegSeconds = sumReg / float64(n)
		snap.AvgOAuthSec = sumOAuth / float64(n)
		snap.AvgTotalSec = sumTotal / float64(n)
	}
	if snap.OAuthOK > 0 && snap.UptimeSeconds > 0 {
		snap.Throughput = snap.UptimeSeconds / float64(snap.OAuthOK)
	}
	return snap
}

func (s *StatsCollector) Reset() {
	s.mu.Lock()
	s.startTime = time.Now()
	s.regOK = 0
	s.regFail = 0
	s.oauthOK = 0
	s.oauthFail = 0
	s.failures = make(map[FailureCategory]int)
	s.recentTimings = nil
	s.mu.Unlock()
}
