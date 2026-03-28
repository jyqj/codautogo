package codex

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	mathrand "math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
)

const (
	OpenAIAuthBase = "https://auth.openai.com"
	ChatGPTBase    = "https://chatgpt.com"
)

type Config struct {
	Root                       string
	TotalAccounts              int
	ConcurrentWorkers          int
	Proxy                      string
	WorkspaceRecordWorkers     int
	WorkspaceLoginWorkers      int
	OAuthStep2MaxRetries       int
	OAuthStep2RetryBaseSeconds float64
	SpaceRecordFile            string
	AccountRecordWorkers       int
	CFWorkerDomain             string
	CFEmailDomain              string
	CFAdminPassword            string
	CFMailConfigs              []CFMailConfig
	OAuthIssuer                string
	OAuthClientID              string
	OAuthRedirectURI           string
	AccountsFile               string
	CSVFile                    string
	AKFile                     string
	RKFile                     string
	ProxyMode                  string
	ProxyFile                  string
	MailProvider               string
	NamePrefix                 string
	DualPool                   bool
	RegisterWorkers            int
	OAuthWorkers               int
	OAuthDelaySeconds          int
	PendingQueueFile           string

	// CPA (CLIProxyAPI) 投递
	CPABaseURL              string
	CPAToken                string
	CPATargetType           string
	CPAUserAgent            string
	CPATimeout              int
	CPARetries              int
	CPAWorkers              int
	CPADeleteWorkers        int
	CPAUsedPercentThreshold int
	SaveLocal               bool

	// 维护模式
	MinCandidates        int
	LoopIntervalSeconds  float64
	FailureCooldownSec   float64
	FailureCooldownAfter int

	// 重试与容错
	StepRetryAttempts     int
	StepRetryDelayBase    float64 // 秒
	StepRetryDelayCap     float64 // 秒
	OAuthOuterRetries     int
	OAuthRetryBackoffBase float64 // 秒
	OAuthRetryBackoffMax  float64 // 秒
	TransientMarkers      []string

	// 注册入口模式
	EntryMode         string // "direct_auth" 或 "chatgpt_web"
	EntryModeFallback bool   // 主模式失败后是否自动回退

	// OTP 校验模式
	OTPValidateOrder []string // ["normal", "sentinel"]
}

type CFMailConfig struct {
	Name          string
	WorkerDomain  string
	EmailDomain   string
	AdminPassword string
}

type BrowserProfile struct {
	Family             string
	Major              int
	FullVersion        string
	UserAgent          string
	AppVersion         string
	Platform           string
	Vendor             string
	SecCHUA            string
	SecCHUAFullVersion string
	SecCHPlatform      string
	AcceptLanguage     string
	AcceptEncoding     string
	SendClientHints    bool
	SendPriority       bool
}

var HardcodedBrowserProfile = BrowserProfile{
	Family:             "Safari",
	Major:              17,
	FullVersion:        "17.6",
	UserAgent:          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
	AppVersion:         "5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
	Platform:           "MacIntel",
	Vendor:             "Apple Computer, Inc.",
	SecCHUA:            "",
	SecCHUAFullVersion: "",
	SecCHPlatform:      "",
	AcceptLanguage:     "zh-CN",
	AcceptEncoding:     "gzip, deflate, br",
	SendClientHints:    false,
	SendPriority:       false,
}

type Session struct {
	Client  *http.Client
	Profile BrowserProfile
	Proxy   string
}

type ClientFactory struct {
	cfg          *Config
	proxyManager *ProxyManager
}

type ProxyManager struct {
	cfg         *Config
	statsPath   string
	mu          sync.Mutex
	cachedPool  []string
	cachedMTime time.Time
	usage       map[string]int
	usageLoaded bool
}

type jsonConfig struct {
	TotalAccounts              int                `json:"total_accounts"`
	ConcurrentWorkers          int                `json:"concurrent_workers"`
	Proxy                      string             `json:"proxy"`
	MailProvider               string             `json:"mail_provider"`
	NamePrefix                 string             `json:"name_prefix"`
	DualPool                   bool               `json:"dual_pool"`
	RegisterWorkers            int                `json:"register_workers"`
	OAuthWorkers               int                `json:"oauth_workers"`
	OAuthDelaySeconds          int                `json:"oauth_delay_seconds"`
	PendingQueueFile           string             `json:"pending_queue_file"`
	WorkspaceRecordWorkers     int                `json:"workspace_record_workers"`
	WorkspaceLoginWorkers      int                `json:"workspace_login_workers"`
	OAuthStep2MaxRetries       int                `json:"oauth_step2_max_retries"`
	OAuthStep2RetryBaseSeconds float64            `json:"oauth_step2_retry_base_seconds"`
	SpaceRecordFile            string             `json:"space_record_file"`
	AccountRecordWorkers       int                `json:"account_record_workers"`
	CFWorkerDomain             string             `json:"cf_worker_domain"`
	CFEmailDomain              string             `json:"cf_email_domain"`
	CFAdminPassword            string             `json:"cf_admin_password"`
	CFMailConfigs              []jsonCFMailConfig `json:"cf_mail_configs"`
	OAuthIssuer                string             `json:"oauth_issuer"`
	OAuthClientID              string             `json:"oauth_client_id"`
	OAuthRedirectURI           string             `json:"oauth_redirect_uri"`
	AccountsFile               string             `json:"accounts_file"`
	CSVFile                    string             `json:"csv_file"`
	AKFile                     string             `json:"ak_file"`
	RKFile                     string             `json:"rk_file"`
	ProxyMode                  string             `json:"proxy_mode"`
	ProxyFile                  string             `json:"proxy_file"`

	// CPA 嵌套配置（兼容参考项目 config 格式）
	Clean        *jsonCleanConfig        `json:"clean"`
	Maintainer   *jsonMaintainerConfig   `json:"maintainer"`
	Run          *jsonRunConfig          `json:"run"`
	Output       *jsonOutputConfig       `json:"output"`
	Flow         *jsonFlowConfig         `json:"flow"`
	Registration *jsonRegistrationConfig `json:"registration"`
}

type jsonCFMailConfig struct {
	Name          string `json:"name"`
	WorkerDomain  string `json:"worker_domain"`
	EmailDomain   string `json:"email_domain"`
	AdminPassword string `json:"admin_password"`
}

type jsonCleanConfig struct {
	BaseURL              string `json:"base_url"`
	Token                string `json:"token"`
	TargetType           string `json:"target_type"`
	Workers              int    `json:"workers"`
	DeleteWorkers        int    `json:"delete_workers"`
	Timeout              int    `json:"timeout"`
	Retries              int    `json:"retries"`
	UserAgent            string `json:"user_agent"`
	UsedPercentThreshold int    `json:"used_percent_threshold"`
}

type jsonMaintainerConfig struct {
	MinCandidates       int     `json:"min_candidates"`
	LoopIntervalSeconds float64 `json:"loop_interval_seconds"`
}

type jsonRunConfig struct {
	Workers                  int     `json:"workers"`
	Proxy                    string  `json:"proxy"`
	FailureThresholdCooldown int     `json:"failure_threshold_for_cooldown"`
	FailureCooldownSeconds   float64 `json:"failure_cooldown_seconds"`
}

type jsonFlowConfig struct {
	StepRetryAttempts  int      `json:"step_retry_attempts"`
	StepRetryDelayBase float64  `json:"step_retry_delay_base"`
	StepRetryDelayCap  float64  `json:"step_retry_delay_cap"`
	OuterRetryAttempts int      `json:"outer_retry_attempts"`
	RetryBackoffBase   float64  `json:"retry_backoff_base"`
	RetryBackoffMax    float64  `json:"retry_backoff_max"`
	TransientMarkers   []string `json:"transient_markers"`
	OTPValidateOrder   []string `json:"otp_validate_order"`
}

type jsonRegistrationConfig struct {
	EntryMode         string `json:"entry_mode"`
	EntryModeFallback *bool  `json:"entry_mode_fallback"`
}

type jsonOutputConfig struct {
	AccountsFile string `json:"accounts_file"`
	CSVFile      string `json:"csv_file"`
	AKFile       string `json:"ak_file"`
	RKFile       string `json:"rk_file"`
	SaveLocal    *bool  `json:"save_local"`
}

func init() {
	mathrand.Seed(time.Now().UnixNano())
}

func LoadConfig(root string) (*Config, error) {
	if root == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		root = cwd
	}
	root, _ = filepath.Abs(root)

	loadEnvIfPresent(filepath.Join(root, ".env"))
	loadEnvIfPresent(filepath.Join(filepath.Dir(root), "config", ".env"))

	cfgFile := filepath.Join(root, "config.json")
	raw, err := os.ReadFile(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("read config.json: %w", err)
	}
	var jc jsonConfig
	if err := json.Unmarshal(raw, &jc); err != nil {
		return nil, fmt.Errorf("parse config.json: %w", err)
	}

	// 从嵌套的 clean/maintainer/run/output 配置中提取值
	cleanCfg := jc.Clean
	if cleanCfg == nil {
		cleanCfg = &jsonCleanConfig{}
	}
	maintainerCfg := jc.Maintainer
	if maintainerCfg == nil {
		maintainerCfg = &jsonMaintainerConfig{}
	}
	runCfg := jc.Run
	if runCfg == nil {
		runCfg = &jsonRunConfig{}
	}
	outputCfg := jc.Output
	if outputCfg == nil {
		outputCfg = &jsonOutputConfig{}
	}
	flowCfg := jc.Flow
	if flowCfg == nil {
		flowCfg = &jsonFlowConfig{}
	}
	regCfg := jc.Registration
	if regCfg == nil {
		regCfg = &jsonRegistrationConfig{}
	}

	// proxy: run.proxy > 顶层 proxy
	proxyValue := strings.TrimSpace(jc.Proxy)
	if strings.TrimSpace(runCfg.Proxy) != "" {
		proxyValue = strings.TrimSpace(runCfg.Proxy)
	}

	// accounts/csv/ak/rk: output.* > 顶层 *
	accountsFile := defaultString(outputCfg.AccountsFile, defaultString(jc.AccountsFile, "accounts.txt"))
	csvFile := defaultString(outputCfg.CSVFile, defaultString(jc.CSVFile, "registered_accounts.csv"))
	akFile := defaultString(outputCfg.AKFile, defaultString(jc.AKFile, "ak.txt"))
	rkFile := defaultString(outputCfg.RKFile, defaultString(jc.RKFile, "rk.txt"))

	saveLocal := true
	if outputCfg.SaveLocal != nil {
		saveLocal = *outputCfg.SaveLocal
	}

	// workers: run.workers > 顶层 concurrent_workers
	workers := defaultInt(runCfg.Workers, defaultInt(jc.ConcurrentWorkers, 1))

	cfg := &Config{
		Root:                       root,
		TotalAccounts:              maxInt(1, defaultInt(jc.TotalAccounts, 30)),
		ConcurrentWorkers:          maxInt(1, workers),
		Proxy:                      proxyValue,
		WorkspaceRecordWorkers:     maxInt(1, defaultInt(jc.WorkspaceRecordWorkers, 4)),
		WorkspaceLoginWorkers:      maxInt(1, defaultInt(jc.WorkspaceLoginWorkers, 5)),
		OAuthStep2MaxRetries:       maxInt(1, defaultInt(jc.OAuthStep2MaxRetries, 5)),
		OAuthStep2RetryBaseSeconds: defaultFloat(jc.OAuthStep2RetryBaseSeconds, 2.0),
		SpaceRecordFile:            defaultString(jc.SpaceRecordFile, "space_record_status.json"),
		AccountRecordWorkers:       maxInt(1, defaultInt(jc.AccountRecordWorkers, 3)),
		CFWorkerDomain:             strings.TrimSpace(jc.CFWorkerDomain),
		CFEmailDomain:              strings.TrimSpace(jc.CFEmailDomain),
		CFAdminPassword:            strings.TrimSpace(jc.CFAdminPassword),
		CFMailConfigs:              buildCFMailConfigs(jc),
		OAuthIssuer:                defaultString(jc.OAuthIssuer, OpenAIAuthBase),
		OAuthClientID:              defaultString(jc.OAuthClientID, "app_EMoamEEZ73f0CkXaXp7hrann"),
		OAuthRedirectURI:           defaultString(jc.OAuthRedirectURI, "http://localhost:1455/auth/callback"),
		AccountsFile:               accountsFile,
		CSVFile:                    csvFile,
		AKFile:                     akFile,
		RKFile:                     rkFile,
		ProxyMode:                  defaultString(jc.ProxyMode, "direct"),
		ProxyFile:                  defaultString(jc.ProxyFile, filepath.Join(root, "proxies.txt")),
		MailProvider:               defaultString(jc.MailProvider, "tabmail"),
		NamePrefix:                 defaultString(jc.NamePrefix, "free"),
		DualPool:                   jc.DualPool,
		RegisterWorkers:            maxInt(1, defaultInt(jc.RegisterWorkers, workers)),
		OAuthWorkers:               maxInt(1, defaultInt(jc.OAuthWorkers, defaultInt(jc.AccountRecordWorkers, 3))),
		OAuthDelaySeconds:          maxInt(0, defaultInt(jc.OAuthDelaySeconds, 0)),
		PendingQueueFile:           defaultString(jc.PendingQueueFile, "pending_oauth.json"),

		// CPA
		CPABaseURL:              strings.TrimRight(defaultString(cleanCfg.BaseURL, ""), "/"),
		CPAToken:                defaultString(cleanCfg.Token, ""),
		CPATargetType:           defaultString(cleanCfg.TargetType, "codex"),
		CPAUserAgent:            defaultString(cleanCfg.UserAgent, "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"),
		CPATimeout:              maxInt(5, defaultInt(cleanCfg.Timeout, 10)),
		CPARetries:              maxInt(0, defaultInt(cleanCfg.Retries, 1)),
		CPAWorkers:              maxInt(1, defaultInt(cleanCfg.Workers, 20)),
		CPADeleteWorkers:        maxInt(1, defaultInt(cleanCfg.DeleteWorkers, 20)),
		CPAUsedPercentThreshold: maxInt(1, defaultInt(cleanCfg.UsedPercentThreshold, 90)),
		SaveLocal:               saveLocal,

		// 维护模式
		MinCandidates:        maxInt(0, defaultInt(maintainerCfg.MinCandidates, 50)),
		LoopIntervalSeconds:  defaultFloat(maintainerCfg.LoopIntervalSeconds, 60.0),
		FailureCooldownSec:   defaultFloat(runCfg.FailureCooldownSeconds, 45.0),
		FailureCooldownAfter: maxInt(1, defaultInt(runCfg.FailureThresholdCooldown, 5)),

		// 重试与容错
		StepRetryAttempts:     maxInt(1, defaultInt(flowCfg.StepRetryAttempts, 2)),
		StepRetryDelayBase:    defaultFloat(flowCfg.StepRetryDelayBase, 0.2),
		StepRetryDelayCap:     defaultFloat(flowCfg.StepRetryDelayCap, 0.8),
		OAuthOuterRetries:     maxInt(1, defaultInt(flowCfg.OuterRetryAttempts, 3)),
		OAuthRetryBackoffBase: defaultFloat(flowCfg.RetryBackoffBase, 2.0),
		OAuthRetryBackoffMax:  defaultFloat(flowCfg.RetryBackoffMax, 60.0),
		TransientMarkers:      flowCfg.TransientMarkers,

		// 注册入口模式
		EntryMode:         defaultString(regCfg.EntryMode, "direct_auth"),
		EntryModeFallback: boolOrDefault(regCfg.EntryModeFallback, true),

		// OTP 校验顺序
		OTPValidateOrder: parseOTPValidateOrder(flowCfg.OTPValidateOrder),
	}
	if !filepath.IsAbs(cfg.ProxyFile) {
		cfg.ProxyFile = filepath.Join(root, cfg.ProxyFile)
	}
	cfg.AccountsFile = resolveMaybeRelative(root, cfg.AccountsFile)
	cfg.CSVFile = resolveMaybeRelative(root, cfg.CSVFile)
	cfg.AKFile = resolveMaybeRelative(root, cfg.AKFile)
	cfg.RKFile = resolveMaybeRelative(root, cfg.RKFile)
	cfg.PendingQueueFile = resolveMaybeRelative(root, cfg.PendingQueueFile)
	cfg.SpaceRecordFile = resolveMaybeRelative(root, cfg.SpaceRecordFile)
	return cfg, nil
}

func buildCFMailConfigs(jc jsonConfig) []CFMailConfig {
	configs := make([]CFMailConfig, 0)
	if len(jc.CFMailConfigs) > 0 {
		for idx, item := range jc.CFMailConfigs {
			cfg := CFMailConfig{
				Name:          strings.TrimSpace(item.Name),
				WorkerDomain:  strings.TrimSpace(item.WorkerDomain),
				EmailDomain:   strings.TrimSpace(item.EmailDomain),
				AdminPassword: strings.TrimSpace(item.AdminPassword),
			}
			if cfg.Name == "" {
				cfg.Name = fmt.Sprintf("cfmail-%d", idx+1)
			}
			if cfg.Configured() {
				configs = append(configs, cfg)
			}
		}
		if len(configs) > 0 {
			return configs
		}
	}
	legacy := CFMailConfig{
		Name:          "cfmail-1",
		WorkerDomain:  strings.TrimSpace(jc.CFWorkerDomain),
		EmailDomain:   strings.TrimSpace(jc.CFEmailDomain),
		AdminPassword: strings.TrimSpace(jc.CFAdminPassword),
	}
	if legacy.Configured() {
		configs = append(configs, legacy)
	}
	return configs
}

func (c CFMailConfig) Configured() bool {
	return strings.TrimSpace(c.WorkerDomain) != "" && strings.TrimSpace(c.EmailDomain) != "" && strings.TrimSpace(c.AdminPassword) != ""
}

func (c CFMailConfig) Key() string {
	if strings.TrimSpace(c.Name) != "" {
		return strings.TrimSpace(c.Name)
	}
	return strings.TrimSpace(c.WorkerDomain)
}

func (cfg *Config) CFMailGroups() []CFMailConfig {
	if len(cfg.CFMailConfigs) > 0 {
		return append([]CFMailConfig(nil), cfg.CFMailConfigs...)
	}
	legacy := CFMailConfig{
		Name:          "cfmail-1",
		WorkerDomain:  strings.TrimSpace(cfg.CFWorkerDomain),
		EmailDomain:   strings.TrimSpace(cfg.CFEmailDomain),
		AdminPassword: strings.TrimSpace(cfg.CFAdminPassword),
	}
	if legacy.Configured() {
		return []CFMailConfig{legacy}
	}
	return nil
}

func resolveMaybeRelative(root, path string) string {
	if path == "" {
		return path
	}
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}

func loadEnvIfPresent(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		if len(v) >= 2 {
			if (strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`)) || (strings.HasPrefix(v, `'`) && strings.HasSuffix(v, `'`)) {
				v = v[1 : len(v)-1]
			}
		}
		if k != "" && os.Getenv(k) == "" {
			_ = os.Setenv(k, v)
		}
	}
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return strings.TrimSpace(v)
}

func defaultInt(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}

func defaultFloat(v, fallback float64) float64 {
	if v == 0 {
		return fallback
	}
	return v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func BuildCommonHeaders(profile BrowserProfile, referer, origin, fetchSite string) map[string]string {
	if origin == "" {
		origin = OpenAIAuthBase
	}
	if fetchSite == "" {
		fetchSite = "same-origin"
	}
	headers := map[string]string{
		"accept":          "application/json",
		"accept-language": profile.AcceptLanguage,
		"content-type":    "application/json",
		"origin":          origin,
		"user-agent":      profile.UserAgent,
		"sec-fetch-dest":  "empty",
		"sec-fetch-mode":  "cors",
		"sec-fetch-site":  fetchSite,
		"accept-encoding": profile.AcceptEncoding,
	}
	if profile.SendClientHints {
		headers["sec-ch-ua"] = profile.SecCHUA
		headers["sec-ch-ua-mobile"] = "?0"
		headers["sec-ch-ua-platform"] = profile.SecCHPlatform
		headers["sec-ch-ua-arch"] = `"x86"`
		headers["sec-ch-ua-bitness"] = `"64"`
		headers["sec-ch-ua-full-version-list"] = profile.SecCHUAFullVersion
		headers["sec-ch-ua-platform-version"] = `"15.0.0"`
		headers["sec-ch-ua-wow64"] = "?0"
	}
	if profile.SendPriority {
		headers["priority"] = "u=1, i"
	}
	if referer != "" {
		headers["referer"] = referer
	}
	return headers
}

func BuildNavigateHeaders(profile BrowserProfile, referer, fetchSite string) map[string]string {
	if fetchSite == "" {
		fetchSite = "same-origin"
	}
	headers := map[string]string{
		"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"accept-language":           profile.AcceptLanguage,
		"user-agent":                profile.UserAgent,
		"sec-fetch-dest":            "document",
		"sec-fetch-mode":            "navigate",
		"sec-fetch-site":            fetchSite,
		"sec-fetch-user":            "?1",
		"upgrade-insecure-requests": "1",
		"accept-encoding":           profile.AcceptEncoding,
	}
	if profile.SendClientHints {
		headers["sec-ch-ua"] = profile.SecCHUA
		headers["sec-ch-ua-mobile"] = "?0"
		headers["sec-ch-ua-platform"] = profile.SecCHPlatform
		headers["sec-ch-ua-arch"] = `"x86"`
		headers["sec-ch-ua-bitness"] = `"64"`
		headers["sec-ch-ua-full-version-list"] = profile.SecCHUAFullVersion
		headers["sec-ch-ua-platform-version"] = `"15.0.0"`
		headers["sec-ch-ua-wow64"] = "?0"
	}
	if profile.SendPriority {
		headers["priority"] = "u=0, i"
	}
	if referer != "" {
		headers["referer"] = referer
	}
	return headers
}

func BuildSentinelHeaders(profile BrowserProfile) map[string]string {
	headers := map[string]string{
		"content-type":    "text/plain;charset=UTF-8",
		"referer":         "https://sentinel.openai.com/backend-api/sentinel/frame.html",
		"origin":          "https://sentinel.openai.com",
		"user-agent":      profile.UserAgent,
		"accept-language": profile.AcceptLanguage,
		"accept-encoding": profile.AcceptEncoding,
	}
	if profile.SendClientHints {
		headers["sec-ch-ua"] = profile.SecCHUA
		headers["sec-ch-ua-mobile"] = "?0"
		headers["sec-ch-ua-platform"] = profile.SecCHPlatform
		headers["sec-ch-ua-full-version-list"] = profile.SecCHUAFullVersion
	}
	return headers
}

func NewClientFactory(cfg *Config) *ClientFactory {
	return &ClientFactory{cfg: cfg, proxyManager: NewProxyManager(cfg)}
}

func NewProxyManager(cfg *Config) *ProxyManager {
	return &ProxyManager{
		cfg:       cfg,
		statsPath: filepath.Join(cfg.Root, "proxies_usage.json"),
	}
}

func (pm *ProxyManager) loadPoolLocked() []string {
	path := pm.cfg.ProxyFile
	if path == "" {
		pm.cachedPool = nil
		return nil
	}
	st, err := os.Stat(path)
	if err == nil && len(pm.cachedPool) > 0 && st.ModTime().Equal(pm.cachedMTime) {
		return append([]string(nil), pm.cachedPool...)
	}
	f, err := os.Open(path)
	if err != nil {
		pm.cachedPool = nil
		return nil
	}
	defer f.Close()
	seen := map[string]struct{}{}
	pool := make([]string, 0)
	s := bufio.NewScanner(f)
	for s.Scan() {
		raw := strings.TrimSpace(s.Text())
		if raw == "" {
			continue
		}
		if strings.HasPrefix(raw, "#") {
			if strings.HasPrefix(strings.ToUpper(raw), "# USED ") {
				raw = strings.TrimSpace(raw[7:])
			} else {
				continue
			}
		}
		proxy := parseProxyLine(raw)
		if proxy == "" {
			continue
		}
		if _, ok := seen[proxy]; ok {
			continue
		}
		seen[proxy] = struct{}{}
		pool = append(pool, proxy)
	}
	if err == nil {
		pm.cachedPool = pool
		if st != nil {
			pm.cachedMTime = st.ModTime()
		}
	}
	return append([]string(nil), pool...)
}

func parseProxyLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") || strings.HasPrefix(line, "socks5://") {
		return line
	}
	parts := strings.Split(line, ":")
	if len(parts) == 4 {
		return fmt.Sprintf("http://%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1])
	}
	if len(parts) == 2 {
		return fmt.Sprintf("http://%s:%s", parts[0], parts[1])
	}
	return ""
}

func (pm *ProxyManager) loadUsageLocked() map[string]int {
	if pm.usageLoaded {
		cp := make(map[string]int, len(pm.usage))
		for k, v := range pm.usage {
			cp[k] = v
		}
		return cp
	}
	pm.usage = map[string]int{}
	raw, err := os.ReadFile(pm.statsPath)
	if err == nil {
		var data map[string]int
		if json.Unmarshal(raw, &data) == nil {
			for k, v := range data {
				if v >= 0 {
					pm.usage[k] = v
				}
			}
		}
	}
	pm.usageLoaded = true
	cp := make(map[string]int, len(pm.usage))
	for k, v := range pm.usage {
		cp[k] = v
	}
	return cp
}

func (pm *ProxyManager) saveUsageLocked(usage map[string]int) {
	pm.usage = usage
	pm.usageLoaded = true
	raw, _ := json.MarshalIndent(usage, "", "  ")
	_ = os.WriteFile(pm.statsPath+".tmp", raw, 0o644)
	_ = os.Rename(pm.statsPath+".tmp", pm.statsPath)
}

func (pm *ProxyManager) ClaimNextProxy() string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pool := pm.loadPoolLocked()
	if len(pool) == 0 {
		return pm.cfg.Proxy
	}
	usage := pm.loadUsageLocked()
	valid := make(map[string]struct{}, len(pool))
	for _, p := range pool {
		valid[p] = struct{}{}
	}
	for k := range usage {
		if _, ok := valid[k]; !ok {
			delete(usage, k)
		}
	}
	chosen := pool[0]
	minCount := usage[chosen]
	for i, p := range pool {
		count := usage[p]
		if i == 0 || count < minCount {
			chosen = p
			minCount = count
		}
	}
	usage[chosen]++
	pm.saveUsageLocked(usage)
	return chosen
}

func (cf *ClientFactory) NewSession(useProxy bool) *Session {
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   64,
		MaxConnsPerHost:       64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	proxyValue := ""
	if useProxy {
		switch cf.cfg.ProxyMode {
		case "file":
			proxyValue = cf.proxyManager.ClaimNextProxy()
		case "direct":
			proxyValue = ""
		default:
			proxyValue = cf.cfg.Proxy
		}
	}
	if proxyValue != "" {
		if proxyURL, err := url.Parse(proxyValue); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: transport, Jar: jar}
	return &Session{Client: client, Profile: HardcodedBrowserProfile, Proxy: proxyValue}
}

func (s *Session) NewRequest(ctx context.Context, method, target string, body []byte, headers map[string]string) (*http.Request, error) {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func (s *Session) NewJSONRequest(ctx context.Context, method, target string, payload any, headers map[string]string) (*http.Request, error) {
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}
	return s.NewRequest(ctx, method, target, body, headers)
}

func ReadBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	defer resp.Body.Close()
	reader := io.Reader(resp.Body)
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	switch encoding {
	case "gzip", "x-gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err == nil {
			defer gz.Close()
			reader = gz
		}
	case "br":
		reader = brotli.NewReader(resp.Body)
	case "deflate":
		zr, err := zlib.NewReader(resp.Body)
		if err == nil {
			defer zr.Close()
			reader = zr
		}
	default:
		peeked, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		if len(peeked) >= 2 && peeked[0] == 0x1f && peeked[1] == 0x8b {
			gz, err := gzip.NewReader(bytes.NewReader(peeked))
			if err == nil {
				defer gz.Close()
				return io.ReadAll(gz)
			}
		}
		if len(peeked) >= 2 && peeked[0] == 0x78 {
			zr, err := zlib.NewReader(bytes.NewReader(peeked))
			if err == nil {
				defer zr.Close()
				return io.ReadAll(zr)
			}
		}
		return peeked, nil
	}
	return io.ReadAll(reader)
}

func DoRequest(req *http.Request, client *http.Client) (*http.Response, []byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	body, err := ReadBody(resp)
	if err != nil {
		return resp, body, err
	}
	resp.Body = ioNopCloser(bytes.NewReader(body))
	return resp, body, nil
}

func DoRequestNoRedirect(req *http.Request, client *http.Client) (*http.Response, []byte, error) {
	clone := *client
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return DoRequest(req, &clone)
}

type nopCloser struct{ *bytes.Reader }

func ioNopCloser(r *bytes.Reader) *nopCloser { return &nopCloser{Reader: r} }
func (n *nopCloser) Close() error            { return nil }

func GenerateDeviceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	buf := make([]byte, 36)
	hex.Encode(buf[0:8], b[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], b[10:16])
	return string(buf)
}

func GenerateRandomPassword(length int) string {
	if length < 8 {
		length = 16
	}
	upper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower := "abcdefghijklmnopqrstuvwxyz"
	digits := "0123456789"
	symbols := "!@#$%"
	chars := upper + lower + digits + symbols
	parts := []byte{
		upper[mathrand.Intn(len(upper))],
		lower[mathrand.Intn(len(lower))],
		digits[mathrand.Intn(len(digits))],
		symbols[mathrand.Intn(len(symbols))],
	}
	for len(parts) < length {
		parts = append(parts, chars[mathrand.Intn(len(chars))])
	}
	mathrand.Shuffle(len(parts), func(i, j int) { parts[i], parts[j] = parts[j], parts[i] })
	return string(parts)
}

func GenerateRandomName() (string, string) {
	first := []string{"James", "Robert", "John", "Michael", "David", "William", "Richard", "Mary", "Jennifer", "Linda", "Elizabeth", "Susan", "Jessica", "Sarah", "Emily", "Emma", "Olivia", "Sophia", "Liam", "Noah", "Oliver", "Ethan"}
	last := []string{"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Martin"}
	return first[mathrand.Intn(len(first))], last[mathrand.Intn(len(last))]
}

func GenerateRandomBirthday() string {
	year := 1996 + mathrand.Intn(11)
	month := 1 + mathrand.Intn(12)
	day := 1 + mathrand.Intn(28)
	return fmt.Sprintf("%04d-%02d-%02d", year, month, day)
}

func GeneratePKCE() (string, string) {
	buf := make([]byte, 64)
	_, _ = rand.Read(buf)
	verifier := strings.TrimRight(base64.RawURLEncoding.EncodeToString(buf), "=")
	sum := sha256.Sum256([]byte(verifier))
	challenge := strings.TrimRight(base64.RawURLEncoding.EncodeToString(sum[:]), "=")
	return verifier, challenge
}

func GenerateDatadogTrace() map[string]string {
	traceID := fmt.Sprintf("%d", mathrand.Uint64())
	parentID := fmt.Sprintf("%d", mathrand.Uint64())
	traceUint, _ := strconv.ParseUint(traceID, 10, 64)
	parentUint, _ := strconv.ParseUint(parentID, 10, 64)
	traceHex := fmt.Sprintf("%016x", traceUint)
	parentHex := fmt.Sprintf("%016x", parentUint)
	return map[string]string{
		"x-datadog-trace-id":          traceID,
		"x-datadog-parent-id":         parentID,
		"x-datadog-origin":            "rum",
		"x-datadog-sampling-priority": "1",
		"traceparent":                 fmt.Sprintf("00-%032s-%016s-01", traceHex, parentHex),
	}
}

func NowLocalString() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func SleepJitter(base time.Duration, maxJitter time.Duration) {
	jitter := time.Duration(0)
	if maxJitter > 0 {
		jitter = time.Duration(mathrand.Int63n(int64(maxJitter)))
	}
	time.Sleep(base + jitter)
}

func boolOrDefault(v *bool, fallback bool) bool {
	if v == nil {
		return fallback
	}
	return *v
}

func parseOTPValidateOrder(raw []string) []string {
	if len(raw) == 0 {
		return []string{"normal", "sentinel"}
	}
	valid := make([]string, 0, len(raw))
	for _, item := range raw {
		normalized := strings.TrimSpace(strings.ToLower(item))
		if normalized == "normal" || normalized == "sentinel" {
			valid = append(valid, normalized)
		}
	}
	if len(valid) == 0 {
		return []string{"normal", "sentinel"}
	}
	return valid
}
