package codex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	codePattern = regexp.MustCompile(`(?m)\b(\d{6})\b`)
	htmlPattern = regexp.MustCompile(`<[^>]+>`)
)

type OTPCandidate struct {
	EmailID      int
	Code         string
	Subject      string
	CreateTimeMS int64
	SavedAt      time.Time
}

type OTPClient interface {
	FetchLatestMailID(ctx context.Context) (int, error)
	FetchOTPCandidates(ctx context.Context, expectedTo string, minCreateTimeMS int64, sinceEmailID int) ([]OTPCandidate, error)
	RememberOTP(code string, emailID int)
	GetRecentOTP(maxAge time.Duration) *OTPCandidate
}

type TempMailProvider interface {
	CreateTempEmail(ctx context.Context) (email string, token string, err error)
	WaitForVerificationCode(ctx context.Context, email string, token string, timeout time.Duration) (string, error)
}

type TabMailService struct {
	cfg     *Config
	factory *ClientFactory
}

type TabMailOTPClient struct {
	email     string
	cfg       *Config
	session   *Session
	recentMu  sync.Mutex
	recentOTP *OTPCandidate
}

type CFWorkerMailProvider struct {
	cfg     *Config
	factory *ClientFactory
	mailCfg CFMailConfig
}

type CFWorkerOTPClient struct {
	email     string
	token     string
	provider  *CFWorkerMailProvider
	cfg       *Config
	session   *Session
	recentMu  sync.Mutex
	recentOTP *OTPCandidate
}

type FallbackOTPClient struct {
	clients   []OTPClient
	recentMu  sync.Mutex
	recentOTP *OTPCandidate
}

func NewTabMailService(cfg *Config, factory *ClientFactory) *TabMailService {
	return &TabMailService{cfg: cfg, factory: factory}
}

func NewCFWorkerMailProvider(cfg *Config, factory *ClientFactory, mailCfg CFMailConfig) *CFWorkerMailProvider {
	return &CFWorkerMailProvider{cfg: cfg, factory: factory, mailCfg: mailCfg}
}

func BuildCFMailProviders(cfg *Config, factory *ClientFactory) []*CFWorkerMailProvider {
	groups := cfg.CFMailGroups()
	providers := make([]*CFWorkerMailProvider, 0, len(groups))
	for _, group := range groups {
		providers = append(providers, NewCFWorkerMailProvider(cfg, factory, group))
	}
	return providers
}

func DescribeMailProviderChain(cfg *Config) string {
	names := make([]string, 0)
	for _, group := range cfg.CFMailGroups() {
		names = append(names, group.Key())
	}
	if len(names) == 0 {
		return "tabmail"
	}
	return fmt.Sprintf("tabmail -> cfmail[%s]", strings.Join(names, ","))
}

func (s *TabMailService) tabMailURL() string {
	return defaultString(os.Getenv("TABMAIL_URL"), "http://192.229.101.130:3000")
}

func (s *TabMailService) tenantID() string {
	return defaultString(os.Getenv("TABMAIL_TENANT_ID"), "00000000-0000-0000-0000-000000000001")
}

func (s *TabMailService) zoneID() string {
	return strings.TrimSpace(os.Getenv("TABMAIL_ZONE_ID"))
}

func (s *TabMailService) adminKey() string {
	return strings.TrimSpace(os.Getenv("TABMAIL_ADMIN_KEY"))
}

func (s *TabMailService) adminHeaders() map[string]string {
	return map[string]string{
		"X-Admin-Key": s.adminKey(),
		"X-Tenant-ID": s.tenantID(),
	}
}

func (s *TabMailService) Configured() bool {
	return strings.TrimSpace(s.zoneID()) != "" && strings.TrimSpace(s.adminKey()) != ""
}

func (s *TabMailService) CreateTempEmail(ctx context.Context) (string, string, error) {
	if s.zoneID() == "" {
		return "", "", errors.New("未配置 TABMAIL_ZONE_ID")
	}
	if s.adminKey() == "" {
		return "", "", errors.New("未配置 TABMAIL_ADMIN_KEY")
	}
	sess := s.factory.NewSession(false)
	target := fmt.Sprintf("%s/api/v1/domains/%s/suggest-address?subdomain=true", strings.TrimRight(s.tabMailURL(), "/"), s.zoneID())
	req, _ := sess.NewRequest(ctx, "GET", target, nil, s.adminHeaders())
	resp, body, err := DoRequest(req, sess.Client)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("TabMail suggest-address 失败: %d %s", resp.StatusCode, truncate(string(body), 240))
	}
	var data struct {
		Data struct {
			Address string `json:"address"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", "", err
	}
	if strings.TrimSpace(data.Data.Address) == "" {
		return "", "", errors.New("TabMail suggest-address 返回空 address")
	}
	return strings.TrimSpace(data.Data.Address), "", nil
}

func (s *TabMailService) WaitForVerificationCode(ctx context.Context, email string, _ string, timeout time.Duration) (string, error) {
	start := time.Now()
	attempt := 0
	backoff429 := 0
	sess := s.factory.NewSession(false)
	target := fmt.Sprintf("%s/api/v1/mailbox/%s", strings.TrimRight(s.tabMailURL(), "/"), email)
	for time.Since(start) < timeout {
		req, _ := sess.NewRequest(ctx, "GET", target, nil, nil)
		resp, body, err := DoRequest(req, sess.Client)
		if err == nil {
			switch resp.StatusCode {
			case 200:
				backoff429 = 0
				var data struct {
					Data []map[string]any `json:"data"`
				}
				_ = json.Unmarshal(body, &data)
				if len(data.Data) > 0 {
					fmt.Printf("  📬 TabMail 收到 %d 封邮件\n", len(data.Data))
				}
				for _, msg := range data.Data {
					sender := strings.ToLower(toString(msg["sender"]))
					subject := strings.ToLower(toString(msg["subject"]))
					if !strings.Contains(sender, "openai") && !strings.Contains(subject, "chatgpt") && !strings.Contains(subject, "code") {
						continue
					}
					detail, _ := s.fetchMessageDetail(ctx, sess, email, toString(msg["id"]))
					if code := ExtractOTPFromMail(firstMap(detail, msg)); code != "" {
						return code, nil
					}
				}
				if len(data.Data) > 0 {
					first := data.Data[0]
					detail, _ := s.fetchMessageDetail(ctx, sess, email, toString(first["id"]))
					if code := ExtractOTPFromMail(firstMap(detail, first)); code != "" {
						return code, nil
					}
				}
			case 429:
				backoff429++
				wait := time.Duration(minInt(5, 1<<(backoff429-1))) * time.Second
				SleepJitter(wait, 500*time.Millisecond)
				continue
			}
		}
		attempt++
		if attempt%5 == 0 {
			fmt.Printf("  ⏳ 等待邮件... (%ds)\n", int(time.Since(start).Seconds()))
		}
		SleepJitter(2*time.Second, 500*time.Millisecond)
	}
	return "", errors.New("等待验证码超时")
}

func (s *TabMailService) fetchMessageDetail(ctx context.Context, sess *Session, email, msgID string) (map[string]any, error) {
	if strings.TrimSpace(msgID) == "" {
		return nil, errors.New("empty message id")
	}
	target := fmt.Sprintf("%s/api/v1/mailbox/%s/%s", strings.TrimRight(s.tabMailURL(), "/"), email, msgID)
	req, _ := sess.NewRequest(ctx, "GET", target, nil, nil)
	resp, body, err := DoRequest(req, sess.Client)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("message detail %d", resp.StatusCode)
	}
	var data struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return data.Data, nil
}

func NewTabMailOTPClient(cfg *Config, factory *ClientFactory, email string) (*TabMailOTPClient, error) {
	service := NewTabMailService(cfg, factory)
	if service.zoneID() == "" {
		return nil, errors.New("未配置 TABMAIL_ZONE_ID")
	}
	if service.adminKey() == "" {
		return nil, errors.New("未配置 TABMAIL_ADMIN_KEY")
	}
	return &TabMailOTPClient{email: strings.ToLower(strings.TrimSpace(email)), cfg: cfg, session: factory.NewSession(false)}, nil
}

func NewCFWorkerOTPClient(provider *CFWorkerMailProvider, email, token string) (*CFWorkerOTPClient, error) {
	if strings.TrimSpace(email) == "" {
		return nil, errors.New("邮箱为空")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("缺少 CF mailbox token")
	}
	if provider == nil || !provider.Configured() {
		return nil, errors.New("未配置可用的 cf mail")
	}
	return &CFWorkerOTPClient{
		email:    strings.ToLower(strings.TrimSpace(email)),
		token:    strings.TrimSpace(token),
		provider: provider,
		cfg:      provider.cfg,
		session:  provider.factory.NewSession(false),
	}, nil
}

func BuildOAuthOTPClient(cfg *Config, factory *ClientFactory, email, cfToken, cfConfigKey string) OTPClient {
	clients := make([]OTPClient, 0, 2)
	if tabmail, err := NewTabMailOTPClient(cfg, factory, email); err == nil {
		clients = append(clients, tabmail)
	}
	if strings.TrimSpace(cfToken) != "" {
		providers := BuildCFMailProviders(cfg, factory)
		matched := false
		for _, provider := range providers {
			if strings.TrimSpace(cfConfigKey) != "" && provider.Key() != strings.TrimSpace(cfConfigKey) {
				continue
			}
			if cfClient, err := NewCFWorkerOTPClient(provider, email, cfToken); err == nil {
				clients = append(clients, cfClient)
				matched = true
			}
		}
		if !matched && strings.TrimSpace(cfConfigKey) != "" {
			for _, provider := range providers {
				if cfClient, err := NewCFWorkerOTPClient(provider, email, cfToken); err == nil {
					clients = append(clients, cfClient)
				}
			}
		}
	}
	if len(clients) == 0 {
		return nil
	}
	if len(clients) == 1 {
		return clients[0]
	}
	return &FallbackOTPClient{clients: clients}
}

func (c *TabMailOTPClient) RememberOTP(code string, emailID int) {
	if strings.TrimSpace(code) == "" {
		return
	}
	c.recentMu.Lock()
	defer c.recentMu.Unlock()
	c.recentOTP = &OTPCandidate{Code: strings.TrimSpace(code), EmailID: emailID, SavedAt: time.Now()}
}

func (c *TabMailOTPClient) GetRecentOTP(maxAge time.Duration) *OTPCandidate {
	c.recentMu.Lock()
	defer c.recentMu.Unlock()
	if c.recentOTP == nil {
		return nil
	}
	if time.Since(c.recentOTP.SavedAt) > maxAge {
		c.recentOTP = nil
		return nil
	}
	cp := *c.recentOTP
	return &cp
}

func (c *CFWorkerOTPClient) RememberOTP(code string, emailID int) {
	if strings.TrimSpace(code) == "" {
		return
	}
	c.recentMu.Lock()
	defer c.recentMu.Unlock()
	c.recentOTP = &OTPCandidate{Code: strings.TrimSpace(code), EmailID: emailID, SavedAt: time.Now()}
}

func (c *CFWorkerOTPClient) GetRecentOTP(maxAge time.Duration) *OTPCandidate {
	c.recentMu.Lock()
	defer c.recentMu.Unlock()
	if c.recentOTP == nil {
		return nil
	}
	if time.Since(c.recentOTP.SavedAt) > maxAge {
		c.recentOTP = nil
		return nil
	}
	cp := *c.recentOTP
	return &cp
}

func (c *TabMailOTPClient) FetchLatestMailID(ctx context.Context) (int, error) {
	target := fmt.Sprintf("%s/api/v1/mailbox/%s", strings.TrimRight(defaultString(os.Getenv("TABMAIL_URL"), "http://192.229.101.130:3000"), "/"), c.email)
	req, _ := c.session.NewRequest(ctx, "GET", target, nil, nil)
	resp, body, err := DoRequest(req, c.session.Client)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != 200 {
		return 0, nil
	}
	var data struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return 0, nil
	}
	return len(data.Data), nil
}

func (c *TabMailOTPClient) FetchOTPCandidates(ctx context.Context, expectedTo string, minCreateTimeMS int64, sinceEmailID int) ([]OTPCandidate, error) {
	service := NewTabMailService(c.cfg, nil)
	target := fmt.Sprintf("%s/api/v1/mailbox/%s", strings.TrimRight(service.tabMailURL(), "/"), c.email)
	req, _ := c.session.NewRequest(ctx, "GET", target, nil, nil)
	resp, body, err := DoRequest(req, c.session.Client)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, nil
	}
	var data struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, nil
	}
	seen := map[string]struct{}{}
	candidates := make([]OTPCandidate, 0)
	scanned := 0
	for idx := len(data.Data) - 1; idx >= 0; idx-- {
		msg := data.Data[idx]
		if sinceEmailID > 0 && idx < sinceEmailID {
			continue
		}
		scanned++
		if scanned > 40 {
			break
		}
		sender := strings.ToLower(toString(msg["sender"]))
		subject := strings.ToLower(toString(msg["subject"]))
		if !strings.Contains(sender, "openai") && !strings.Contains(sender, "chatgpt") && !strings.Contains(subject, "chatgpt") && !strings.Contains(subject, "code") && !strings.Contains(subject, "verification") {
			continue
		}
		detail, _ := service.fetchMessageDetail(ctx, c.session, c.email, toString(msg["id"]))
		code := ExtractOTPFromMail(firstMap(detail, msg))
		if code == "" {
			continue
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		candidates = append(candidates, OTPCandidate{EmailID: idx + 1, Code: code, Subject: truncate(toString(msg["subject"]), 80)})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].EmailID > candidates[j].EmailID })
	return candidates, nil
}

func (c *CFWorkerOTPClient) FetchLatestMailID(ctx context.Context) (int, error) {
	if c.provider == nil {
		return 0, errors.New("未配置可用的 cf mail")
	}
	items, err := c.provider.fetchEmails(ctx, c.session, c.token)
	if err != nil {
		return 0, err
	}
	return len(items), nil
}

func (c *CFWorkerOTPClient) FetchOTPCandidates(ctx context.Context, expectedTo string, minCreateTimeMS int64, sinceEmailID int) ([]OTPCandidate, error) {
	if c.provider == nil {
		return nil, errors.New("未配置可用的 cf mail")
	}
	items, err := c.provider.fetchEmails(ctx, c.session, c.token)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	candidates := make([]OTPCandidate, 0, len(items))
	for idx, item := range items {
		code := ExtractVerificationCode(toString(item["raw"]))
		if code == "" {
			code = ExtractOTPFromMail(item)
		}
		if code == "" {
			continue
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		candidates = append(candidates, OTPCandidate{
			EmailID: idx + 1,
			Code:    code,
			Subject: truncate(toString(item["subject"]), 80),
		})
	}
	return candidates, nil
}

func (c *FallbackOTPClient) RememberOTP(code string, emailID int) {
	if strings.TrimSpace(code) == "" {
		return
	}
	c.recentMu.Lock()
	c.recentOTP = &OTPCandidate{Code: strings.TrimSpace(code), EmailID: emailID, SavedAt: time.Now()}
	c.recentMu.Unlock()
	for _, client := range c.clients {
		client.RememberOTP(code, emailID)
	}
}

func (c *FallbackOTPClient) GetRecentOTP(maxAge time.Duration) *OTPCandidate {
	c.recentMu.Lock()
	if c.recentOTP != nil {
		if time.Since(c.recentOTP.SavedAt) <= maxAge {
			cp := *c.recentOTP
			c.recentMu.Unlock()
			return &cp
		}
		c.recentOTP = nil
	}
	c.recentMu.Unlock()
	for _, client := range c.clients {
		if recent := client.GetRecentOTP(maxAge); recent != nil {
			return recent
		}
	}
	return nil
}

func (c *FallbackOTPClient) FetchLatestMailID(ctx context.Context) (int, error) {
	return 0, nil
}

func (c *FallbackOTPClient) FetchOTPCandidates(ctx context.Context, expectedTo string, minCreateTimeMS int64, sinceEmailID int) ([]OTPCandidate, error) {
	seen := map[string]struct{}{}
	candidates := make([]OTPCandidate, 0)
	for _, client := range c.clients {
		items, err := client.FetchOTPCandidates(ctx, expectedTo, minCreateTimeMS, 0)
		if err != nil {
			continue
		}
		for _, item := range items {
			key := strings.TrimSpace(item.Code)
			if key == "" {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			candidates = append(candidates, item)
		}
	}
	return candidates, nil
}

func (p *CFWorkerMailProvider) CreateTempEmail(ctx context.Context) (string, string, error) {
	sess := p.factory.NewSession(false)
	name := randomCFName()
	payload := map[string]any{"enablePrefix": true, "name": name, "domain": p.mailCfg.EmailDomain}
	headers := map[string]string{"x-admin-auth": p.mailCfg.AdminPassword, "content-type": "application/json"}
	targetURL := fmt.Sprintf("https://%s/admin/new_address", p.mailCfg.WorkerDomain)
	req, _ := sess.NewJSONRequest(ctx, "POST", targetURL, payload, headers)
	resp, body, err := DoRequest(req, sess.Client)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("CF Worker 创建邮箱失败: %d %s", resp.StatusCode, truncate(string(body), 240))
	}
	var data struct {
		Address string `json:"address"`
		JWT     string `json:"jwt"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", "", err
	}
	if strings.TrimSpace(data.Address) == "" {
		return "", "", errors.New("CF Worker 返回空邮箱")
	}
	return data.Address, data.JWT, nil
}

func (p *CFWorkerMailProvider) Configured() bool {
	return p.mailCfg.Configured()
}

func (p *CFWorkerMailProvider) WaitForVerificationCode(ctx context.Context, email, token string, timeout time.Duration) (string, error) {
	start := time.Now()
	sess := p.factory.NewSession(false)
	for time.Since(start) < timeout {
		if items, err := p.fetchEmails(ctx, sess, token); err == nil {
			for _, item := range items {
				if code := ExtractVerificationCode(toString(item["raw"])); code != "" {
					return code, nil
				}
			}
		}
		SleepJitter(3*time.Second, 0)
	}
	return "", errors.New("等待验证码超时")
}

func (p *CFWorkerMailProvider) fetchEmails(ctx context.Context, sess *Session, token string) ([]map[string]any, error) {
	targetURL := fmt.Sprintf("https://%s/api/mails?limit=10&offset=0", p.mailCfg.WorkerDomain)
	req, _ := sess.NewRequest(ctx, "GET", targetURL, nil, map[string]string{"Authorization": "Bearer " + token})
	resp, body, err := DoRequest(req, sess.Client)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("cfmail mails %d", resp.StatusCode)
	}
	var data struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return data.Results, nil
}

func (p *CFWorkerMailProvider) Key() string {
	return p.mailCfg.Key()
}

func ExtractOTPFromMail(mail map[string]any) string {
	if code := ExtractOTPText(toString(mail["subject"])); code != "" {
		return code
	}
	for _, field := range []string{"text_body", "html_body", "text", "content", "html", "raw"} {
		if code := ExtractOTPText(stripHTML(toString(mail[field]))); code != "" {
			return code
		}
	}
	return ""
}

func ExtractOTPText(content string) string {
	content = strings.TrimSpace(content)
	if content == "" {
		return ""
	}
	if m := regexp.MustCompile(`Your ChatGPT code is (\d{6})`).FindStringSubmatch(content); len(m) > 1 {
		return m[1]
	}
	if m := codePattern.FindStringSubmatch(content); len(m) > 1 && m[1] != "177010" {
		return m[1]
	}
	return ""
}

func ExtractVerificationCode(content string) string {
	return ExtractOTPText(content)
}

func randomCFName() string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz")
	digits := []rune("0123456789")
	n := 10 + rand.Intn(5)
	buf := make([]rune, 0, n+2)
	for i := 0; i < n; i++ {
		buf = append(buf, letters[rand.Intn(len(letters))])
	}
	insertCount := 1 + rand.Intn(2)
	for i := 0; i < insertCount; i++ {
		pos := 2 + rand.Intn(len(buf)-2)
		buf = append(buf[:pos], append([]rune{digits[rand.Intn(len(digits))]}, buf[pos:]...)...)
	}
	return string(buf)
}

func stripHTML(s string) string {
	return htmlPattern.ReplaceAllString(s, "")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		b, _ := json.Marshal(x)
		if string(b) == "null" {
			return ""
		}
		return strings.Trim(string(b), `"`)
	}
}

func firstMap(values ...map[string]any) map[string]any {
	for _, v := range values {
		if len(v) > 0 {
			return v
		}
	}
	return map[string]any{}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
