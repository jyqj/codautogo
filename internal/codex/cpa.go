package codex

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ──────────────── CPA Client ────────────────

type CPAClient struct {
	BaseURL   string
	Token     string
	UserAgent string
	Timeout   int
	factory   *ClientFactory
}

type CPAAuthFile struct {
	Name      string `json:"name"`
	AuthIndex string `json:"auth_index"`
	Type      string `json:"type"`
	Account   string `json:"account"`
	Email     string `json:"email"`
	Disabled  bool   `json:"disabled"`
	Status    string `json:"status"`
	Provider  string `json:"provider"`
	AccountID string `json:"account_id"`
}

type CPATokenData struct {
	Type         string `json:"type"`
	Email        string `json:"email"`
	Expired      string `json:"expired"`
	IDToken      string `json:"id_token"`
	AccountID    string `json:"account_id"`
	AccessToken  string `json:"access_token"`
	LastRefresh  string `json:"last_refresh"`
	RefreshToken string `json:"refresh_token"`
}

type CPAProbeResult struct {
	Name               string
	Account            string
	AuthIndex          string
	StatusCode         int
	Invalid401         bool
	InvalidUsedPercent bool
	UsedPercent        *float64
	IsQuota            bool
	IsHealthy          bool
	Action             string // keep, delete, disable, enable
	Error              string
}

type CPACleanSummary struct {
	TotalFiles      int
	TargetFiles     int
	Invalid401      int
	DeletePlan      int
	DeleteOK        int
	DeleteFail      int
	DisablePlan     int
	DisableOK       int
	DisableFail     int
	EnablePlan      int
	EnableOK        int
	EnableFail      int
	CandidatesAfter int
}

func NewCPAClient(cfg *Config, factory *ClientFactory) *CPAClient {
	return &CPAClient{
		BaseURL:   cfg.CPABaseURL,
		Token:     cfg.CPAToken,
		UserAgent: defaultString(cfg.CPAUserAgent, "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"),
		Timeout:   maxInt(5, cfg.CPATimeout),
		factory:   factory,
	}
}

func (c *CPAClient) mgmtHeaders() map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + c.Token,
		"Accept":        "application/json",
	}
}

// ──────────────── 库存查询 ────────────────

func (c *CPAClient) FetchAuthFiles(ctx context.Context) ([]CPAAuthFile, error) {
	sess := c.factory.NewSession(false)
	target := fmt.Sprintf("%s/v0/management/auth-files", c.BaseURL)
	req, _ := sess.NewRequest(ctx, "GET", target, nil, c.mgmtHeaders())
	resp, body, err := DoRequest(req, sess.Client)
	if err != nil {
		return nil, fmt.Errorf("CPA auth-files 请求失败: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("CPA auth-files 返回 %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var data struct {
		Files []CPAAuthFile `json:"files"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("CPA auth-files 解析失败: %w", err)
	}
	return data.Files, nil
}

func (c *CPAClient) GetCandidatesCount(ctx context.Context, targetType string) (total int, candidates int, err error) {
	files, err := c.FetchAuthFiles(ctx)
	if err != nil {
		return 0, 0, err
	}
	for _, f := range files {
		if !strings.EqualFold(f.Type, targetType) {
			continue
		}
		total++
		if !f.Disabled && !strings.EqualFold(f.Status, "disabled") && !strings.EqualFold(f.Status, "inactive") {
			candidates++
		}
	}
	return total, candidates, nil
}

// ──────────────── Token 上传 ────────────────

func (c *CPAClient) UploadToken(ctx context.Context, email string, tokens Tokens) (bool, error) {
	if strings.TrimSpace(c.BaseURL) == "" || strings.TrimSpace(c.Token) == "" {
		return false, fmt.Errorf("CPA 未配置 base_url 或 token")
	}

	tokenData := BuildCPATokenData(email, tokens)
	return c.uploadTokenData(ctx, fmt.Sprintf("%s.json", email), tokenData)
}

func BuildCPATokenData(email string, tokens Tokens) CPATokenData {
	now := time.Now().In(time.FixedZone("CST", 8*3600))
	accountID := ""
	expiredStr := ""

	if payload, err := decodeJWTPayload(tokens.AccessToken); err == nil {
		if auth, ok := payload["https://api.openai.com/auth"].(map[string]any); ok {
			accountID = toString(auth["chatgpt_account_id"])
		}
		if exp, ok := payload["exp"].(float64); ok && exp > 0 {
			expTime := time.Unix(int64(exp), 0).In(time.FixedZone("CST", 8*3600))
			expiredStr = expTime.Format("2006-01-02T15:04:05+08:00")
		}
	}

	return CPATokenData{
		Type:         "codex",
		Email:        email,
		Expired:      expiredStr,
		IDToken:      tokens.IDToken,
		AccountID:    accountID,
		AccessToken:  tokens.AccessToken,
		LastRefresh:  now.Format("2006-01-02T15:04:05+08:00"),
		RefreshToken: tokens.RefreshToken,
	}
}

func (c *CPAClient) uploadTokenData(ctx context.Context, filename string, tokenData CPATokenData) (bool, error) {
	content, _ := json.Marshal(tokenData)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return false, err
	}
	if _, err := part.Write(content); err != nil {
		return false, err
	}
	if err := writer.Close(); err != nil {
		return false, err
	}

	target := fmt.Sprintf("%s/v0/management/auth-files", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", target, &buf)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	sess := c.factory.NewSession(false)
	resp, body, err := DoRequest(req, sess.Client)
	if err != nil {
		return false, fmt.Errorf("CPA 上传失败: %w", err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, nil
	}
	return false, fmt.Errorf("CPA 上传失败: %d %s", resp.StatusCode, truncate(string(body), 200))
}

// ──────────────── 账号删除 ────────────────

func (c *CPAClient) DeleteAccount(ctx context.Context, name string) (bool, error) {
	if strings.TrimSpace(name) == "" {
		return false, fmt.Errorf("name 为空")
	}
	sess := c.factory.NewSession(false)
	target := fmt.Sprintf("%s/v0/management/auth-files?name=%s", c.BaseURL, name)
	req, _ := sess.NewRequest(ctx, "DELETE", target, nil, c.mgmtHeaders())
	resp, body, err := DoRequest(req, sess.Client)
	if err != nil {
		return false, err
	}
	if resp.StatusCode == 200 {
		var data map[string]any
		if json.Unmarshal(body, &data) == nil && toString(data["status"]) == "ok" {
			return true, nil
		}
	}
	return false, fmt.Errorf("CPA 删除失败: %d %s", resp.StatusCode, truncate(string(body), 200))
}

// ──────────────── 账号禁用/启用 ────────────────

func (c *CPAClient) SetAccountDisabled(ctx context.Context, name string, disable bool) (bool, error) {
	if strings.TrimSpace(name) == "" {
		return false, fmt.Errorf("name 为空")
	}
	sess := c.factory.NewSession(false)
	payload := map[string]any{"name": name, "disabled": disable}
	headers := c.mgmtHeaders()
	headers["Content-Type"] = "application/json"
	target := fmt.Sprintf("%s/v0/management/auth-files", c.BaseURL)
	req, _ := sess.NewJSONRequest(ctx, "PATCH", target, payload, headers)
	resp, body, err := DoRequest(req, sess.Client)
	if err != nil {
		return false, err
	}
	if resp.StatusCode == 200 {
		return true, nil
	}
	action := "disable"
	if !disable {
		action = "enable"
	}
	return false, fmt.Errorf("CPA %s 失败: %d %s", action, resp.StatusCode, truncate(string(body), 200))
}

// ──────────────── 账号探测 ────────────────

func (c *CPAClient) ProbeAccount(ctx context.Context, authIndex string, chatgptAccountID string) (*CPAProbeResult, error) {
	callHeader := map[string]any{
		"Authorization": "Bearer $TOKEN$",
		"Content-Type":  "application/json",
		"User-Agent":    c.UserAgent,
	}
	if chatgptAccountID != "" {
		callHeader["Chatgpt-Account-Id"] = chatgptAccountID
	}
	payload := map[string]any{
		"authIndex": authIndex,
		"method":    "GET",
		"url":       "https://chatgpt.com/backend-api/wham/usage",
		"header":    callHeader,
	}
	sess := c.factory.NewSession(false)
	headers := c.mgmtHeaders()
	headers["Content-Type"] = "application/json"
	target := fmt.Sprintf("%s/v0/management/api-call", c.BaseURL)
	req, _ := sess.NewJSONRequest(ctx, "POST", target, payload, headers)
	resp, body, err := DoRequest(req, sess.Client)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("CPA api-call %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var data map[string]any
	_ = json.Unmarshal(body, &data)
	sc := 0
	if v, ok := data["status_code"].(float64); ok {
		sc = int(v)
	}
	result := &CPAProbeResult{
		AuthIndex:  authIndex,
		StatusCode: sc,
		Invalid401: sc == 401,
		Action:     "keep",
	}
	// 解析 usage
	bodyObj := parseUsageBody(data["body"])
	if bodyObj != nil {
		result.IsHealthy = sc == 200
		if usedPct, ok := bodyObj["used_percent"].(float64); ok {
			result.UsedPercent = &usedPct
			if usedPct > float64(maxInt(80, c.usedPercentThreshold())) {
				result.InvalidUsedPercent = true
			}
		}
		if toString(bodyObj["is_quota"]) == "true" || bodyObj["is_quota"] == true {
			result.IsQuota = true
		}
	}
	// 决策
	result.Action = decideCleanAction(sc, false, result.IsQuota, result.InvalidUsedPercent)
	return result, nil
}

func (c *CPAClient) usedPercentThreshold() int {
	return 80 // 后续可配置化
}

func parseUsageBody(raw any) map[string]any {
	switch v := raw.(type) {
	case map[string]any:
		return v
	case string:
		var out map[string]any
		if json.Unmarshal([]byte(v), &out) == nil {
			return out
		}
	}
	return nil
}

func decideCleanAction(statusCode int, disabled, isQuota, overThreshold bool) string {
	if statusCode == 401 {
		return "delete"
	}
	if isQuota || overThreshold {
		if !disabled {
			return "disable"
		}
		return "keep"
	}
	if statusCode == 200 && disabled {
		return "enable"
	}
	return "keep"
}

// ──────────────── JWT 解码 ────────────────

func decodeJWTPayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid JWT")
	}
	payload := parts[1]
	if pad := len(payload) % 4; pad != 0 {
		payload += strings.Repeat("=", 4-pad)
	}
	raw, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, err
		}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ──────────────── 精细化用量分析 ────────────────

// AnalyzeUsageStatus 分析 rate_limit 窗口用量百分比，匹配 Python 版本的逻辑。
func AnalyzeUsageStatus(statusCode int, bodyObj map[string]any, bodyText string, threshold int) (usedPercent *float64, overThreshold, isQuota, isHealthy bool) {
	if bodyObj == nil {
		return
	}
	rateLimit, _ := bodyObj["rate_limit"].(map[string]any)
	if rateLimit == nil {
		rateLimit = map[string]any{}
	}

	// 从 primary_window / secondary_window 提取 used_percent
	var usedValues []float64
	for _, key := range []string{"primary_window", "secondary_window"} {
		window, _ := rateLimit[key].(map[string]any)
		if window == nil {
			continue
		}
		if v := normalizeUsedPercent(window["used_percent"]); v != nil {
			usedValues = append(usedValues, *v)
		}
	}

	if len(usedValues) > 0 {
		max := usedValues[0]
		for _, v := range usedValues[1:] {
			if v > max {
				max = v
			}
		}
		usedPercent = &max
		overThreshold = max >= float64(threshold)
	}

	// limit_reached 检测
	limitReached := false
	if lr, ok := rateLimit["limit_reached"].(bool); ok && lr {
		limitReached = true
	}
	if allowed, ok := rateLimit["allowed"].(bool); ok && !allowed {
		limitReached = true
	}
	if !limitReached {
		for _, v := range usedValues {
			if v >= 100.0 {
				limitReached = true
				break
			}
		}
	}

	// quota markers 检测
	merged := strings.ToLower(fmt.Sprintf("%v %s", bodyObj, defaultString(bodyText, "")))
	quotaMarkers := []string{"quota exhausted", "limit reached", "payment_required"}
	isQuota = limitReached || statusCode == 402
	if !isQuota {
		for _, marker := range quotaMarkers {
			if strings.Contains(merged, marker) {
				isQuota = true
				break
			}
		}
	}
	isQuota = isQuota || overThreshold

	isHealthy = statusCode == 200 && !isQuota && !overThreshold
	return
}

func normalizeUsedPercent(v any) *float64 {
	switch n := v.(type) {
	case float64:
		if n < 0 {
			r := 0.0
			return &r
		}
		if n > 100 {
			r := 100.0
			return &r
		}
		return &n
	case int:
		f := float64(n)
		return normalizeUsedPercent(f)
	case json.Number:
		if f, err := n.Float64(); err == nil {
			return normalizeUsedPercent(f)
		}
	}
	return nil
}

// ──────────────── RunClean401 完整清理流程 ────────────────

// RunClean401 执行完整的清理流程:
//  1. 拉取所有 auth-files
//  2. 并发探测每个候选账号的健康状态
//  3. 精细化分析用量（rate_limit 窗口）
//  4. 按 action 分类: delete/disable/enable/keep
//  5. 并发执行 delete/disable/enable
//  6. 返回清理汇总
func (r *Runner) RunClean401(ctx context.Context) *CPACleanSummary {
	cpa := r.CPAClient()
	fmt.Println("\n🧹 开始清理账号...")

	// 1. 拉取全部 auth-files
	files, err := cpa.FetchAuthFiles(ctx)
	if err != nil {
		fmt.Printf("❌ 拉取 auth-files 失败: %v\n", err)
		return nil
	}
	totalFiles := len(files)
	targetFiles := 0
	for _, f := range files {
		if strings.EqualFold(f.Type, r.cfg.CPATargetType) {
			targetFiles++
		}
	}
	fmt.Printf("  📊 auth-files: 总 %d | 目标类型(%s) %d\n", totalFiles, r.cfg.CPATargetType, targetFiles)

	// 2. 并发探测
	workers := maxInt(1, minInt(r.cfg.CPAWorkers, targetFiles))
	probeResults := r.probeAllAccounts(ctx, cpa, files, workers)

	// 3. 按 action 分类
	deleteNames := map[string]bool{}
	disableNames := map[string]bool{}
	enableNames := map[string]bool{}
	invalid401 := 0
	overThresholdCount := 0
	for _, pr := range probeResults {
		switch pr.Action {
		case "delete":
			if pr.Name != "" {
				deleteNames[pr.Name] = true
			}
			if pr.Invalid401 {
				invalid401++
			}
		case "disable":
			if pr.Name != "" {
				disableNames[pr.Name] = true
			}
			overThresholdCount++
		case "enable":
			if pr.Name != "" {
				enableNames[pr.Name] = true
			}
		}
	}

	fmt.Printf("  📋 清理计划: delete=%d | disable=%d | enable=%d | invalid401=%d | overThreshold=%d\n",
		len(deleteNames), len(disableNames), len(enableNames), invalid401, overThresholdCount)

	// 4. 并发执行 delete
	deleteOK, deleteFail := r.executeDeletes(ctx, cpa, deleteNames)

	// 5. 并发执行 disable
	disableOK, disableFail := r.executeDisableEnable(ctx, cpa, disableNames, true)

	// 6. 并发执行 enable
	enableOK, enableFail := r.executeDisableEnable(ctx, cpa, enableNames, false)

	// 7. 统计清理后候选数
	_, candidates, _ := cpa.GetCandidatesCount(ctx, r.cfg.CPATargetType)

	summary := &CPACleanSummary{
		TotalFiles:      totalFiles,
		TargetFiles:     targetFiles,
		Invalid401:      invalid401,
		DeletePlan:      len(deleteNames),
		DeleteOK:        deleteOK,
		DeleteFail:      deleteFail,
		DisablePlan:     len(disableNames),
		DisableOK:       disableOK,
		DisableFail:     disableFail,
		EnablePlan:      len(enableNames),
		EnableOK:        enableOK,
		EnableFail:      enableFail,
		CandidatesAfter: candidates,
	}

	fmt.Printf("  🧹 清理完成: delete ✅%d ❌%d | disable ✅%d ❌%d | enable ✅%d ❌%d | 候选=%d\n",
		deleteOK, deleteFail, disableOK, disableFail, enableOK, enableFail, candidates)

	return summary
}

func (r *Runner) probeAllAccounts(ctx context.Context, cpa *CPAClient, files []CPAAuthFile, workers int) []*CPAProbeResult {
	results := make([]*CPAProbeResult, 0)
	resultCh := make(chan *CPAProbeResult, len(files))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, file := range files {
		if !strings.EqualFold(file.Type, r.cfg.CPATargetType) {
			continue
		}
		if strings.TrimSpace(file.AuthIndex) == "" {
			continue
		}
		wg.Add(1)
		file := file
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			pr, err := cpa.ProbeAccount(ctx, file.AuthIndex, file.AccountID)
			if err != nil {
				pr = &CPAProbeResult{
					Name:      file.Name,
					AuthIndex: file.AuthIndex,
					Account:   file.Account,
					Action:    "keep",
					Error:     err.Error(),
				}
			}
			if pr.Name == "" {
				pr.Name = file.Name
			}
			if pr.Account == "" {
				pr.Account = file.Account
			}

			// 精细化用量分析（覆盖简单的 decideCleanAction）
			if pr.StatusCode > 0 {
				usedPct, overThreshold, isQuota, isHealthy := AnalyzeUsageStatus(
					pr.StatusCode, nil, "", r.cfg.CPAUsedPercentThreshold,
				)
				pr.IsHealthy = isHealthy
				if usedPct != nil {
					pr.UsedPercent = usedPct
					pr.InvalidUsedPercent = overThreshold
				}
				pr.IsQuota = isQuota
				pr.Action = decideCleanAction(pr.StatusCode, file.Disabled, pr.IsQuota, pr.InvalidUsedPercent)
			}

			resultCh <- pr
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for pr := range resultCh {
		results = append(results, pr)
	}
	return results
}

func (r *Runner) executeDeletes(ctx context.Context, cpa *CPAClient, names map[string]bool) (int, int) {
	if len(names) == 0 {
		return 0, 0
	}
	workers := maxInt(1, minInt(r.cfg.CPADeleteWorkers, len(names)))
	return r.executeConcurrentAction(ctx, cpa, names, workers, func(name string) (bool, error) {
		return cpa.DeleteAccount(ctx, name)
	})
}

func (r *Runner) executeDisableEnable(ctx context.Context, cpa *CPAClient, names map[string]bool, disable bool) (int, int) {
	if len(names) == 0 {
		return 0, 0
	}
	workers := maxInt(1, minInt(r.cfg.CPADeleteWorkers, len(names)))
	return r.executeConcurrentAction(ctx, cpa, names, workers, func(name string) (bool, error) {
		return cpa.SetAccountDisabled(ctx, name, disable)
	})
}

func (r *Runner) executeConcurrentAction(ctx context.Context, cpa *CPAClient, names map[string]bool, workers int, actionFn func(string) (bool, error)) (int, int) {
	okCount := 0
	failCount := 0
	var mu sync.Mutex
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for name := range names {
		wg.Add(1)
		name := name
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ok, err := actionFn(name)
			mu.Lock()
			if ok && err == nil {
				okCount++
			} else {
				failCount++
				if err != nil {
					fmt.Printf("  ❌ action 失败: %s: %v\n", name, err)
				}
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return okCount, failCount
}
