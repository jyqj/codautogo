package codex

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"codex/internal/sentinel"
)

type Registrar struct {
	cfg      *Config
	session  *Session
	deviceID string
	sentinel *sentinel.Generator

	// 步骤间传递的状态
	step0CodeVerifier string
	step0State        string
}

type OAuthPrepare struct {
	Session      *Session
	DeviceID     string
	CodeVerifier string
	ConsentURL   string
}

type OAuthStatus struct {
	WorkspaceTotal   int
	PrepareFailed    bool
	AllSkipped       bool
	TokenCount       int
	AccountBanned    bool
	FallbackSingle   bool
	NoWorkspaceAbout bool
}

func NewRegistrar(cfg *Config, factory *ClientFactory) *Registrar {
	sess := factory.NewSession(true)
	deviceID := GenerateDeviceID()
	return &Registrar{
		cfg:      cfg,
		session:  sess,
		deviceID: deviceID,
		sentinel: sentinel.NewGenerator(deviceID, sess.Profile.UserAgent),
	}
}

func setOaiDidCookies(sess *Session, deviceID string) {
	u, _ := url.Parse(OpenAIAuthBase)
	sess.Client.Jar.SetCookies(u, []*http.Cookie{{Name: "oai-did", Value: deviceID, Domain: ".auth.openai.com", Path: "/"}, {Name: "oai-did", Value: deviceID, Domain: "auth.openai.com", Path: "/"}})
}

func getCookiesFor(sess *Session, rawURL string) []*http.Cookie {
	u, _ := url.Parse(rawURL)
	return sess.Client.Jar.Cookies(u)
}

func getCookieValue(sess *Session, rawURL, name string) string {
	for _, c := range getCookiesFor(sess, rawURL) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func hasCookie(sess *Session, rawURL, name string) bool {
	return getCookieValue(sess, rawURL, name) != ""
}

func (r *Registrar) buildHeaders(referer string, withSentinel bool, flow string) (map[string]string, error) {
	headers := BuildCommonHeaders(r.session.Profile, referer, OpenAIAuthBase, "same-origin")
	headers["oai-device-id"] = r.deviceID
	for k, v := range GenerateDatadogTrace() {
		headers[k] = v
	}
	if withSentinel {
		token, err := buildSentinelToken(r.session, r.deviceID, flow)
		if err != nil {
			return nil, err
		}
		headers["openai-sentinel-token"] = token
	}
	return headers, nil
}

func (r *Registrar) Step0InitOAuthSession(ctx context.Context, email string) (string, string, bool) {
	fmt.Println("\n🔗 [步骤0] OAuth 会话初始化 + 邮箱提交（Go）")

	// 尝试 direct_auth，失败则 fallback 到 chatgpt_web
	for idx, mode := range r.entryModeCandidates() {
		var codeVerifier, state string
		var initOK bool

		if mode == "chatgpt_web" {
			codeVerifier, state, initOK = r.initSessionViaChatGPTWeb(ctx, email)
		} else {
			codeVerifier, state, initOK = r.initSessionViaDirectAuth(ctx, email)
		}
		if !initOK {
			if idx < len(r.entryModeCandidates())-1 {
				fmt.Printf("  ⚠️ 入口 %s 失败，尝试下一个入口\n", mode)
			}
			continue
		}
		return codeVerifier, state, true
	}
	return "", "", false
}

func (r *Registrar) entryModeCandidates() []string {
	primary := defaultString(r.cfg.EntryMode, "direct_auth")
	fallback := ""
	if r.cfg.EntryModeFallback {
		if primary == "direct_auth" {
			fallback = "chatgpt_web"
		} else {
			fallback = "direct_auth"
		}
	}
	modes := []string{primary}
	if fallback != "" {
		modes = append(modes, fallback)
	}
	return modes
}

func (r *Registrar) initSessionViaDirectAuth(ctx context.Context, email string) (string, string, bool) {
	result := RunStepWithRetry("0a_direct_auth", func() StepResult {
		setOaiDidCookies(r.session, r.deviceID)
		codeVerifier, codeChallenge := GeneratePKCE()
		state := GenerateDeviceID()
		params := url.Values{}
		params.Set("response_type", "code")
		params.Set("client_id", r.cfg.OAuthClientID)
		params.Set("redirect_uri", r.cfg.OAuthRedirectURI)
		params.Set("scope", "openid profile email offline_access")
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
		params.Set("state", state)
		params.Set("screen_hint", "signup")
		params.Set("prompt", "login")
		authorizeURL := fmt.Sprintf("%s/oauth/authorize?%s", OpenAIAuthBase, params.Encode())
		req, _ := r.session.NewRequest(ctx, "GET", authorizeURL, nil, BuildNavigateHeaders(r.session.Profile, "", "none"))
		resp, _, err := DoRequest(req, r.session.Client)
		if err != nil {
			return StepResult{OK: false, Reason: fmt.Sprintf("oauth_authorize_failed:%v", err)}
		}
		if resp.StatusCode != 200 && resp.StatusCode != 302 {
			return StepResult{OK: false, Reason: fmt.Sprintf("oauth_authorize_http_%d", resp.StatusCode)}
		}
		if !hasCookie(r.session, OpenAIAuthBase, "login_session") {
			return StepResult{OK: false, Reason: "login_session_missing"}
		}
		// 保存以便外层使用
		r.step0CodeVerifier = codeVerifier
		r.step0State = state
		return StepResult{OK: true}
	}, r.cfg.StepRetryAttempts, time.Duration(r.cfg.StepRetryDelayBase*float64(time.Second)), time.Duration(r.cfg.StepRetryDelayCap*float64(time.Second)))

	if !result.OK {
		return "", "", false
	}
	// 提交邮箱（带重试）
	return r.submitSignupEmail(ctx, email)
}

func (r *Registrar) initSessionViaChatGPTWeb(ctx context.Context, email string) (string, string, bool) {
	result := RunStepWithRetry("0a_chatgpt_web", func() StepResult {
		setOaiDidCookies(r.session, r.deviceID)
		// 访问 chatgpt.com 获取 CSRF token
		req1, _ := r.session.NewRequest(ctx, "GET", ChatGPTBase+"/", nil, BuildNavigateHeaders(r.session.Profile, "", "none"))
		resp1, _, err := DoRequest(req1, r.session.Client)
		if err != nil {
			return StepResult{OK: false, Reason: fmt.Sprintf("chatgpt_home_failed:%v", err)}
		}
		if resp1.StatusCode != 200 {
			return StepResult{OK: false, Reason: fmt.Sprintf("chatgpt_home_http_%d", resp1.StatusCode)}
		}
		// 获取 CSRF token
		csrfToken := getCookieValue(r.session, ChatGPTBase, "__Secure-next-auth.session-token")
		if csrfToken == "" {
			// 尝试从 /api/auth/csrf 获取
			reqCSRF, _ := r.session.NewRequest(ctx, "GET", ChatGPTBase+"/api/auth/csrf", nil, BuildCommonHeaders(r.session.Profile, ChatGPTBase, ChatGPTBase, "same-origin"))
			_, bodyCSRF, err := DoRequest(reqCSRF, r.session.Client)
			if err != nil {
				return StepResult{OK: false, Reason: fmt.Sprintf("csrf_fetch_failed:%v", err)}
			}
			var csrfData map[string]any
			_ = json.Unmarshal(bodyCSRF, &csrfData)
			csrfToken = toString(csrfData["csrfToken"])
		}
		// POST /api/auth/signin/login-web
		signinHeaders := BuildCommonHeaders(r.session.Profile, ChatGPTBase, ChatGPTBase, "same-origin")
		signinHeaders["content-type"] = "application/x-www-form-urlencoded"
		signinPayload := url.Values{"callbackUrl": {"/"}, "csrfToken": {csrfToken}, "json": {"true"}}
		reqSignin, _ := r.session.NewRequest(ctx, "POST", ChatGPTBase+"/api/auth/signin/login-web", []byte(signinPayload.Encode()), signinHeaders)
		respSignin, bodySignin, err := DoRequest(reqSignin, r.session.Client)
		if err != nil {
			return StepResult{OK: false, Reason: fmt.Sprintf("chatgpt_signin_failed:%v", err)}
		}
		if respSignin.StatusCode != 200 {
			return StepResult{OK: false, Reason: fmt.Sprintf("chatgpt_signin_http_%d", respSignin.StatusCode)}
		}
		// 解析 redirect URL 并跟随到 auth.openai.com
		var signinResp map[string]any
		_ = json.Unmarshal(bodySignin, &signinResp)
		redirectURL := toString(signinResp["url"])
		if redirectURL == "" {
			return StepResult{OK: false, Reason: "chatgpt_signin_no_redirect_url"}
		}
		reqFollow, _ := r.session.NewRequest(ctx, "GET", redirectURL, nil, BuildNavigateHeaders(r.session.Profile, ChatGPTBase, "cross-site"))
		_, _, err = DoRequest(reqFollow, r.session.Client)
		if err != nil {
			return StepResult{OK: false, Reason: fmt.Sprintf("chatgpt_follow_failed:%v", err)}
		}
		if !hasCookie(r.session, OpenAIAuthBase, "login_session") {
			return StepResult{OK: false, Reason: "login_session_missing_via_chatgpt_web"}
		}
		// PKCE 参数
		codeVerifier, codeChallenge := GeneratePKCE()
		state := GenerateDeviceID()
		r.step0CodeVerifier = codeVerifier
		r.step0State = state
		_ = codeChallenge
		return StepResult{OK: true}
	}, r.cfg.StepRetryAttempts, time.Duration(r.cfg.StepRetryDelayBase*float64(time.Second)), time.Duration(r.cfg.StepRetryDelayCap*float64(time.Second)))

	if !result.OK {
		return "", "", false
	}
	return r.submitSignupEmail(ctx, email)
}

func (r *Registrar) submitSignupEmail(ctx context.Context, email string) (string, string, bool) {
	result := RunStepWithRetry("0b_submit_email", func() StepResult {
		headers, err := r.buildHeaders(OpenAIAuthBase+"/create-account", true, "authorize_continue")
		if err != nil {
			return StepResult{OK: false, Reason: fmt.Sprintf("sentinel_failed:%v", err)}
		}
		payload := map[string]any{"username": map[string]any{"kind": "email", "value": email}, "screen_hint": "signup"}
		req, _ := r.session.NewJSONRequest(ctx, "POST", OpenAIAuthBase+"/api/accounts/authorize/continue", payload, headers)
		resp, body, err := DoRequest(req, r.session.Client)
		if err != nil {
			return StepResult{OK: false, Reason: fmt.Sprintf("authorize_continue_failed:%v", err)}
		}
		if resp.StatusCode == 200 {
			return StepResult{OK: true}
		}
		reason := fmt.Sprintf("authorize_continue_http_%d", resp.StatusCode)
		if IsTransientFlowError(truncate(string(body), 200), r.cfg.TransientMarkers) {
			reason += ":" + truncate(string(body), 100)
		}
		return StepResult{OK: false, Reason: reason}
	}, r.cfg.StepRetryAttempts, time.Duration(r.cfg.StepRetryDelayBase*float64(time.Second)), time.Duration(r.cfg.StepRetryDelayCap*float64(time.Second)))

	if !result.OK {
		return "", "", false
	}
	return r.step0CodeVerifier, r.step0State, true
}

func (r *Registrar) Step2RegisterUser(ctx context.Context, email, password string) bool {
	fmt.Printf("\n🔑 [步骤2] 注册用户: %s\n", email)
	result := RunStepWithRetry("2_register", func() StepResult {
		headers, err := r.buildHeaders(OpenAIAuthBase+"/create-account/password", true, "authorize_continue")
		if err != nil {
			return StepResult{OK: false, Reason: fmt.Sprintf("build_headers_failed:%v", err)}
		}
		payload := map[string]any{"username": email, "password": password}
		req, _ := r.session.NewJSONRequest(ctx, "POST", OpenAIAuthBase+"/api/accounts/user/register", payload, headers)
		resp, body, err := DoRequest(req, r.session.Client)
		if err != nil {
			return StepResult{OK: false, Reason: fmt.Sprintf("register_request_failed:%v", err)}
		}
		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
			fmt.Println("  ✅ 注册成功")
			return StepResult{OK: true}
		}
		reason := fmt.Sprintf("register_http_%d", resp.StatusCode)
		bodyStr := string(body)
		if IsTransientFlowError(truncate(bodyStr, 200), r.cfg.TransientMarkers) {
			reason += ":" + truncate(bodyStr, 100)
		}
		return StepResult{OK: false, Reason: reason}
	}, r.cfg.StepRetryAttempts, time.Duration(r.cfg.StepRetryDelayBase*float64(time.Second)), time.Duration(r.cfg.StepRetryDelayCap*float64(time.Second)))
	return result.OK
}

func (r *Registrar) Step3SendOTP(ctx context.Context) bool {
	fmt.Println("\n📬 [步骤3] 触发验证码发送")
	result := RunStepWithRetry("3_send_otp", func() StepResult {
		headers := BuildNavigateHeaders(r.session.Profile, OpenAIAuthBase+"/create-account/password", "same-origin")
		req1, _ := r.session.NewRequest(ctx, "GET", OpenAIAuthBase+"/api/accounts/email-otp/send", nil, headers)
		resp1, _, err := DoRequest(req1, r.session.Client)
		if err != nil {
			return StepResult{OK: false, Reason: fmt.Sprintf("send_otp_failed:%v", err)}
		}
		fmt.Printf("  send 状态码: %d\n", resp1.StatusCode)
		if resp1.StatusCode >= 500 {
			return StepResult{OK: false, Reason: fmt.Sprintf("send_otp_http_%d", resp1.StatusCode)}
		}
		req2, _ := r.session.NewRequest(ctx, "GET", OpenAIAuthBase+"/email-verification", nil, headers)
		resp2, _, err := DoRequest(req2, r.session.Client)
		if err != nil {
			return StepResult{OK: false, Reason: fmt.Sprintf("email_verification_failed:%v", err)}
		}
		fmt.Printf("  email-verification 状态码: %d\n", resp2.StatusCode)
		return StepResult{OK: true}
	}, r.cfg.StepRetryAttempts, time.Duration(r.cfg.StepRetryDelayBase*float64(time.Second)), time.Duration(r.cfg.StepRetryDelayCap*float64(time.Second)))
	return result.OK
}

func (r *Registrar) Step4ValidateOTP(ctx context.Context, code string) bool {
	fmt.Printf("\n🔢 [步骤4] 验证邮箱 OTP: %s\n", code)
	// otpValidateOrder 默认 ["normal", "sentinel"]，先 normal 再 sentinel fallback
	modes := r.otpValidateOrder()
	triedNormal := false
	for _, mode := range modes {
		includeSentinel := mode == "sentinel"
		if includeSentinel && triedNormal {
			fmt.Println("  ⚠️ 普通 OTP 校验失败，尝试 Sentinel fallback")
		}
		result := RunStepWithRetry(fmt.Sprintf("4_validate_otp_%s", mode), func() StepResult {
			headers, err := r.buildHeaders(OpenAIAuthBase+"/email-verification", includeSentinel, "email_otp_validate")
			if err != nil {
				return StepResult{OK: false, Reason: fmt.Sprintf("build_headers_failed:%v", err)}
			}
			req, _ := r.session.NewJSONRequest(ctx, "POST", OpenAIAuthBase+"/api/accounts/email-otp/validate", map[string]any{"code": code}, headers)
			resp, body, err := DoRequest(req, r.session.Client)
			if err != nil {
				return StepResult{OK: false, Reason: fmt.Sprintf("email_otp_validate_failed:%v", err)}
			}
			if resp.StatusCode == 200 {
				return StepResult{OK: true}
			}
			reason := fmt.Sprintf("email_otp_validate_http_%d", resp.StatusCode)
			bodyStr := string(body)
			if IsTransientFlowError(truncate(bodyStr, 200), r.cfg.TransientMarkers) {
				reason += ":" + truncate(bodyStr, 100)
			}
			return StepResult{OK: false, Reason: reason}
		}, r.cfg.StepRetryAttempts, time.Duration(r.cfg.StepRetryDelayBase*float64(time.Second)), time.Duration(r.cfg.StepRetryDelayCap*float64(time.Second)))

		if result.OK {
			if includeSentinel {
				fmt.Println("  ✅ OTP Sentinel fallback 命中")
			}
			return true
		}
		triedNormal = triedNormal || !includeSentinel
	}
	return false
}

func (r *Registrar) otpValidateOrder() []string {
	if len(r.cfg.OTPValidateOrder) > 0 {
		return r.cfg.OTPValidateOrder
	}
	return []string{"normal", "sentinel"}
}

func (r *Registrar) Step5CreateAccount(ctx context.Context, firstName, lastName, birthdate string) bool {
	fmt.Println("\n👤 [步骤5] 创建账号资料")
	result := RunStepWithRetry("5_create_account", func() StepResult {
		headers, err := r.buildHeaders(OpenAIAuthBase+"/about-you", true, "authorize_continue")
		if err != nil {
			return StepResult{OK: false, Reason: fmt.Sprintf("build_headers_failed:%v", err)}
		}
		payload := map[string]any{"name": strings.TrimSpace(firstName + " " + lastName), "birthdate": birthdate}
		req, _ := r.session.NewJSONRequest(ctx, "POST", OpenAIAuthBase+"/api/accounts/create_account", payload, headers)
		resp, body, err := DoRequest(req, r.session.Client)
		if err != nil {
			return StepResult{OK: false, Reason: fmt.Sprintf("create_account_failed:%v", err)}
		}
		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
			fmt.Println("  ✅ 账号创建完成")
			return StepResult{OK: true}
		}
		// 403 sentinel → 重新生成 sentinel token 再试
		if resp.StatusCode == 403 && strings.Contains(strings.ToLower(string(body)), "sentinel") {
			newToken, sentinelErr := buildSentinelToken(r.session, r.deviceID, "authorize_continue")
			if sentinelErr == nil {
				headers["openai-sentinel-token"] = newToken
				reqRetry, _ := r.session.NewJSONRequest(ctx, "POST", OpenAIAuthBase+"/api/accounts/create_account", payload, headers)
				respRetry, bodyRetry, errRetry := DoRequest(reqRetry, r.session.Client)
				if errRetry == nil && (respRetry.StatusCode == 200 || respRetry.StatusCode == 301 || respRetry.StatusCode == 302) {
					fmt.Println("  ✅ 账号创建完成（sentinel 重试成功）")
					return StepResult{OK: true}
				}
				return StepResult{OK: false, Reason: fmt.Sprintf("create_account_sentinel_retry_http_%d: %s", respRetry.StatusCode, truncate(string(bodyRetry), 200))}
			}
		}
		reason := fmt.Sprintf("create_account_http_%d", resp.StatusCode)
		bodyStr := string(body)
		if IsTransientFlowError(truncate(bodyStr, 200), r.cfg.TransientMarkers) {
			reason += ":" + truncate(bodyStr, 100)
		}
		return StepResult{OK: false, Reason: reason}
	}, r.cfg.StepRetryAttempts, time.Duration(r.cfg.StepRetryDelayBase*float64(time.Second)), time.Duration(r.cfg.StepRetryDelayCap*float64(time.Second)))
	return result.OK
}

// registerBase runs steps 0 and 2 (with the standard sleeps between them).
// It does NOT call Step3SendOTP so callers can sequence baseline fetches correctly.
func (r *Registrar) registerBase(ctx context.Context, email, password string) bool {
	if _, _, ok := r.Step0InitOAuthSession(ctx, email); !ok {
		return false
	}
	time.Sleep(1 * time.Second)
	if !r.Step2RegisterUser(ctx, email, password) {
		return false
	}
	time.Sleep(1 * time.Second)
	return true
}

func (r *Registrar) Register(ctx context.Context, email, password string, tempMail TempMailProvider, cfToken string) bool {
	firstName, lastName := GenerateRandomName()
	birthdate := GenerateRandomBirthday()
	fmt.Printf("\n📝 注册: %s\n", email)
	if !r.registerBase(ctx, email, password) {
		return false
	}
	_ = r.Step3SendOTP(ctx)
	if tempMail == nil {
		return false
	}
	code, err := tempMail.WaitForVerificationCode(ctx, email, cfToken, 120*time.Second)
	if err != nil || strings.TrimSpace(code) == "" {
		fmt.Println("❌ 未收到验证码")
		return false
	}
	if !r.Step4ValidateOTP(ctx, code) {
		return false
	}
	time.Sleep(1 * time.Second)
	if !r.Step5CreateAccount(ctx, firstName, lastName, birthdate) {
		return false
	}
	fmt.Println("\n🎉 注册成功！")
	return true
}

func RegisterAccountWithOTPClient(ctx context.Context, cfg *Config, factory *ClientFactory, email, password string, mailClient OTPClient) bool {
	registrar := NewRegistrar(cfg, factory)
	if !registrar.registerBase(ctx, email, password) {
		return false
	}
	baseline, _ := mailClient.FetchLatestMailID(ctx)
	_ = registrar.Step3SendOTP(ctx)
	fmt.Println("  ⏳ 等待验证码...")
	startMS := time.Now().UnixMilli()
	deadline := time.Now().Add(120 * time.Second)
	lastTried := 0
	time.Sleep(6 * time.Second)
	for time.Now().Before(deadline) {
		useSince := 0
		if baseline > 0 && time.Since(time.UnixMilli(startMS)) < 30*time.Second {
			useSince = baseline
		}
		candidates, _ := mailClient.FetchOTPCandidates(ctx, email, startMS-5000, useSince)
		if len(candidates) > 0 {
			cand := candidates[0]
			if cand.EmailID > lastTried {
				lastTried = cand.EmailID
				fmt.Printf("  🔢 尝试验证码: %s (emailId=%d, sub=%s)\n", cand.Code, cand.EmailID, cand.Subject)
				if registrar.Step4ValidateOTP(ctx, cand.Code) {
					mailClient.RememberOTP(cand.Code, cand.EmailID)
					firstName, lastName := GenerateRandomName()
					birthdate := GenerateRandomBirthday()
					if registrar.Step5CreateAccount(ctx, firstName, lastName, birthdate) {
						fmt.Println("\n🎉 注册成功！")
						return true
					}
					return false
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
	fmt.Println("❌ 未收到可用验证码")
	return false
}

func fetchSentinelChallenge(sess *Session, deviceID, flow string) (map[string]any, error) {
	gen := sentinel.NewGenerator(deviceID, sess.Profile.UserAgent)
	body := map[string]any{"p": gen.GenerateRequirementsToken(), "id": deviceID, "flow": flow}
	headers := BuildSentinelHeaders(sess.Profile)
	req, _ := sess.NewJSONRequest(context.Background(), "POST", "https://sentinel.openai.com/backend-api/sentinel/req", body, headers)
	resp, data, err := DoRequest(req, sess.Client)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("sentinel API 返回 %d: %s", resp.StatusCode, truncate(string(data), 200))
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

func buildSentinelToken(sess *Session, deviceID, flow string) (string, error) {
	challenge, err := fetchSentinelChallenge(sess, deviceID, flow)
	if err != nil {
		return "", err
	}
	powData := asMap(challenge["proofofwork"])
	gen := sentinel.NewGenerator(deviceID, sess.Profile.UserAgent)
	pValue := gen.GenerateRequirementsToken()
	if truthy(powData["required"]) && strings.TrimSpace(toString(powData["seed"])) != "" {
		pValue = gen.GenerateToken(toString(powData["seed"]), toString(powData["difficulty"]))
	}
	tokenBody := map[string]any{"p": pValue, "t": "", "c": toString(challenge["token"]), "id": deviceID, "flow": flow}
	raw, _ := json.Marshal(tokenBody)
	return string(raw), nil
}

func truthy(v any) bool {
	s := strings.ToLower(strings.TrimSpace(toString(v)))
	return s == "true" || s == "1"
}

func PerformOAuthLoginHTTP(ctx context.Context, cfg *Config, factory *ClientFactory, email, password string, mailClient OTPClient, prepareOnly bool) (*OAuthPrepare, *Tokens, string, error) {
	fmt.Println("\n🔐 执行 Codex OAuth 登录（Go HTTP 模式）...")
	oauthStart := time.Now()
	sess := factory.NewSession(true)
	deviceID := GenerateDeviceID()
	setOaiDidCookies(sess, deviceID)
	codeVerifier, codeChallenge := GeneratePKCE()
	state := GenerateDeviceID()
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", cfg.OAuthClientID)
	params.Set("redirect_uri", cfg.OAuthRedirectURI)
	params.Set("scope", "openid profile email offline_access api.connectors.read api.connectors.invoke")
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	params.Set("state", state)
	params.Set("prompt", "login")
	params.Set("id_token_add_organizations", "true")
	params.Set("codex_cli_simplified_flow", "true")
	params.Set("originator", "codex_cli")
	authorizeURL := fmt.Sprintf("%s/oauth/authorize?%s", cfg.OAuthIssuer, params.Encode())
	req1, _ := sess.NewRequest(ctx, "GET", authorizeURL, nil, BuildNavigateHeaders(sess.Profile, "", "none"))
	resp1, _, err := DoRequest(req1, sess.Client)
	if err != nil {
		return nil, nil, "", err
	}
	fmt.Printf("  状态码: %d\n", resp1.StatusCode)
	fmt.Printf("  [耗时] authorize: %.2fs\n", time.Since(oauthStart).Seconds())
	if !hasCookie(sess, OpenAIAuthBase, "login_session") {
		fmt.Println("  ⚠️ 未获得 login_session")
	}

	var resp2 *http.Response
	var body2 []byte
	for attempt := 1; attempt <= cfg.OAuthStep2MaxRetries; attempt++ {
		headers := BuildCommonHeaders(sess.Profile, cfg.OAuthIssuer+"/log-in", cfg.OAuthIssuer, "same-origin")
		headers["oai-device-id"] = deviceID
		for k, v := range GenerateDatadogTrace() {
			headers[k] = v
		}
		token, err := buildSentinelToken(sess, deviceID, "authorize_continue")
		if err != nil {
			return nil, nil, "", err
		}
		headers["openai-sentinel-token"] = token
		req2, _ := sess.NewJSONRequest(ctx, "POST", cfg.OAuthIssuer+"/api/accounts/authorize/continue", map[string]any{"username": map[string]any{"kind": "email", "value": email}}, headers)
		resp2, body2, err = DoRequest(req2, sess.Client)
		if err == nil {
			fmt.Printf("  步骤2: %d (尝试 %d/%d)\n", resp2.StatusCode, attempt, cfg.OAuthStep2MaxRetries)
			if resp2.StatusCode == 200 {
				break
			}
			if resp2.StatusCode == 429 && attempt < cfg.OAuthStep2MaxRetries {
				time.Sleep(time.Duration(cfg.OAuthStep2RetryBaseSeconds*float64(time.Second)) * time.Duration(1<<(attempt-1)))
				continue
			}
			break
		}
		if attempt == cfg.OAuthStep2MaxRetries {
			return nil, nil, "", err
		}
		time.Sleep(time.Duration(cfg.OAuthStep2RetryBaseSeconds*float64(time.Second)) * time.Duration(1<<(attempt-1)))
	}
	if resp2 == nil || resp2.StatusCode != 200 {
		return nil, nil, "", fmt.Errorf("邮箱提交失败: %s", truncate(string(body2), 180))
	}
	fmt.Printf("  [耗时] authorize_continue: %.2fs\n", time.Since(oauthStart).Seconds())

	headers3 := BuildCommonHeaders(sess.Profile, cfg.OAuthIssuer+"/log-in/password", cfg.OAuthIssuer, "same-origin")
	headers3["oai-device-id"] = deviceID
	for k, v := range GenerateDatadogTrace() {
		headers3[k] = v
	}
	pwdToken, err := buildSentinelToken(sess, deviceID, "password_verify")
	if err != nil {
		return nil, nil, "", err
	}
	headers3["openai-sentinel-token"] = pwdToken
	req3, _ := sess.NewJSONRequest(ctx, "POST", cfg.OAuthIssuer+"/api/accounts/password/verify", map[string]any{"password": password}, headers3)
	resp3, body3, err := DoRequest(req3, sess.Client)
	if err != nil {
		return nil, nil, "", err
	}
	fmt.Printf("  步骤3: %d\n", resp3.StatusCode)
	fmt.Printf("  [耗时] password_verify: %.2fs\n", time.Since(oauthStart).Seconds())
	if resp3.StatusCode != 200 {
		if resp3.StatusCode == 403 && strings.Contains(strings.ToLower(string(body3)), "deleted or deactivated") {
			return nil, nil, "ACCOUNT_BANNED", nil
		}
		return nil, nil, "", fmt.Errorf("密码验证失败: %s", truncate(string(body3), 180))
	}
	var data3 map[string]any
	_ = json.Unmarshal(body3, &data3)
	continueURL := toString(data3["continue_url"])
	pageType := toString(asMap(data3["page"])["type"])
	fmt.Printf("  page.type: %s\n", pageType)
	fmt.Printf("  continue_url: %s\n", truncate(continueURL, 160))
	if continueURL == "" {
		fmt.Printf("  password/verify body: %s\n", truncate(string(body3), 400))
		return nil, nil, "", fmt.Errorf("未获取到 continue_url")
	}

	if pageType == "email_otp_verification" || strings.Contains(continueURL, "email-verification") {
		// 先 GET /email-verification 建立 OTP 页面上下文（与注册流一致）
		evURL := cfg.OAuthIssuer + "/email-verification"
		if strings.HasPrefix(continueURL, "http") && strings.Contains(continueURL, "email-verification") {
			evURL = continueURL
		}
		reqEV, _ := sess.NewRequest(ctx, "GET", evURL, nil, BuildNavigateHeaders(sess.Profile, cfg.OAuthIssuer+"/log-in/password", "same-origin"))
		DoRequest(reqEV, sess.Client)

		validationHeaders := BuildCommonHeaders(sess.Profile, cfg.OAuthIssuer+"/email-verification", cfg.OAuthIssuer, "same-origin")
		validationHeaders["oai-device-id"] = deviceID
		for k, v := range GenerateDatadogTrace() {
			validationHeaders[k] = v
		}
		if sentinelTok, err := buildSentinelToken(sess, deviceID, "email_otp_validate"); err == nil && sentinelTok != "" {
			validationHeaders["openai-sentinel-token"] = sentinelTok
		}
		validated := false
		if mailClient != nil {
			otpWaitStart := time.Now()
			if recent := mailClient.GetRecentOTP(120 * time.Second); recent != nil {
				reqV, _ := sess.NewJSONRequest(ctx, "POST", cfg.OAuthIssuer+"/api/accounts/email-otp/validate", map[string]any{"code": recent.Code}, validationHeaders)
				respV, bodyV, _ := DoRequest(reqV, sess.Client)
				if respV != nil && respV.StatusCode == 200 {
					validated = true
					_ = json.Unmarshal(bodyV, &data3)
					continueURL = toString(data3["continue_url"])
					pageType = toString(asMap(data3["page"])["type"])
				}
			}
			if !validated {
				baseline, _ := mailClient.FetchLatestMailID(ctx)
				deadline := time.Now().Add(120 * time.Second)
				startMS := time.Now().UnixMilli()
				tried := map[string]struct{}{}
				for time.Now().Before(deadline) && !validated {
					useSince := 0
					if baseline > 0 && time.Since(time.UnixMilli(startMS)) < 30*time.Second {
						useSince = baseline
					}
					candidates, _ := mailClient.FetchOTPCandidates(ctx, email, startMS-5000, useSince)
					for _, cand := range candidates {
						key := fmt.Sprintf("%d:%s", cand.EmailID, cand.Code)
						if _, ok := tried[key]; ok {
							continue
						}
						tried[key] = struct{}{}
						reqV, _ := sess.NewJSONRequest(ctx, "POST", cfg.OAuthIssuer+"/api/accounts/email-otp/validate", map[string]any{"code": cand.Code}, validationHeaders)
						respV, bodyV, _ := DoRequest(reqV, sess.Client)
						if respV != nil && respV.StatusCode == 200 {
							validated = true
							mailClient.RememberOTP(cand.Code, cand.EmailID)
							_ = json.Unmarshal(bodyV, &data3)
							continueURL = toString(data3["continue_url"])
							pageType = toString(asMap(data3["page"])["type"])
							break
						}
						if respV != nil && respV.StatusCode == 403 && strings.Contains(strings.ToLower(string(bodyV)), "deleted or deactivated") {
							return nil, nil, "ACCOUNT_BANNED", nil
						}
					}
					if !validated {
						time.Sleep(1 * time.Second)
					}
				}
			}
			if validated {
				fmt.Printf("  [耗时] oauth_email_otp: %.2fs\n", time.Since(otpWaitStart).Seconds())
				fmt.Printf("  [OTP后] continue_url: %s | page.type: %s\n", truncate(continueURL, 160), pageType)
			}
		}
		if !validated {
			return nil, nil, "", fmt.Errorf("验证码等待超时")
		}
		if strings.Contains(continueURL, "about-you") {
			reqAbout, _ := sess.NewRequest(ctx, "GET", cfg.OAuthIssuer+"/about-you", nil, BuildNavigateHeaders(sess.Profile, cfg.OAuthIssuer+"/email-verification", "same-origin"))
			respAbout, _, _ := DoRequest(reqAbout, sess.Client)
			if respAbout != nil && strings.Contains(respAbout.Request.URL.String(), "consent") {
				continueURL = respAbout.Request.URL.String()
			} else {
				firstName, lastName := GenerateRandomName()
				birthdate := GenerateRandomBirthday()
				headersCreate := BuildCommonHeaders(sess.Profile, cfg.OAuthIssuer+"/about-you", cfg.OAuthIssuer, "same-origin")
				headersCreate["oai-device-id"] = deviceID
				for k, v := range GenerateDatadogTrace() {
					headersCreate[k] = v
				}
				if sentinelTok, err := buildSentinelToken(sess, deviceID, "authorize_continue"); err == nil && sentinelTok != "" {
					headersCreate["openai-sentinel-token"] = sentinelTok
				}
				reqCreate, _ := sess.NewJSONRequest(ctx, "POST", cfg.OAuthIssuer+"/api/accounts/create_account", map[string]any{"name": strings.TrimSpace(firstName + " " + lastName), "birthdate": birthdate}, headersCreate)
				respCreate, bodyCreate, _ := DoRequest(reqCreate, sess.Client)
				if respCreate != nil && respCreate.StatusCode == 200 {
					var out map[string]any
					_ = json.Unmarshal(bodyCreate, &out)
					continueURL = toString(out["continue_url"])
				} else if strings.Contains(strings.ToLower(string(bodyCreate)), "already_exists") {
					continueURL = cfg.OAuthIssuer + "/sign-in-with-chatgpt/codex/consent"
				}
			}
		}
		if strings.Contains(pageType, "consent") {
			continueURL = cfg.OAuthIssuer + "/sign-in-with-chatgpt/codex/consent"
		}
	}
	if strings.TrimSpace(continueURL) == "" {
		return nil, nil, "", fmt.Errorf("未获取到 consent URL")
	}
	consentURL := continueURL
	if strings.HasPrefix(consentURL, "/") {
		consentURL = cfg.OAuthIssuer + consentURL
	}
	if prepareOnly {
		fmt.Printf("  prepare_only consent URL: %s\n", truncate(consentURL, 160))
		fmt.Printf("  [耗时] prepare_only_total: %.2fs\n", time.Since(oauthStart).Seconds())
		return &OAuthPrepare{Session: sess, DeviceID: deviceID, CodeVerifier: codeVerifier, ConsentURL: consentURL}, nil, "", nil
	}
	code := extractCodeFromURL(consentURL)
	if code == "" {
		code = followAndExtractCode(ctx, sess, consentURL, cfg.OAuthIssuer, 10)
	}
	if code == "" {
		if sessionData := decodeAuthSessionForWorkspaces(sess); len(sessionData) > 0 {
			workspaces := extractWorkspaces(sessionData)
			if len(workspaces) > 0 {
				selected := workspaces[0]
				code = exchangeWorkspaceSelection(ctx, cfg, sess, deviceID, codeVerifier, consentURL, selected, nil)
			}
		}
	}
	if code == "" {
		return nil, nil, "", fmt.Errorf("未获取到 authorization code")
	}
	tokens, err := codexExchangeCode(ctx, cfg, factory, code, codeVerifier)
	if err != nil {
		return nil, nil, "", err
	}
	fmt.Printf("  [耗时] oauth_total: %.2fs\n", time.Since(oauthStart).Seconds())
	return nil, &tokens, "", nil
}

// fallbackSingleOAuth attempts a full (non-prepare-only) OAuth login and records the result
// as a single "default" workspace token. It mutates status and returns the result slice plus
// a boolean indicating whether the caller should return immediately.
func fallbackSingleOAuth(ctx context.Context, cfg *Config, factory *ClientFactory, email, password string, mailClient OTPClient, onResult func(SpaceResult) bool, status *OAuthStatus) ([]SpaceResult, bool) {
	_, tokens, marker, err := PerformOAuthLoginHTTP(ctx, cfg, factory, email, password, mailClient, false)
	if marker == "ACCOUNT_BANNED" {
		status.AccountBanned = true
		return nil, true
	}
	if err == nil && tokens != nil {
		status.FallbackSingle = true
		result := SpaceResult{Workspace: "default", Org: "default", WorkspaceID: "default", OrgID: "default", Tokens: *tokens}
		if onResult != nil {
			onResult(result)
		}
		return []SpaceResult{result}, true
	}
	if err != nil {
		fmt.Printf("  ⚠️ fallback single 失败: %v\n", err)
	}
	return nil, false
}

func PerformOAuthLoginHTTPAllSpaces(ctx context.Context, cfg *Config, factory *ClientFactory, state *StateStore, email, password string, mailClient OTPClient, onResult func(SpaceResult) bool) ([]SpaceResult, *OAuthStatus) {
	status := &OAuthStatus{}
	prep, _, marker, err := PerformOAuthLoginHTTP(ctx, cfg, factory, email, password, mailClient, true)
	if err != nil {
		fmt.Printf("  ⚠️ OAuth prepare 失败: %v\n", err)
		status.PrepareFailed = true
		return nil, status
	}
	if marker == "ACCOUNT_BANNED" {
		status.AccountBanned = true
		return nil, status
	}
	if prep == nil {
		status.PrepareFailed = true
		return nil, status
	}
	sessionData := decodeAuthSessionForWorkspaces(prep.Session)
	workspaces := extractWorkspaces(sessionData)
	status.WorkspaceTotal = len(workspaces)
	fmt.Printf("  workspace 总数: %d\n", len(workspaces))
	if len(workspaces) == 0 {
		fmt.Printf("  consent URL: %s\n", truncate(prep.ConsentURL, 160))
		if strings.Contains(prep.ConsentURL, "about-you") {
			status.NoWorkspaceAbout = true
			return nil, status
		}
		if res, handled := fallbackSingleOAuth(ctx, cfg, factory, email, password, mailClient, onResult, status); handled {
			return res, status
		}
		return nil, status
	}
	pending := make([]map[string]any, 0)
	for _, ws := range workspaces {
		wid := toString(ws["id"])
		if state.workspaceRecordedAll(email, wid) {
			fmt.Printf("  ⏭️ 跳过已录 workspace: %s (%s)\n", workspaceName(ws), wid)
			continue
		}
		pending = append(pending, ws)
	}
	if len(pending) == 0 {
		status.AllSkipped = true
		return nil, status
	}
	results := make([]SpaceResult, 0)
	seenTokens := map[string]struct{}{}
	var mu sync.Mutex
	workers := minInt(maxInt(1, cfg.WorkspaceLoginWorkers), len(pending))
	fmt.Printf("  🔀 workspace 并行登录: %d 并发（待处理 %d 个）\n", workers, len(pending))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i, ws := range pending {
		wg.Add(1)
		ws := ws
		idx := i
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var prepWS *OAuthPrepare
			if idx == 0 {
				prepWS = prep
			} else {
				prepWS, _, marker3, err3 := PerformOAuthLoginHTTP(ctx, cfg, factory, email, password, mailClient, true)
				if marker3 == "ACCOUNT_BANNED" {
					status.AccountBanned = true
					return
				}
				if err3 != nil || prepWS == nil {
					wid := toString(ws["id"])
					state.updateSpaceRecord(email, SpaceResult{Workspace: workspaceName(ws), Org: "default", WorkspaceID: wid, OrgID: "default"}, "failed", "prepare_failed")
					state.updateWorkspaceStatus(email, wid, workspaceName(ws), "failed", "prepare_failed")
					return
				}
			}
			spaceResults := runWorkspaceFlow(ctx, cfg, factory, prepWS, ws)
			for _, item := range spaceResults {
				if strings.TrimSpace(item.Tokens.AccessToken) == "" {
					continue
				}
				mu.Lock()
				if _, ok := seenTokens[item.Tokens.AccessToken]; ok {
					mu.Unlock()
					continue
				}
				seenTokens[item.Tokens.AccessToken] = struct{}{}
				results = append(results, item)
				mu.Unlock()
				if onResult != nil {
					onResult(item)
				}
			}
		}()
	}
	wg.Wait()
	status.TokenCount = len(results)
	if len(results) == 0 && !status.AccountBanned {
		if res, handled := fallbackSingleOAuth(ctx, cfg, factory, email, password, mailClient, onResult, status); handled {
			return res, status
		}
	}
	return results, status
}

func workspaceName(ws map[string]any) string {
	return firstString(toString(ws["name"]), toString(ws["title"]), toString(ws["id"]))
}

func runWorkspaceFlow(ctx context.Context, cfg *Config, factory *ClientFactory, prep *OAuthPrepare, workspace map[string]any) []SpaceResult {
	results := make([]SpaceResult, 0)
	wid := toString(workspace["id"])
	wname := workspaceName(workspace)
	code := exchangeWorkspaceSelection(ctx, cfg, prep.Session, prep.DeviceID, prep.CodeVerifier, prep.ConsentURL, workspace, &results)
	if code != "" {
		if tokens, err := codexExchangeCode(ctx, cfg, factory, code, prep.CodeVerifier); err == nil {
			results = append(results, SpaceResult{Workspace: wname, Org: "default", WorkspaceID: wid, OrgID: "default", Tokens: tokens})
		}
	}
	return results
}

func exchangeWorkspaceSelection(ctx context.Context, cfg *Config, sess *Session, deviceID, codeVerifier, consentURL string, workspace map[string]any, results *[]SpaceResult) string {
	wid := toString(workspace["id"])
	wname := workspaceName(workspace)
	headers := BuildCommonHeaders(sess.Profile, consentURL, cfg.OAuthIssuer, "same-origin")
	headers["oai-device-id"] = deviceID
	for k, v := range GenerateDatadogTrace() {
		headers[k] = v
	}
	req, _ := sess.NewJSONRequest(ctx, "POST", cfg.OAuthIssuer+"/api/accounts/workspace/select", map[string]any{"workspace_id": wid}, headers)
	resp, body, err := DoRequestNoRedirect(req, sess.Client)
	if err != nil {
		return ""
	}
	if isRedirect(resp.StatusCode) {
		return extractCodeFromURL(resp.Header.Get("Location"))
	}
	if resp.StatusCode != 200 {
		return ""
	}
	var wsData map[string]any
	_ = json.Unmarshal(body, &wsData)
	orgs := sliceOfMaps(asMap(wsData["data"])["orgs"])
	wsNext := toString(wsData["continue_url"])
	if len(orgs) == 0 {
		if wsNext != "" {
			fullNext := wsNext
			if strings.HasPrefix(fullNext, "/") {
				fullNext = cfg.OAuthIssuer + fullNext
			}
			return followAndExtractCode(ctx, sess, fullNext, cfg.OAuthIssuer, 10)
		}
		return ""
	}
	for _, org := range orgs {
		orgID := toString(org["id"])
		orgName := firstString(toString(org["name"]), toString(org["title"]), orgID)
		projects := sliceOfMaps(org["projects"])
		if len(projects) == 0 {
			projects = []map[string]any{{}}
		}
		for _, project := range projects {
			bodyOrg := map[string]any{"org_id": orgID}
			projectID := toString(project["id"])
			projectName := firstString(toString(project["name"]), toString(project["title"]))
			if projectID != "" {
				bodyOrg["project_id"] = projectID
			}
			orgRef := consentURL
			if wsNext != "" {
				orgRef = wsNext
				if strings.HasPrefix(orgRef, "/") {
					orgRef = cfg.OAuthIssuer + orgRef
				}
			}
			headersOrg := BuildCommonHeaders(sess.Profile, orgRef, cfg.OAuthIssuer, "same-origin")
			headersOrg["oai-device-id"] = deviceID
			for k, v := range GenerateDatadogTrace() {
				headersOrg[k] = v
			}
			reqOrg, _ := sess.NewJSONRequest(ctx, "POST", cfg.OAuthIssuer+"/api/accounts/organization/select", bodyOrg, headersOrg)
			respOrg, bodyOrgResp, err := DoRequestNoRedirect(reqOrg, sess.Client)
			if err != nil {
				continue
			}
			code := ""
			if isRedirect(respOrg.StatusCode) {
				code = extractCodeFromURL(respOrg.Header.Get("Location"))
				if code == "" {
					code = followAndExtractCode(ctx, sess, respOrg.Header.Get("Location"), cfg.OAuthIssuer, 10)
				}
			} else if respOrg.StatusCode == 200 {
				var dataOrg map[string]any
				_ = json.Unmarshal(bodyOrgResp, &dataOrg)
				next := toString(dataOrg["continue_url"])
				if next != "" {
					if strings.HasPrefix(next, "/") {
						next = cfg.OAuthIssuer + next
					}
					code = followAndExtractCode(ctx, sess, next, cfg.OAuthIssuer, 10)
				}
			}
			if code != "" {
				if tokens, err := codexExchangeCode(ctx, cfg, nil, code, codeVerifier); err == nil {
					*results = append(*results, SpaceResult{Workspace: wname, Org: orgName, Project: projectName, WorkspaceID: wid, OrgID: orgID, ProjectID: projectID, Tokens: tokens})
				}
			}
		}
	}
	return ""
}

func isRedirect(status int) bool {
	return status == 301 || status == 302 || status == 303 || status == 307 || status == 308
}

func sliceOfMaps(v any) []map[string]any {
	out := make([]map[string]any, 0)
	switch x := v.(type) {
	case []any:
		for _, it := range x {
			if m, ok := it.(map[string]any); ok {
				out = append(out, m)
			}
		}
	case []map[string]any:
		out = append(out, x...)
	}
	return out
}

func extractCodeFromURL(raw string) string {
	if !strings.Contains(raw, "code=") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Query().Get("code")
}

func followAndExtractCode(ctx context.Context, sess *Session, rawURL, issuer string, maxDepth int) string {
	if maxDepth <= 0 || strings.TrimSpace(rawURL) == "" {
		return ""
	}
	if strings.HasPrefix(rawURL, "/") {
		rawURL = issuer + rawURL
	}
	req, _ := sess.NewRequest(ctx, "GET", rawURL, nil, BuildNavigateHeaders(sess.Profile, "", "same-origin"))
	resp, _, err := DoRequestNoRedirect(req, sess.Client)
	if err != nil {
		return ""
	}
	if isRedirect(resp.StatusCode) {
		loc := resp.Header.Get("Location")
		if code := extractCodeFromURL(loc); code != "" {
			return code
		}
		return followAndExtractCode(ctx, sess, loc, issuer, maxDepth-1)
	}
	if resp.Request != nil {
		return extractCodeFromURL(resp.Request.URL.String())
	}
	return ""
}

func decodeAuthSessionForWorkspaces(sess *Session) map[string]any {
	val := getCookieValue(sess, OpenAIAuthBase, "oai-client-auth-session")
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ".")
	first := parts[0]
	if pad := len(first) % 4; pad != 0 {
		first += strings.Repeat("=", 4-pad)
	}
	raw, err := base64.URLEncoding.DecodeString(first)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return nil
		}
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

func extractWorkspaces(sessionData map[string]any) []map[string]any {
	if sessionData == nil {
		return nil
	}
	return sliceOfMaps(sessionData["workspaces"])
}

func codexExchangeCode(ctx context.Context, cfg *Config, factory *ClientFactory, code, codeVerifier string) (Tokens, error) {
	var sess *Session
	if factory != nil {
		sess = factory.NewSession(true)
	} else {
		sess = &Session{Client: &http.Client{Timeout: 30 * time.Second}, Profile: HardcodedBrowserProfile}
	}
	payload := url.Values{}
	payload.Set("grant_type", "authorization_code")
	payload.Set("client_id", cfg.OAuthClientID)
	payload.Set("redirect_uri", cfg.OAuthRedirectURI)
	payload.Set("code", code)
	payload.Set("code_verifier", codeVerifier)
	headers := map[string]string{"content-type": "application/x-www-form-urlencoded", "accept": "application/json", "user-agent": HardcodedBrowserProfile.UserAgent}
	req, _ := sess.NewRequest(ctx, "POST", cfg.OAuthIssuer+"/oauth/token", []byte(payload.Encode()), headers)
	resp, body, err := DoRequest(req, sess.Client)
	if err != nil {
		return Tokens{}, err
	}
	if resp.StatusCode != 200 {
		return Tokens{}, fmt.Errorf("oauth/token 失败: %d %s", resp.StatusCode, truncate(string(body), 200))
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: toString(data["access_token"]), RefreshToken: toString(data["refresh_token"]), IDToken: toString(data["id_token"])}, nil
}
