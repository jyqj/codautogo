package codex

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Runner struct {
	cfg           *Config
	factory       *ClientFactory
	state         *StateStore
	tabmail       *TabMailService
	cfProviders   []*CFWorkerMailProvider
	stats         *StatsCollector
	cooldown      *CooldownGate
	maintainMu    sync.Mutex
	maintainState MaintainState
}

func (r *Runner) SetStats(s *StatsCollector) { r.stats = s }
func (r *Runner) Stats() *StatsCollector     { return r.stats }
func (r *Runner) Cfg() *Config               { return r.cfg }

type RunResult struct {
	Email         string
	OK            bool
	SpacesOK      int
	SpacesSkipped int
}

type TempMailbox struct {
	Email         string
	Provider      string
	Token         string
	MailConfigKey string
}

type MaintainState struct {
	OauthPoolActive bool          `json:"oauth_pool_active"`
	CandidatesCount int           `json:"available_candidates"`
	MinCandidates   int           `json:"min_candidates"`
	PendingCount    int           `json:"pending_count"`
	LastCheckTime   time.Time     `json:"-"`
	NextCheckAfter  time.Duration `json:"-"`
	LoopRound       int           `json:"loop_round"`
	CompletedCount  int           `json:"completed"`
	TotalTarget     int           `json:"total"`
	Message         string        `json:"message"`
}

func NewRunner(cfg *Config) *Runner {
	factory := NewClientFactory(cfg)
	runner := &Runner{
		cfg:         cfg,
		factory:     factory,
		state:       NewStateStore(cfg, factory),
		tabmail:     NewTabMailService(cfg, factory),
		cfProviders: BuildCFMailProviders(cfg, factory),
		cooldown:    NewCooldownGate(cfg.FailureCooldownAfter, time.Duration(cfg.FailureCooldownSec*float64(time.Second))),
	}
	runner.maintainState = MaintainState{
		MinCandidates: cfg.MinCandidates,
		Message:       "等待维护任务启动",
	}
	runner.updateMaintainState(0, false)
	return runner
}

func (r *Runner) MaintainStateSnapshot() MaintainState {
	r.maintainMu.Lock()
	defer r.maintainMu.Unlock()
	snap := r.maintainState
	return snap
}

func (r *Runner) updateMaintainState(candidates int, oauthActive bool) {
	r.maintainMu.Lock()
	r.maintainState.OauthPoolActive = oauthActive
	r.maintainState.CandidatesCount = maxInt(0, candidates)
	r.maintainState.MinCandidates = r.cfg.MinCandidates
	if r.state != nil {
		r.maintainState.PendingCount = r.state.PendingQueueLength()
	}
	r.maintainMu.Unlock()
}

func (r *Runner) updateMaintainMessage(msg string) {
	r.maintainMu.Lock()
	r.maintainState.Message = strings.TrimSpace(msg)
	r.maintainMu.Unlock()
}

func (r *Runner) updateLoopRound(round int) {
	r.maintainMu.Lock()
	r.maintainState.LoopRound = maxInt(0, round)
	r.maintainMu.Unlock()
}

func (r *Runner) updateMaintainSleep(d time.Duration) {
	r.maintainMu.Lock()
	if d <= 0 {
		r.maintainState.LastCheckTime = time.Time{}
		r.maintainState.NextCheckAfter = 0
	} else {
		r.maintainState.LastCheckTime = time.Now()
		r.maintainState.NextCheckAfter = d
	}
	r.maintainMu.Unlock()
}

func (r *Runner) updateMaintainProgress(completed, total int) {
	if completed < 0 {
		completed = 0
	}
	if total < 0 {
		total = 0
	}
	r.maintainMu.Lock()
	r.maintainState.CompletedCount = completed
	r.maintainState.TotalTarget = total
	r.maintainMu.Unlock()
}

func (r *Runner) createMailboxWithFallback(ctx context.Context, tag string) (TempMailbox, TempMailProvider, error) {
	var errs []string
	if r.tabmail != nil && r.tabmail.Configured() {
		email, token, err := r.tabmail.CreateTempEmail(ctx)
		if err == nil && strings.TrimSpace(email) != "" {
			return TempMailbox{
				Email:    strings.TrimSpace(email),
				Provider: "tabmail",
				Token:    strings.TrimSpace(token),
			}, r.tabmail, nil
		}
		fmt.Printf("%s ⚠️ tabmail 创建邮箱失败: %v\n", tag, err)
		errs = append(errs, fmt.Sprintf("tabmail: %v", err))
	} else {
		errs = append(errs, "tabmail: 未配置")
	}

	for idx, provider := range r.cfProviders {
		if provider == nil || !provider.Configured() {
			continue
		}
		email, token, err := provider.CreateTempEmail(ctx)
		if err == nil && strings.TrimSpace(email) != "" {
			fmt.Printf("%s ✅ 邮箱 fallback 成功，切换到 cfmail[%s]: %s\n", tag, provider.Key(), email)
			return TempMailbox{
				Email:         strings.TrimSpace(email),
				Provider:      "cfmail",
				Token:         strings.TrimSpace(token),
				MailConfigKey: provider.Key(),
			}, provider, nil
		}
		fmt.Printf("%s ⚠️ cfmail[%s] 创建邮箱失败: %v\n", tag, provider.Key(), err)
		errs = append(errs, fmt.Sprintf("cfmail[%s]: %v", provider.Key(), err))
		if idx == len(r.cfProviders)-1 {
			continue
		}
	}
	return TempMailbox{}, nil, fmt.Errorf("创建临时邮箱失败（%s）", strings.Join(errs, "; "))
}

func (r *Runner) buildOAuthOTPClient(email, cfToken, cfConfigKey string) OTPClient {
	return BuildOAuthOTPClient(r.cfg, r.factory, email, cfToken, cfConfigKey)
}

// registerAccount creates a temp email, registers the account, and saves credentials.
// Returns (mailbox, password, regTime, ok). If ok is false and mailbox.Email is empty,
// temp email creation failed; if email is set, registration itself failed.
func (r *Runner) registerAccount(ctx context.Context, tag string, start time.Time) (mailbox TempMailbox, password string, regTime float64, ok bool) {
	var err error
	var provider TempMailProvider
	mailbox, provider, err = r.createMailboxWithFallback(ctx, tag)
	if err != nil || mailbox.Email == "" {
		fmt.Printf("%s ❌ 创建临时邮箱失败: %v\n", tag, err)
		return
	}
	if provider == nil {
		fmt.Printf("%s ❌ 邮箱提供商不可用: %s\n", tag, mailbox.Provider)
		return
	}
	password = GenerateRandomPassword(16)
	ok = NewRegistrar(r.cfg, r.factory).Register(ctx, mailbox.Email, password, provider, mailbox.Token)
	_ = r.state.SaveAccount(mailbox.Email, password)
	regTime = time.Since(start).Seconds()
	return
}

func (r *Runner) RegisterOne(ctx context.Context, workerID int) (string, string, bool, float64, float64) {
	tag := ""
	if r.cfg.ConcurrentWorkers > 1 {
		tag = fmt.Sprintf("[W%d]", workerID)
	}
	// 等待链路冷却
	if r.cooldown != nil {
		r.cooldown.WaitForAvailability()
	}
	start := time.Now()
	mailbox, password, regTime, ok := r.registerAccount(ctx, tag, start)
	if mailbox.Email == "" {
		if r.stats != nil {
			r.stats.RecordRegFailure(FailMailCreate)
		}
		r.noteFailure("mail_create", "", "邮箱创建失败")
		return "", "", false, 0, 0
	}
	if !ok {
		if r.stats != nil {
			r.stats.RecordRegFailure(FailRegister)
		}
		r.noteFailure("register", mailbox.Email, "注册失败")
		return mailbox.Email, password, false, regTime, regTime
	}
	if r.stats != nil {
		r.stats.RecordRegSuccess()
	}
	fmt.Printf("  📝 注册耗时: %.1fs\n", regTime)
	loginMail := r.buildOAuthOTPClient(mailbox.Email, mailbox.Token, mailbox.MailConfigKey)
	submit, waitFn := r.state.CreateAccountStreamRecorder(ctx, mailbox.Email, tag)
	results, status := PerformOAuthLoginHTTPAllSpaces(ctx, r.cfg, r.factory, r.state, mailbox.Email, password, loginMail, submit)
	recStats := waitFn()
	if status.AccountBanned {
		r.state.markAccountBanned(mailbox.Email)
		fmt.Printf("%s 🚫 %s | 账号已被封禁/停用，跳过全部空间\n", tag, mailbox.Email)
		if r.stats != nil {
			r.stats.RecordOAuthFailure(FailAccountBanned)
		}
		return mailbox.Email, password, false, regTime, time.Since(start).Seconds()
	}
	totalTime := time.Since(start).Seconds()
	if len(results) > 0 {
		fmt.Printf("%s ✅ %s | token %d 组 | 录入成功 %d | 跳过 %d | 注册 %.1fs + OAuth %.1fs = 总 %.1fs\n", tag, mailbox.Email, len(results), recStats["ok"], recStats["skipped"], regTime, totalTime-regTime, totalTime)
		r.noteSuccess()
		if r.stats != nil {
			r.stats.RecordOAuthSuccess()
			r.stats.RecordTiming(AccountTiming{
				Email:        mailbox.Email,
				RegSeconds:   regTime,
				OAuthSeconds: totalTime - regTime,
				TotalSeconds: totalTime,
				Timestamp:    NowLocalString(),
			})
		}
	} else if status.AllSkipped {
		fmt.Printf("%s ✅ %s | 当前账号空间均已录入，全部跳过\n", tag, mailbox.Email)
		if r.stats != nil {
			r.stats.RecordOAuthSuccess()
		}
	} else {
		fmt.Printf("%s ⚠️ OAuth 失败（注册已成功）\n", tag)
		if r.stats != nil {
			r.stats.RecordOAuthFailure(FailOAuthError)
		}
		r.noteFailure("oauth", mailbox.Email, "oauth_all_failed")
	}
	return mailbox.Email, password, true, regTime, totalTime
}

func (r *Runner) RegisterOnly(ctx context.Context, workerID int) (string, string, bool, float64) {
	tag := ""
	if r.cfg.RegisterWorkers > 1 {
		tag = fmt.Sprintf("[R%d]", workerID)
	}
	start := time.Now()
	mailbox, password, regTime, ok := r.registerAccount(ctx, tag, start)
	if mailbox.Email == "" {
		if r.stats != nil {
			r.stats.RecordRegFailure(FailMailCreate)
		}
		return "", "", false, 0
	}
	if !ok {
		if r.stats != nil {
			r.stats.RecordRegFailure(FailRegister)
		}
		return mailbox.Email, password, false, regTime
	}
	if r.stats != nil {
		r.stats.RecordRegSuccess()
	}
	if err := r.state.EnqueuePending(mailbox.Email, password, mailbox.Provider, mailbox.Token, mailbox.MailConfigKey); err != nil {
		fmt.Printf("%s ⚠️ 入队失败: %v\n", tag, err)
	}
	if mailbox.MailConfigKey != "" {
		fmt.Printf("%s ✅ 注册完成 → 入队: %s [%s:%s] (%.1fs)\n", tag, mailbox.Email, mailbox.Provider, mailbox.MailConfigKey, regTime)
	} else {
		fmt.Printf("%s ✅ 注册完成 → 入队: %s [%s] (%.1fs)\n", tag, mailbox.Email, mailbox.Provider, regTime)
	}
	return mailbox.Email, password, true, regTime
}

func (r *Runner) OAuthOne(ctx context.Context, workerID int, email, password, cfToken, cfConfigKey string) bool {
	tag := fmt.Sprintf("[O%d]", workerID)
	start := time.Now()
	if r.state.isAccountBanned(email) {
		fmt.Printf("%s 🚫 %s 已封禁，跳过\n", tag, email)
		r.state.MarkPendingDone(email, "failed")
		if r.stats != nil {
			r.stats.RecordOAuthFailure(FailAccountBanned)
		}
		return false
	}
	mailClient := r.buildOAuthOTPClient(email, cfToken, cfConfigKey)
	submit, waitFn := r.state.CreateAccountStreamRecorder(ctx, email, tag)
	results, status := PerformOAuthLoginHTTPAllSpaces(ctx, r.cfg, r.factory, r.state, email, password, mailClient, submit)
	recStats := waitFn()
	if status.AccountBanned {
		r.state.markAccountBanned(email)
		r.state.MarkPendingDone(email, "failed")
		fmt.Printf("%s 🚫 %s | 账号已被封禁/停用\n", tag, email)
		if r.stats != nil {
			r.stats.RecordOAuthFailure(FailAccountBanned)
		}
		return false
	}
	oauthTime := time.Since(start).Seconds()
	if len(results) > 0 {
		r.state.MarkPendingDone(email, "done")
		fmt.Printf("%s ✅ %s | token %d 组 | 录入 %d | 跳过 %d | OAuth %.1fs\n", tag, email, len(results), recStats["ok"], recStats["skipped"], oauthTime)
		if r.stats != nil {
			r.stats.RecordOAuthSuccess()
			r.stats.RecordTiming(AccountTiming{
				Email:        email,
				OAuthSeconds: oauthTime,
				TotalSeconds: oauthTime,
				Timestamp:    NowLocalString(),
			})
		}
		return true
	}
	if status.AllSkipped {
		r.state.MarkPendingDone(email, "done")
		fmt.Printf("%s ✅ %s | 空间均已录入，全部跳过\n", tag, email)
		if r.stats != nil {
			r.stats.RecordOAuthSuccess()
		}
		return true
	}
	r.state.MarkPendingDone(email, "failed")
	fmt.Printf("%s ⚠️ %s | OAuth 失败 (%.1fs)\n", tag, email, oauthTime)
	if r.stats != nil {
		r.stats.RecordOAuthFailure(FailOAuthError)
	}
	return false
}

func (r *Runner) RunDualPool(ctx context.Context) {
	batchStart := time.Now()
	regWorkers := maxInt(1, r.cfg.RegisterWorkers)
	oauthWorkers := maxInt(1, r.cfg.OAuthWorkers)
	delaySeconds := r.cfg.OAuthDelaySeconds

	fmt.Printf("\n🚀 双池模式 — %d 个账号 | 注册池 %d 并发 | OAuth 池 %d 并发 | OAuth 延迟 %ds | 邮箱 %s\n",
		r.cfg.TotalAccounts, regWorkers, oauthWorkers, delaySeconds, DescribeMailProviderChain(r.cfg))

	var regOK, regFail int
	var oauthOK, oauthFail int
	var mu sync.Mutex
	regDone := make(chan struct{})

	// ──── 注册池 ────
	go func() {
		defer close(regDone)
		sem := make(chan struct{}, regWorkers)
		var wg sync.WaitGroup
		for i := 0; i < r.cfg.TotalAccounts; i++ {
			wg.Add(1)
			workerID := (i % regWorkers) + 1
			i := i
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				if i > 0 {
					time.Sleep(time.Duration(workerID) * time.Second)
				}
				_, _, ok, _ := r.RegisterOnly(ctx, workerID)
				mu.Lock()
				if ok {
					regOK++
				} else {
					regFail++
				}
				done := regOK + regFail
				fmt.Printf("📊 注册池: %d/%d | ✅%d ❌%d\n", done, r.cfg.TotalAccounts, regOK, regFail)
				mu.Unlock()
			}()
		}
		wg.Wait()
	}()

	// ──── OAuth 池 ────
	// 启动前等一会让注册池先产出一些账号
	initialDelay := maxInt(5, delaySeconds)
	fmt.Printf("⏳ OAuth 池将在 %ds 后启动...\n", initialDelay)
	time.Sleep(time.Duration(initialDelay) * time.Second)

	oauthDone := make(chan struct{})
	go func() {
		defer close(oauthDone)
		sem := make(chan struct{}, oauthWorkers)
		var wg sync.WaitGroup
		workerCounter := 0
		for {
			account := r.state.DequeuePending()
			if account != nil {
				wg.Add(1)
				workerCounter++
				wid := (workerCounter % oauthWorkers) + 1
				go func(acc PendingAccount, wid int) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					if delaySeconds > 0 {
						time.Sleep(time.Duration(delaySeconds) * time.Second)
					}
					ok := r.OAuthOne(ctx, wid, acc.Email, acc.Password, acc.MailToken, acc.MailConfigKey)
					mu.Lock()
					if ok {
						oauthOK++
					} else {
						oauthFail++
					}
					fmt.Printf("📊 OAuth 池: ✅%d ❌%d\n", oauthOK, oauthFail)
					mu.Unlock()
				}(*account, wid)
				continue
			}
			// 没有 pending 的了
			select {
			case <-regDone:
				// 注册池结束，最后再扫一遍
				for {
					acc := r.state.DequeuePending()
					if acc == nil {
						break
					}
					wg.Add(1)
					workerCounter++
					wid := (workerCounter % oauthWorkers) + 1
					go func(a PendingAccount, w int) {
						defer wg.Done()
						sem <- struct{}{}
						defer func() { <-sem }()
						if delaySeconds > 0 {
							time.Sleep(time.Duration(delaySeconds) * time.Second)
						}
						ok := r.OAuthOne(ctx, w, a.Email, a.Password, a.MailToken, a.MailConfigKey)
						mu.Lock()
						if ok {
							oauthOK++
						} else {
							oauthFail++
						}
						mu.Unlock()
					}(*acc, wid)
				}
				wg.Wait()
				return
			default:
				time.Sleep(2 * time.Second)
			}
		}
	}()

	<-oauthDone
	elapsed := time.Since(batchStart).Seconds()
	fmt.Printf("\n🏁 双池完成: 注册 ✅%d ❌%d | OAuth ✅%d ❌%d | 总耗时 %.1fs\n", regOK, regFail, oauthOK, oauthFail, elapsed)
	if oauthOK > 0 {
		fmt.Printf("   吞吐: %.1fs/个\n", elapsed/float64(oauthOK))
	}
}

func (r *Runner) RunBatch(ctx context.Context) {
	workers := maxInt(1, r.cfg.ConcurrentWorkers)
	batchStart := time.Now()
	fmt.Printf("\n🚀 Go 协议注册机 — %d 个账号 | 并发 %d | 邮箱 %s\n", r.cfg.TotalAccounts, workers, DescribeMailProviderChain(r.cfg))
	okCount := 0
	failCount := 0
	regTimes := make([]float64, 0)
	totalTimes := make([]float64, 0)
	var mu sync.Mutex
	if workers == 1 {
		for i := 0; i < r.cfg.TotalAccounts; i++ {
			_, _, ok, tReg, tTotal := r.RegisterOne(ctx, 0)
			if ok {
				okCount++
				regTimes = append(regTimes, tReg)
				totalTimes = append(totalTimes, tTotal)
			} else {
				failCount++
			}
			fmt.Printf("📊 %d/%d | ✅%d ❌%d | 已用 %.0fs\n", i+1, r.cfg.TotalAccounts, okCount, failCount, time.Since(batchStart).Seconds())
			if i < r.cfg.TotalAccounts-1 {
				time.Sleep(time.Duration(3+taskIndexMod(i, 5)) * time.Second)
			}
		}
	} else {
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		for i := 0; i < r.cfg.TotalAccounts; i++ {
			wg.Add(1)
			i := i
			workerID := (i % workers) + 1
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				if i > 0 {
					time.Sleep(time.Duration(workerID) * time.Second)
				}
				_, _, ok, tReg, tTotal := r.RegisterOne(ctx, workerID)
				mu.Lock()
				if ok {
					okCount++
					regTimes = append(regTimes, tReg)
					totalTimes = append(totalTimes, tTotal)
				} else {
					failCount++
				}
				done := okCount + failCount
				fmt.Printf("📊 %d/%d | ✅%d ❌%d | 已用 %.0fs\n", done, r.cfg.TotalAccounts, okCount, failCount, time.Since(batchStart).Seconds())
				mu.Unlock()
			}()
		}
		wg.Wait()
	}
	elapsed := time.Since(batchStart).Seconds()
	avgReg := avgFloat(regTimes)
	avgTotal := avgFloat(totalTimes)
	throughput := 0.0
	if okCount > 0 {
		throughput = elapsed / float64(okCount)
	}
	fmt.Printf("\n🏁 完成: ✅%d ❌%d | 总耗时 %.1fs | 吞吐 %.1fs/个 | 单号(注册 %.1fs + OAuth %.1fs = %.1fs)\n", okCount, failCount, elapsed, throughput, avgReg, avgTotal-avgReg, avgTotal)
}

func (r *Runner) ProcessSpecifiedEmail(ctx context.Context, email string, skipRegister bool, passwordOverride string, forceRefresh bool) RunResult {
	password := passwordOverride
	if password == "" {
		parts := strings.Split(email, "@")
		password = parts[0]
	}
	fmt.Println("\n============================================================")
	fmt.Println("  指定邮箱模式（Go）")
	fmt.Println("============================================================")
	fmt.Printf("  📧 邮箱: %s\n", email)
	fmt.Printf("  🔑 密码: %s\n", password)
	fmt.Printf("  ⏭️ 跳过注册: %v\n", skipRegister)
	if r.state.isAccountBanned(email) {
		fmt.Printf("  🚫 账号已被封禁/停用（已记录），跳过: %s\n", email)
		return RunResult{Email: email}
	}
	if !forceRefresh {
		if done, st := r.state.accountRecordedAll(email); done {
			fmt.Printf("  ⏭️ 账号已全部录入，整账号跳过（%s）\n", toString(st["detail"]))
			return RunResult{Email: email, OK: true}
		}
	}
	mailClient := r.buildOAuthOTPClient(email, "", "")
	if mailClient == nil {
		fmt.Printf("❌ 初始化邮箱客户端失败: 无可用邮箱链路（%s）\n", DescribeMailProviderChain(r.cfg))
		return RunResult{Email: email}
	}
	_ = r.state.SaveAccount(email, password)
	if !skipRegister {
		if !RegisterAccountWithOTPClient(ctx, r.cfg, r.factory, email, password, mailClient) {
			fmt.Println("  ⚠️ 注册失败，继续尝试登录录入")
		}
		time.Sleep(3 * time.Second)
	}
	submit, waitFn := r.state.CreateAccountStreamRecorder(ctx, email, "")
	results, status := PerformOAuthLoginHTTPAllSpaces(ctx, r.cfg, r.factory, r.state, email, password, mailClient, submit)
	stats := waitFn()
	if status.AccountBanned {
		r.state.markAccountBanned(email)
		fmt.Printf("🚫 账号已被封禁/停用，跳过: %s\n", email)
		return RunResult{Email: email}
	}
	if len(results) > 0 {
		fmt.Printf("✅ 完成: %s（token %d 组，录入成功 %d，跳过 %d）\n", email, len(results), stats["ok"], stats["skipped"])
		return RunResult{Email: email, OK: true, SpacesOK: stats["ok"], SpacesSkipped: stats["skipped"]}
	}
	if status.AllSkipped {
		fmt.Printf("✅ 完成: %s（workspace 均已录入，全部跳过）\n", email)
		return RunResult{Email: email, OK: true, SpacesSkipped: status.WorkspaceTotal}
	}
	_, tokens, marker, err := PerformOAuthLoginHTTP(ctx, r.cfg, r.factory, email, password, mailClient, false)
	if marker == "ACCOUNT_BANNED" {
		r.state.markAccountBanned(email)
		fmt.Printf("🚫 账号已被封禁/停用，跳过: %s\n", email)
		return RunResult{Email: email}
	}
	if err == nil && tokens != nil {
		_, _ = r.state.SaveTokens(ctx, email, *tokens)
		fmt.Printf("✅ 完成: %s\n", email)
		return RunResult{Email: email, OK: true, SpacesOK: 1}
	}
	fmt.Printf("❌ 登录或录入失败: %s\n", email)
	return RunResult{Email: email}
}

func BuildTeamRangeEmails(teamStart, teamEnd, perTeam, qiumingStart int, emailDomain string) []string {
	out := make([]string, 0)
	domain := "tabcode.edu.kg"
	if strings.TrimSpace(emailDomain) == "tabmail" {
		domain = "tabcode.edu.kg"
	}
	for teamNo := teamStart; teamNo <= teamEnd; teamNo++ {
		for idx := qiumingStart; idx < qiumingStart+perTeam; idx++ {
			out = append(out, fmt.Sprintf("qiuming%dteam%d@%s", idx, teamNo, domain))
		}
	}
	return out
}

func ParseTeamRange(raw string) (int, int, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return 0, 0, fmt.Errorf("team-range 不能为空")
	}
	if strings.Contains(text, "-") {
		parts := strings.SplitN(text, "-", 2)
		var a, b int
		fmt.Sscanf(strings.TrimSpace(parts[0]), "%d", &a)
		fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &b)
		if a > b {
			a, b = b, a
		}
		return a, b, nil
	}
	var v int
	fmt.Sscanf(text, "%d", &v)
	return v, v, nil
}

func (r *Runner) RunSpecifiedEmailsBatch(ctx context.Context, emails []string, skipRegister bool, workers int, forceRefresh bool, emailDomain string) []RunResult {
	workers = minInt(maxInt(1, workers), len(emails))
	results := make([]RunResult, 0, len(emails))
	fmt.Println("\n============================================================")
	fmt.Println("  区间批量录入模式（Go）")
	fmt.Println("============================================================")
	fmt.Printf("  总邮箱数: %d\n", len(emails))
	fmt.Printf("  账号并发: %d\n", workers)
	fmt.Printf("  邮箱域名: %s\n", emailDomain)
	fmt.Printf("  workspace 登录并发(单账号内): %d\n", r.cfg.WorkspaceLoginWorkers)
	fmt.Printf("  空间录入并发(单账号内): %d\n", r.cfg.WorkspaceRecordWorkers)
	var mu sync.Mutex
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, email := range emails {
		wg.Add(1)
		email := email
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := r.ProcessSpecifiedEmail(ctx, email, skipRegister, "", forceRefresh)
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}()
	}
	wg.Wait()
	okCount := 0
	totalSpacesOK := 0
	totalSpacesSkipped := 0
	for _, item := range results {
		if item.OK {
			okCount++
		}
		totalSpacesOK += item.SpacesOK
		totalSpacesSkipped += item.SpacesSkipped
	}
	fmt.Printf("\n🏁 区间批量完成: ✅%d ❌%d / 总 %d 个账号\n", okCount, len(results)-okCount, len(results))
	fmt.Printf("   📊 本次空间录入: %d 个成功, %d 个跳过(已录入)\n", totalSpacesOK, totalSpacesSkipped)
	return results
}

func avgFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func taskIndexMod(i, mod int) int {
	if mod <= 0 {
		return 0
	}
	return i % mod
}

// ──────────────── 维护模式 ────────────────

func (r *Runner) CPAClient() *CPAClient {
	return NewCPAClient(r.cfg, r.factory)
}

func (r *Runner) RunMaintainOnce(ctx context.Context) {
	cpa := r.CPAClient()
	if strings.TrimSpace(cpa.BaseURL) == "" || strings.TrimSpace(cpa.Token) == "" {
		r.updateMaintainProgress(0, 0)
		r.updateMaintainState(0, false)
		r.updateMaintainSleep(0)
		r.updateMaintainMessage("CPA 未配置 clean.base_url 或 clean.token，无法执行单次维护")
		fmt.Println("❌ CPA 未配置 clean.base_url 或 clean.token")
		return
	}

	r.updateMaintainSleep(0)
	r.updateMaintainProgress(0, 0)
	r.updateMaintainState(0, false)
	r.updateMaintainMessage("开始单次维护：清理无效账号...")

	summary := r.RunClean401(ctx)
	if summary == nil {
		r.updateMaintainMessage("单次维护失败：清理阶段未完成")
		r.updateMaintainState(0, false)
		return
	}

	r.updateMaintainMessage("清理完成，正在查询 CPA 库存...")
	_, candidates, err := cpa.GetCandidatesCount(ctx, r.cfg.CPATargetType)
	if err != nil {
		r.updateMaintainMessage(fmt.Sprintf("查询 CPA 库存失败: %v", err))
		r.updateMaintainState(0, false)
		fmt.Printf("❌ 查询 CPA 库存失败: %v\n", err)
		return
	}

	r.updateMaintainState(candidates, false)
	if candidates >= r.cfg.MinCandidates {
		r.updateMaintainProgress(0, 0)
		r.updateMaintainMessage(fmt.Sprintf("库存充足 (%d >= %d)，本轮无需补号", candidates, r.cfg.MinCandidates))
		fmt.Printf("✅ 单次维护完成：库存充足 (%d >= %d)\n", candidates, r.cfg.MinCandidates)
		return
	}

	gap := r.cfg.MinCandidates - candidates
	initialPending := 0
	if r.state != nil {
		initialPending = r.state.PendingQueueLength()
	}
	regTarget := gap - initialPending
	if regTarget < 0 {
		regTarget = 0
	}

	r.updateMaintainProgress(0, gap)
	r.updateMaintainState(candidates, true)
	if initialPending > 0 {
		r.updateMaintainMessage(fmt.Sprintf("库存不足 (%d < %d)，正在补号；优先消费现有队列 %d 个", candidates, r.cfg.MinCandidates, initialPending))
	} else {
		r.updateMaintainMessage(fmt.Sprintf("库存不足 (%d < %d)，正在补号...", candidates, r.cfg.MinCandidates))
	}
	fmt.Printf("\n🚀 单次维护模式\n")
	fmt.Printf("   当前库存: %d/%d | 缺口=%d | 队列现存=%d | 本轮新增注册=%d\n", candidates, r.cfg.MinCandidates, gap, initialPending, regTarget)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var progressMu sync.Mutex
	completed := 0
	approxCandidates := candidates
	progressSnapshot := func() (int, int) {
		progressMu.Lock()
		defer progressMu.Unlock()
		return completed, approxCandidates
	}
	markProgress := func(success bool) bool {
		progressMu.Lock()
		if success && completed < gap {
			completed++
			approxCandidates = candidates + completed
		}
		done := completed >= gap
		currentCompleted := completed
		currentCandidates := approxCandidates
		progressMu.Unlock()
		r.updateMaintainProgress(currentCompleted, gap)
		r.updateMaintainState(currentCandidates, true)
		return done
	}

	regDone := make(chan struct{})
	go func() {
		defer close(regDone)
		if regTarget <= 0 {
			return
		}
		workers := maxInt(1, minInt(r.cfg.RegisterWorkers, regTarget))
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
	registerLoop:
		for i := 0; i < regTarget; i++ {
			select {
			case <-runCtx.Done():
				break registerLoop
			default:
			}
			wg.Add(1)
			sem <- struct{}{}
			workerID := (i % workers) + 1
			taskIndex := i
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				if taskIndex > 0 {
					SleepJitter(time.Duration(workerID)*250*time.Millisecond, 350*time.Millisecond)
				}
				if r.cooldown != nil {
					r.cooldown.WaitForAvailability()
				}
				_, _, _, _ = r.RegisterOnly(runCtx, workerID)
				currentCompleted, currentCandidates := progressSnapshot()
				r.updateMaintainProgress(currentCompleted, gap)
				r.updateMaintainState(currentCandidates, true)
			}()
		}
		wg.Wait()
	}()

	oauthWorkers := maxInt(1, r.cfg.OAuthWorkers)
	if gap > 0 {
		oauthWorkers = minInt(oauthWorkers, gap)
	}
	var oauthWG sync.WaitGroup
	for i := 0; i < oauthWorkers; i++ {
		workerID := i + 1
		oauthWG.Add(1)
		go func(wid int) {
			defer oauthWG.Done()
			for {
				select {
				case <-runCtx.Done():
					return
				default:
				}

				currentCompleted, _ := progressSnapshot()
				if currentCompleted >= gap {
					return
				}

				account := r.state.DequeuePending()
				if account == nil {
					select {
					case <-regDone:
						if r.state.PendingQueueLength() == 0 {
							return
						}
					default:
					}
					currentCompleted, currentCandidates := progressSnapshot()
					r.updateMaintainProgress(currentCompleted, gap)
					r.updateMaintainState(currentCandidates, true)
					time.Sleep(1 * time.Second)
					continue
				}

				if r.cooldown != nil {
					r.cooldown.WaitForAvailability()
				}
				if r.cfg.OAuthDelaySeconds > 0 {
					select {
					case <-runCtx.Done():
						return
					case <-time.After(time.Duration(r.cfg.OAuthDelaySeconds) * time.Second):
					}
				}
				ok := r.OAuthOne(runCtx, wid, account.Email, account.Password, account.MailToken, account.MailConfigKey)
				if markProgress(ok) {
					cancel()
					return
				}
			}
		}(workerID)
	}

	oauthWG.Wait()
	<-regDone

	finalCompleted, finalApproxCandidates := progressSnapshot()
	finalCandidates := finalApproxCandidates
	if _, freshCandidates, err := cpa.GetCandidatesCount(ctx, r.cfg.CPATargetType); err == nil {
		finalCandidates = freshCandidates
	}

	r.updateMaintainProgress(finalCompleted, gap)
	r.updateMaintainState(finalCandidates, false)
	switch {
	case finalCandidates >= r.cfg.MinCandidates:
		r.updateMaintainMessage(fmt.Sprintf("单次维护完成：库存已恢复到 %d/%d", finalCandidates, r.cfg.MinCandidates))
	case finalCompleted > 0:
		r.updateMaintainMessage(fmt.Sprintf("单次维护结束：补号 %d/%d，当前库存 %d/%d", finalCompleted, gap, finalCandidates, r.cfg.MinCandidates))
	default:
		r.updateMaintainMessage(fmt.Sprintf("单次维护结束：未完成补号，当前库存 %d/%d", finalCandidates, r.cfg.MinCandidates))
	}
	fmt.Printf("🏁 单次维护结束：补号 %d/%d | 当前库存 %d/%d\n", finalCompleted, gap, finalCandidates, r.cfg.MinCandidates)
}

func (r *Runner) RunMaintainLoop(ctx context.Context) {
	interval := time.Duration(r.cfg.LoopIntervalSeconds * float64(time.Second))
	if interval < 5*time.Second {
		interval = 60 * time.Second
	}

	round := 0
	for {
		select {
		case <-ctx.Done():
			r.updateMaintainSleep(0)
			r.updateMaintainState(r.MaintainStateSnapshot().CandidatesCount, false)
			r.updateMaintainMessage("循环维护已停止")
			return
		default:
		}

		round++
		r.updateLoopRound(round)
		r.updateMaintainSleep(0)
		r.updateMaintainMessage(fmt.Sprintf(">>> 循环轮次 #%d 开始", round))
		r.RunMaintainOnce(ctx)

		select {
		case <-ctx.Done():
			r.updateMaintainSleep(0)
			r.updateMaintainState(r.MaintainStateSnapshot().CandidatesCount, false)
			r.updateMaintainMessage("循环维护已停止")
			return
		default:
		}

		snap := r.MaintainStateSnapshot()
		r.updateMaintainState(snap.CandidatesCount, false)
		r.updateMaintainMessage(fmt.Sprintf("第 %d 轮完成，%.0fs 后开始下一轮巡检", round, interval.Seconds()))
		r.updateMaintainSleep(interval)

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			r.updateMaintainSleep(0)
			r.updateMaintainState(r.MaintainStateSnapshot().CandidatesCount, false)
			r.updateMaintainMessage("循环维护已停止")
			return
		case <-timer.C:
		}
	}
}

// RunMaintain 持续维护模式:
//   - 注册池: 永不停，按固定并发持续注册，账号入队
//   - OAuth 池: 受 CPA 库存控制，库存够了暂停消费，不够了恢复
//   - 库存巡检: 周期性查询 CPA candidates，控制 OAuth 池开关
func (r *Runner) RunMaintain(ctx context.Context) {
	cpa := r.CPAClient()
	if strings.TrimSpace(cpa.BaseURL) == "" || strings.TrimSpace(cpa.Token) == "" {
		fmt.Println("❌ CPA 未配置 clean.base_url 或 clean.token")
		return
	}

	regWorkers := maxInt(1, r.cfg.RegisterWorkers)
	oauthWorkers := maxInt(1, r.cfg.OAuthWorkers)
	delaySeconds := r.cfg.OAuthDelaySeconds
	checkInterval := r.cfg.LoopIntervalSeconds
	if checkInterval < 5 {
		checkInterval = 60
	}

	fmt.Printf("\n🚀 持续维护模式\n")
	fmt.Printf("   注册池: %d 并发（持续运行）\n", regWorkers)
	fmt.Printf("   OAuth 池: %d 并发（库存驱动）\n", oauthWorkers)
	fmt.Printf("   CPA: %s | target_type=%s\n", cpa.BaseURL, r.cfg.CPATargetType)
	fmt.Printf("   阈值: min_candidates=%d | 巡检间隔=%.0fs\n", r.cfg.MinCandidates, checkInterval)
	fmt.Printf("   邮箱: %s\n", DescribeMailProviderChain(r.cfg))

	batchStart := time.Now()
	var regOK, regFail int
	var oauthOK, oauthFail, oauthPaused int
	var mu sync.Mutex

	// oauthGate: 1 = OAuth 池可消费, 0 = 暂停
	oauthGate := make(chan struct{}, 1)
	oauthGate <- struct{}{} // 初始打开

	// ──── 注册池: 永不停 ────
	go func() {
		sem := make(chan struct{}, regWorkers)
		regIndex := 0
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			sem <- struct{}{}
			regIndex++
			workerID := ((regIndex - 1) % regWorkers) + 1
			go func(idx, wid int) {
				defer func() { <-sem }()
				if idx > 1 {
					SleepJitter(time.Duration(wid)*time.Second, 500*time.Millisecond)
				}
				_, _, ok, _ := r.RegisterOnly(ctx, wid)
				mu.Lock()
				if ok {
					regOK++
				} else {
					regFail++
				}
				total := regOK + regFail
				if total%10 == 0 || total <= 5 {
					fmt.Printf("📊 注册池: 已完成 %d | ✅%d ❌%d | 队列待消费中\n", total, regOK, regFail)
				}
				mu.Unlock()
			}(regIndex, workerID)
		}
	}()

	// ──── 库存巡检: 控制 OAuth 池开关 ────
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(checkInterval) * time.Second):
			}
			_, candidates, err := cpa.GetCandidatesCount(ctx, r.cfg.CPATargetType)
			if err != nil {
				fmt.Printf("⚠️ CPA 库存查询失败: %v\n", err)
				continue
			}
			mu.Lock()
			elapsed := time.Since(batchStart).Seconds()
			fmt.Printf("📊 巡检: CPA candidates=%d, 阈值=%d | 注册 ✅%d ❌%d | OAuth ✅%d ❌%d 暂停%d | 运行 %.0fs\n",
				candidates, r.cfg.MinCandidates, regOK, regFail, oauthOK, oauthFail, oauthPaused, elapsed)
			mu.Unlock()

			if candidates >= r.cfg.MinCandidates {
				// 库存够了，排空 gate（暂停 OAuth 池）
				select {
				case <-oauthGate:
					fmt.Printf("⏸️ CPA 库存充足 (%d >= %d)，OAuth 池暂停\n", candidates, r.cfg.MinCandidates)
					mu.Lock()
					oauthPaused++
					mu.Unlock()
				default:
					// 已经是暂停状态
				}
			} else {
				// 库存不足，确保 gate 打开
				select {
				case oauthGate <- struct{}{}:
					gap := r.cfg.MinCandidates - candidates
					fmt.Printf("▶️ CPA 库存不足 (%d < %d, 缺口=%d)，OAuth 池恢复\n", candidates, r.cfg.MinCandidates, gap)
				default:
					// 已经是运行状态
				}
			}
		}
	}()

	// ──── OAuth 池: 受库存门控 ────
	sem := make(chan struct{}, oauthWorkers)
	var wg sync.WaitGroup
	workerCounter := 0

	// 初始等一会让注册池先产出
	initialDelay := maxInt(5, delaySeconds)
	fmt.Printf("⏳ OAuth 池将在 %ds 后启动...\n", initialDelay)
	time.Sleep(time.Duration(initialDelay) * time.Second)

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			elapsed := time.Since(batchStart).Seconds()
			mu.Lock()
			fmt.Printf("\n🏁 维护模式结束: 注册 ✅%d ❌%d | OAuth ✅%d ❌%d | 暂停次数 %d | 总运行 %.1fs\n",
				regOK, regFail, oauthOK, oauthFail, oauthPaused, elapsed)
			mu.Unlock()
			return
		default:
		}

		// 等待 gate 开放（库存不足时才消费）
		select {
		case <-ctx.Done():
			continue
		case _, open := <-oauthGate:
			if !open {
				return
			}
			// gate 拿到了信号，放回去让其他迭代也能通过（直到巡检收回）
			oauthGate <- struct{}{}
		}

		account := r.state.DequeuePending()
		if account == nil {
			time.Sleep(2 * time.Second)
			continue
		}

		wg.Add(1)
		workerCounter++
		wid := (workerCounter % oauthWorkers) + 1
		go func(acc PendingAccount, wid int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if delaySeconds > 0 {
				time.Sleep(time.Duration(delaySeconds) * time.Second)
			}
			ok := r.OAuthOne(ctx, wid, acc.Email, acc.Password, acc.MailToken, acc.MailConfigKey)
			mu.Lock()
			if ok {
				oauthOK++
			} else {
				oauthFail++
			}
			fmt.Printf("📊 OAuth 池: ✅%d ❌%d\n", oauthOK, oauthFail)
			mu.Unlock()
		}(*account, wid)
	}
}

func (r *Runner) noteSuccess() {
	if r.cooldown != nil {
		r.cooldown.NoteSuccess()
	}
}

func (r *Runner) noteFailure(stage, email, detail string) {
	if r.cooldown != nil {
		r.cooldown.NoteFailure(stage, email, detail)
	}
}
