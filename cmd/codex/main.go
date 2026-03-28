package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"codex/internal/codex"
)

func main() {
	cfg, err := codex.LoadConfig("")
	if err != nil {
		fmt.Printf("❌ 加载配置失败: %v\n", err)
		os.Exit(1)
	}

	email := flag.String("email", "", "指定邮箱")
	password := flag.String("password", "", "指定密码")
	skipRegister := flag.Bool("skip-register", false, "跳过注册，直接登录并录入")
	forceRefresh := flag.Bool("force-refresh", false, "忽略本地录入记录，强制重新执行")
	teamRange := flag.String("team-range", "", "团队区间，例如 10031-10035")
	perTeam := flag.Int("per-team", 7, "每个团队邮箱数量")
	qiumingStart := flag.Int("qiuming-start", 1, "qiuming 起始编号")
	accountWorkers := flag.Int("account-workers", cfg.AccountRecordWorkers, "账号并发数")
	workspaceWorkers := flag.Int("workspace-workers", 0, "空间录入并发数")
	wsLoginWorkers := flag.Int("ws-login-workers", 0, "workspace 登录并发数")
	prefix := flag.String("prefix", "", "录入名称前缀")
	noPrefix := flag.Bool("no-prefix", false, "录入名称不加前缀")
	mailProvider := flag.String("mail-provider", "", "已废弃，无效；邮箱链路固定为 tabmail -> cfmail")
	emailDomain := flag.String("email-domain", "tabmail", "邮箱域名: 仅支持 tabmail")
	proxyMode := flag.String("proxy-mode", "", "代理模式: direct/file")
	proxyFile := flag.String("proxy-file", "", "代理文件路径")
	dualPool := flag.Bool("dual-pool", false, "启用双池模式：注册池+OAuth池异步运行")
	regWorkers := flag.Int("reg-workers", 0, "双池模式：注册池并发数")
	oauthWorkers := flag.Int("oauth-workers", 0, "双池模式：OAuth池并发数")
	oauthDelay := flag.Int("oauth-delay", 0, "双池模式：OAuth池每个账号的延迟秒数")

	// 维护模式参数
	maintain := flag.Bool("maintain", false, "持续维护模式：注册池不停 + OAuth池受CPA库存控制")
	minCandidates := flag.Int("min-candidates", 0, "维护模式：CPA最低候选账号数")
	loopInterval := flag.Float64("loop-interval", 0, "维护模式：CPA库存巡检间隔秒数")
	flag.Parse()

	if strings.TrimSpace(*mailProvider) != "" {
		fmt.Println("⚠️ --mail-provider 已废弃，当前固定链路为 tabmail -> cfmail")
	}
	if strings.TrimSpace(*proxyMode) != "" {
		cfg.ProxyMode = strings.TrimSpace(*proxyMode)
	}
	if strings.TrimSpace(*proxyFile) != "" {
		cfg.ProxyFile = *proxyFile
	}
	if *workspaceWorkers > 0 {
		cfg.WorkspaceRecordWorkers = *workspaceWorkers
	}
	if *wsLoginWorkers > 0 {
		cfg.WorkspaceLoginWorkers = *wsLoginWorkers
	}
	if *noPrefix {
		cfg.NamePrefix = ""
	} else if strings.TrimSpace(*prefix) != "" {
		cfg.NamePrefix = strings.TrimSpace(*prefix)
	}
	if *dualPool {
		cfg.DualPool = true
	}
	if *regWorkers > 0 {
		cfg.RegisterWorkers = *regWorkers
	}
	if *oauthWorkers > 0 {
		cfg.OAuthWorkers = *oauthWorkers
	}
	if *oauthDelay > 0 {
		cfg.OAuthDelaySeconds = *oauthDelay
	}
	if *minCandidates > 0 {
		cfg.MinCandidates = *minCandidates
	}
	if *loopInterval > 0 {
		cfg.LoopIntervalSeconds = *loopInterval
	}

	// 投递目标提示
	if strings.TrimSpace(cfg.CPABaseURL) != "" {
		fmt.Printf("📌 投递目标: CPA (%s)\n", cfg.CPABaseURL)
	} else {
		fmt.Println("📌 投递目标: 仅本地保存")
	}
	fmt.Printf("📌 邮箱提供链: %s\n", codex.DescribeMailProviderChain(cfg))
	fmt.Printf("📌 代理模式: %s\n", cfg.ProxyMode)
	if cfg.NamePrefix == "" {
		fmt.Println("📌 录入名称前缀: (无)")
	} else {
		fmt.Printf("📌 录入名称前缀: %s\n", cfg.NamePrefix)
	}

	runner := codex.NewRunner(cfg)
	ctx := context.Background()

	// 持续维护模式: 注册池永不停 + OAuth池受CPA库存门控
	if *maintain {
		runner.RunMaintain(ctx)
		return
	}

	if strings.TrimSpace(*email) != "" {
		res := runner.ProcessSpecifiedEmail(ctx, strings.TrimSpace(*email), *skipRegister, strings.TrimSpace(*password), *forceRefresh)
		if !res.OK {
			os.Exit(1)
		}
		return
	}

	if strings.TrimSpace(*teamRange) != "" {
		start, end, err := codex.ParseTeamRange(*teamRange)
		if err != nil {
			fmt.Printf("❌ team-range 参数错误: %v\n", err)
			os.Exit(1)
		}
		emails := codex.BuildTeamRangeEmails(start, end, max(1, *perTeam), max(1, *qiumingStart), strings.TrimSpace(*emailDomain))
		results := runner.RunSpecifiedEmailsBatch(ctx, emails, *skipRegister, max(1, *accountWorkers), *forceRefresh, strings.TrimSpace(*emailDomain))
		okCount := 0
		for _, item := range results {
			if item.OK {
				okCount++
			}
		}
		if okCount == 0 {
			os.Exit(1)
		}
		return
	}

	if cfg.DualPool {
		runner.RunDualPool(ctx)
		return
	}
	runner.RunBatch(ctx)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
