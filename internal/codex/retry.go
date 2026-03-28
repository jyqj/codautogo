package codex

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"strings"
	"time"
)

var cryptoRandRead = cryptorand.Read

// ──────────────── 瞬时错误判定 ────────────────

var defaultTransientMarkers = []string{
	"sentinel_",
	"oauth_authorization_code_not_found",
	"headers_failed",
	"server disconnected",
	"unexpected_eof_while_reading",
	"unexpected eof while reading",
	"timeout",
	"timed out",
	"transport",
	"remoteprotocolerror",
	"connection reset",
	"temporarily unavailable",
	"network",
	"eof occurred",
	"http_429",
	"http_500",
	"http_502",
	"http_503",
	"http_504",
}

// IsTransientFlowError 判断错误信息是否属于瞬时可恢复错误。
// 用于决定是否在步骤内或外层重试。
func IsTransientFlowError(reason string, markers []string) bool {
	text := strings.TrimSpace(reason)
	if text == "" {
		return false
	}
	lower := strings.ToLower(text)
	search := markers
	if len(search) == 0 {
		search = defaultTransientMarkers
	}
	for _, marker := range search {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// ──────────────── 通用步骤重试包装器 ────────────────

// StepResult 表示单步执行的返回值。
type StepResult struct {
	OK     bool
	Reason string
}

// StepAction 是一个可重试的单步操作，返回 (成功?, 失败原因)。
type StepAction func() StepResult

// RunStepWithRetry 通用步骤重试包装器，在瞬时错误时自动重试。
// maxAttempts: 最大尝试次数（≥1）
// delayBase/delayCap: 重试延迟参数，delay = min(delayCap, delayBase * attempt)
func RunStepWithRetry(stepName string, action StepAction, maxAttempts int, delayBase, delayCap time.Duration) StepResult {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	lastReason := ""
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result := action()
		if result.OK {
			return result
		}
		lastReason = result.Reason
		if attempt < maxAttempts && IsTransientFlowError(lastReason, nil) {
			delay := delayBase * time.Duration(attempt)
			if delay > delayCap && delayCap > 0 {
				delay = delayCap
			}
			if delay < 50*time.Millisecond {
				delay = 50 * time.Millisecond
			}
			fmt.Printf("  ⚠️ 步骤%s瞬时失败(第%d/%d次): %s，%.1fs 后重试\n", stepName, attempt, maxAttempts, truncate(lastReason, 120), delay.Seconds())
			time.Sleep(delay)
			continue
		}
		return result
	}
	return StepResult{OK: false, Reason: defaultString(lastReason, stepName+"_failed")}
}

// ──────────────── OAuth 外层重试 ────────────────

// OAuthRetryConfig OAuth 外层重试配置。
type OAuthRetryConfig struct {
	MaxAttempts int
	BackoffBase time.Duration // 指数退避基数，如 2s
	BackoffMax  time.Duration // 退避上限，如 60s
	JitterMin   float64       // 随机抖动下限(秒)
	JitterMax   float64       // 随机抖动上限(秒)
}

// DefaultOAuthRetryConfig 返回默认 OAuth 重试配置。
func DefaultOAuthRetryConfig() OAuthRetryConfig {
	return OAuthRetryConfig{
		MaxAttempts: 3,
		BackoffBase: 2 * time.Second,
		BackoffMax:  60 * time.Second,
		JitterMin:   0.2,
		JitterMax:   0.8,
	}
}

// OAuthLoginWithRetry 对完整的 OAuth 登录流程做外层重试，指数退避 + 随机抖动。
// loginFn 应返回 (tokens, marker, error)，marker 用于识别 ACCOUNT_BANNED 等特殊状态。
func OAuthLoginWithRetry(ctx context.Context, cfg OAuthRetryConfig, loginFn func() (*Tokens, string, error)) (*Tokens, string, error) {
	attempts := cfg.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		default:
		}

		tokens, marker, err := loginFn()
		if err == nil && tokens != nil {
			return tokens, marker, nil
		}
		// ACCOUNT_BANNED 不重试
		if marker == "ACCOUNT_BANNED" {
			return nil, marker, err
		}
		lastErr = err
		if attempt < attempts {
			backoff := cfg.BackoffBase
			for i := 1; i < attempt; i++ {
				backoff *= 2
				if backoff > cfg.BackoffMax {
					backoff = cfg.BackoffMax
					break
				}
			}
			if backoff > cfg.BackoffMax {
				backoff = cfg.BackoffMax
			}
			jitter := time.Duration(randomRange(cfg.JitterMin, cfg.JitterMax) * float64(time.Second))
			sleepTime := backoff + jitter
			fmt.Printf("  ⚠️ OAuth 尝试 %d/%d 失败: %v，%.1fs 后重试\n", attempt, attempts, err, sleepTime.Seconds())
			select {
			case <-time.After(sleepTime):
			case <-ctx.Done():
				return nil, "", ctx.Err()
			}
		}
	}
	return nil, "", fmt.Errorf("OAuth 重试 %d 次仍失败: %w", attempts, lastErr)
}

func randomRange(min, max float64) float64 {
	if max <= min {
		return min
	}
	return min + float64(cryptoRandInt63n(int64((max-min)*1000)))/1000.0
}

func cryptoRandInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	mask := n - 1
	if n&mask == 0 {
		var x [8]byte
		_, _ = cryptoRandRead(x[:])
		v := int64(x[0])<<56 | int64(x[1])<<48 | int64(x[2])<<40 | int64(x[3])<<32 |
			int64(x[4])<<24 | int64(x[5])<<16 | int64(x[6])<<8 | int64(x[7])
		return v & int64(mask)
	}
	// fallback
	var x [8]byte
	_, _ = cryptoRandRead(x[:])
	v := int64(x[0])<<56 | int64(x[1])<<48 | int64(x[2])<<40 | int64(x[3])<<32 |
		int64(x[4])<<24 | int64(x[5])<<16 | int64(x[6])<<8 | int64(x[7])
	return v % n
}
