package codex

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestConfig(t *testing.T) *Config {
	t.Helper()
	root := t.TempDir()
	return &Config{
		Root:                 root,
		ProxyMode:            "direct",
		AccountsFile:         filepath.Join(root, "accounts.txt"),
		CSVFile:              filepath.Join(root, "accounts.csv"),
		AKFile:               filepath.Join(root, "ak.txt"),
		RKFile:               filepath.Join(root, "rk.txt"),
		SpaceRecordFile:      filepath.Join(root, "space_record_status.json"),
		PendingQueueFile:     filepath.Join(root, "pending_oauth.json"),
		MinCandidates:        50,
		RegisterWorkers:      2,
		OAuthWorkers:         2,
		FailureCooldownAfter: 5,
		FailureCooldownSec:   45,
		LoopIntervalSeconds:  60,
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}
