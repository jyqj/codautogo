package codex

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

type SpaceResult struct {
	Workspace   string `json:"workspace"`
	Org         string `json:"org"`
	Project     string `json:"project,omitempty"`
	WorkspaceID string `json:"workspace_id"`
	OrgID       string `json:"org_id"`
	ProjectID   string `json:"project_id,omitempty"`
	Tokens      Tokens `json:"tokens"`
}

type spaceMeta struct {
	Key         string
	Label       string
	WorkspaceID string
	OrgID       string
	ProjectID   string
	Workspace   string
	Org         string
	Project     string
}

type PendingAccount struct {
	Email         string `json:"email"`
	Password      string `json:"password"`
	MailProvider  string `json:"mail_provider,omitempty"`
	MailToken     string `json:"mail_token,omitempty"`
	MailConfigKey string `json:"mail_config_key,omitempty"`
	CreatedAt     string `json:"created_at"`
	Status        string `json:"status"` // pending, processing, done, failed
}

type StateStore struct {
	cfg         *Config
	factory     *ClientFactory
	mu          sync.Mutex
	stateLoaded bool
	spaceRecord map[string]any
	pendingMu   sync.Mutex
}

func NewStateStore(cfg *Config, factory *ClientFactory) *StateStore {
	return &StateStore{cfg: cfg, factory: factory}
}

func (s *StateStore) SaveAccount(email, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.cfg.AccountsFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%s:%s\n", email, password); err != nil {
		_ = f.Close()
		return err
	}
	_ = f.Close()

	csvExists := fileExists(s.cfg.CSVFile)
	cf, err := os.OpenFile(s.cfg.CSVFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	w := csv.NewWriter(cf)
	if !csvExists {
		_ = w.Write([]string{"email", "password", "timestamp"})
	}
	_ = w.Write([]string{email, password, NowLocalString()})
	w.Flush()
	_ = cf.Close()
	return w.Error()
}

func (s *StateStore) SaveTokens(ctx context.Context, email string, tokens Tokens) (bool, error) {
	// 本地保存 AK/RK（如果 save_local 启用）
	if s.cfg.SaveLocal {
		s.mu.Lock()
		if strings.TrimSpace(tokens.AccessToken) != "" {
			_ = appendLine(s.cfg.AKFile, tokens.AccessToken)
		}
		if strings.TrimSpace(tokens.RefreshToken) != "" {
			_ = appendLine(s.cfg.RKFile, tokens.RefreshToken)
		}
		s.mu.Unlock()
	}
	if strings.TrimSpace(tokens.AccessToken) == "" {
		return false, nil
	}

	// 优先 CPA 投递
	if strings.TrimSpace(s.cfg.CPABaseURL) != "" && strings.TrimSpace(s.cfg.CPAToken) != "" {
		return s.submitToCPA(ctx, email, tokens)
	}
	fmt.Println("  ⚠️ 未配置 clean.base_url 或 clean.token，仅本地保存")
	return s.cfg.SaveLocal, nil
}

func (s *StateStore) submitToCPA(ctx context.Context, email string, tokens Tokens) (bool, error) {
	cpa := NewCPAClient(s.cfg, s.factory)
	ok, err := cpa.UploadToken(ctx, email, tokens)
	if err != nil {
		fmt.Printf("  ❌ CPA 上传失败: %v\n", err)
		return false, err
	}
	if ok {
		fmt.Printf("  ✅ Token 已上传 CPA: %s\n", email)
	}
	return ok, nil
}

func appendLine(path, value string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s\n", value)
	return err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (s *StateStore) loadStateLocked() map[string]any {
	if s.stateLoaded && s.spaceRecord != nil {
		return s.spaceRecord
	}
	s.stateLoaded = true
	raw, err := os.ReadFile(s.cfg.SpaceRecordFile)
	if err != nil {
		s.spaceRecord = map[string]any{"version": 1, "updated_at": NowLocalString(), "accounts": map[string]any{}}
		return s.spaceRecord
	}
	var data map[string]any
	if json.Unmarshal(raw, &data) != nil || data == nil {
		data = map[string]any{}
	}
	if _, ok := data["accounts"]; !ok {
		data["accounts"] = map[string]any{}
	}
	if _, ok := data["version"]; !ok {
		data["version"] = 1
	}
	if _, ok := data["updated_at"]; !ok {
		data["updated_at"] = NowLocalString()
	}
	s.spaceRecord = data
	return s.spaceRecord
}

func (s *StateStore) saveStateLocked() error {
	if s.spaceRecord == nil {
		return nil
	}
	raw, _ := json.MarshalIndent(s.spaceRecord, "", "  ")
	tmp := s.cfg.SpaceRecordFile + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.cfg.SpaceRecordFile)
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func metaFromItem(item SpaceResult) spaceMeta {
	workspaceID := firstString(item.WorkspaceID, item.Workspace, "unknown_workspace")
	orgID := firstString(item.OrgID, item.Org, "unknown_org")
	projectID := strings.TrimSpace(item.ProjectID)
	projectLabel := strings.TrimSpace(item.Project)
	if projectID == "" {
		projectID = "-"
	}
	workspace := firstString(item.Workspace, workspaceID)
	org := firstString(item.Org, orgID)
	label := workspace + "/" + org
	if projectLabel != "" {
		label += "/" + projectLabel
	}
	return spaceMeta{Key: workspaceID + "|" + orgID + "|" + projectID, Label: label, WorkspaceID: workspaceID, OrgID: orgID, ProjectID: projectID, Workspace: workspace, Org: org, Project: projectLabel}
}

func firstString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func recomputeAccountStatus(account map[string]any) map[string]any {
	wsMap := asMap(account["workspace_status"])
	total := len(wsMap)
	recordedAll := 0
	partial := 0
	failed := 0
	for _, raw := range wsMap {
		st := strings.TrimSpace(toString(asMap(raw)["status"]))
		switch st {
		case "recorded_all":
			recordedAll++
		case "partial":
			partial++
		case "failed":
			failed++
		}
	}
	status := "empty"
	detail := "no_workspace_status"
	if total > 0 && recordedAll == total {
		status = "recorded_all"
		detail = fmt.Sprintf("workspace_recorded_all:%d/%d", recordedAll, total)
	} else if recordedAll > 0 || partial > 0 {
		status = "partial"
		detail = fmt.Sprintf("workspace_partial:%d/%d", recordedAll, total)
	} else if total > 0 {
		status = "failed"
		detail = fmt.Sprintf("workspace_failed:%d/%d", failed, total)
	}
	account["account_status"] = map[string]any{"status": status, "detail": detail, "workspace_total": total, "workspace_recorded": recordedAll, "updated_at": NowLocalString()}
	return asMap(account["account_status"])
}

func (s *StateStore) spaceAlreadyRecorded(email string, item SpaceResult) (bool, spaceMeta) {
	meta := metaFromItem(item)
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.loadStateLocked()
	accounts := asMap(state["accounts"])
	account := asMap(accounts[email])
	spaces := asMap(account["spaces"])
	status := strings.TrimSpace(toString(asMap(spaces[meta.Key])["status"]))
	return status == "recorded", meta
}

func (s *StateStore) updateSpaceRecord(email string, item SpaceResult, status, detail string) {
	meta := metaFromItem(item)
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.loadStateLocked()
	accounts := asMap(state["accounts"])
	account := asMap(accounts[email])
	if len(account) == 0 {
		account = map[string]any{"updated_at": NowLocalString(), "spaces": map[string]any{}, "workspace_status": map[string]any{}}
	}
	spaces := asMap(account["spaces"])
	entry := asMap(spaces[meta.Key])
	entry["workspace"] = meta.Workspace
	entry["workspace_id"] = meta.WorkspaceID
	entry["org"] = meta.Org
	entry["org_id"] = meta.OrgID
	entry["project"] = meta.Project
	if meta.ProjectID == "-" {
		entry["project_id"] = nil
	} else {
		entry["project_id"] = meta.ProjectID
	}
	entry["status"] = status
	entry["detail"] = detail
	entry["updated_at"] = NowLocalString()
	spaces[meta.Key] = entry
	account["spaces"] = spaces
	account["updated_at"] = NowLocalString()
	recomputeAccountStatus(account)
	accounts[email] = account
	state["accounts"] = accounts
	state["updated_at"] = NowLocalString()
	s.spaceRecord = state
	_ = s.saveStateLocked()
}

func (s *StateStore) workspaceRecordedAll(email, workspaceID string) bool {
	if strings.TrimSpace(workspaceID) == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.loadStateLocked()
	accounts := asMap(state["accounts"])
	account := asMap(accounts[email])
	wsMap := asMap(account["workspace_status"])
	return strings.TrimSpace(toString(asMap(wsMap[workspaceID])["status"])) == "recorded_all"
}

func (s *StateStore) accountRecordedAll(email string) (bool, map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.loadStateLocked()
	accounts := asMap(state["accounts"])
	account := asMap(accounts[email])
	status := asMap(account["account_status"])
	if len(status) == 0 {
		status = recomputeAccountStatus(account)
		accounts[email] = account
		state["accounts"] = accounts
		state["updated_at"] = NowLocalString()
		s.spaceRecord = state
		_ = s.saveStateLocked()
	}
	return strings.TrimSpace(toString(status["status"])) == "recorded_all", status
}

func (s *StateStore) markAccountBanned(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.loadStateLocked()
	accounts := asMap(state["accounts"])
	account := asMap(accounts[email])
	if len(account) == 0 {
		account = map[string]any{"updated_at": NowLocalString(), "spaces": map[string]any{}, "workspace_status": map[string]any{}}
	}
	account["account_status"] = map[string]any{"status": "banned", "detail": "account_deleted_or_deactivated", "updated_at": NowLocalString()}
	account["updated_at"] = NowLocalString()
	accounts[email] = account
	state["accounts"] = accounts
	state["updated_at"] = NowLocalString()
	s.spaceRecord = state
	_ = s.saveStateLocked()
}

func (s *StateStore) isAccountBanned(email string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.loadStateLocked()
	accounts := asMap(state["accounts"])
	account := asMap(accounts[email])
	return strings.TrimSpace(toString(asMap(account["account_status"])["status"])) == "banned"
}

func (s *StateStore) updateWorkspaceStatus(email, workspaceID, workspaceName, status, detail string) {
	if strings.TrimSpace(workspaceID) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.loadStateLocked()
	accounts := asMap(state["accounts"])
	account := asMap(accounts[email])
	if len(account) == 0 {
		account = map[string]any{"updated_at": NowLocalString(), "spaces": map[string]any{}, "workspace_status": map[string]any{}}
	}
	wsMap := asMap(account["workspace_status"])
	wsMap[workspaceID] = map[string]any{"workspace": firstString(workspaceName, workspaceID), "workspace_id": workspaceID, "status": status, "detail": detail, "updated_at": NowLocalString()}
	account["workspace_status"] = wsMap
	account["updated_at"] = NowLocalString()
	recomputeAccountStatus(account)
	accounts[email] = account
	state["accounts"] = accounts
	state["updated_at"] = NowLocalString()
	s.spaceRecord = state
	_ = s.saveStateLocked()
}

func (s *StateStore) refreshWorkspaceStatusFromItems(email string, items []SpaceResult) {
	grouped := map[string]map[string]spaceMeta{}
	for _, item := range items {
		meta := metaFromItem(item)
		if _, ok := grouped[meta.WorkspaceID]; !ok {
			grouped[meta.WorkspaceID] = map[string]spaceMeta{}
		}
		grouped[meta.WorkspaceID][meta.Key] = meta
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.loadStateLocked()
	accounts := asMap(state["accounts"])
	account := asMap(accounts[email])
	spaces := asMap(account["spaces"])
	wsMap := asMap(account["workspace_status"])
	for wid, entries := range grouped {
		statuses := make([]string, 0, len(entries))
		workspaceName := wid
		for _, meta := range entries {
			workspaceName = meta.Workspace
			statuses = append(statuses, strings.TrimSpace(toString(asMap(spaces[meta.Key])["status"])))
		}
		status := "failed"
		detail := fmt.Sprintf("all_failed:%d", len(statuses))
		if len(statuses) > 0 {
			allRecorded := true
			anyRecorded := false
			for _, st := range statuses {
				if st != "recorded" {
					allRecorded = false
				}
				if st == "recorded" {
					anyRecorded = true
				}
			}
			if allRecorded {
				status = "recorded_all"
				detail = fmt.Sprintf("all_recorded:%d", len(statuses))
			} else if anyRecorded {
				status = "partial"
				count := 0
				for _, st := range statuses {
					if st == "recorded" {
						count++
					}
				}
				detail = fmt.Sprintf("partial_recorded:%d/%d", count, len(statuses))
			}
		}
		wsMap[wid] = map[string]any{"workspace": workspaceName, "workspace_id": wid, "status": status, "detail": detail, "updated_at": NowLocalString()}
	}
	account["workspace_status"] = wsMap
	account["updated_at"] = NowLocalString()
	recomputeAccountStatus(account)
	accounts[email] = account
	state["accounts"] = accounts
	state["updated_at"] = NowLocalString()
	s.spaceRecord = state
	_ = s.saveStateLocked()
}

func prefixTag(prefix string) string {
	if strings.TrimSpace(prefix) == "" {
		return ""
	}
	return prefix + " "
}

func (s *StateStore) CreateAccountStreamRecorder(ctx context.Context, email, prefix string) (func(SpaceResult) bool, func() map[string]int) {
	workers := maxInt(1, s.cfg.WorkspaceRecordWorkers)
	fmt.Printf("%s⚙️ 空间流式录入并发: %d\n", prefixTag(prefix), workers)
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	stats := map[string]int{"submitted": 0, "skipped": 0, "ok": 0, "fail": 0}
	var mu sync.Mutex
	seen := map[string]struct{}{}
	items := make([]SpaceResult, 0)
	submit := func(item SpaceResult) bool {
		recorded, meta := s.spaceAlreadyRecorded(email, item)
		mu.Lock()
		items = append(items, item)
		mu.Unlock()
		if recorded {
			fmt.Printf("%s⏭️ 跳过已录入空间: %s\n", prefixTag(prefix), meta.Label)
			s.updateSpaceRecord(email, item, "recorded", "already_recorded_skip")
			mu.Lock()
			stats["skipped"]++
			mu.Unlock()
			return false
		}
		mu.Lock()
		if _, ok := seen[meta.Key]; ok {
			stats["skipped"]++
			mu.Unlock()
			return false
		}
		seen[meta.Key] = struct{}{}
		stats["submitted"]++
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fmt.Printf("%s📤 录入空间: %s\n", prefixTag(prefix), meta.Label)
			ok, _ := s.SaveTokens(ctx, email, item.Tokens)
			mu.Lock()
			if ok {
				stats["ok"]++
			} else {
				stats["fail"]++
			}
			mu.Unlock()
			if ok {
				s.updateSpaceRecord(email, item, "recorded", "submit_ok_stream")
			} else {
				s.updateSpaceRecord(email, item, "failed", "submit_failed_stream")
			}
		}()
		return true
	}
	waitFn := func() map[string]int {
		wg.Wait()
		mu.Lock()
		snapshotItems := append([]SpaceResult(nil), items...)
		snapshotStats := map[string]int{}
		for k, v := range stats {
			snapshotStats[k] = v
		}
		mu.Unlock()
		s.refreshWorkspaceStatusFromItems(email, snapshotItems)
		return snapshotStats
	}
	return submit, waitFn
}

// ──────────────── Pending OAuth Queue ────────────────

func (s *StateStore) loadPendingQueue() []PendingAccount {
	raw, err := os.ReadFile(s.cfg.PendingQueueFile)
	if err != nil {
		return nil
	}
	var queue []PendingAccount
	if json.Unmarshal(raw, &queue) != nil {
		return nil
	}
	return queue
}

func (s *StateStore) savePendingQueue(queue []PendingAccount) error {
	raw, _ := json.MarshalIndent(queue, "", "  ")
	tmp := s.cfg.PendingQueueFile + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.cfg.PendingQueueFile)
}

func (s *StateStore) EnqueuePending(email, password, mailProvider, mailToken, mailConfigKey string) error {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	queue := s.loadPendingQueue()
	for i, item := range queue {
		if item.Email == email {
			updated := false
			if strings.TrimSpace(mailProvider) != "" && strings.TrimSpace(queue[i].MailProvider) == "" {
				queue[i].MailProvider = strings.TrimSpace(mailProvider)
				updated = true
			}
			if strings.TrimSpace(mailToken) != "" && strings.TrimSpace(queue[i].MailToken) == "" {
				queue[i].MailToken = strings.TrimSpace(mailToken)
				updated = true
			}
			if strings.TrimSpace(mailConfigKey) != "" && strings.TrimSpace(queue[i].MailConfigKey) == "" {
				queue[i].MailConfigKey = strings.TrimSpace(mailConfigKey)
				updated = true
			}
			if updated {
				return s.savePendingQueue(queue)
			}
			return nil // already in queue
		}
	}
	queue = append(queue, PendingAccount{
		Email:         email,
		Password:      password,
		MailProvider:  strings.TrimSpace(mailProvider),
		MailToken:     strings.TrimSpace(mailToken),
		MailConfigKey: strings.TrimSpace(mailConfigKey),
		CreatedAt:     NowLocalString(),
		Status:        "pending",
	})
	return s.savePendingQueue(queue)
}

func (s *StateStore) DequeuePending() *PendingAccount {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	queue := s.loadPendingQueue()
	for i, item := range queue {
		if item.Status == "pending" {
			queue[i].Status = "processing"
			_ = s.savePendingQueue(queue)
			return &queue[i]
		}
	}
	return nil
}

func (s *StateStore) PendingQueueLength() int {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	queue := s.loadPendingQueue()
	count := 0
	for _, item := range queue {
		if item.Status == "pending" || item.Status == "processing" {
			count++
		}
	}
	return count
}

func (s *StateStore) MarkPendingDone(email, status string) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	queue := s.loadPendingQueue()
	for i, item := range queue {
		if item.Email == email {
			queue[i].Status = status
			_ = s.savePendingQueue(queue)
			return
		}
	}
}
