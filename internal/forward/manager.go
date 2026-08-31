package forward

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"go-port-forward/internal/config"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
	"go-port-forward/pkg/pool"

	"github.com/google/uuid"
)

var (
	// ErrInvalidRule indicates invalid or out-of-range rule input.
	ErrInvalidRule = errors.New("invalid rule")
	// ErrPortConflict indicates listen address/port/protocol overlap.
	ErrPortConflict = errors.New("port conflict")
)

type entry struct {
	tcp *TCPForwarder
	udp *UDPForwarder
}

// Manager owns the lifecycle of all active forwarders.
type Manager struct {
	store           storage.Store
	rules           map[string]*models.ForwardRule
	active          map[string]*entry // rule ID → forwarders
	errors          map[string]string // rule ID → current error message
	lastErrors      map[string]string // rule ID → most recent error message
	errorTimes      map[string]time.Time
	errorCounts     map[string]int64
	statuses        map[string]models.RuleStatus
	statusChangedAt map[string]time.Time
	cfg             config.ForwardConfig
	svc             *forwardServices // ACL/嗅探/玩家/日志 旁路服务集合
	opsMu           sync.Mutex
	mu              sync.RWMutex
}

// NewManager creates a Manager and loads existing rules from storage.
// The goroutine pool is managed globally via pkg/pool.
func NewManager(store storage.Store, cfg config.ForwardConfig) (*Manager, error) {
	// Ensure global goroutine pool is initialized (lazy init if not done yet).
	poolSize := cfg.PoolSize
	if poolSize <= 0 {
		poolSize = 10000
	}
	if err := pool.InitGoroutinePool(poolSize, true); err != nil {
		return nil, err
	}

	m := &Manager{
		store:           store,
		cfg:             cfg,
		rules:           make(map[string]*models.ForwardRule),
		active:          make(map[string]*entry),
		errors:          make(map[string]string),
		lastErrors:      make(map[string]string),
		errorTimes:      make(map[string]time.Time),
		errorCounts:     make(map[string]int64),
		statuses:        make(map[string]models.RuleStatus),
		statusChangedAt: make(map[string]time.Time),
	}

	// 旁路服务：访问控制 / 玩家嗅探 / 连接日志（任何一部分失败都不阻断启动）
	if err := m.initServices(); err != nil {
		return nil, err
	}

	// Start all enabled rules persisted from a previous run.
	rules, err := store.ListRules()
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		m.rules[r.ID] = cloneRule(r)
		if r.Enabled {
			if e2 := m.startForwarders(r); e2 != nil {
				logger.S.Warnw("failed to start rule on boot", "rule", r.Name, "err", e2)
				m.setRuleError(r.ID, e2.Error())
			} else {
				m.recordRuleStatus(r.ID, models.StatusActive, time.Now())
			}
		} else {
			m.recordRuleStatus(r.ID, models.StatusInactive, statusAnchorTime(r))
		}
	}
	return m, nil
}

// initServices loads the ACL from storage and builds the shared bypass
// services handed to every forwarder.
func (m *Manager) initServices() error {
	maxLog := m.cfg.ConnLogMaxEntries
	if maxLog <= 0 {
		maxLog = 2000
	}

	entries, err := m.store.ListACLEntries()
	if err != nil {
		return fmt.Errorf("加载访问控制名单失败 | failed to load ACL: %w", err)
	}
	guard := &ACLGuard{}
	guard.Reload(entries)

	m.svc = &forwardServices{
		guard:    guard,
		sessions: newSessionRegistry(),
		logs:     newConnLogger(m.store, maxLog),
	}
	return nil
}

// --- ACL / sessions / logs 公共接口（供 Web 层调用）---

// ListACLEntries returns every IP access-control entry.
func (m *Manager) ListACLEntries() ([]*models.ACLEntry, error) {
	return m.store.ListACLEntries()
}

// AddACLEntry validates, persists and applies an IP access-control entry.
func (m *Manager) AddACLEntry(req *models.CreateACLRequest) (*models.ACLEntry, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: 请求不能为空 | request is required", ErrInvalidRule)
	}
	entry, err := models.NormalizeAndValidateACL(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	if entry.RuleID != "" {
		m.mu.RLock()
		_, ok := m.rules[entry.RuleID]
		m.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("%w: 规则不存在 %s | rule not found: %s", ErrInvalidRule, entry.RuleID, entry.RuleID)
		}
	}
	entry.ID = uuid.NewString()
	entry.CreatedAt = time.Now()
	if err := m.store.SaveACLEntry(entry); err != nil {
		return nil, err
	}
	m.reloadACL()
	return entry, nil
}

// DeleteACLEntry removes an entry and re-applies the list live.
func (m *Manager) DeleteACLEntry(id string) error {
	if err := m.store.DeleteACLEntry(id); err != nil {
		return err
	}
	m.reloadACL()
	return nil
}

// SessionsForUser 返回归属于某用户的规则上的活跃会话。
// userID 为空时返回全部（管理员视图）。
func (m *Manager) SessionsForUser(userID string) []models.SessionEntry {
	all := m.svc.sessions.snapshot()
	if userID == "" {
		return all
	}
	owned := m.ruleOwners()
	out := make([]models.SessionEntry, 0, len(all))
	for _, s := range all {
		if owned[s.RuleID] == userID {
			out = append(out, s)
		}
	}
	return out
}

// SessionIPsByCode 按「规则目标地址 → 访问码」分组活跃会话的来源 IP。
//
// 这是隧道回程路由推送的数据源。分组是隔离的一部分：把全部玩家 IP 推给每个
// 隧道客户端，等于让 A 为 B 的玩家安装 /32 回程路由，也把 B 的玩家地址泄漏
// 给了 A。
//
// tunIPToCode 由调用方（装配层）提供，因为「哪个隧道地址属于哪个访问码」是
// 用户服务的知识，manager 不该知道访问码的存在。
func (m *Manager) SessionIPsByCode(tunIPToCode map[string]string) map[string][]string {
	if len(tunIPToCode) == 0 {
		return nil
	}
	targets := m.ruleTargets()
	out := make(map[string][]string)
	seen := make(map[string]map[string]bool)
	for _, s := range m.svc.sessions.snapshot() {
		if s.SrcIP == "" {
			continue
		}
		codeID := tunIPToCode[targets[s.RuleID]]
		if codeID == "" {
			continue
		}
		if seen[codeID] == nil {
			seen[codeID] = make(map[string]bool)
		}
		if seen[codeID][s.SrcIP] {
			continue
		}
		seen[codeID][s.SrcIP] = true
		out[codeID] = append(out[codeID], s.SrcIP)
	}
	return out
}

// ruleTargets 返回「规则 ID → 目标地址」快照。
func (m *Manager) ruleTargets() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.rules))
	for id, r := range m.rules {
		out[id] = r.TargetAddr
	}
	return out
}

// ruleOwners 返回「规则 ID → 归属用户 ID」快照。
func (m *Manager) ruleOwners() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.rules))
	for id, r := range m.rules {
		out[id] = r.UserID
	}
	return out
}

// CountRulesByUser 返回某用户名下的规则数（配额校验用）。
func (m *Manager) CountRulesByUser(userID string) int {
	if userID == "" {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, r := range m.rules {
		if r.UserID == userID {
			n++
		}
	}
	return n
}

// CountRulesByTarget 返回目标地址等于 addr 的规则数。
//
// 删访问码前用它确认没有规则还指着那条隧道：规则的 target_addr 就是「这条规则
// 喂给哪条隧道」的唯一真相，删掉访问码而留下规则，流量会被发进一个不再属于
// 任何人的地址，而界面上看不出异常。
func (m *Manager) CountRulesByTarget(addr string) int {
	if addr == "" {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, r := range m.rules {
		if r.TargetAddr == addr {
			n++
		}
	}
	return n
}

// ConnLogsForUser 分页返回某用户的连接日志（userID 为空 = admin 全量视图）。
// 日志落桶时已带归属（UserID 在产生点写入），存储按用户分桶，这里不再需要
// 「多取再过滤」的补偿逻辑。
func (m *Manager) ConnLogsForUser(userID string, page, perPage int) ([]*models.ConnLogEntry, int, error) {
	if page < 1 {
		page = 1
	}
	return m.store.ListConnLogs(userID, (page-1)*perPage, perPage)
}

// DeleteConnLogs 按 ID 批量删除连接日志（userID 为空 = admin 全量）。
func (m *Manager) DeleteConnLogs(userID string, ids []string) (int, error) {
	return m.store.DeleteConnLogs(userID, ids)
}

// ClearConnLogs 清空某用户（或全部）的连接日志。
func (m *Manager) ClearConnLogs(userID string) (int, error) {
	return m.store.ClearConnLogs(userID)
}

// SetConnLogMaxProvider 挂接每用户日志保留上限的运行时来源。main.go 在
// users 服务就绪后调用；未挂接时用 config.yaml 的 connlog_max_entries。
func (m *Manager) SetConnLogMaxProvider(fn func() int) {
	m.svc.logs.SetMaxProvider(fn)
}

func (m *Manager) reloadACL() {
	if entries, err := m.store.ListACLEntries(); err == nil {
		m.svc.guard.Reload(entries)
	} else {
		logger.S.Warnw("ACL reload failed", "err", err)
	}
}

// ValidateCreateRequest normalizes and validates a create request without persisting it.
func (m *Manager) ValidateCreateRequest(req *models.CreateRuleRequest) error {
	if err := models.ValidateCreateRuleRequest(req); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	if err := m.checkPortConflict(req.ListenAddr, req.ListenPort, req.Protocol, ""); err != nil {
		return err
	}
	return nil
}

// AddRule validates, persists and starts a new rule.
func (m *Manager) AddRule(req *models.CreateRuleRequest) (*models.ForwardRule, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: 请求不能为空 | request is required", ErrInvalidRule)
	}
	m.opsMu.Lock()
	defer m.opsMu.Unlock()

	normalized := *req
	if err := m.ValidateCreateRequest(&normalized); err != nil {
		return nil, err
	}
	r := &models.ForwardRule{
		ID:            uuid.NewString(),
		Name:          normalized.Name,
		ListenAddr:    normalized.ListenAddr,
		ListenPort:    normalized.ListenPort,
		Protocol:      normalized.Protocol,
		TargetAddr:    normalized.TargetAddr,
		TargetPort:    normalized.TargetPort,
		UserID:        normalized.UserID,
		AddFirewall:   normalized.AddFirewall,
		ProxyProtocol: normalized.ProxyProtocol,
		Transparent:   normalized.Transparent,
		Comment:       normalized.Comment,
		Enabled:       normalized.Enabled,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := m.store.SaveRule(r); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.rules[r.ID] = cloneRule(r)
	delete(m.errors, r.ID)
	m.mu.Unlock()
	if r.Enabled {
		if err := m.startForwarders(r); err != nil {
			m.setRuleError(r.ID, err.Error())
		} else {
			m.clearRuleError(r.ID)
			m.recordRuleStatus(r.ID, models.StatusActive, time.Now())
		}
	} else {
		m.recordRuleStatus(r.ID, models.StatusInactive, statusAnchorTime(r))
	}
	return m.decorateRule(r), nil
}

// UpdateRule applies partial updates to an existing rule (restarts forwarders as needed).
func (m *Manager) UpdateRule(id string, req *models.UpdateRuleRequest) (*models.ForwardRule, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: 请求不能为空 | request is required", ErrInvalidRule)
	}
	m.opsMu.Lock()
	defer m.opsMu.Unlock()

	current, err := m.ruleFromCache(id)
	if err != nil {
		return nil, err
	}
	next := cloneRule(current)
	applyUpdate(next, req)
	next.UpdatedAt = time.Now()

	if err := models.ValidateForwardRule(next); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}

	// Port conflict detection (exclude self)
	if err := m.checkPortConflict(next.ListenAddr, next.ListenPort, next.Protocol, id); err != nil {
		return nil, err
	}

	if err := m.store.SaveRule(next); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.rules[id] = cloneRule(next)
	m.mu.Unlock()

	if !requiresForwarderRestart(current, next) {
		return m.decorateRule(next), nil
	}

	m.stopForwarders(id)
	statusChangedAt := time.Now()
	if next.Enabled {
		if err := m.startForwarders(next); err != nil {
			m.setRuleError(next.ID, err.Error())
		} else {
			m.clearRuleError(next.ID)
			m.recordRuleStatus(next.ID, models.StatusActive, statusChangedAt)
		}
	} else {
		m.clearRuleError(next.ID)
		m.recordRuleStatus(next.ID, models.StatusInactive, statusChangedAt)
	}
	return m.decorateRule(next), nil
}

// DeleteRule stops and removes a rule permanently.
func (m *Manager) DeleteRule(id string) error {
	m.opsMu.Lock()
	defer m.opsMu.Unlock()

	if _, err := m.ruleFromCache(id); err != nil {
		return err
	}
	if err := m.store.DeleteRule(id); err != nil {
		return err
	}
	m.stopForwarders(id)
	m.mu.Lock()
	delete(m.rules, id)
	delete(m.errors, id)
	delete(m.lastErrors, id)
	delete(m.errorTimes, id)
	delete(m.errorCounts, id)
	delete(m.statuses, id)
	delete(m.statusChangedAt, id)
	m.mu.Unlock()
	return nil
}

// ToggleRule enables or disables a rule.
func (m *Manager) ToggleRule(id string, enabled bool) (*models.ForwardRule, error) {
	on := enabled
	return m.UpdateRule(id, &models.UpdateRuleRequest{Enabled: &on})
}

// ListRules returns all rules with live stats merged in.
func (m *Manager) ListRules() ([]*models.ForwardRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rules := m.ruleClonesLocked()
	for _, r := range rules {
		m.applyRuntimeStateLocked(r)
	}
	return rules, nil
}

// ListRulesForUser returns rules owned by userID with live stats merged in.
// userID 为空时返回全部（管理员视图）。
func (m *Manager) ListRulesForUser(userID string) ([]*models.ForwardRule, error) {
	all, err := m.ListRules()
	if err != nil {
		return nil, err
	}
	if userID == "" {
		return all, nil
	}
	out := make([]*models.ForwardRule, 0, len(all))
	for _, r := range all {
		if r.UserID == userID {
			out = append(out, r)
		}
	}
	return out, nil
}

// Snapshot returns current rules together with aggregated stats derived from the same snapshot.
func (m *Manager) Snapshot() ([]*models.ForwardRule, *models.Stats, error) {
	rules, err := m.ListRules()
	if err != nil {
		return nil, nil, err
	}
	return rules, buildStats(rules), nil
}

// SnapshotForUser 是 Snapshot 的按用户视图：统计只覆盖该用户自己的规则，
// 否则普通用户会在仪表盘上看到全站流量。
func (m *Manager) SnapshotForUser(userID string) ([]*models.ForwardRule, *models.Stats, error) {
	rules, err := m.ListRulesForUser(userID)
	if err != nil {
		return nil, nil, err
	}
	return rules, buildStats(rules), nil
}

// GetRule returns one rule with live stats.
func (m *Manager) GetRule(id string) (*models.ForwardRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.rules[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", storage.ErrRuleNotFound, id)
	}
	r = cloneRule(r)
	m.applyRuntimeStateLocked(r)
	return r, nil
}

// GlobalStats aggregates stats across all rules.
func (m *Manager) GlobalStats() *models.Stats {
	_, stats, err := m.Snapshot()
	if err != nil {
		return &models.Stats{}
	}
	return stats
}

// Diagnostics returns a lightweight operational snapshot for troubleshooting.
func (m *Manager) Diagnostics() (*models.ManagerDiagnostics, error) {
	rules, stats, err := m.Snapshot()
	if err != nil {
		return nil, err
	}
	d := &models.ManagerDiagnostics{
		CachedRules:     len(rules),
		Stats:           stats,
		HotRules:        make([]models.RuleTrafficSummary, 0),
		TopActiveRules:  make([]models.RuleTrafficSummary, 0),
		TopTrafficRules: make([]models.RuleTrafficSummary, 0),
		TopErrorRules:   make([]models.RuleErrorSummary, 0),
	}
	m.mu.RLock()
	d.ActiveForwarders = len(m.active)
	d.ErrorRules = len(m.errors)
	lastErrors := cloneStringMap(m.lastErrors)
	errorTimes := cloneTimeMap(m.errorTimes)
	errorCounts := cloneInt64Map(m.errorCounts)
	statusChangedAt := cloneTimeMap(m.statusChangedAt)
	for _, e := range m.active {
		if e == nil {
			continue
		}
		if e.tcp != nil {
			bi, bo, a, t := e.tcp.Stats()
			accumulateProtocolTraffic(&d.Protocols.TCP, bi, bo, a, t)
		}
		if e.udp != nil {
			bi, bo, a, t := e.udp.Stats()
			accumulateProtocolTraffic(&d.Protocols.UDP, bi, bo, a, t)
		}
	}
	m.mu.RUnlock()
	hotRules := make([]models.RuleTrafficSummary, 0, len(rules))
	activeRules := make([]models.RuleTrafficSummary, 0, len(rules))
	trafficRules := make([]models.RuleTrafficSummary, 0, len(rules))
	errorRules := make([]models.RuleErrorSummary, 0, len(rules))
	for _, r := range rules {
		addProtocolConfiguredCounts(&d.Protocols, r.Protocol)
		trafficSummary := buildRuleTrafficSummary(r, statusChangedAt[r.ID], errorTimes[r.ID])
		totalBytes := trafficSummary.TotalBytes
		if r.ActiveConns > 0 || r.TotalConns > 0 || totalBytes > 0 || r.Status == models.StatusActive {
			hotRules = append(hotRules, trafficSummary)
			activeRules = append(activeRules, trafficSummary)
			trafficRules = append(trafficRules, trafficSummary)
		}
		switch r.Status {
		case models.StatusActive:
			d.RuleHealth.Active++
		case models.StatusInactive:
			d.RuleHealth.Inactive++
		case models.StatusError:
			d.RuleHealth.Error++
			if r.ErrorMsg != "" {
				d.Errors = append(d.Errors, buildRuleErrorSummary(r, r.ErrorMsg, errorCounts[r.ID], statusChangedAt[r.ID], errorTimes[r.ID]))
			}
		}
		if errorCounts[r.ID] > 0 || !errorTimes[r.ID].IsZero() || lastErrors[r.ID] != "" {
			errorRules = append(errorRules, buildRuleErrorSummary(r, lastErrors[r.ID], errorCounts[r.ID], statusChangedAt[r.ID], errorTimes[r.ID]))
		}
	}
	sort.Slice(d.Errors, func(i, j int) bool {
		if !d.Errors[i].LastErrorAt.Equal(d.Errors[j].LastErrorAt) {
			return d.Errors[i].LastErrorAt.After(d.Errors[j].LastErrorAt)
		}
		if d.Errors[i].ErrorCount != d.Errors[j].ErrorCount {
			return d.Errors[i].ErrorCount > d.Errors[j].ErrorCount
		}
		if d.Errors[i].Name != d.Errors[j].Name {
			return d.Errors[i].Name < d.Errors[j].Name
		}
		if d.Errors[i].ListenPort != d.Errors[j].ListenPort {
			return d.Errors[i].ListenPort < d.Errors[j].ListenPort
		}
		return d.Errors[i].ID < d.Errors[j].ID
	})
	sort.Slice(hotRules, func(i, j int) bool {
		if hotRules[i].ActiveConns != hotRules[j].ActiveConns {
			return hotRules[i].ActiveConns > hotRules[j].ActiveConns
		}
		if hotRules[i].TotalBytes != hotRules[j].TotalBytes {
			return hotRules[i].TotalBytes > hotRules[j].TotalBytes
		}
		if hotRules[i].TotalConns != hotRules[j].TotalConns {
			return hotRules[i].TotalConns > hotRules[j].TotalConns
		}
		if hotRules[i].Name != hotRules[j].Name {
			return hotRules[i].Name < hotRules[j].Name
		}
		return hotRules[i].ID < hotRules[j].ID
	})
	sort.Slice(activeRules, func(i, j int) bool {
		if activeRules[i].ActiveConns != activeRules[j].ActiveConns {
			return activeRules[i].ActiveConns > activeRules[j].ActiveConns
		}
		if activeRules[i].TotalConns != activeRules[j].TotalConns {
			return activeRules[i].TotalConns > activeRules[j].TotalConns
		}
		if activeRules[i].TotalBytes != activeRules[j].TotalBytes {
			return activeRules[i].TotalBytes > activeRules[j].TotalBytes
		}
		if activeRules[i].Name != activeRules[j].Name {
			return activeRules[i].Name < activeRules[j].Name
		}
		return activeRules[i].ID < activeRules[j].ID
	})
	sort.Slice(trafficRules, func(i, j int) bool {
		if trafficRules[i].TotalBytes != trafficRules[j].TotalBytes {
			return trafficRules[i].TotalBytes > trafficRules[j].TotalBytes
		}
		if trafficRules[i].ActiveConns != trafficRules[j].ActiveConns {
			return trafficRules[i].ActiveConns > trafficRules[j].ActiveConns
		}
		if trafficRules[i].TotalConns != trafficRules[j].TotalConns {
			return trafficRules[i].TotalConns > trafficRules[j].TotalConns
		}
		if trafficRules[i].Name != trafficRules[j].Name {
			return trafficRules[i].Name < trafficRules[j].Name
		}
		return trafficRules[i].ID < trafficRules[j].ID
	})
	sort.Slice(errorRules, func(i, j int) bool {
		if errorRules[i].ErrorCount != errorRules[j].ErrorCount {
			return errorRules[i].ErrorCount > errorRules[j].ErrorCount
		}
		if !errorRules[i].LastErrorAt.Equal(errorRules[j].LastErrorAt) {
			return errorRules[i].LastErrorAt.After(errorRules[j].LastErrorAt)
		}
		if errorRules[i].Name != errorRules[j].Name {
			return errorRules[i].Name < errorRules[j].Name
		}
		return errorRules[i].ID < errorRules[j].ID
	})
	if len(hotRules) > 5 {
		hotRules = hotRules[:5]
	}
	if len(activeRules) > 5 {
		activeRules = activeRules[:5]
	}
	if len(trafficRules) > 5 {
		trafficRules = trafficRules[:5]
	}
	if len(errorRules) > 5 {
		errorRules = errorRules[:5]
	}
	d.HotRules = hotRules
	d.TopActiveRules = activeRules
	d.TopTrafficRules = trafficRules
	d.TopErrorRules = errorRules
	return d, nil
}

func buildRuleTrafficSummary(r *models.ForwardRule, lastStatusChangeAt, lastErrorAt time.Time) models.RuleTrafficSummary {
	return models.RuleTrafficSummary{
		ID:                 r.ID,
		Name:               r.Name,
		Protocol:           r.Protocol,
		Status:             r.Status,
		ListenAddr:         r.ListenAddr,
		ListenPort:         r.ListenPort,
		BytesIn:            r.BytesIn,
		BytesOut:           r.BytesOut,
		TotalBytes:         r.BytesIn + r.BytesOut,
		ActiveConns:        r.ActiveConns,
		TotalConns:         r.TotalConns,
		UpdatedAt:          r.UpdatedAt,
		LastErrorAt:        lastErrorAt,
		LastStatusChangeAt: lastStatusChangeAt,
	}
}

func buildRuleErrorSummary(r *models.ForwardRule, errMsg string, errCount int64, lastStatusChangeAt, lastErrorAt time.Time) models.RuleErrorSummary {
	return models.RuleErrorSummary{
		ID:                 r.ID,
		Name:               r.Name,
		Protocol:           r.Protocol,
		Status:             r.Status,
		ListenAddr:         r.ListenAddr,
		ListenPort:         r.ListenPort,
		Error:              errMsg,
		ErrorCount:         errCount,
		UpdatedAt:          r.UpdatedAt,
		LastErrorAt:        lastErrorAt,
		LastStatusChangeAt: lastStatusChangeAt,
	}
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return map[string]string{}
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func cloneTimeMap(src map[string]time.Time) map[string]time.Time {
	if len(src) == 0 {
		return map[string]time.Time{}
	}
	dst := make(map[string]time.Time, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func cloneInt64Map(src map[string]int64) map[string]int64 {
	if len(src) == 0 {
		return map[string]int64{}
	}
	dst := make(map[string]int64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func addProtocolConfiguredCounts(d *models.ProtocolBreakdownDiagnostics, proto models.Protocol) {
	switch models.NormalizeProtocol(proto) {
	case models.ProtocolTCP:
		d.TCP.ConfiguredRules++
	case models.ProtocolUDP:
		d.UDP.ConfiguredRules++
	case models.ProtocolBoth:
		d.TCP.ConfiguredRules++
		d.UDP.ConfiguredRules++
	}
}

func accumulateProtocolTraffic(d *models.ProtocolTrafficDiagnostics, bytesIn, bytesOut, active, total int64) {
	d.ActiveForwarders++
	d.BytesIn += bytesIn
	d.BytesOut += bytesOut
	d.ActiveConns += active
	d.TotalConns += total
}

func buildStats(rules []*models.ForwardRule) *models.Stats {
	s := &models.Stats{TotalRules: len(rules)}
	for _, r := range rules {
		if r.Enabled {
			s.EnabledRules++
		}
		if r.Status == models.StatusActive {
			s.ActiveRules++
		}
		s.TotalBytesIn += r.BytesIn
		s.TotalBytesOut += r.BytesOut
		s.TotalConns += r.TotalConns
	}
	return s
}

// Shutdown stops all active forwarders.
// The global goroutine pool is released separately in main shutdown.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	for id := range m.active {
		m.stopForwardersLocked(id)
	}
	m.mu.Unlock()
}

// --- internal helpers ---

// checkPortConflict returns an error if the given listen addr/port/protocol
// overlaps with any existing rule (excluding the rule with excludeID).
func (m *Manager) checkPortConflict(listenAddr string, listenPort int, proto models.Protocol, excludeID string) error {
	addrA := models.NormalizeListenAddr(listenAddr)
	proto = models.NormalizeProtocol(proto)
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.rules {
		if r.ID == excludeID {
			continue
		}
		addrB := models.NormalizeListenAddr(r.ListenAddr)
		if addrA != addrB || r.ListenPort != listenPort {
			continue
		}
		if protocolsOverlap(proto, r.Protocol) {
			return fmt.Errorf("%w: %s:%d 已被规则 | already used by rule %q 占用 (协议 | protocol %s)",
				ErrPortConflict,
				addrA, listenPort, r.Name, r.Protocol)
		}
	}
	return nil
}

// protocolsOverlap returns true if protocol a and b share any common transport.
func protocolsOverlap(a, b models.Protocol) bool {
	a = models.NormalizeProtocol(a)
	b = models.NormalizeProtocol(b)
	if a == models.ProtocolBoth || b == models.ProtocolBoth {
		return true
	}
	return a == b
}

func (m *Manager) startForwarders(r *models.ForwardRule) error {
	// 透明模式环境预检（fail-closed：非 Linux / 无权限直接失败并写入规则错误）
	if r.Transparent {
		if r.ProxyProtocol {
			return fmt.Errorf("透明模式与 PROXY 协议互斥 | transparent conflicts with proxy_protocol")
		}
		if r.Protocol != models.ProtocolUDP {
			return fmt.Errorf("透明模式仅支持 UDP 规则（TCP 回包无法送达透明 socket），请将协议改为 udp | transparent mode only supports UDP rules")
		}
		if err := checkTransparentSupport(); err != nil {
			return err
		}
	}
	e := &entry{}
	if r.Protocol == models.ProtocolTCP || r.Protocol == models.ProtocolBoth {
		t := newTCPForwarder(r, m.cfg.DialTimeout, m.cfg.BufferSize)
		t.svc = m.svc
		if err := t.Start(); err != nil {
			return err
		}
		e.tcp = t
	}
	if r.Protocol == models.ProtocolUDP || r.Protocol == models.ProtocolBoth {
		u := newUDPForwarder(r, m.cfg.UDPTimeout)
		u.svc = m.svc
		if err := u.Start(); err != nil {
			if e.tcp != nil {
				e.tcp.Stop()
			}
			return err
		}
		e.udp = u
	}
	m.mu.Lock()
	m.active[r.ID] = e
	m.mu.Unlock()
	return nil
}

func (m *Manager) stopForwarders(id string) {
	m.mu.Lock()
	m.stopForwardersLocked(id)
	m.mu.Unlock()
}

func (m *Manager) stopForwardersLocked(id string) {
	e, ok := m.active[id]
	if !ok {
		return
	}
	if e.tcp != nil {
		e.tcp.Stop()
	}
	if e.udp != nil {
		e.udp.Stop()
	}
	delete(m.active, id)
}

func mergeStats(e *entry) (bytesIn, bytesOut, active, total int64) {
	if e.tcp != nil {
		bi, bo, a, t := e.tcp.Stats()
		bytesIn += bi
		bytesOut += bo
		active += a
		total += t
	}
	if e.udp != nil {
		bi, bo, a, t := e.udp.Stats()
		bytesIn += bi
		bytesOut += bo
		active += a
		total += t
	}
	return
}

func cloneRule(r *models.ForwardRule) *models.ForwardRule {
	if r == nil {
		return nil
	}
	clone := *r
	return &clone
}

func (m *Manager) ruleFromCache(id string) (*models.ForwardRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.rules[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", storage.ErrRuleNotFound, id)
	}
	return cloneRule(r), nil
}

func (m *Manager) ruleClonesLocked() []*models.ForwardRule {
	rules := make([]*models.ForwardRule, 0, len(m.rules))
	for _, r := range m.rules {
		if r != nil {
			rules = append(rules, cloneRule(r))
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		if !rules[i].CreatedAt.Equal(rules[j].CreatedAt) {
			return rules[i].CreatedAt.Before(rules[j].CreatedAt)
		}
		if rules[i].Name != rules[j].Name {
			return rules[i].Name < rules[j].Name
		}
		return rules[i].ID < rules[j].ID
	})
	return rules
}

func (m *Manager) applyRuntimeStateLocked(r *models.ForwardRule) {
	if e, ok := m.active[r.ID]; ok {
		r.Status = models.StatusActive
		r.ErrorMsg = ""
		r.BytesIn, r.BytesOut, r.ActiveConns, r.TotalConns = mergeStats(e)
		return
	}
	if r.Enabled {
		r.Status = models.StatusError
		r.ErrorMsg = m.errors[r.ID]
		return
	}
	r.Status = models.StatusInactive
	r.ErrorMsg = ""
}

func (m *Manager) decorateRule(r *models.ForwardRule) *models.ForwardRule {
	r = cloneRule(r)
	m.mu.RLock()
	m.applyRuntimeStateLocked(r)
	m.mu.RUnlock()
	return r
}

func (m *Manager) setRuleError(id, msg string) {
	now := time.Now()
	m.mu.Lock()
	m.errors[id] = msg
	m.lastErrors[id] = msg
	m.errorTimes[id] = now
	m.errorCounts[id]++
	m.recordRuleStatusLocked(id, models.StatusError, now)
	m.mu.Unlock()
}

func (m *Manager) clearRuleError(id string) {
	m.mu.Lock()
	delete(m.errors, id)
	m.mu.Unlock()
}

func (m *Manager) recordRuleStatus(id string, status models.RuleStatus, at time.Time) {
	m.mu.Lock()
	m.recordRuleStatusLocked(id, status, at)
	m.mu.Unlock()
}

func (m *Manager) recordRuleStatusLocked(id string, status models.RuleStatus, at time.Time) {
	if at.IsZero() {
		at = time.Now()
	}
	prev, ok := m.statuses[id]
	if !ok || prev != status {
		m.statuses[id] = status
		m.statusChangedAt[id] = at
		return
	}
	if _, exists := m.statusChangedAt[id]; !exists {
		m.statusChangedAt[id] = at
	}
}

func statusAnchorTime(r *models.ForwardRule) time.Time {
	if r == nil {
		return time.Time{}
	}
	if !r.UpdatedAt.IsZero() {
		return r.UpdatedAt
	}
	return r.CreatedAt
}

func applyUpdate(r *models.ForwardRule, req *models.UpdateRuleRequest) {
	if req.Name != nil {
		r.Name = *req.Name
	}
	if req.ListenAddr != nil {
		r.ListenAddr = *req.ListenAddr
	}
	if req.ListenPort != nil {
		r.ListenPort = *req.ListenPort
	}
	if req.Protocol != nil {
		r.Protocol = *req.Protocol
	}
	if req.TargetAddr != nil {
		r.TargetAddr = *req.TargetAddr
	}
	if req.TargetPort != nil {
		r.TargetPort = *req.TargetPort
	}
	if req.UserID != nil {
		r.UserID = *req.UserID
	}
	if req.AddFirewall != nil {
		r.AddFirewall = *req.AddFirewall
	}
	if req.ProxyProtocol != nil {
		r.ProxyProtocol = *req.ProxyProtocol
	}
	if req.Transparent != nil {
		r.Transparent = *req.Transparent
	}
	if req.Comment != nil {
		r.Comment = *req.Comment
	}
	if req.Enabled != nil {
		r.Enabled = *req.Enabled
	}
}

func requiresForwarderRestart(before, after *models.ForwardRule) bool {
	if before == nil || after == nil {
		return true
	}
	// UserID 不在此列：归属只影响「谁能看到/改这条规则」与回程路由推送的
	// 分组，转发器本身不读它。为一次纯元数据变更重启转发器会掐掉所有在线
	// 玩家，代价与收益完全不成比例。
	return before.Enabled != after.Enabled ||
		models.NormalizeListenAddr(before.ListenAddr) != models.NormalizeListenAddr(after.ListenAddr) ||
		before.ListenPort != after.ListenPort ||
		models.NormalizeProtocol(before.Protocol) != models.NormalizeProtocol(after.Protocol) ||
		before.TargetAddr != after.TargetAddr ||
		before.TargetPort != after.TargetPort ||
		before.ProxyProtocol != after.ProxyProtocol ||
		before.Transparent != after.Transparent
}
