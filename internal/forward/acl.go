package forward

import (
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ACLGuard 持有编译后的黑白名单快照；热路径无锁读取。
// ACLGuard holds a compiled snapshot of the IP access-control list.
type ACLGuard struct {
	v atomic.Pointer[aclSnapshot]
}

type aclSnapshot struct {
	denies []scopedNet
	allows []scopedNet
}

type scopedNet struct {
	ipnet  *net.IPNet
	global bool // RuleID 为空表示作用于全部规则 | applies to all rules
	ruleID string
}

func compileACL(entries []*models.ACLEntry) *aclSnapshot {
	s := &aclSnapshot{}
	for _, e := range entries {
		_, ipnet, err := net.ParseCIDR(e.CIDR)
		if err != nil {
			continue // 存储里的脏数据直接跳过 | skip stale rows
		}
		sc := scopedNet{ipnet: ipnet, global: e.RuleID == "", ruleID: e.RuleID}
		if strings.EqualFold(e.Action, models.ACLActionDeny) {
			s.denies = append(s.denies, sc)
		} else {
			s.allows = append(s.allows, sc)
		}
	}
	return s
}

// Reload replaces the snapshot.
func (g *ACLGuard) Reload(entries []*models.ACLEntry) {
	g.v.Store(compileACL(entries))
}

// Allowed reports whether a source IP may reach the given rule.
// 判定顺序：先看是否命中 deny，再看是否存在未被任何 allow 覆盖的空白——
// 单一算法同时支持黑名单与白名单两种用法。nil 守卫视为全部放行。
// 注意：allow 的"白名单隐式拒绝"只作用于其作用域内的规则。
func (g *ACLGuard) Allowed(ruleID string, ip net.IP) bool {
	if g == nil || ip == nil {
		return true
	}
	s := g.v.Load()
	if s == nil {
		return true
	}
	scopeMatch := func(sc *scopedNet) bool {
		return sc.global || sc.ruleID == ruleID
	}
	for i := range s.denies {
		if scopeMatch(&s.denies[i]) && s.denies[i].ipnet.Contains(ip) {
			return false
		}
	}
	allowScoped := false
	matchedAllow := false
	for i := range s.allows {
		if !scopeMatch(&s.allows[i]) {
			continue
		}
		allowScoped = true
		if s.allows[i].ipnet.Contains(ip) {
			matchedAllow = true
		}
	}
	if allowScoped && !matchedAllow {
		return false // 本规则作用域存在 allow，但该来源不在其列：隐式拒绝
	}
	return true
}

// connLogger 异步把连接事件写入存储（热路径非阻塞，队列满则丢弃）。
// connLogger persists connection events asynchronously off the hot path;
// overflow drops newest events rather than blocking forwarders.
type connLogger struct {
	store      storage.Store
	ch         chan models.ConnLogEntry
	maxEntries int
	// maxFn 返回管理员在全局设置里配置的每用户保留上限；nil/返回非正值时
	// 回落 maxEntries（config.yaml 的旧配置面）。
	maxFn    func() int
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	appends  int
}

func newConnLogger(store storage.Store, maxEntries int) *connLogger {
	l := &connLogger{
		store:      store,
		ch:         make(chan models.ConnLogEntry, 1024),
		maxEntries: maxEntries,
		stop:       make(chan struct{}),
	}
	l.wg.Add(1)
	go l.loop()
	return l
}

// SetMaxProvider 挂接运行时的保留上限来源（main.go 装配完 users 服务后调用）。
func (l *connLogger) SetMaxProvider(fn func() int) {
	if l == nil {
		return
	}
	l.maxFn = fn
}

func (l *connLogger) effectiveMax() int {
	if l.maxFn != nil {
		if v := l.maxFn(); v > 0 {
			return v
		}
	}
	if l.maxEntries <= 0 {
		return 2000
	}
	return l.maxEntries
}

func (l *connLogger) Log(e models.ConnLogEntry) {
	if l == nil {
		return
	}
	select {
	case l.ch <- e:
	default: // 队列满宁可丢日志也不阻塞转发 | drop instead of blocking
	}
}

func (l *connLogger) Close() {
	if l == nil {
		return
	}
	l.stopOnce.Do(func() {
		close(l.stop)
		l.wg.Wait()
	})
}

func (l *connLogger) loop() {
	defer l.wg.Done()
	const trimEvery = 256
	for {
		select {
		case <-l.stop:
			return
		case e := <-l.ch:
			if err := l.store.AppendConnLog(&e); err != nil {
				continue
			}
			l.appends++
			if l.appends%trimEvery == 0 {
				_, _ = l.store.TrimConnLogs(l.effectiveMax())
			}
		}
	}
}

// sessionRegistry 跟踪当前活跃的客户端会话（conntrack 风格视图），TCP/UDP 通用。
// sessionRegistry tracks currently-active client sessions; shared by TCP and UDP.
type sessionRegistry struct {
	// RWMutex：快照是周期性的只读全量遍历，与热路径的登记/移除用读写锁分开，
	// 避免风暴期间快照把会话登记卡住。
	mu sync.RWMutex
	m  map[string]*sessionInfo
}

// sessionInfo is one live client session; bytes are per-connection atomics.
type sessionInfo struct {
	key      string // "<proto>|<ruleID>|<srcIP>:<srcPort>"
	Protocol models.Protocol
	RuleID   string
	RuleName string
	UserID   string
	SrcIP    string
	SrcPort  int
	Since    time.Time
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{m: make(map[string]*sessionInfo)}
}

// obtain returns the existing session info or registers a fresh one.
func (r *sessionRegistry) obtain(key string, fresh *sessionInfo) *sessionInfo {
	if r == nil {
		return fresh
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if si, ok := r.m[key]; ok {
		return si
	}
	r.m[key] = fresh
	return fresh
}

func (r *sessionRegistry) remove(key string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.m, key)
	r.mu.Unlock()
}

func (r *sessionRegistry) snapshot() []models.SessionEntry {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]models.SessionEntry, 0, len(r.m))
	for _, si := range r.m {
		out = append(out, si.view())
	}
	return out
}

// view 生成会话面板的只读视图。
func (si *sessionInfo) view() models.SessionEntry {
	return models.SessionEntry{
		Key:      si.key,
		Protocol: si.Protocol,
		RuleID:   si.RuleID,
		RuleName: si.RuleName,
		SrcIP:    si.SrcIP,
		SrcPort:  si.SrcPort,
		Since:    si.Since,
		BytesIn:  si.bytesIn.Load(),
		BytesOut: si.bytesOut.Load(),
	}
}

// finish 结束会话：有实际流量时落一条离开日志（控制噪音）。
func (si *sessionInfo) finish(ev models.ConnEvent, logs *connLogger) {
	in, out := si.bytesIn.Load(), si.bytesOut.Load()
	if logs == nil || (in == 0 && out == 0) {
		return
	}
	logs.Log(models.ConnLogEntry{
		Protocol: si.Protocol,
		RuleID:   si.RuleID,
		RuleName: si.RuleName,
		UserID:   si.UserID,
		SrcIP:    si.SrcIP,
		SrcPort:  si.SrcPort,
		Event:    ev,
		BytesIn:  in,
		BytesOut: out,
	})
}

// forwardServices 是注入到各转发器的旁路服务集合；所有字段与方法都可空。
type forwardServices struct {
	guard    *ACLGuard
	sessions *sessionRegistry
	logs     *connLogger
}

func (s *forwardServices) allowed(ruleID string, ip net.IP) bool {
	if s == nil {
		return true
	}
	return s.guard.Allowed(ruleID, ip)
}

func (s *forwardServices) logEvent(e models.ConnLogEntry) {
	if s == nil {
		return
	}
	s.logs.Log(e)
}
