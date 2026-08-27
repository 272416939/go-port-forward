package forward

import (
	"go-port-forward/internal/models"
	"go-port-forward/internal/raksniff"
	"go-port-forward/internal/storage"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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

// BanGuard 持有按玩家封禁名单的编译快照。
// BanGuard holds the compiled banned-players snapshot.
type BanGuard struct {
	v atomic.Pointer[banSnapshot]
}

type banSnapshot struct {
	gamertags map[string]struct{} // 统一小写比较 | lower-cased
	xuids     map[string]struct{}
}

func compileBans(bans []*models.PlayerBan) *banSnapshot {
	s := &banSnapshot{
		gamertags: make(map[string]struct{}),
		xuids:     make(map[string]struct{}),
	}
	for _, b := range bans {
		v := strings.TrimSpace(b.Value)
		if v == "" {
			continue
		}
		if strings.EqualFold(b.Type, models.PlayerBanTypeXUID) {
			s.xuids[strings.ToLower(v)] = struct{}{}
		} else {
			s.gamertags[strings.ToLower(v)] = struct{}{}
		}
	}
	return s
}

// Reload replaces the snapshot.
func (b *BanGuard) Reload(bans []*models.PlayerBan) {
	b.v.Store(compileBans(bans))
}

// Banned reports whether this identity should be cut immediately.
func (b *BanGuard) Banned(gamertag, xuid string) bool {
	if b == nil || (gamertag == "" && xuid == "") {
		return false
	}
	s := b.v.Load()
	if s == nil {
		return false
	}
	if gamertag != "" {
		if _, hit := s.gamertags[strings.ToLower(gamertag)]; hit {
			return true
		}
	}
	if xuid != "" {
		if _, hit := s.xuids[strings.ToLower(xuid)]; hit {
			return true
		}
	}
	return false
}

// connLogger 异步把连接事件写入存储（热路径非阻塞，队列满则丢弃）。
// connLogger persists connection events asynchronously off the hot path;
// overflow drops newest events rather than blocking forwarders.
type connLogger struct {
	store      storage.Store
	ch         chan models.ConnLogEntry
	maxEntries int
	stop       chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
	appends    int
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
				_, _ = l.store.TrimConnLogs(l.maxEntries)
			}
		}
	}
}

// playerRegistry tracks currently-known Bedrock client sessions（key 同 udpSession.key）。
// 存的是 *udpSession 本体，字节数/身份等直接读会话上的原子计数，避免双份状态。
type playerRegistry struct {
	mu sync.Mutex
	m  map[string]*udpSession
}

func newPlayerRegistry() *playerRegistry {
	return &playerRegistry{m: make(map[string]*udpSession)}
}

func (r *playerRegistry) put(key string, s *udpSession) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.m[key] = s
	r.mu.Unlock()
}

func (r *playerRegistry) get(key string) (*udpSession, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.m[key]
	return s, ok
}

func (r *playerRegistry) remove(key string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.m, key)
	r.mu.Unlock()
}

func (r *playerRegistry) snapshot() []models.OnlinePlayer {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]models.OnlinePlayer, 0, len(r.m))
	for _, s := range r.m {
		out = append(out, s.onlineView())
	}
	return out
}

// forwardServices 是注入到各转发器的旁路服务集合；所有字段与方法都可空。
type forwardServices struct {
	guard   *ACLGuard
	bans    *BanGuard
	sniff   *raksniff.Controller
	players *playerRegistry
	logs    *connLogger
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
