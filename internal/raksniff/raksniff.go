// Package raksniff passively extracts Bedrock player identities (gamertag /
// XUID) from the cleartext RakNet login handshake transiting a UDP forwarder.
//
// 纯旁路设计：只解析客户端方向的握手副本，绝不修改或拦截数据流；
// 解析失败时静默降级为"只记 IP"，任何错误都不允许影响转发主链路。
package raksniff

import (
	"sync"
	"time"
)

// Identity is the extracted player identity from a Login handshake.
type Identity struct {
	Gamertag string
	XUID     string
}

const (
	// per-session/session-count limits keep memory bounded under garbage traffic
	maxRawWindow   = 96 * 1024 // 未识别载荷累计上限，超过即放弃 | buffered-payload budget
	maxPayloadSize = 32 * 1024 // 单个重组载荷上限 | single reassembled packet cap
	maxSessions    = 4096      // 同时追踪会话上限 | concurrent tracked sessions
	sessionTTL     = time.Minute
)

// Session accumulates client payloads of one address tuple until identity is
// extracted or the byte budget runs out.
type Session struct {
	mu         sync.Mutex
	splits     map[uint16]*pendingSplit // 进行中的分片重组 | in-flight fragment groups
	rawPieces  [][]byte                 // 已完成的候选载荷 | completed candidate payloads
	rawBytes   int                      // 累计预算 | accumulated bytes
	identified bool
	failed     bool // 预算耗尽放弃 | gave up
	lastTouch  time.Time
}

type pendingSplit struct {
	total    uint32
	frags    map[uint32][]byte
	received uint32
	bytes    int
}

// IdentityCallback fires once per session when an identity resolves; it runs
// on the forwarding worker goroutine and must stay fast and non-blocking.
type IdentityCallback func(key, srcIP string, srcPort int, id Identity)

// Controller owns tracked sessions keyed by an opaque string (typically
// "<ruleID>|<srcIP>:<srcPort>"). Safe for concurrent use; nil-safe methods.
type Controller struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

// NewController creates a controller.
func NewController() *Controller {
	return &Controller{sessions: make(map[string]*Session)}
}

// Observe feeds one raw client datagram for the given session key. When the
// login handshake resolves, ok=true and the identity are returned exactly
// once per session. Observe never fails loudly: malformed input is silent.
func (c *Controller) Observe(key string, datagram []byte, srcIP string, srcPort int, cb IdentityCallback) (Identity, bool) {
	if c == nil || len(datagram) == 0 {
		return Identity{}, false
	}

	c.mu.Lock()
	s, exists := c.sessions[key]
	if !exists {
		if len(c.sessions) >= maxSessions {
			c.sweepLocked(true)
		}
		if len(c.sessions) >= maxSessions {
			c.mu.Unlock()
			return Identity{}, false
		}
		s = newSession()
		c.sessions[key] = s
	}
	s.lastTouch = time.Now()
	c.mu.Unlock()

	id, ok := s.observe(key, datagram)
	if ok && cb != nil {
		cb(key, srcIP, srcPort, id)
	}
	return id, ok
}

// Release drops all state for one session.
func (c *Controller) Release(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.sessions, key)
	c.mu.Unlock()
}

// Close releases everything.
func (c *Controller) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.sessions = make(map[string]*Session)
	c.mu.Unlock()
}

// DebugObserve 本地测试诊断用：返回内部阶段状态（生产勿用）。
func (c *Controller) DebugObserve(key string, datagram []byte) (payloads int, identified, failed, panicked bool, id Identity) {
	if c == nil || len(datagram) == 0 {
		return 0, false, false, false, Identity{}
	}
	c.mu.Lock()
	s, exists := c.sessions[key]
	if !exists {
		s = newSession()
		c.sessions[key] = s
	}
	c.mu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
		s.mu.Lock()
		identified, failed = s.identified, s.failed
		s.mu.Unlock()
	}()
	newPayloads := s.accept(datagram)
	payloads = len(newPayloads)
	if len(newPayloads) > 0 {
		if i, f := extractIdentity(s.rawPieces); f {
			id = i
			identified = true
		}
	}
	return payloads, identified, failed, panicked, id
}

func (c *Controller) sweepLocked(force bool) {
	now := time.Now()
	for k, s := range c.sessions {
		if force || now.Sub(s.lastTouch) > sessionTTL {
			delete(c.sessions, k)
		}
	}
}

func newSession() *Session {
	return &Session{
		splits:    make(map[uint16]*pendingSplit),
		lastTouch: time.Now(),
	}
}

// observe implements the per-session pipeline: parse frames → reassemble →
// accumulate → attempt extraction. All failures are silent no-ops by design.
func (s *Session) observe(key string, datagram []byte) (id Identity, found bool) {
	// 解析器对未知格式的任何缺陷都不允许波及转发链路
	defer func() {
		if r := recover(); r != nil {
			s.identified = true // 视为已处理，停止对该会话的嗅探投入
			id, found = Identity{}, false
		}
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.identified || s.failed {
		return Identity{}, false
	}

	newPayloads := s.accept(datagram)
	if len(newPayloads) > 0 {
		s.rawPieces = append(s.rawPieces, newPayloads...)
		s.rawBytes += totalLen(newPayloads)
		for s.rawBytes > maxRawWindow && len(s.rawPieces) > 1 {
			// 超出预算：丢最旧的候选 | budget exceeded: drop oldest candidate
			s.rawBytes -= len(s.rawPieces[0])
			s.rawPieces = s.rawPieces[1:]
		}
		if id, found := extractIdentity(s.rawPieces); found {
			s.identified = true
			return id, true
		}
	}
	if s.rawBytes >= maxRawWindow {
		s.failed = true
		s.rawPieces = nil
	}
	return Identity{}, false
}

func totalLen(ps [][]byte) int {
	n := 0
	for _, p := range ps {
		n += len(p)
	}
	return n
}
