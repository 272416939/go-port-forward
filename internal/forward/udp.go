package forward

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/raksniff"
	"go-port-forward/pkg/pool"

	"github.com/pires/go-proxyproto"
	"go.uber.org/zap"
)

// udpAddrKey 是 UDP 地址的固定大小可比较 key，避免每包调用 String() 产生字符串分配。
// udpAddrKey is a fixed-size comparable key for UDP addresses, avoiding per-packet
// string allocation from String().
type udpAddrKey struct {
	ip   [net.IPv6len]byte // 16 bytes，同时容纳 IPv4 和 IPv6 | fits both IPv4 and IPv6
	port uint16
	len  uint8 // IP 原始长度（4 或 16），确保不同表示不会碰撞 | raw IP length (4 or 16)
	zone string
}

// makeUDPAddrKey 从 *net.UDPAddr 构造零分配的 map key。
// makeUDPAddrKey constructs a zero-allocation map key from *net.UDPAddr.
func makeUDPAddrKey(addr *net.UDPAddr) udpAddrKey {
	var k udpAddrKey
	k.port = uint16(addr.Port)
	k.len = uint8(len(addr.IP))
	k.zone = addr.Zone
	copy(k.ip[:], addr.IP)
	return k
}

// udpSession tracks an upstream UDP connection for a specific client address.
type udpSession struct {
	upstream   *net.UDPConn
	lastSeen   time.Time
	key        string // 全局会话键 "<ruleID>|<src>" | global session key
	srcIP      string
	srcPort    int
	ruleName   string
	idMu       sync.Mutex // 保护下面三个身份字段 | guards identity fields
	playerName string     // 嗅探到的玩家名（可能为空）| sniffed gamertag (may be empty)
	xuid       string
	identified atomic.Bool
	killed     atomic.Bool  // 命中玩家封禁后被踢 | set when banned player is cut
	bIn        atomic.Int64 // client→upstream 实际转发字节 | forwarded client bytes
	bOut       atomic.Int64 // upstream→client 回写字节 | relayed response bytes
	finalOnce  sync.Once
}

// setIdentity 写入嗅探到的身份（并发安全）。
func (s *udpSession) setIdentity(id raksniff.Identity) {
	s.idMu.Lock()
	if id.Gamertag != "" {
		s.playerName = id.Gamertag
	}
	if id.XUID != "" {
		s.xuid = id.XUID
	}
	s.idMu.Unlock()
	s.identified.Store(true)
}

// identityView 返回身份快照。
func (s *udpSession) identityView() (player, xuid string, identified bool) {
	s.idMu.Lock()
	defer s.idMu.Unlock()
	return s.playerName, s.xuid, s.identified.Load()
}

// onlineView 生成在线玩家面板的只读视图。
func (s *udpSession) onlineView() models.OnlinePlayer {
	player, xuid, _ := s.identityView()
	return models.OnlinePlayer{
		SessionKey: s.key,
		RuleName:   s.ruleName,
		Player:     player,
		XUID:       xuid,
		SrcIP:      s.srcIP,
		SrcPort:    s.srcPort,
		Since:      s.lastSeen,
		BytesIn:    s.bIn.Load(),
		BytesOut:   s.bOut.Load(),
	}
}

// sessionKey 构造跨转发器唯一的会话键。
func sessionKey(ruleID string, addr *net.UDPAddr) string {
	return ruleID + "|" + addr.String()
}

// UDPForwarder listens on a local UDP port and forwards datagrams to a target.
type UDPForwarder struct {
	rule        *models.ForwardRule
	conn        *net.UDPConn
	targetAddr  *net.UDPAddr
	sessions    map[udpAddrKey]*udpSession
	stopCh      chan struct{}
	wg          sync.WaitGroup
	timeout     time.Duration
	proxyProto  bool
	svc         *forwardServices // 旁路服务（ACL/嗅探/玩家/日志），测试下可为 nil
	lastDenied  atomic.Int64     // 拒绝日志限频 | denial-log rate limit anchor
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
	active      atomic.Int64
	totalConns  atomic.Int64
	stopOnce    sync.Once
	mu          sync.Mutex
}

func newUDPForwarder(rule *models.ForwardRule, timeoutSec int) *UDPForwarder {
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	return &UDPForwarder{
		rule:       rule,
		timeout:    time.Duration(timeoutSec) * time.Second,
		proxyProto: rule.ProxyProtocol,
		sessions:   make(map[udpAddrKey]*udpSession),
		stopCh:     make(chan struct{}),
	}
}

func (f *UDPForwarder) Start() error {
	listenAddr := fmt.Sprintf("%s:%d", f.rule.ListenAddr, f.rule.ListenPort)
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("UDP 监听失败 | UDP listen failed %s: %w", listenAddr, err)
	}
	targetAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", f.rule.TargetAddr, f.rule.TargetPort))
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("UDP 目标地址无效 | invalid UDP target address: %w", err)
	}
	f.conn = conn
	f.targetAddr = targetAddr

	f.wg.Add(2)
	go f.readLoop()
	go f.cleanupLoop()

	logger.S.Infow("UDP forwarder started", "rule", f.rule.Name, "listen", listenAddr,
		"target", fmt.Sprintf("%s:%d", f.rule.TargetAddr, f.rule.TargetPort),
		"proxy_protocol", f.proxyProto)
	return nil
}

func (f *UDPForwarder) Stop() {
	f.stopOnce.Do(func() {
		close(f.stopCh)
		if f.conn != nil {
			_ = f.conn.Close()
		}
		f.mu.Lock()
		for key, s := range f.sessions {
			_ = s.upstream.Close()
			f.finalizeSession(s, models.ConnEventLeave)
			delete(f.sessions, key)
		}
		f.active.Store(0)
		f.mu.Unlock()
	})
	f.wg.Wait()
}

func (f *UDPForwarder) readLoop() {
	defer f.wg.Done()
	// Use pooled buffer for reading
	buf := pool.GetBuffer(65535)
	defer pool.PutBuffer(buf)
	for {
		n, srcAddr, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-f.stopCh:
				return
			default:
				if ne, ok := errors.AsType[net.Error](err); ok && ne.Temporary() {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				logger.L.Warn("UDP read error", zap.Error(err))
				return
			}
		}
		// 访问控制：拒绝的包直接丢弃（UDP 无"拒绝应答"概念）
		if !f.svc.allowed(f.rule.ID, srcAddr.IP) {
			f.logDenied(srcAddr)
			continue
		}
		// Copy packet data for async processing
		pkt := pool.GetBuffer(n)[:n]
		copy(pkt, buf[:n])
		// Use goroutine pool via pkg/pool
		if err := pool.Submit(func() { f.forward(srcAddr, pkt) }); err != nil {
			go f.forward(srcAddr, pkt)
		}
	}
}

// logDenied 记录被访问控制拒绝的来源，按 5 秒限频避免日志刷屏。
func (f *UDPForwarder) logDenied(srcAddr *net.UDPAddr) {
	now := time.Now().Unix()
	last := f.lastDenied.Load()
	if now-last < 5 && !f.lastDenied.CompareAndSwap(last, now) {
		return
	}
	logger.S.Warnw("UDP source denied by ACL", "rule", f.rule.Name,
		"src", srcAddr.String())
	if f.svc != nil {
		f.svc.logEvent(models.ConnLogEntry{
			Protocol: models.ProtocolUDP,
			RuleID:   f.rule.ID,
			RuleName: f.rule.Name,
			SrcIP:    srcAddr.IP.String(),
			SrcPort:  srcAddr.Port,
			Event:    models.ConnEventDenied,
		})
	}
}

func (f *UDPForwarder) forward(srcAddr *net.UDPAddr, data []byte) {
	defer pool.PutBuffer(data)
	if f.isStopping() {
		return
	}
	sess, created := f.getOrCreateSession(srcAddr)
	if sess == nil {
		return
	}
	if sess.killed.Load() {
		return // 被封禁玩家的后续包直接丢弃 | banned player: drop silently
	}

	// 玩家身份嗅探（仅在识别完成前生效；失败自动降级为只记 IP）
	if !sess.identified.Load() && f.svc != nil && f.svc.sniff != nil {
		f.svc.sniff.Observe(sess.key, data, srcAddr.IP.String(), srcAddr.Port,
			func(_ string, _ string, _ int, id raksniff.Identity) {
				f.onIdentity(sess, id)
			})
		if sess.killed.Load() {
			return
		}
	}

	// PROXY Protocol v2：仅在每个客户端会话的首个数据报前附加头，
	// 后续数据报原样透传（与后端的 PROXY 解析端按会话缓存语义配合）。
	payload := data
	if created && f.proxyProto {
		hdr := proxyproto.HeaderProxyFromAddrs(0, srcAddr, f.targetAddr)
		withHeader, err := hdr.FormatUDPDatagram(data)
		if err != nil {
			logger.L.Warn("PROXY v2 header format failed", zap.String("rule", f.rule.Name), zap.Error(err))
		} else {
			payload = withHeader
		}
	}

	n, _ := sess.upstream.Write(payload)
	sess.bIn.Add(int64(n))
	f.bytesIn.Add(int64(n))
}

// onIdentity 登记嗅探到的玩家身份并执行封禁检查。
func (f *UDPForwarder) onIdentity(sess *udpSession, id raksniff.Identity) {
	sess.setIdentity(id)
	if f.svc == nil || f.svc.players == nil {
		return
	}
	if _, exists := f.svc.players.get(sess.key); !exists {
		f.svc.players.put(sess.key, sess)
	}
	player, xuid, _ := sess.identityView()
	logger.S.Infow("player identified", "rule", f.rule.Name,
		"player", player, "xuid", xuid, "src", sess.srcIP)
	f.svc.logEvent(models.ConnLogEntry{
		Protocol: models.ProtocolUDP,
		RuleID:   f.rule.ID,
		RuleName: f.rule.Name,
		SrcIP:    sess.srcIP,
		SrcPort:  sess.srcPort,
		Player:   player,
		XUID:     xuid,
		Event:    models.ConnEventJoin,
	})
	if f.svc.bans.Banned(player, xuid) {
		f.kickSession(sess, "命中玩家封禁名单 | matched player ban list")
	}
}

// kickSession 掐断会话：停止转发并关闭上游 socket，玩家侧表现为掉线。
func (f *UDPForwarder) kickSession(sess *udpSession, reason string) {
	if sess.killed.CompareAndSwap(false, true) {
		player, xuid, _ := sess.identityView()
		logger.S.Warnw("kicking session", "rule", f.rule.Name,
			"player", player, "xuid", xuid, "src", sess.srcIP, "reason", reason)
		_ = sess.upstream.Close()
		f.finalizeSession(sess, models.ConnEventKick)
	}
}

// finalizeSession 每会话仅执行一次：清理注册表/嗅探状态并落一条离开日志。
func (f *UDPForwarder) finalizeSession(sess *udpSession, ev models.ConnEvent) {
	sess.finalOnce.Do(func() {
		if f.svc != nil {
			if f.svc.players != nil {
				f.svc.players.remove(sess.key)
			}
			if f.svc.sniff != nil {
				f.svc.sniff.Release(sess.key)
			}
			player, xuid, _ := sess.identityView()
			// 只有识别过身份或有过实际流量的会话才值得一条离开日志
			if sess.identified.Load() || sess.bIn.Load() > 0 || sess.bOut.Load() > 0 {
				f.svc.logEvent(models.ConnLogEntry{
					Protocol: models.ProtocolUDP,
					RuleID:   f.rule.ID,
					RuleName: f.rule.Name,
					SrcIP:    sess.srcIP,
					SrcPort:  sess.srcPort,
					Player:   player,
					XUID:     xuid,
					Event:    ev,
					BytesIn:  sess.bIn.Load(),
					BytesOut: sess.bOut.Load(),
				})
			}
		}
	})
}

func (f *UDPForwarder) relayBack(clientAddr *net.UDPAddr, sess *udpSession) {
	defer f.wg.Done()
	// Use pooled buffer for relay
	buf := pool.GetBuffer(65535)
	defer pool.PutBuffer(buf)
	for {
		n, err := sess.upstream.Read(buf)
		if err != nil {
			return
		}
		if sess.killed.Load() {
			return
		}
		out, _ := f.conn.WriteToUDP(buf[:n], clientAddr)
		sess.bOut.Add(int64(out))
		f.bytesOut.Add(int64(out))
	}
}

func (f *UDPForwarder) cleanupLoop() {
	defer f.wg.Done()
	ticker := time.NewTicker(f.timeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-f.stopCh:
			return
		case <-ticker.C:
			f.mu.Lock()
			now := time.Now()
			for k, s := range f.sessions {
				if now.Sub(s.lastSeen) > f.timeout {
					_ = s.upstream.Close()
					f.finalizeSession(s, models.ConnEventLeave)
					delete(f.sessions, k)
					f.active.Add(-1)
				}
			}
			f.mu.Unlock()
		}
	}
}

func (f *UDPForwarder) Stats() (bytesIn, bytesOut, active, total int64) {
	return f.bytesIn.Load(), f.bytesOut.Load(), f.active.Load(), f.totalConns.Load()
}

// getOrCreateSession returns the upstream session for srcAddr, creating it on
// first sight. created reports whether the returned session was just created
// by this call (used to emit the PROXY header exactly once per session).
func (f *UDPForwarder) getOrCreateSession(srcAddr *net.UDPAddr) (sess *udpSession, created bool) {
	key := makeUDPAddrKey(srcAddr) // 零分配 | zero allocation
	now := time.Now()

	f.mu.Lock()
	if sess, ok := f.sessions[key]; ok {
		sess.lastSeen = now
		f.mu.Unlock()
		return sess, false
	}
	f.mu.Unlock()
	if f.isStopping() {
		return nil, false
	}

	up, err := net.DialUDP("udp", nil, f.targetAddr)
	if err != nil {
		logger.L.Warn("UDP dial failed", zap.String("target", f.targetAddr.String()), zap.Error(err))
		return nil, false
	}

	f.mu.Lock()
	if sess, ok := f.sessions[key]; ok {
		sess.lastSeen = now
		f.mu.Unlock()
		_ = up.Close()
		return sess, false
	}
	if f.isStopping() {
		f.mu.Unlock()
		_ = up.Close()
		return nil, false
	}
	sess = &udpSession{
		upstream: up,
		lastSeen: now,
		key:      sessionKey(f.rule.ID, srcAddr),
		srcIP:    srcAddr.IP.String(),
		srcPort:  srcAddr.Port,
		ruleName: f.rule.Name,
	}
	f.sessions[key] = sess
	f.active.Add(1)
	f.totalConns.Add(1)
	f.wg.Add(1)
	go f.relayBack(cloneUDPAddr(srcAddr), sess)
	f.mu.Unlock()
	return sess, true
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	clone := *addr
	if addr.IP != nil {
		clone.IP = append(net.IP(nil), addr.IP...)
	}
	return &clone
}

func (f *UDPForwarder) isStopping() bool {
	select {
	case <-f.stopCh:
		return true
	default:
		return false
	}
}
