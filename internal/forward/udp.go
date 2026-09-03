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
	"go-port-forward/pkg/pool"

	"github.com/pires/go-proxyproto"
	"go.uber.org/zap"
)

// udpSocketBuffer 是 UDP socket 读写缓冲的目标值。Linux 实际生效值受
// net.core.rmem_max/wmem_max 钳制。
const udpSocketBuffer = 4 << 20 // 4MB

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
// IPv4 的 v4-mapped 16 字节表示必须归一化为 4 字节：ResolveUDPAddr 产出
// 16 字节形式，ReadFromUDP 产出 4 字节形式——同一地址两处键不一致会让
// 回程分发（后端源 → 订阅）永远 miss（透明共享注册表依赖此一致性）。
func makeUDPAddrKey(addr *net.UDPAddr) udpAddrKey {
	var k udpAddrKey
	k.port = uint16(addr.Port)
	ip := addr.IP
	if v4 := ip.To4(); v4 != nil {
		k.len = 4
		ip = v4
	} else {
		k.len = uint8(len(ip))
	}
	copy(k.ip[:], ip)
	k.zone = addr.Zone
	return k
}

// udpSession tracks an upstream UDP connection for a specific client address.
type udpSession struct {
	upstream  *net.UDPConn // 透明模式下为注册表共享的 socket（写按各自 target 走 WriteToUDP）
	tup       *tupleHandle // 透明模式非 nil：共享绑定持有凭证（引用归零才关 fd）
	lastSeen  time.Time
	key       string       // 全局会话键 "<proto>|<ruleID>|<src>" | global session key
	sinfo     *sessionInfo // 活跃会话注册表条目（字节数/日志都在其上）| live session entry
	finalOnce sync.Once
}

// sessionKey 构造跨转发器唯一的会话键。
func sessionKey(proto models.Protocol, ruleID string, addr net.Addr) string {
	return string(proto) + "|" + ruleID + "|" + addr.String()
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
	// 通用模式目标安全边界执行点：本转发器整个生命周期都用这一个解析结果，
	// 启动时校验一次即覆盖全部实际拨号。透明模式例外（目标本来就是隧道内网
	// 地址）。TCP 侧对应检查在拨号 Control 里（每次连接重新解析）。
	if !f.rule.Transparent {
		if terr := TargetPolicy(targetAddr.IP); terr != nil {
			_ = conn.Close()
			return terr
		}
	}
	f.conn = conn
	f.targetAddr = targetAddr
	// 默认 ~200KB 的读缓冲只够一百多个 MTU 包，玩家进服/重试风暴的突发会在
	// 内核层丢包，应用层毫无感知。实际生效值受 net.core.rmem_max 钳制，
	// 设置失败沿用系统默认，不影响转发。
	_ = conn.SetReadBuffer(udpSocketBuffer)
	_ = conn.SetWriteBuffer(udpSocketBuffer)

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
			s.releaseUpstream()
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
			UserID:   f.rule.UserID,
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

	// 非透明路径为已连接 socket（用 Write）；透明路径为共享注册表的未连接
	// socket（用 WriteToUDP 指定各自 target，*net.UDPConn 并发写安全）。
	// Windows 上 connected socket 调 WriteToUDP 会静默失败，必须按模式分流。
	var n int
	if f.rule.Transparent {
		n, _ = sess.upstream.WriteToUDP(payload, f.targetAddr)
	} else {
		n, _ = sess.upstream.Write(payload)
	}
	if sess.sinfo != nil {
		sess.sinfo.bytesIn.Add(int64(n))
	}
	f.bytesIn.Add(int64(n))
}

// finalizeSession 每会话仅执行一次：从注册表移除并按流量决定是否落离开日志。
func (f *UDPForwarder) finalizeSession(sess *udpSession, ev models.ConnEvent) {
	sess.finalOnce.Do(func() {
		if f.svc == nil {
			return
		}
		f.svc.sessions.remove(sess.key)
		if sess.sinfo != nil {
			sess.sinfo.finish(ev, f.svc.logs)
		}
	})
}

// relayBack 是非透明模式回程：connected socket 读后端回包，经转发口发回
// 玩家。透明模式的回程由共享绑定的分发器接管（tuple_registry.go 的
// dispatch——那是透明回程的最后一跳，绝不可省，完整链路注释在那里）。
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
		out, _ := f.conn.WriteToUDP(buf[:n], clientAddr)
		if sess.sinfo != nil {
			sess.sinfo.bytesOut.Add(int64(out))
		}
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
					s.releaseUpstream()
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

	up, tup, err := f.openUpstream(srcAddr)
	if err != nil {
		// 透明模式绑定失败多为权限问题：限频记录，丢弃该包（fail-closed）
		nowUnix := time.Now().Unix()
		last := f.lastDenied.Load()
		if nowUnix-last >= 5 && f.lastDenied.CompareAndSwap(last, nowUnix) {
			logger.L.Warn("UDP upstream dial failed", zap.String("rule", f.rule.Name),
				zap.String("src", srcAddr.String()), zap.Error(err))
		}
		return nil, false
	}

	f.mu.Lock()
	if sess, ok := f.sessions[key]; ok {
		sess.lastSeen = now
		f.mu.Unlock()
		discardUpstream(tup, up)
		return sess, false
	}
	if f.isStopping() {
		f.mu.Unlock()
		discardUpstream(tup, up)
		return nil, false
	}
	sess = &udpSession{
		upstream: up,
		tup:      tup,
		lastSeen: now,
		key:      sessionKey(models.ProtocolUDP, f.rule.ID, srcAddr),
	}
	if f.svc != nil && f.svc.sessions != nil {
		sess.sinfo = f.svc.sessions.obtain(sess.key, &sessionInfo{
			key:      sess.key,
			Protocol: models.ProtocolUDP,
			RuleID:   f.rule.ID,
			RuleName: f.rule.Name,
			UserID:   f.rule.UserID,
			SrcIP:    srcAddr.IP.String(),
			SrcPort:  srcAddr.Port,
			Since:    now,
		})
		f.svc.logEvent(models.ConnLogEntry{
			Protocol: models.ProtocolUDP,
			RuleID:   f.rule.ID,
			RuleName: f.rule.Name,
			UserID:   f.rule.UserID,
			SrcIP:    srcAddr.IP.String(),
			SrcPort:  srcAddr.Port,
			Event:    models.ConnEventJoin,
		})
	}
	if tup != nil {
		// 透明会话：回程由共享绑定的分发器接管（tuple_registry.go 的
		// dispatch——那是回程最后一跳），不再起每会话 relayBack
		tup.attach(sess, srcAddr)
	} else {
		f.wg.Add(1)
		go f.relayBack(cloneUDPAddr(srcAddr), sess)
	}
	f.sessions[key] = sess
	f.active.Add(1)
	f.totalConns.Add(1)
	f.mu.Unlock()
	return sess, true
}

// openUpstream 建立到目标的上游 socket。非透明：connected socket（用 Write，
// 会话回包由 relayBack 读）。透明：经全机共享注册表取得（或共享）以玩家
// IP:端口 为源的绑定（IP_TRANSPARENT，需 root）——跨规则共享是 2026-09
// 两条透明规则互抢同一玩家绑定（EADDRINUSE 永久断流）的正解，回程由注册表
// 分发器接管，见 tuple_registry.go。
func (f *UDPForwarder) openUpstream(srcAddr *net.UDPAddr) (up *net.UDPConn, tup *tupleHandle, err error) {
	if !f.rule.Transparent {
		up, err = net.DialUDP("udp", nil, f.targetAddr)
		return up, nil, err
	}
	reg := f.svc.tuplesOrNil()
	if reg == nil {
		return nil, nil, errors.New("透明模式未装配共享绑定注册表 | transparent tuple registry unavailable")
	}
	tup, err = reg.acquire(f, srcAddr)
	if err != nil {
		return nil, nil, err
	}
	return tup.conn(), tup, nil
}

// discardUpstream 双检输家的回退（建好的上游没成为会话）：透明走注册表
// 引用计数，非透明直接关。
func discardUpstream(tup *tupleHandle, up *net.UDPConn) {
	if tup != nil {
		tup.release()
		return
	}
	_ = up.Close()
}

// releaseUpstream 释放会话的上游：透明走注册表引用计数（归零才真正关 fd，
// 规则 A 的回收不得拆掉规则 B 还在用的绑定），非透明直接关。调用方必须
// 持有 f.mu——沿用 635bf3b「先关 fd、后摘会话条目」的临界区纪律。
func (s *udpSession) releaseUpstream() {
	if s.tup != nil {
		s.tup.release()
		return
	}
	_ = s.upstream.Close()
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
