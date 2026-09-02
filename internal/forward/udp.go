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
	upstream  *net.UDPConn
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

	// 非透明路径为已连接 socket（用 Write）；透明路径为按源绑定的未连接
	// socket（用 WriteToUDP 指定目标）。Windows 上 connected socket 调
	// WriteToUDP 会静默失败，必须按模式分流。
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

// udpSocketBuffer 是 UDP socket 读写缓冲的目标值。Linux 实际生效值受
// net.core.rmem_max/wmem_max 钳制。
const udpSocketBuffer = 4 << 20 // 4MB

func (f *UDPForwarder) cleanupLoop() {
	defer f.wg.Done()
	ticker := time.NewTicker(f.timeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-f.stopCh:
			return
		case <-ticker.C:
			// Close 必须在锁内、先于条目摘除对外生效：否则出现「条目已删、
			// 旧 socket 仍绑着玩家源端口」的窗口，期间同 key 的新包会走完整
			// 建会话路径去 bind，撞 EADDRINUSE 被丢弃（2026-09-02 生产日志
			// 实录：玩家重连复用 NAT 端口正好落进窗口，RakNet 握手全灭）。
			// Close 是微秒级 syscall，留在锁内；慢的 finalizeSession（要拿
			// sessionRegistry 的锁 + 发日志）继续留在锁外，风暴清理不卡热路径。
			now := time.Now()
			expired := make([]*udpSession, 0, 16)
			f.mu.Lock()
			for k, s := range f.sessions {
				if now.Sub(s.lastSeen) > f.timeout {
					_ = s.upstream.Close()
					delete(f.sessions, k)
					expired = append(expired, s)
				}
			}
			f.mu.Unlock()
			for _, s := range expired {
				f.finalizeSession(s, models.ConnEventLeave)
				f.active.Add(-1)
			}
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

	up, err := f.dialUpstream(srcAddr)
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

	// 注册表登记与 join 日志都在锁外做：obtain 要拿 sessionRegistry 的锁
	//（每 10 秒的活跃 IP 快照会把它排他占住一阵），拿在 f.mu 临界区里，
	// 就形成「f.mu → sessionRegistry.mu」的锁链——快照期间所有老会话的包
	// 都在 f.mu 上排队。
	skey := sessionKey(models.ProtocolUDP, f.rule.ID, srcAddr)
	var sinfo *sessionInfo
	if f.svc != nil && f.svc.sessions != nil {
		sinfo = f.svc.sessions.obtain(skey, &sessionInfo{
			key:      skey,
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

	// 关键区只做 map 插入与双检：并发创建时输家关掉多余的 socket。
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
		key:      skey,
		sinfo:    sinfo,
	}
	f.sessions[key] = sess
	f.active.Add(1)
	f.totalConns.Add(1)
	f.mu.Unlock()

	// relayBack 在锁外起。透明模式的回包不经此 socket（见 dialUpstream 注释），
	// 起 goroutine 也永远读不到数据——直接跳过，省下每个会话一个挂起的
	// goroutine + fd；重试风暴下的会话峰值因此减半。
	if !f.rule.Transparent {
		f.wg.Add(1)
		go f.relayBack(cloneUDPAddr(srcAddr), sess)
	}
	return sess, true
}

// dialUpstream 建立到目标的上游 socket；透明模式以玩家 IP:端口 为源绑定
// （IP_TRANSPARENT，需 root；回包经隧道/SNAT 独立路径返回，不经过此 socket）。
func (f *UDPForwarder) dialUpstream(srcAddr *net.UDPAddr) (*net.UDPConn, error) {
	if !f.rule.Transparent {
		up, err := net.DialUDP("udp", nil, f.targetAddr)
		if err != nil {
			return nil, err
		}
		// 通用模式的回包从这里读（relayBack），缓冲与转发口对齐。
		_ = up.SetReadBuffer(udpSocketBuffer)
		_ = up.SetWriteBuffer(udpSocketBuffer)
		return up, nil
	}
	pc, err := transparentListenPacket(srcAddr.String())
	if err != nil {
		return nil, err
	}
	udp, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("透明模式：上游 socket 类型异常 | unexpected packet conn type")
	}
	// 不调用 Connect（部分平台不可用）；发送统一走 WriteToUDP 指定目标
	return udp, nil
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
