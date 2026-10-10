package nethernet

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go-port-forward/internal/logger"
)

// PlayerSocket 是一个以**玩家真实地址**为源的 UDP socket。
//
// NetherNet 的数据面必须用它而不是多路复用器自己的 socket：否则 BDS 收到的
// 源地址是中转机，「后端零插件看到玩家真实 IP」这个透明模式的核心承诺就丢了。
// Linux 上由 IP_TRANSPARENT 绑定玩家 IP:端口实现（与普通透明转发同一机制）。
type PlayerSocket interface {
	// SendTo 向 dst 发送一个数据报（源地址 = 绑定时指定的玩家地址）。
	SendTo(packet []byte, dst *net.UDPAddr) error
	// Read 读一个来自后端的回程数据报。
	Read(buf []byte) (int, error)
	Close() error
}

// SocketFactory 按玩家地址创建 PlayerSocket。返回 nil 表示当前环境不支持
// （非 Linux / 无 root），多路复用器会退化为共享 socket 并明确告警。
type SocketFactory func(src *net.UDPAddr) (PlayerSocket, error)

// SessionSink 让上层（forward.Manager）看到 NetherNet 数据面会话的生死与流量。
//
// 为什么必须有它：透明 socket 让 BDS 看到玩家**真实**地址，于是 BDS 的 STUN
// 响应与 DTLS ClientHello 是**直接发给玩家 IP** 的——这条回程必须经隧道回到
// 中转机，依赖 Windows 客户端上的 /32 回程路由（route add <玩家IP> mask
// 255.255.255.255 10.66.0.1）。服务端每 10 秒推送一次活跃会话来源 IP，数据源
// 是 forward 的会话注册表；NetherNet 会话若不登记，推送列表恒为空（日志
// 「回程路由 IP 已推送 count:0」），客户端装不上回程路由，BDS 回包就从后端机
// 物理网卡漏出去（源地址变成后端自己的公网 IP），玩家 ICE/DTLS 永远等不到
// 应答——症状是信令通、有 learned、约 15 秒后 InitialConnection-83。
type SessionSink interface {
	// NetherSessionStart 在会话学到客户端地址（首个 STUN）时调用一次。
	NetherSessionStart(ufrag string, client *net.UDPAddr)
	// NetherSessionBytes 汇报自上次调用以来的**增量**字节
	// （in=玩家→BDS，out=BDS→玩家）。
	NetherSessionBytes(ufrag string, client *net.UDPAddr, in, out int)
	// NetherSessionEnd 在会话被回收、被同一 ufrag 的新会话顶替或复用器停止
	// 时调用一次，与 Start 严格配对。
	NetherSessionEnd(ufrag string, client *net.UDPAddr)
}

// Multiplexer handles UDP data plane multiplexing for NetherNet sessions.
//
// 公网只开一个 UDP 端口（数据端口）承载全部玩家：STUN 包按 ice-ufrag 找到会话
// 并借此「学习」客户端真实地址，之后的 DTLS/SCTP 包按已学习的 5-tuple 转发。
type Multiplexer struct {
	listenAddr string
	conn       *net.UDPConn
	factory    SocketFactory
	sink       SessionSink // 会话事件接收者（可为 nil）；所有调用都在 m.mu 内串行完成
	sessions   map[string]*netherSession // ice-ufrag -> session
	addrMap    map[string]*netherSession // client addr -> session (5-tuple learned)
	mu         sync.RWMutex
	stopCh     chan struct{}
	stopOnce   sync.Once
	warnedNoTx atomic.Bool

	// 规则级累计计数（不随会话回收归零，语义同 TCPForwarder/UDPForwarder 的
	// bytesIn/bytesOut）：面板规则表与仪表盘的「流入/流出」读它们。
	bytesIn  atomic.Int64 // 玩家 → BDS 累计
	bytesOut atomic.Int64 // BDS → 玩家 累计
	total    atomic.Int64 // 累计学习到的会话数（面板「累计连接数」）
}

// netherSession represents a NetherNet session
type netherSession struct {
	ufrag      string
	clientAddr *net.UDPAddr
	targetIP   net.IP
	targetPort int
	lastSeen   time.Time
	learned    bool // Whether client address has been learned from STUN

	// sock 是以玩家地址为源的出站 socket（nil = 退化为共享 socket）。
	// 只在 m.mu 内赋值，读方向由本会话的 reader goroutine 独占。
	sock PlayerSocket

	// 流量计数（原子，转发/回程路径无锁累加）；repIn/repOut 是已向 sink 汇报
	// 过的水位，由 statsLoop 在 m.mu 内推进。
	bytesIn  atomic.Int64 // 玩家 → BDS 累计
	bytesOut atomic.Int64 // BDS → 玩家 累计
	repIn    int64
	repOut   int64
}

// NewMultiplexer creates a new UDP multiplexer.
//
// factory 可为 nil（非透明环境）；此时数据面仍能工作，但 BDS 看到的是中转机地址。
func NewMultiplexer(listenAddr string, factory SocketFactory) *Multiplexer {
	return &Multiplexer{
		listenAddr: listenAddr,
		factory:    factory,
		sessions:   make(map[string]*netherSession),
		addrMap:    make(map[string]*netherSession),
		stopCh:     make(chan struct{}),
	}
}

// Start starts the multiplexer
func (m *Multiplexer) Start() error {
	addr, err := net.ResolveUDPAddr("udp", m.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen UDP: %w", err)
	}

	m.conn = conn
	logger.S.Infow("NetherNet multiplexer started",
		"listen", m.listenAddr, "transparent_source", m.factory != nil)

	go m.readLoop()
	go m.cleanupLoop()
	go m.statsLoop()

	return nil
}

// readLoop reads UDP packets and routes them
func (m *Multiplexer) readLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-m.stopCh:
			return
		default:
		}

		n, clientAddr, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-m.stopCh:
				return
			default:
				logger.S.Warnw("UDP read error", "err", err)
				continue
			}
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		go m.handlePacket(packet, clientAddr)
	}
}

// handlePacket handles a single UDP packet
func (m *Multiplexer) handlePacket(packet []byte, clientAddr *net.UDPAddr) {
	if len(packet) < 20 {
		return
	}

	isSTUN := packet[0] == 0x00 || packet[0] == 0x01

	m.mu.Lock()
	// Try to find session by client address (5-tuple learned)
	addrKey := clientAddr.String()
	if sess, ok := m.addrMap[addrKey]; ok {
		sess.lastSeen = time.Now()
		m.forwardToTarget(packet, sess)
		m.mu.Unlock()
		return
	}

	// If STUN packet, try to learn the session
	if isSTUN {
		ufrag := m.extractUfragFromSTUN(packet)
		if ufrag != "" {
			if sess, ok := m.sessions[ufrag]; ok && !sess.learned {
				sess.clientAddr = clientAddr
				sess.learned = true
				sess.lastSeen = time.Now()
				m.addrMap[addrKey] = sess
				logger.S.Infow("learned NetherNet client address",
					"ufrag", ufrag, "client", clientAddr.String())
				// 登记必须早于首次转发：回程路由推送以会话注册表为唯一数据源，
				// 漏登记 = BDS 的回包送不回玩家（见 SessionSink 注释）。
				if m.sink != nil {
					m.sink.NetherSessionStart(ufrag, clientAddr)
				}
				m.total.Add(1) // 规则级「累计连接数」
				m.forwardToTarget(packet, sess)
				m.mu.Unlock()
				return
			}
		}
	}
	m.mu.Unlock()

	// warn：包到了中转机却匹配不到会话——要么 ufrag 没对上（路由键错），要么是
	// 扫端口/杂散 UDP。用 warn 让"失败case"从 info 的成功序列里跳出来。
	logger.S.Warnw("dropped packet from unknown session", "client", clientAddr.String())
}


// stunMagicCookie 是每个 STUN 消息头里固定出现的魔数（RFC 5389），位于偏移 4。
const stunMagicCookie = 0x2112A442

// extractUfragFromSTUN 从 STUN 包的 USERNAME 属性提取**服务端 ice-ufrag**（路由键）。
//
// 按 RFC 8445 §7.2.1.2，客户端发给服务端的 binding request 的 USERNAME 是
// "serverUfrag:clientUfrag"（对端片段在前）。路由键是**冒号前**那段，它等于
// SDP answer 的 a=ice-ufrag，也正是 RegisterSession 存进的键。
//
// 之前按 "长度对半切"（username[:len/2]）是错的：只有两个 ufrag 等长时才碰巧
// 切对。真实 ufrag 不等长时切出的键匹配不到任何会话，每个包都被当成 unknown
// session 丢弃——玩家侧表现为 InitialConnection-115。
func (m *Multiplexer) extractUfragFromSTUN(packet []byte) string {
	if len(packet) < 20 {
		return ""
	}
	// 校验 STUN 魔数（RFC 5389，偏移 4）。挡掉那些首字节恰好是 0x00/0x01 的
	// DTLS/SCTP/其它 UDP 数据报被误当成 STUN 解析。
	if binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return ""
	}

	msgLen := binary.BigEndian.Uint16(packet[2:4])
	if len(packet) < 20+int(msgLen) {
		return ""
	}

	// Parse attributes
	offset := 20
	for offset+4 <= len(packet) {
		attrType := binary.BigEndian.Uint16(packet[offset : offset+2])
		attrLen := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		offset += 4

		if offset+int(attrLen) > len(packet) {
			break
		}

		// USERNAME attribute (0x0006)
		if attrType == 0x0006 {
			username := string(packet[offset : offset+int(attrLen)])
			// USERNAME format: "serverUfrag:clientUfrag" — 取冒号前的服务端
			// ufrag 作为路由键。
			if idx := strings.IndexByte(username, ':'); idx > 0 {
				return username[:idx]
			}
			return username
		}

		// Align to 4-byte boundary
		offset += int(attrLen)
		if pad := attrLen % 4; pad != 0 {
			offset += int(4 - pad)
		}
	}

	return ""
}

// forwardToTarget forwards packet to BDS target.
//
// 调用方必须持有 m.mu。会话第一次转发时按玩家地址创建透明 socket，之后所有
// 出站包都走它——BDS 因此看到玩家的真实 IP:端口。
func (m *Multiplexer) forwardToTarget(packet []byte, sess *netherSession) {
	targetAddr := &net.UDPAddr{
		IP:   sess.targetIP,
		Port: sess.targetPort,
	}

	if sess.sock == nil && m.factory != nil && sess.clientAddr != nil {
		sock, err := m.factory(sess.clientAddr)
		if err != nil {
			// 绑定玩家地址失败（极少见：地址被占、权限变化）。退化为共享
			// socket 让会话至少能通，同时明确告警——静默降级会让「真实 IP」
			// 在不被察觉的情况下失效。
			if m.warnedNoTx.CompareAndSwap(false, true) {
				logger.S.Warnw("NetherNet 透明源绑定失败，退化为中转机地址 | transparent source bind failed, falling back to relay address",
					"client", sess.clientAddr.String(), "err", err)
			}
		} else {
			sess.sock = sock
			go m.readBackend(sess, sock)
		}
	}

	if sess.sock != nil {
		if err := sess.sock.SendTo(packet, targetAddr); err != nil {
			logger.S.Warnw("failed to forward to target", "err", err, "target", targetAddr.String())
		} else {
			sess.bytesIn.Add(int64(len(packet)))
			m.bytesIn.Add(int64(len(packet)))
		}
		return
	}

	// 无透明 socket（非 Linux / 无 root / 绑定失败）：走共享 socket。
	if m.warnedNoTx.CompareAndSwap(false, true) {
		logger.S.Warnw("NetherNet 数据面未使用透明源，BDS 将看到中转机地址 | NetherNet data plane is not using transparent source; the backend will see the relay address")
	}
	if _, err := m.conn.WriteToUDP(packet, targetAddr); err != nil {
		logger.S.Warnw("failed to forward to target", "err", err, "target", targetAddr.String())
	} else {
		sess.bytesIn.Add(int64(len(packet)))
		m.bytesIn.Add(int64(len(packet)))
	}
}

// readBackend 把一个会话的后端回程包读出来，经数据端口发回玩家。
//
// 每个会话恰好一个 reader（socket 的读方向独占）。它随会话的透明 socket 一起
// 创建、随会话回收盘子；socket 被 Close 时阻塞的 Read 立即返回错误。
//
// ⚠️ sock 必须作为参数传进来，不能在函数里读 sess.sock：cleanup 会把
// sess.sock 置 nil，而 goroutine 的首次执行可能被排到那之后——那时读到的就是
// nil，直接 panic。参数让 reader 对自己的 socket 有明确的所有权。
func (m *Multiplexer) readBackend(sess *netherSession, sock PlayerSocket) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-m.stopCh:
			return
		default:
		}

		n, err := sock.Read(buf)
		if err != nil {
			return // socket 已关（会话回收 / Stop）
		}
		if n == 0 {
			continue
		}

		m.mu.RLock()
		dst := sess.clientAddr
		conn := m.conn
		m.mu.RUnlock()
		if dst == nil || conn == nil {
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])
		if _, err := conn.WriteToUDP(packet, dst); err != nil {
			logger.S.Warnw("failed to relay backend reply to player",
				"err", err, "client", dst.String())
		} else {
			sess.bytesOut.Add(int64(n))
			m.bytesOut.Add(int64(n))
		}

		// 双向都算活跃：BDS 还在往下游发，说明这条会话没死。配合偏短的空闲
		// 阈值（见 sessionIdleTimeout），只按上游刷新会把「上游安静但仍在收包」
		// 的活会话误收割——NetherNet 会话被收割后没有重新学习的路径（没有新
		// 信令就永远是 unknown session），玩家会直接掉线。
		m.mu.Lock()
		sess.lastSeen = time.Now()
		m.mu.Unlock()
	}
}

// RegisterSession registers a new NetherNet session keyed by the server's
// ice-ufrag. 客户端地址要等第一个 STUN 包才学得到，所以这里只登记目标。
func (m *Multiplexer) RegisterSession(ufrag string, targetIP net.IP, targetPort int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 重复 ufrag（玩家重连 / 信令重放）必须先把旧会话收尾再覆盖。旧实现直接
	// 覆盖 map 条目：旧会话的透明 socket 没人 Close——内核层的独占绑定与它的
	// reader goroutine 一起泄漏；同一个玩家元组下次重连时工厂还会 EADDRINUSE，
	// 静默退化成「BDS 看到中转机地址」，透明模式的核心承诺就丢了。
	if old, ok := m.sessions[ufrag]; ok {
		m.endSessionLocked(ufrag, old)
	}

	m.sessions[ufrag] = &netherSession{
		ufrag:      ufrag,
		targetIP:   targetIP,
		targetPort: targetPort,
		lastSeen:   time.Now(),
		learned:    false,
	}
	logger.S.Infow("registered NetherNet session",
		"ufrag", ufrag,
		"target", fmt.Sprintf("%s:%d", targetIP, targetPort),
	)
}

// cleanupLoop removes stale sessions
func (m *Multiplexer) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

// sessionIdleTimeout 是会话的本地空闲回收时限。信令完成后玩家可能一直不发
// 数据面（例如卡在 ICE），回收只是放开条目与 socket，不影响已建立的连接语义。
//
// 取 60s（对齐 NetherProxy 的 tuple_stale_timeout）：这个值同时决定**回程路由
// 推送**什么时候停止把该玩家 IP 报活（见 SessionSink），报活一停，服务端才会
// 下发结束事件、客户端摘掉 /32 回程路由。旧值 5 分钟的后果是玩家早就不在线了，
// 路由还挂着——同一 CGNAT 出口下的其他玩家会被这条残留路由把回包吸进隧道。
//
// 不能再短：NetherNet 会话被收割后**没有重新学习的路径**（没有新信令就永远是
// unknown session），误收割等于把在线玩家踢下线；双向流量都会刷新 lastSeen，
// 只有真正两厢寂静 60s 才会走到回收。
const sessionIdleTimeout = 60 * time.Second

func (m *Multiplexer) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for ufrag, sess := range m.sessions {
		if now.Sub(sess.lastSeen) <= sessionIdleTimeout {
			continue
		}
		m.endSessionLocked(ufrag, sess)
		logger.S.Debugw("removed stale NetherNet session", "ufrag", ufrag)
	}
}

// SetSessionSink 安装会话事件接收者（可为 nil 表示不关心）。
//
// 必须在 Start 之前调用：Start 之后才可能有玩家包到达，晚安装会漏掉会话的
// start 事件，回程路由推送随之少一份数据。
func (m *Multiplexer) SetSessionSink(sink SessionSink) { m.sink = sink }

// endSessionLocked 收尾一个会话：摘路由条目、关透明 socket、通知上层。
// 调用方必须持有 m.mu——sink 的调用因此被串行化，上层无需自己加锁。
//
// 顺序有讲究：先摘条目再关 socket——reader 的阻塞 Read 随 Close 立即返回，
// goroutine 随之退出；反过来的话 reader 会多活一个超时周期。
func (m *Multiplexer) endSessionLocked(ufrag string, sess *netherSession) {
	delete(m.sessions, ufrag)
	if sess.clientAddr != nil {
		// 身份校验：同一 ufrag 重连时 addrMap 可能已指向新会话，不能按旧地址
		// 字符串把新条目一起删掉。
		if cur, ok := m.addrMap[sess.clientAddr.String()]; ok && cur == sess {
			delete(m.addrMap, sess.clientAddr.String())
		}
	}
	// 先关 socket：reader 的阻塞 Read 立即返回，goroutine 随之退出。
	if sess.sock != nil {
		_ = sess.sock.Close()
		sess.sock = nil
	}
	if m.sink != nil && sess.clientAddr != nil {
		m.sink.NetherSessionEnd(ufrag, sess.clientAddr)
	}
}

// statsLoop 周期把会话流量增量报给 sink——Web 面板「活跃玩家流量」的数据源。
// 「包在往返但进不去游戏」这类故障，首先看的就是这里有没有上下行。
func (m *Multiplexer) statsLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.reportBytes()
		}
	}
}

// reportBytes 汇报各会话自上次以来的字节增量。调用方是 statsLoop；内部自行
// 持锁，与 endSessionLocked 的 sink 调用串行，不会并发进入上层。
func (m *Multiplexer) reportBytes() {
	if m.sink == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for ufrag, sess := range m.sessions {
		in, out := sess.bytesIn.Load(), sess.bytesOut.Load()
		dIn, dOut := in-sess.repIn, out-sess.repOut
		if dIn == 0 && dOut == 0 {
			continue
		}
		sess.repIn, sess.repOut = in, out
		if sess.clientAddr != nil {
			m.sink.NetherSessionBytes(ufrag, sess.clientAddr, int(dIn), int(dOut))
		}
	}
}

// Stats 返回规则级流量与连接数，语义与 TCPForwarder/UDPForwarder.Stats 一致：
// bytesIn/bytesOut 是进程启动以来的累计值（不随会话回收归零），active 是当前
// 已学到地址（玩家真实在线）的会话数，total 是累计学到的会话数。
//
// 面板规则表与仪表盘的「流入/流出/连接数」读这里；漏接的后果是 NetherNet 规则
// 恒显示 0 B，而会话明细里明明有流量——排查时两边数字对不上，最容易误判成
// 「数据面没通」。
func (m *Multiplexer) Stats() (bytesIn, bytesOut, active, total int64) {
	m.mu.RLock()
	for _, sess := range m.sessions {
		if sess.learned {
			active++
		}
	}
	m.mu.RUnlock()
	return m.bytesIn.Load(), m.bytesOut.Load(), active, m.total.Load()
}

// Stop stops the multiplexer
func (m *Multiplexer) Stop() error {
	var err error
	m.stopOnce.Do(func() {
		close(m.stopCh)
		m.mu.Lock()
		for ufrag, sess := range m.sessions {
			// 走同一条收尾路径：规则重启/停机也要让上层摘掉会话条目，
			// 否则回程路由推送永远认为该玩家还活着，客户端的 /32 路由
			// 只能等本地空闲宽限期才消失。
			m.endSessionLocked(ufrag, sess)
		}
		m.mu.Unlock()
		if m.conn != nil {
			err = m.conn.Close()
		}
	})
	return err
}
