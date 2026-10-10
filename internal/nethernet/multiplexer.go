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

// Multiplexer handles UDP data plane multiplexing for NetherNet sessions.
//
// 公网只开一个 UDP 端口（数据端口）承载全部玩家：STUN 包按 ice-ufrag 找到会话
// 并借此「学习」客户端真实地址，之后的 DTLS/SCTP 包按已学习的 5-tuple 转发。
type Multiplexer struct {
	listenAddr string
	conn       *net.UDPConn
	factory    SocketFactory
	sessions   map[string]*netherSession // ice-ufrag -> session
	addrMap    map[string]*netherSession // client addr -> session (5-tuple learned)
	mu         sync.RWMutex
	stopCh     chan struct{}
	stopOnce   sync.Once
	warnedNoTx atomic.Bool
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
				logger.S.Debugw("learned NetherNet client address",
					"ufrag", ufrag, "client", clientAddr.String())
				m.forwardToTarget(packet, sess)
				m.mu.Unlock()
				return
			}
		}
	}
	m.mu.Unlock()

	logger.S.Debugw("dropped packet from unknown session", "client", clientAddr.String())
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
		}
		return
	}

	// 无透明 socket（非 Linux / 无 root / 绑定失败）：走共享 socket。
	if m.warnedNoTx.CompareAndSwap(false, true) {
		logger.S.Warnw("NetherNet 数据面未使用透明源，BDS 将看到中转机地址 | NetherNet data plane is not using transparent source; the backend will see the relay address")
	}
	if _, err := m.conn.WriteToUDP(packet, targetAddr); err != nil {
		logger.S.Warnw("failed to forward to target", "err", err, "target", targetAddr.String())
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
		}
	}
}

// RegisterSession registers a new NetherNet session keyed by the server's
// ice-ufrag. 客户端地址要等第一个 STUN 包才学得到，所以这里只登记目标。
func (m *Multiplexer) RegisterSession(ufrag string, targetIP net.IP, targetPort int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 重复 ufrag（玩家重连 / 信令重放）直接覆盖：旧会话的 reader 会随旧
	// socket 关闭而退出，不会泄漏。
	m.sessions[ufrag] = &netherSession{
		ufrag:      ufrag,
		targetIP:   targetIP,
		targetPort: targetPort,
		lastSeen:   time.Now(),
		learned:    false,
	}
	logger.S.Debugw("registered NetherNet session",
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
const sessionIdleTimeout = 5 * time.Minute

func (m *Multiplexer) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for ufrag, sess := range m.sessions {
		if now.Sub(sess.lastSeen) <= sessionIdleTimeout {
			continue
		}
		delete(m.sessions, ufrag)
		if sess.clientAddr != nil {
			delete(m.addrMap, sess.clientAddr.String())
		}
		// 先关 socket：reader 的阻塞 Read 立即返回，goroutine 随之退出。
		// 顺序反了（先摘条目后关 socket）会让 reader 多活一个超时周期。
		if sess.sock != nil {
			_ = sess.sock.Close()
			sess.sock = nil
		}
		logger.S.Debugw("removed stale NetherNet session", "ufrag", ufrag)
	}
}

// Stop stops the multiplexer
func (m *Multiplexer) Stop() error {
	var err error
	m.stopOnce.Do(func() {
		close(m.stopCh)
		m.mu.Lock()
		for _, sess := range m.sessions {
			if sess.sock != nil {
				_ = sess.sock.Close()
				sess.sock = nil
			}
		}
		m.mu.Unlock()
		if m.conn != nil {
			err = m.conn.Close()
		}
	})
	return err
}
