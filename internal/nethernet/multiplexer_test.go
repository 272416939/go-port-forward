package nethernet

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"go-port-forward/internal/logger"
	"go.uber.org/zap"
)

func init() {
	// Initialize logger for tests
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()
}

// buildSTUNBindingRequest 构造一个只带单个 USERNAME 属性的最小 STUN binding
// request（RFC 5389/8445 头 + TLV），供 ufrag 提取测试复用。
func buildSTUNBindingRequest(username string) []byte {
	attrLen := 4 + len(username)
	if pad := len(username) % 4; pad != 0 {
		attrLen += 4 - pad
	}
	p := make([]byte, 20+attrLen)
	binary.BigEndian.PutUint16(p[0:2], 0x0001)          // Binding Request
	binary.BigEndian.PutUint16(p[2:4], uint16(attrLen)) // Message Length
	binary.BigEndian.PutUint32(p[4:8], stunMagicCookie) // Magic Cookie
	copy(p[8:20], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	binary.BigEndian.PutUint16(p[20:22], 0x0006) // USERNAME
	binary.BigEndian.PutUint16(p[22:24], uint16(len(username)))
	copy(p[24:], []byte(username))
	return p
}

func TestExtractUfragFromSTUN(t *testing.T) {
	m := &Multiplexer{}
	// USERNAME = "serverUfrag:clientUfrag"，路由键是冒号前的服务端 ufrag。
	// 三个用例覆盖等长、服务端更长、服务端更短——旧的 len/2 切法只在等长时碰巧对。
	cases := []struct {
		username string
		want     string
	}{
		{"test123:remote", "test123"},
		{"abcdefghij:xy", "abcdefghij"},
		{"ab:cdefghijklmnop", "ab"},
	}
	for _, c := range cases {
		if got := m.extractUfragFromSTUN(buildSTUNBindingRequest(c.username)); got != c.want {
			t.Errorf("username %q: got ufrag %q, want %q", c.username, got, c.want)
		}
	}
}

// 首字节 0x00/0x01 但不是 STUN 的数据报（魔数不对）必须被拒，否则会把 DTLS/SCTP
// 误当 STUN、甚至污染 ufrag 路由。
func TestExtractUfragFromSTUNRejectsNonSTUN(t *testing.T) {
	m := &Multiplexer{}
	p := buildSTUNBindingRequest("srv:cli")
	binary.BigEndian.PutUint32(p[4:8], 0xDEADBEEF) // 破坏魔数
	if got := m.extractUfragFromSTUN(p); got != "" {
		t.Errorf("non-STUN packet: got ufrag %q, want empty", got)
	}
}

func TestMultiplexerSessionManagement(t *testing.T) {
	m := NewMultiplexer(":0", nil)

	// Register a session
	targetIP := net.ParseIP("10.66.0.3")
	m.RegisterSession("test123", targetIP, 19132)

	m.mu.RLock()
	sess, ok := m.sessions["test123"]
	m.mu.RUnlock()

	if !ok {
		t.Fatal("Session not registered")
	}

	if sess.ufrag != "test123" {
		t.Errorf("Expected ufrag 'test123', got '%s'", sess.ufrag)
	}

	if !sess.targetIP.Equal(targetIP) {
		t.Errorf("Expected target IP %s, got %s", targetIP, sess.targetIP)
	}

	if sess.targetPort != 19132 {
		t.Errorf("Expected target port 19132, got %d", sess.targetPort)
	}

	if sess.learned {
		t.Error("Session should not be learned yet")
	}
}

func TestMultiplexerCleanup(t *testing.T) {
	m := NewMultiplexer(":0", nil)

	// Register a session
	targetIP := net.ParseIP("10.66.0.3")
	m.RegisterSession("test123", targetIP, 19132)

	// Manually set lastSeen to old time
	m.mu.Lock()
	m.sessions["test123"].lastSeen = time.Now().Add(-10 * time.Minute)
	m.mu.Unlock()

	// Run cleanup
	m.cleanup()

	// Session should be removed
	m.mu.RLock()
	_, ok := m.sessions["test123"]
	m.mu.RUnlock()

	if ok {
		t.Error("Stale session should have been cleaned up")
	}
}

func TestMultiplexerAddressLearning(t *testing.T) {
	m := NewMultiplexer(":0", nil)

	// Register a session
	targetIP := net.ParseIP("10.66.0.3")
	m.RegisterSession("test123", targetIP, 19132)

	// Simulate learning client address
	clientAddr := &net.UDPAddr{
		IP:   net.ParseIP("1.2.3.4"),
		Port: 12345,
	}

	m.mu.Lock()
	sess := m.sessions["test123"]
	sess.clientAddr = clientAddr
	sess.learned = true
	m.addrMap[clientAddr.String()] = sess
	m.mu.Unlock()

	// Check if address is learned
	m.mu.RLock()
	learnedSess, ok := m.addrMap[clientAddr.String()]
	m.mu.RUnlock()

	if !ok {
		t.Fatal("Client address not learned")
	}

	if !learnedSess.learned {
		t.Error("Session should be marked as learned")
	}

	if learnedSess.clientAddr.String() != clientAddr.String() {
		t.Errorf("Expected client addr %s, got %s", clientAddr, learnedSess.clientAddr)
	}
}

// fakePlayerSocket 记录通过它发出的包，并允许测试注入「后端回包」。
type fakePlayerSocket struct {
	sent    [][]byte
	dst     []*net.UDPAddr
	replies chan []byte
	closed  chan struct{}
}

func newFakePlayerSocket() *fakePlayerSocket {
	return &fakePlayerSocket{replies: make(chan []byte, 4), closed: make(chan struct{})}
}

func (s *fakePlayerSocket) SendTo(packet []byte, dst *net.UDPAddr) error {
	s.sent = append(s.sent, append([]byte(nil), packet...))
	s.dst = append(s.dst, dst)
	return nil
}

func (s *fakePlayerSocket) Read(buf []byte) (int, error) {
	select {
	case p := <-s.replies:
		return copy(buf, p), nil
	case <-s.closed:
		return 0, net.ErrClosed
	}
}

func (s *fakePlayerSocket) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return nil
}

// 数据面必须以玩家真实地址为源——这是 NetherNet 复用透明模式的核心断言。
// 工厂要被调用、出站包要走工厂返回的 socket，而不是多路复用器自己的 socket。
func TestMultiplexerUsesTransparentPlayerSocket(t *testing.T) {
	targetIP := net.ParseIP("10.66.0.3")

	sock := newFakePlayerSocket()
	var gotSrc *net.UDPAddr
	factory := func(src *net.UDPAddr) (PlayerSocket, error) {
		gotSrc = src
		return sock, nil
	}

	m := NewMultiplexer(":0", factory)
	m.RegisterSession("ufrag1", targetIP, 19132)

	m.mu.Lock()
	sess := m.sessions["ufrag1"]
	sess.clientAddr = &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 5555}
	sess.learned = true
	m.addrMap[sess.clientAddr.String()] = sess
	m.forwardToTarget([]byte("hello-bds"), sess)
	m.mu.Unlock()

	if gotSrc == nil {
		t.Fatal("socket factory was never called — data plane would use the relay address")
	}
	if gotSrc.String() != "203.0.113.9:5555" {
		t.Fatalf("factory got src %v, want 203.0.113.9:5555", gotSrc)
	}
	if len(sock.sent) != 1 {
		t.Fatalf("sent %d packets through the player socket, want 1", len(sock.sent))
	}
	if string(sock.sent[0]) != "hello-bds" {
		t.Fatalf("forwarded payload = %q, want hello-bds", sock.sent[0])
	}
	if sock.dst[0].String() != "10.66.0.3:19132" {
		t.Fatalf("destination = %v, want 10.66.0.3:19132", sock.dst[0])
	}

	// 会话回收必须关掉 socket（否则 reader goroutine 与绑定一起泄漏）。
	m.mu.Lock()
	m.sessions["ufrag1"].lastSeen = time.Now().Add(-time.Hour)
	m.mu.Unlock()
	m.cleanup()
	select {
	case <-sock.closed:
	default:
		t.Fatal("cleanup did not close the player socket")
	}
}

// 工厂缺失（非 Linux / 无 root）时必须退化为共享 socket 且告警——
// 不能静默丢失玩家真实 IP，那是这个模式存在的意义。
func TestMultiplexerFallsBackWithoutFactory(t *testing.T) {
	targetIP := net.ParseIP("10.66.0.3")

	m := NewMultiplexer(":0", nil)
	if err := m.Start(); err != nil { // 回退路径要写共享 socket，必须先起监听
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()
	m.RegisterSession("ufrag1", targetIP, 19132)

	m.mu.Lock()
	sess := m.sessions["ufrag1"]
	sess.clientAddr = &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 5555}
	sess.learned = true
	m.forwardToTarget([]byte("payload"), sess)
	m.mu.Unlock()

	if sess.sock != nil {
		t.Fatal("no factory was provided, yet a player socket was created")
	}
	if !m.warnedNoTx.Load() {
		t.Fatal("fallback must warn — silently losing the real player IP is the bug this guards")
	}
}

