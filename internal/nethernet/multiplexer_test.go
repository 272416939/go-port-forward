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

func TestExtractUfragFromSTUN(t *testing.T) {
	// Create a mock STUN Binding Request with USERNAME attribute
	// STUN message format:
	// 0-1: Message Type (0x0001 = Binding Request)
	// 2-3: Message Length
	// 4-7: Magic Cookie (0x2112A442)
	// 8-19: Transaction ID
	// 20+: Attributes

	username := "test123:remote"
	usernameLen := len(username)

	// Calculate message length (excluding 20-byte header)
	attrLen := 4 + usernameLen // Type(2) + Length(2) + Value
	if pad := usernameLen % 4; pad != 0 {
		attrLen += 4 - pad
	}

	packet := make([]byte, 20+attrLen)

	// Message Type: Binding Request (0x0001)
	binary.BigEndian.PutUint16(packet[0:2], 0x0001)

	// Message Length
	binary.BigEndian.PutUint16(packet[2:4], uint16(attrLen))

	// Magic Cookie
	binary.BigEndian.PutUint32(packet[4:8], 0x2112A442)

	// Transaction ID (12 bytes, can be random)
	copy(packet[8:20], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C})

	// USERNAME attribute (0x0006)
	offset := 20
	binary.BigEndian.PutUint16(packet[offset:offset+2], 0x0006)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], uint16(usernameLen))
	copy(packet[offset+4:], []byte(username))

	m := &Multiplexer{}
	ufrag := m.extractUfragFromSTUN(packet)

	// Should extract "test123" (first half of username)
	expectedUfrag := "test123"
	if ufrag != expectedUfrag {
		t.Errorf("Expected ufrag '%s', got '%s'", expectedUfrag, ufrag)
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

