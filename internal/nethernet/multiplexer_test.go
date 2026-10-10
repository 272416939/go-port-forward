package nethernet

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
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

// recordingSink 记录 sink 事件，供会话生命周期断言使用。
type recordingSink struct {
	mu     sync.Mutex
	starts []string // "ufrag|client"
	bytes  []string // "ufrag|in|out"
	ends   []string // "ufrag|client"
}

func (s *recordingSink) NetherSessionStart(ufrag string, client *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.starts = append(s.starts, ufrag+"|"+client.String())
}

func (s *recordingSink) NetherSessionBytes(ufrag string, client *net.UDPAddr, in, out int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bytes = append(s.bytes, fmt.Sprintf("%s|%d|%d", ufrag, in, out))
}

func (s *recordingSink) NetherSessionEnd(ufrag string, client *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ends = append(s.ends, ufrag+"|"+client.String())
}

// waitFor 轮询到 cond 为真或超时。用于等 readBackend goroutine 把回程包写完。
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// 会话生命周期：learned → start（带上玩家真实地址）；转发/回程都要计字节；
// 回收 → end；Stop 不得重复 end。
//
// start/end 是回程路由推送的唯一数据源（SessionIPsByCode 只认会话注册表），
// 漏一个玩家就拿不到 /32 回程路由，BDS 回包送不回来。
func TestMultiplexerSessionSinkLifecycle(t *testing.T) {
	targetIP := net.ParseIP("10.66.0.3")
	sock := newFakePlayerSocket()
	factory := func(src *net.UDPAddr) (PlayerSocket, error) { return sock, nil }
	sink := &recordingSink{}

	m := NewMultiplexer(":0", factory)
	m.SetSessionSink(sink)
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()
	m.RegisterSession("ufrag1", targetIP, 19132)

	client := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 5555}
	// 走真实入口：带 USERNAME "ufrag1:cli" 的 STUN binding request。
	m.handlePacket(buildSTUNBindingRequest("ufrag1:cli"), client)

	sink.mu.Lock()
	starts := append([]string(nil), sink.starts...)
	sink.mu.Unlock()
	if len(starts) != 1 || starts[0] != "ufrag1|203.0.113.9:5555" {
		t.Fatalf("starts = %v, want exactly one ufrag1|203.0.113.9:5555", starts)
	}
	if len(sock.sent) != 1 {
		t.Fatalf("forwarded %d packets through the player socket, want 1", len(sock.sent))
	}

	// 注入一条「BDS 回包」，readBackend 应经数据端口发回玩家并计入 bytesOut。
	sock.replies <- []byte("bds-reply")
	m.mu.RLock()
	sess := m.sessions["ufrag1"]
	m.mu.RUnlock()
	waitFor(t, "backend reply relayed", func() bool { return sess.bytesOut.Load() > 0 })

	m.reportBytes()
	sink.mu.Lock()
	bytes := append([]string(nil), sink.bytes...)
	sink.mu.Unlock()
	if len(bytes) != 1 || bytes[0] != fmt.Sprintf("ufrag1|%d|%d", len(sock.sent[0]), len("bds-reply")) {
		t.Fatalf("bytes report = %v, want one ufrag1|<in>|<out> entry", bytes)
	}

	// 回收 → end，且 Stop 不得再补一个（重复 end 会让上层多删一次会话条目）。
	m.mu.Lock()
	m.sessions["ufrag1"].lastSeen = time.Now().Add(-time.Hour)
	m.mu.Unlock()
	m.cleanup()

	sink.mu.Lock()
	ends := append([]string(nil), sink.ends...)
	sink.mu.Unlock()
	if len(ends) != 1 || ends[0] != "ufrag1|203.0.113.9:5555" {
		t.Fatalf("ends = %v, want exactly one ufrag1|203.0.113.9:5555", ends)
	}

	m.Stop()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.ends) != 1 {
		t.Fatalf("Stop fired a duplicate end: ends = %v", sink.ends)
	}
}

// 同一 ufrag 重复登记（玩家重连 / 信令重放）必须收尾旧会话：
// 旧透明 socket 要关（独占绑定 + reader goroutine 不泄漏）、旧会话要通知 end、
// addrMap 不能留下指向已死会话的条目（否则玩家包被转发到旧端口）。
func TestMultiplexerRegisterSessionReplacesPrevious(t *testing.T) {
	targetIP := net.ParseIP("10.66.0.3")
	first := newFakePlayerSocket()
	second := newFakePlayerSocket()
	socks := []*fakePlayerSocket{first, second}
	next := 0
	factory := func(src *net.UDPAddr) (PlayerSocket, error) {
		s := socks[next]
		next++
		return s, nil
	}
	sink := &recordingSink{}

	m := NewMultiplexer(":0", factory)
	m.SetSessionSink(sink)
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	m.RegisterSession("ufrag1", targetIP, 19132)
	client := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 5555}
	m.handlePacket(buildSTUNBindingRequest("ufrag1:cli"), client)

	// 同一 ufrag 再来一次（BDS 为这次连接分配了新数据端口）。
	m.RegisterSession("ufrag1", targetIP, 19133)

	select {
	case <-first.closed:
	default:
		t.Fatal("re-registering the same ufrag leaked the previous player socket")
	}
	sink.mu.Lock()
	ends := append([]string(nil), sink.ends...)
	sink.mu.Unlock()
	if len(ends) != 1 || ends[0] != "ufrag1|203.0.113.9:5555" {
		t.Fatalf("ends = %v, want one end for the replaced session", ends)
	}

	// 死会话的 addrMap 条目必须被摘掉（新会话尚未 learn，所以应为空）。
	m.mu.RLock()
	_, stale := m.addrMap[client.String()]
	m.mu.RUnlock()
	if stale {
		t.Fatal("addrMap still references the replaced (dead) session")
	}

	// 重连玩家再发一个 STUN，必须重新 learn 并拿到新端口。
	m.handlePacket(buildSTUNBindingRequest("ufrag1:cli"), client)
	m.mu.RLock()
	cur, ok := m.addrMap[client.String()]
	m.mu.RUnlock()
	if !ok || cur.targetPort != 19133 {
		t.Fatalf("re-learn after re-register failed: addrMap hit=%v port=%v", ok, cur)
	}
}

// 规则级统计必须两个方向都算，且 active/total 语义与 TCP/UDP 转发器一致：
// 面板规则表与仪表盘的「流入/流出/连接数」读它。曾因 Manager 漏接这一支，
// NetherNet 规则恒显示 0 B 而会话明细里有流量——排查时两边数字打架。
func TestMultiplexerStatsCountsBothDirections(t *testing.T) {
	targetIP := net.ParseIP("10.66.0.3")
	sock := newFakePlayerSocket()
	m := NewMultiplexer(":0", func(src *net.UDPAddr) (PlayerSocket, error) { return sock, nil })
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()
	m.RegisterSession("ufrag1", targetIP, 19132)

	if bi, bo, a, tot := m.Stats(); bi != 0 || bo != 0 || a != 0 || tot != 0 {
		t.Fatalf("fresh mux stats = %d/%d/%d/%d, want all zero", bi, bo, a, tot)
	}

	client := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 5555}
	stun := buildSTUNBindingRequest("ufrag1:cli")
	m.handlePacket(stun, client)

	// BDS 回程一包：readBackend 经数据端口发回玩家并计入流出。
	sock.replies <- []byte("bds-reply")
	m.mu.RLock()
	sess := m.sessions["ufrag1"]
	m.mu.RUnlock()
	waitFor(t, "backend reply relayed", func() bool { return sess.bytesOut.Load() > 0 })

	bi, bo, a, tot := m.Stats()
	if bi != int64(len(stun)) {
		t.Fatalf("bytesIn = %d, want %d", bi, len(stun))
	}
	if bo != int64(len("bds-reply")) {
		t.Fatalf("bytesOut = %d, want %d", bo, len("bds-reply"))
	}
	if a != 1 || tot != 1 {
		t.Fatalf("active/total = %d/%d, want 1/1", a, tot)
	}

	// 回收后累计流量不清零（同 TCP/UDP 转发器语义），active 归零、total 保留。
	m.mu.Lock()
	m.sessions["ufrag1"].lastSeen = time.Now().Add(-time.Hour)
	m.mu.Unlock()
	m.cleanup()

	bi, bo, a, tot = m.Stats()
	if bi == 0 || bo == 0 {
		t.Fatalf("cumulative bytes zeroed by cleanup: %d/%d", bi, bo)
	}
	if a != 0 || tot != 1 {
		t.Fatalf("after cleanup active/total = %d/%d, want 0/1", a, tot)
	}
}


