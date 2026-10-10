package tunnelapp

import (
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/pkg/tunnel"

	"go.uber.org/zap"
)

// nopLogging 给测试装上静默日志（handleHello / queueHello 的日志路径依赖
// 全局 logger.S，未初始化时是 nil）。
func nopLogging() {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()
}

// fakeTunWriter 收下出向批里的包，只计数——测试只关心「有没有递送」。
type fakeTunWriter struct{ n int }

func (w *fakeTunWriter) add(pkt []byte, to netip.AddrPort) bool {
	w.n++
	return true
}
func (w *fakeTunWriter) flush() (int, error) { return w.n, nil }
func (w *fakeTunWriter) pending() int        { return w.n }

// ipv4Pkt 造一个 20 字节的 IPv4 头，只填源/目的地址——srcIP4/dstIP4 只读这两处。
func ipv4Pkt(src, dst string) []byte {
	p := make([]byte, 20)
	p[0] = 0x45 // version 4 + IHL 5
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	return p
}

// 出向源地址隔离：隧道内地址一律拒绝，唯一例外是网关地址。
//
// 这条例外是 NetherNet 信令网关经隧道访问后端 BDS 的唯一通路——网关是普通
// http.Client，内核给它的源地址就是 pftun0 自身的地址。零例外时 SDP/MOTD
// 请求全被丢，玩家拿到的是 "Service unavailable"，而服务端只留下一行
// 「丢弃隧道内互访的包（用户隔离）」，指不到真正原因。
//
// 同时锁死安全属性没有跟着回退：入向 dst 检查（isTunnelInternal 零例外）
// 未随本例外放宽，客户端仍然到不了网关、也到不了别的客户端。
func TestForwardOutboundSourceIsolation(t *testing.T) {
	nopLogging()
	pool, gw, err := parseTunAddr("10.66.0.1/16")
	if err != nil {
		t.Fatal(err)
	}
	var c2s, s2c [32]byte
	for i := range c2s {
		c2s[i] = byte(i)
		s2c[i] = byte(255 - i)
	}
	sess, err := tunnel.NewServerSession(&c2s, &s2c, 0, tunnel.MaxTunMTU)
	if err != nil {
		t.Fatalf("建会话失败: %v", err)
	}
	ps := newPeerSession(
		Identity{CodeID: "c1", CodeName: "222", UserName: "tester",
			TunIP: netip.MustParseAddr("10.66.0.7")},
		sess, &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 5000}, tunnel.MaxTunMTU)

	s := &Server{tunPool: pool, gateway: gw, peers: newRegistry()}
	s.peers.upsert(ps)

	cases := []struct {
		name     string
		src      string
		wantDrop bool
	}{
		{"网关地址放行——NetherNet 信令经隧道访问 BDS 的唯一通路", "10.66.0.1", false},
		{"玩家公网 IP 放行——正常数据面", "203.0.113.9", false},
		{"别的客户端隧道地址仍然拒绝", "10.66.0.8", true},
		{"本客户端自己的隧道地址也拒绝（不能拿它当互访目标）", "10.66.0.7", true},
		{"网段内未分配地址拒绝", "10.66.0.250", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &fakeTunWriter{}
			s.forwardOutbound(w, make([]byte, 0, 64), ipv4Pkt(tc.src, "10.66.0.7"))
			if tc.wantDrop && w.n != 0 {
				t.Fatalf("源 %s 应被隔离丢弃，却递送了 %d 个包", tc.src, w.n)
			}
			if !tc.wantDrop && w.n == 0 {
				t.Fatalf("源 %s 应被递送", tc.src)
			}
		})
	}
}

// 入向方向不受出向例外影响：客户端发往隧道内地址（含网关）的包一律丢弃。
// 与 TestForwardOutboundSourceIsolation 配对——「用户间隔离」每条边都要有
// 独立的执行语句，只放开一半不成立。
func TestHandleDataStillBlocksTunnelDestination(t *testing.T) {
	nopLogging()
	pool, gw, err := parseTunAddr("10.66.0.1/16")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{tunPool: pool, gateway: gw}
	for _, dst := range []string{"10.66.0.1", "10.66.0.8", "10.66.0.250"} {
		if !s.isTunnelInternal(netip.MustParseAddr(dst)) {
			t.Fatalf("入向 dst 检查必须把 %s 判为隧道内地址（零例外，含网关）", dst)
		}
	}
	if s.isTunnelInternal(netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("玩家公网 IP 不应判为隧道内地址")
	}
}

// tcpPkt 造一个带 TCP 头的 IPv4 包，flags 写进 TCP 头偏移 13。
// ihlOpts 让用例能覆盖「带 IP 选项头」的形态——flags 偏移必须跟着 IHL 走。
func tcpPkt(src, dst string, flags byte, ihlOpts int) []byte {
	ihl := 5 + ihlOpts/4
	p := make([]byte, ihl*4+20)
	p[0] = byte(0x40 | ihl)
	p[9] = 6 // IPPROTO_TCP
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	p[ihl*4+13] = flags
	return p
}

// 入向网关豁免必须收窄成「只放行回包」：TCP 新建连接（SYN 且无 ACK）在
// 用户态就拒，不让客户端借网关地址摸中转机服务；SYN-ACK / ACK / FIN-ACK /
// RST 等回包形态放行，交给内核 conntrack 做最终裁决。
//
// 这是 7237a82 那次收紧没有的部分——当时网关是完全豁免、只靠内核 INPUT
// 一层兜底；现在用户态先挡一道，内核降为兜底。
func TestAllowReturnToGatewayOnlyLetsRepliesThrough(t *testing.T) {
	nopLogging()
	pool, gw, err := parseTunAddr("10.66.0.1/16")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{tunPool: pool, gateway: gw}
	gateway := "10.66.0.1"
	other := "10.66.0.8" // 别人的隧道地址——任何形态都不放行

	const (
		syn    = 0x02
		synAck = 0x12
		ack    = 0x10
		pshAck = 0x18
		finAck = 0x11
		rst    = 0x04
		ecnSyn = 0xc2 // SYN + ECE + CWR，仍是新建连接
	)
	cases := []struct {
		name    string
		dst     string
		flags   byte
		ihlOpts int
		wantLet bool
	}{
		{"SYN-ACK 回包放行", gateway, synAck, 0, true},
		{"纯 ACK 回包放行", gateway, ack, 0, true},
		{"PSH+ACK 数据回包放行", gateway, pshAck, 0, true},
		{"FIN+ACK 回包放行", gateway, finAck, 0, true},
		{"RST 回包放行", gateway, rst, 0, true},
		{"带 IP 选项头的 ACK 也放行（偏移必须跟 IHL 走）", gateway, ack, 4, true},
		{"TCP 新建连接拒绝", gateway, syn, 0, false},
		{"ECN SYN 新建连接也拒绝", gateway, ecnSyn, 0, false},
		{"别人的隧道地址：SYN-ACK 也不放行", other, synAck, 0, false},
		{"别人的隧道地址：ACK 也不放行", other, ack, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := tcpPkt("10.66.0.3", tc.dst, tc.flags, tc.ihlOpts)
			got := s.allowReturnToGateway(pkt, netip.MustParseAddr(tc.dst))
			if got != tc.wantLet {
				t.Fatalf("allowReturnToGateway(dst=%s, flags=%#x, ihlOpts=%d) = %v, 期望 %v",
					tc.dst, tc.flags, tc.ihlOpts, got, tc.wantLet)
			}
		})
	}
}

// 非 TCP 没有「新建连接」可判，交给内核 conntrack（没有对应流一律 INVALID）。
// 畸形/过短的包不得panic——解析失败按「不是 TCP 新建连接」处理，最终仍由内核裁决。
func TestIsTCPConnectAttemptNonTCPAndMalformed(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"空包", nil, false},
		{"不足 20 字节", []byte{0x45, 0, 0, 0}, false},
		{"IPv6 包", func() []byte { p := make([]byte, 40); p[0] = 0x60; return p }(), false},
		{"UDP 包（协议 17）", func() []byte {
			p := make([]byte, 28)
			p[0] = 0x45
			p[9] = 17
			return p
		}(), false},
		{"ICMP 包（协议 1）", func() []byte {
			p := make([]byte, 28)
			p[0] = 0x45
			p[9] = 1
			return p
		}(), false},
		{"TCP 但长度不够放 flags", func() []byte {
			p := make([]byte, 24) // IHL=5 需要至少 20+14=34
			p[0] = 0x45
			p[9] = 6
			return p
		}(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTCPConnectAttempt(tc.pkt); got != tc.want {
				t.Fatalf("isTCPConnectAttempt() = %v, 期望 %v", got, tc.want)
			}
		})
	}
}

// fakeTunBatch 记录有多少个包被 Commit 进了 TUN 写批。
//
// Next 必须返回**带容量的非 nil 缓冲**：deliverInbound 拿 nil 会当成「批满」
// 去 Flush 再重取，仍为 nil 就整体 return——那样测的就不是隔离逻辑了。
type fakeTunBatch struct {
	commits  int
	lastSize int
	flushes  int
}

func (b *fakeTunBatch) Next() []byte { return make([]byte, 0, 4096) }
func (b *fakeTunBatch) Commit(size int) {
	if size <= 0 {
		return
	}
	b.commits++
	b.lastSize = size
}
func (b *fakeTunBatch) Flush() error { b.flushes++; return nil }

// sessionPairForInbound 走完整握手派生两端方向密钥，返回一对会话。
// 客户端会话用来封包（模拟后端 BDS 的回包），服务端会话装进 peerSession。
func sessionPairForInbound(t *testing.T) (client, server *tunnel.Session) {
	t.Helper()
	secret := []byte("per-code-secret")
	uid, err := tunnel.ParseUID("3f2b1c4d-5e6f-4071-8293-a4b5c6d7e8f9")
	if err != nil {
		t.Fatalf("ParseUID: %v", err)
	}
	var dev, dev2 [32]byte
	for i := range dev {
		dev[i] = byte(i)
		dev2[i] = byte(200 - i)
	}
	hello, clientPriv, err := tunnel.NewClientHelloV6(secret, uid, dev, dev2)
	if err != nil {
		t.Fatalf("NewClientHelloV6: %v", err)
	}
	parsed, err := tunnel.ParseClientHello(secret, hello.Marshal())
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	accept, serverPriv, err := tunnel.NewServerAccept(secret, parsed.Eph,
		netip.MustParseAddr("10.66.0.3"), netip.MustParseAddr("10.66.0.1"), 24, tunnel.MaxTunMTU, 0)
	if err != nil {
		t.Fatalf("NewServerAccept: %v", err)
	}
	acceptBack, err := tunnel.ParseServerAccept(secret, accept.Marshal(), hello.Eph)
	if err != nil {
		t.Fatalf("ParseServerAccept: %v", err)
	}
	cC2S, cS2C, err := tunnel.DeriveSessionKeys(tunnel.ECDHShared(&acceptBack.Eph, clientPriv), secret, hello.Eph, acceptBack.Eph)
	if err != nil {
		t.Fatalf("DeriveSessionKeys(client): %v", err)
	}
	sC2S, sS2C, err := tunnel.DeriveSessionKeys(tunnel.ECDHShared(&parsed.Eph, serverPriv), secret, parsed.Eph, accept.Eph)
	if err != nil {
		t.Fatalf("DeriveSessionKeys(server): %v", err)
	}
	client, err = tunnel.NewClientSession(cC2S, cS2C, 0, tunnel.MaxTunMTU)
	if err != nil {
		t.Fatalf("NewClientSession: %v", err)
	}
	server, err = tunnel.NewServerSession(sC2S, sS2C, 0, tunnel.MaxTunMTU)
	if err != nil {
		t.Fatalf("NewServerSession: %v", err)
	}
	return client, server
}

// 入向隔离的**接线**测试：用真会话封一个 Data 包打进 deliverInbound，验证
// 「哪些包真的进了 TUN 批」。
//
// 纯函数 allowReturnToGateway 的单测探不到调用点——把调用点改回零例外时那些
// 单测照样全绿，而线上表现是「请求发出去了、回程被丢、HTTP 超时」，服务端
// 日志只有一行隔离丢弃。这个用例就是堵那个缺口。
func TestDeliverInboundGatewayWiring(t *testing.T) {
	nopLogging()
	pool, gw, err := parseTunAddr("10.66.0.1/16")
	if err != nil {
		t.Fatal(err)
	}
	client, server := sessionPairForInbound(t)
	ps := newPeerSession(
		Identity{CodeID: "c1", CodeName: "222", UserName: "tester",
			TunIP: netip.MustParseAddr("10.66.0.3")},
		server, &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 5000}, tunnel.MaxTunMTU)
	// binder 必须给：deliverInbound 会 markActive，首包 shouldPersistTouch 为真，
	// 于是 goroutine 里调 TouchCode——nil binder 直接 panic。
	s := &Server{tunPool: pool, gateway: gw, binder: &fakeBinder{}}

	cases := []struct {
		name    string
		dst     string
		flags   byte
		ihlOpts int
		wantIn  bool // true = 应写进 TUN 批（递送给中转机）
	}{
		{"发往网关的 ACK 回包必须进 TUN（信令回程）", "10.66.0.1", 0x10, 0, true},
		{"发往网关的 PSH+ACK 数据回包必须进 TUN", "10.66.0.1", 0x18, 0, true},
		{"发往网关的 TCP SYN 不得进 TUN", "10.66.0.1", 0x02, 0, false},
		{"发往别人隧道地址不得进 TUN", "10.66.0.8", 0x10, 0, false},
		{"发往公网地址照常进 TUN", "203.0.113.9", 0x10, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := client.SealData(nil, tcpPkt("10.66.0.3", tc.dst, tc.flags, tc.ihlOpts))
			b := &fakeTunBatch{}
			s.deliverInbound(ps, wire, b)
			if tc.wantIn && b.commits == 0 {
				t.Fatalf("dst=%s flags=%#x 应写进 TUN 批，却被隔离丢弃", tc.dst, tc.flags)
			}
			if !tc.wantIn && b.commits != 0 {
				t.Fatalf("dst=%s flags=%#x 应被隔离丢弃，却写进了 TUN 批（%d 个）", tc.dst, tc.flags, b.commits)
			}
		})
	}
}

// Stop 必须在没有任何流量时也能立即返回。
//
// 两个泵 goroutine 阻塞在 ReadFromUDP / ReadPacket 上，只有拿到包才会回头看
// stop 通道；如果 Stop 先等 goroutine 退出再关 socket，闲置的隧道会让整个进程
// 永久卡在 Ctrl+C 上（实测现象：打完 "shutting down …" 就不动了）。
//
// 这里不建真 TUN（需要 root），只验证关闭顺序：socket 先关，等待有超时兜底。
func TestStopReturnsWithoutTraffic(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	udpConn := pc.(*net.UDPConn)

	s := &Server{
		cfg:  Config{TunName: "pftest0"}, // NAT=false，不会去动系统路由
		udp:  udpConn,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}

	// 模拟读循环：阻塞在 ReadFromUDP 上，socket 关闭后带错误返回。
	go func() {
		defer close(s.done)
		buf := make([]byte, 64)
		for {
			if _, _, err := s.udp.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()

	// 让读循环真正进入阻塞状态。
	time.Sleep(50 * time.Millisecond)

	returned := make(chan struct{})
	go func() {
		s.Stop()
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop 未能在 2 秒内返回：闲置隧道会导致进程无法退出")
	}
}

// Stop 可重复调用（stopOnce），第二次不得 panic 或阻塞。
func TestStopIsIdempotent(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	s := &Server{
		cfg:  Config{TunName: "pftest0"},
		udp:  pc.(*net.UDPConn),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	close(s.done) // 假装读循环已退出

	s.Stop()
	done := make(chan struct{})
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("第二次 Stop 阻塞了")
	}
}

// fakeBinder 记录 BindDevice/MigrateDevice 调用次数，用于验证指纹未变时的
// 短路与指纹 v2 的迁移路径。
type fakeBinder struct {
	binds    int
	migrates int
	lastBind string
}

func (b *fakeBinder) BindDevice(codeID, fingerprint, label, addr string) error {
	b.binds++
	b.lastBind = fingerprint
	return nil
}

func (b *fakeBinder) MigrateDevice(codeID, fromFP, toFP, label, addr string) (bool, error) {
	b.migrates++
	return true, nil
}

func (b *fakeBinder) TouchCode(codeID, addr string) {}

// 指纹未变化的重握手必须短路掉 BindDevice：每次握手都写库会把 fsync 拖进
// 握手路径，重试风暴下就是持续卡顿——这正是「有人疯狂重连全服卡顿」的
// 服务端病根之一。
func TestHandleHelloSkipsBindWhenFingerprintUnchanged(t *testing.T) {
	nopLogging()
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer clientConn.Close()
	from := addrPortOf(clientConn.LocalAddr().(*net.UDPAddr))

	secret := []byte("test-secret-test-secret-test!")
	uid, uerr := tunnel.ParseUID("3d2f5a1e-0000-0000-0000-000000000001")
	if uerr != nil {
		t.Fatalf("构造 uid 失败: %v", uerr)
	}
	device := [tunnel.FingerprintSize]byte{0xA1, 0xB2, 0xC3, 0xD4}
	fp := hex.EncodeToString(device[:])

	tunIP := netip.MustParseAddr("10.66.0.7")
	pool := netip.MustParsePrefix("10.66.0.0/16").Masked()
	binder := &fakeBinder{}
	ident := Identity{
		CodeID: "c1", UserName: "tester", Secret: secret,
		TunIP: tunIP, Fingerprint: fp,
	}
	s := &Server{
		udp:      serverConn.(*net.UDPConn),
		peers:    newRegistry(),
		identity: func(string) (Identity, bool) { return ident, true },
		binder:   binder,
		tunPool:  pool,
		gateway:  netip.MustParseAddr("10.66.0.1"),
		helloQ:   make(chan helloTask, helloQueueCap),
		tunMTU:   tunnel.MaxTunMTU,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}

	hello, _, herr := tunnel.NewClientHelloV6(secret, uid, device, device)
	if herr != nil {
		t.Fatalf("构造握手失败: %v", herr)
	}
	wire := hello.Marshal()

	// 首次接入（库里指纹为空）：必须写库绑定。
	ident.Fingerprint = ""
	s.handleHello(s.udp, wire, from)
	if binder.binds != 1 {
		t.Fatalf("首次握手应绑定设备，binds = %d", binder.binds)
	}

	// 重握手（库里指纹已是本机）：必须短路，不得再写库。
	ident.Fingerprint = fp
	s.handleHello(s.udp, wire, from)
	if binder.binds != 1 {
		t.Fatalf("指纹未变应短路 BindDevice，binds = %d", binder.binds)
	}

	// 换了设备（库里指纹是别的机器）：必须再次写库（互斥绑定语义不变）。
	other := [tunnel.FingerprintSize]byte{0x11, 0x22, 0x33, 0x44}
	hello2, _, herr := tunnel.NewClientHelloV6(secret, uid, other, other)
	if herr != nil {
		t.Fatalf("构造握手失败: %v", herr)
	}
	s.handleHello(s.udp, hello2.Marshal(), from)
	if binder.binds != 2 {
		t.Fatalf("指纹变化时应重新绑定，binds = %d", binder.binds)
	}
}

// 握手队列满时 queueHello 必须立刻返回（丢弃 + 限频告警），绝不能阻塞
// 数据泵——阻塞了就等于握手又一次卡住全体玩家的包。
func TestQueueHelloNeverBlocks(t *testing.T) {
	nopLogging()
	s := &Server{helloQ: make(chan helloTask, 1), stop: make(chan struct{})}
	from := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 9999)
	pkt := []byte{tunnel.TypeHello, 0x01}

	s.queueHello(pkt, from) // 队列还有空位
	done := make(chan struct{})
	go func() {
		s.queueHello(pkt, from) // 队列已满：必须丢弃而非阻塞
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("队列满时 queueHello 阻塞了——这会卡死数据泵")
	}
}

// 版本不匹配的跨版本应答（legacy.go 的服务端接线）：
//   - 旧版（MAC 可验证）的 Hello 必须收到拒绝应答——否则旧客户端只能显示
//     「服务端无应答（请检查防火墙）」，把版本问题误报成网络问题；
//   - 伪造/重放（MAC 无效）与未知访问码必须保持静默——不引入访问码存在性
//     探测口子，这是「Reject 只在认证后发」的同一条约束。
func TestHandleHelloRepliesVersionMismatch(t *testing.T) {
	nopLogging()
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer clientConn.Close()
	from := addrPortOf(clientConn.LocalAddr().(*net.UDPAddr))

	secret := []byte("test-secret-test-secret-test!")
	uid, uerr := tunnel.ParseUID("3d2f5a1e-0000-0000-0000-000000000001")
	if uerr != nil {
		t.Fatalf("构造 uid 失败: %v", uerr)
	}
	device := [tunnel.FingerprintSize]byte{0xA1, 0xB2, 0xC3, 0xD4}

	// 身份替身只认已知的 uid——「未知访问码」用例依赖它返回 false。
	knownUID := uid.String()
	s := &Server{
		udp:   serverConn.(*net.UDPConn),
		peers: newRegistry(),
		identity: func(codeID string) (Identity, bool) {
			if codeID != knownUID {
				return Identity{}, false
			}
			return Identity{CodeID: "c1", Secret: secret}, true
		},
		binder: &fakeBinder{},
		helloQ: make(chan helloTask, helloQueueCap),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}

	// 旧版（v3 格式）Hello：必须收到 35 字节的跨版本拒绝应答。
	legacy, lerr := tunnel.NewLegacyProbeHello(secret, uid, device)
	if lerr != nil {
		t.Fatalf("构造 v3 探测包失败: %v", lerr)
	}
	s.handleHello(s.udp, legacy, from)
	client := clientConn.(*net.UDPConn)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, tunnel.MaxPacket+64)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("旧客户端未收到任何应答（会显示「服务端无应答」）: %v", err)
	}
	const legacyRejectLen = 35 // [type][ver][reason][mac32]
	if n != legacyRejectLen {
		t.Fatalf("应答长度 = %d，期望 %d", n, legacyRejectLen)
	}
	if verdict := tunnel.ClassifyLegacyProbeReply(buf[:n]); verdict != tunnel.ProbeVersionSkew {
		t.Fatalf("旧客户端视角的应答判定 = %v，期望 ProbeVersionSkew（reason 0 的 v3 形拒绝）", verdict)
	}

	// MAC 无效（伪造/篡改）：必须静默，不回任何东西。
	tampered := append([]byte(nil), legacy...)
	tampered[25] ^= 0xFF
	s.handleHello(s.udp, tampered, from)
	if got := readDrop(client, buf); got {
		t.Fatal("MAC 无效的 Hello 被应答了：这会变成访问码存在性的探测口子")
	}

	// 未知访问码：同样静默（与正常握手「查无此码连 Reject 都不回」一致）。
	unknownUID, _ := tunnel.ParseUID("3d2f5a1e-0000-0000-0000-00000000dead")
	unknown, _ := tunnel.NewLegacyProbeHello(secret, unknownUID, device)
	s.handleHello(s.udp, unknown, from)
	if got := readDrop(client, buf); got {
		t.Fatal("未知访问码被应答了：这会变成访问码存在性的探测口子")
	}
}

// readDrop 短超时读一次，返回是否真的读到了包。
func readDrop(conn *net.UDPConn, buf []byte) bool {
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, _, err := conn.ReadFromUDP(buf)
	return err == nil
}

// 设备指纹 v2（Hello v5）的绑定与迁移矩阵：
// ① 未绑定 → 直接绑 v2；② 已绑主指纹 + 带 v2 → CAS 迁移；③ 已绑 v2 → 短路；
// ④ device2 == device（本机无第二指纹来源）→ 视为未携带，不迁移；
// ⑤ 绑定他机 → 拒绝且不得改写绑定。
func TestHandleHelloFingerprintV2BindingAndMigration(t *testing.T) {
	nopLogging()
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer serverConn.Close()
	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer clientConn.Close()
	from := addrPortOf(clientConn.LocalAddr().(*net.UDPAddr))

	secret := []byte("test-secret-test-secret-test!")
	uid, uerr := tunnel.ParseUID("3d2f5a1e-0000-0000-0000-000000000001")
	if uerr != nil {
		t.Fatalf("构造 uid 失败: %v", uerr)
	}
	device := [tunnel.FingerprintSize]byte{0xA1, 0xB2, 0xC3, 0xD4}
	device2 := [tunnel.FingerprintSize]byte{0x11, 0x22, 0x33, 0x44}
	otherDevice := [tunnel.FingerprintSize]byte{0x99, 0x88, 0x77, 0x66}
	fp := hex.EncodeToString(device[:])
	fp2 := hex.EncodeToString(device2[:])

	binder := &fakeBinder{}
	ident := Identity{
		CodeID: "c1", UserName: "tester", Secret: secret,
		TunIP: netip.MustParseAddr("10.66.0.7"), Fingerprint: "",
	}
	s := &Server{
		udp:      serverConn.(*net.UDPConn),
		peers:    newRegistry(),
		identity: func(string) (Identity, bool) { return ident, true },
		binder:   binder,
		tunPool:  netip.MustParsePrefix("10.66.0.0/16").Masked(),
		gateway:  netip.MustParseAddr("10.66.0.1"),
		helloQ:   make(chan helloTask, helloQueueCap),
		tunMTU:   tunnel.MaxTunMTU,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}

	hello5, _, herr := tunnel.NewClientHelloV6(secret, uid, device, device2)
	if herr != nil {
		t.Fatalf("构造 v6 握手失败: %v", herr)
	}
	wire5 := hello5.Marshal()
	hello5same, _, herr := tunnel.NewClientHelloV6(secret, uid, device, device)
	if herr != nil {
		t.Fatalf("构造退化 v6 握手失败: %v", herr)
	}
	wire5same := hello5same.Marshal()

	// ① 未绑定：直接绑更强的指纹 v2。
	s.handleHello(s.udp, wire5, from)
	if binder.binds != 1 || binder.lastBind != fp2 {
		t.Fatalf("未绑定应直接绑指纹 v2：binds=%d lastBind=%q", binder.binds, binder.lastBind)
	}

	// ② 已绑主指纹 + 带 v2：迁移（不新增 bind）。
	ident.Fingerprint = fp
	s.handleHello(s.udp, wire5, from)
	if binder.migrates != 1 || binder.binds != 1 {
		t.Fatalf("应迁移到指纹 v2：migrates=%d binds=%d", binder.migrates, binder.binds)
	}

	// ③ 已绑 v2：短路，无任何写库。
	ident.Fingerprint = fp2
	s.handleHello(s.udp, wire5, from)
	if binder.migrates != 1 || binder.binds != 1 {
		t.Fatalf("已绑 v2 应短路：migrates=%d binds=%d", binder.migrates, binder.binds)
	}

	// ④ device2 == device：视为未携带 v2，绑主指纹语义（短路）。
	ident.Fingerprint = fp
	s.handleHello(s.udp, wire5same, from)
	if binder.migrates != 1 || binder.binds != 1 {
		t.Fatalf("退化 v5 应视为未携带：migrates=%d binds=%d", binder.migrates, binder.binds)
	}

	// ⑤ 绑定他机：仍会尝试登记（互斥语义由存储层拒绝，见 storage 测试），
	// 但不得发生迁移。
	ident.Fingerprint = hex.EncodeToString(otherDevice[:])
	binder.binds, binder.migrates = 0, 0
	s.handleHello(s.udp, wire5, from)
	if binder.binds != 1 || binder.migrates != 0 {
		t.Fatalf("绑定他机应尝试登记且不迁移：binds=%d migrates=%d", binder.binds, binder.migrates)
	}
}

// TestSubnetBroadcast 锁广播地址计算：/16 → 10.66.255.255（用户日志里那种
// 客户端固有噪音的目的地）；/24 → 尾段 255；/32 与无效前缀退化为零值
// （logTunnelInternal 按「不等于」处理，天然不降级）。
func TestSubnetBroadcast(t *testing.T) {
	cases := []struct {
		prefix string
		want   string
	}{
		{"10.66.0.0/16", "10.66.255.255"},
		{"10.66.0.0/24", "10.66.0.255"},
		{"192.168.1.128/25", "192.168.1.255"},
	}
	for _, tc := range cases {
		got := subnetBroadcast(netip.MustParsePrefix(tc.prefix))
		if got.String() != tc.want {
			t.Fatalf("%s 广播 = %s, want %s", tc.prefix, got, tc.want)
		}
	}
	if got := subnetBroadcast(netip.MustParsePrefix("10.66.0.4/32")); got.IsValid() {
		t.Fatalf("/32 应退化为零值，得到 %v", got)
	}
	if got := subnetBroadcast(netip.Prefix{}); got.IsValid() {
		t.Fatalf("无效前缀应退化为零值，得到 %v", got)
	}
}

// TestHandlePongObservesRTT 锁「面板往返延迟」的数据源：服务端心跳 Ping 的
// 应答经验证后必须观测 RTT（此前 TypePong 只刷活跃时间，往返延迟恒为空）。
// 无效 Pong（错误密钥）必须拒绝且不产生观测。
func TestHandlePongObservesRTT(t *testing.T) {
	var k1, k2 [32]byte
	k1[0], k2[0] = 0x11, 0x22
	clientSess, err := tunnel.NewClientSession(&k1, &k2, 0, 1400)
	if err != nil {
		t.Fatal(err)
	}
	serverSess, err := tunnel.NewServerSession(&k1, &k2, 0, 1400)
	if err != nil {
		t.Fatal(err)
	}
	ident := Identity{
		CodeID: "c1", UserName: "tester", CodeName: "code",
		TunIP: netip.MustParseAddr("10.66.0.7"),
	}
	ps := newPeerSession(ident, serverSess,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}, 1400)
	ps.lastPingSentNanos.Store(time.Now().UnixNano() - int64(50*time.Millisecond))

	s := &Server{}
	wire := clientSess.SealPong(make([]byte, 0, 64), 0, 0)
	if !s.handlePong(ps, wire) {
		t.Fatal("有效 Pong 应通过验证")
	}
	if rtt := serverSess.Stats().View().RTTMS; rtt <= 0 {
		t.Fatalf("RTT 应有观测值（约 50ms），得到 %v", rtt)
	}

	// 错误密钥的 Pong：拒绝且不污染观测。
	bad1, bad2 := [32]byte{0x99}, [32]byte{0x99}
	otherSess, err := tunnel.NewClientSession(&bad1, &bad2, 0, 1400)
	if err != nil {
		t.Fatal(err)
	}
	if s.handlePong(ps, otherSess.SealPong(make([]byte, 0, 64), 0, 0)) {
		t.Fatal("错误密钥的 Pong 必须拒绝")
	}
}
