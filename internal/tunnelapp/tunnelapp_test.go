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

// fakeBinder 记录 BindDevice 调用次数，用于验证指纹未变时的短路。
type fakeBinder struct {
	binds int
}

func (b *fakeBinder) BindDevice(codeID, fingerprint, label, addr string) error {
	b.binds++
	return nil
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

	hello, _, herr := tunnel.NewClientHello(secret, uid, device)
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
	hello2, _, herr := tunnel.NewClientHello(secret, uid, other)
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

	s := &Server{
		udp:      serverConn.(*net.UDPConn),
		peers:    newRegistry(),
		identity: func(codeID string) (Identity, bool) { return Identity{CodeID: "c1", Secret: secret}, true },
		binder:   &fakeBinder{},
		helloQ:   make(chan helloTask, helloQueueCap),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
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
