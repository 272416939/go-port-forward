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
	from := clientConn.LocalAddr().(*net.UDPAddr)

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
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
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
