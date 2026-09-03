package tunnelapp

// UDP 收发路径的用例（OPT-6 / OPT-11 / OPT-16）。
//
// 批量化是数据面上最容易引入「静默丢包 / 乱序 / 串包」的一处改动，而它在
// Windows 上根本走不到 recvmmsg——所以这里的重点是：① 逐包与批量两条路径的
// 交付语义必须一致；② 平台不支持时必须**明确降级**而不是静默失败；③ GSO 的
// 等长约束与 GRO 的拆包边界必须逐条锁死（内核对违反者不报错，只给出长度错乱
// 的包）。

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"go-port-forward/pkg/tunnel"
)

func localUDP(t testing.TB) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.(*net.UDPConn)
}

// 逐包读源必须原样交付包内容与来源地址，且 v4-in-v6 映射要被归一——不归一
// 会让同一个客户端在会话表里占两个键，症状是换端口重连后包发到旧地址。
func TestSimpleReaderDeliversPackets(t *testing.T) {
	server := localUDP(t)
	client := localUDP(t)
	reader := newSimpleReader(server)

	want := []byte{tunnel.TypeData, 1, 2, 3}
	if _, err := client.WriteToUDP(want, server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	pkt, from, err := reader.read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(pkt) != string(want) {
		t.Fatalf("内容 = %x，期望 %x", pkt, want)
	}
	if from.Addr().Is4In6() {
		t.Fatal("来源地址未归一成 IPv4：会在会话表里占两个键")
	}
	if from.Port() != uint16(client.LocalAddr().(*net.UDPAddr).Port) {
		t.Fatalf("来源端口 = %d", from.Port())
	}
	// 逐包模式没有批的概念，buffered 恒为 0（每包都会触发一次冲刷）。
	if reader.buffered() != 0 {
		t.Fatalf("buffered = %d，逐包模式应恒为 0", reader.buffered())
	}
	if reader.mode() != "simple" {
		t.Fatalf("mode = %q", reader.mode())
	}
}

// 逐包写出口必须立即发出（pending 恒为 0），否则包会攒在一个永不冲刷的批里。
func TestSimpleWriterSendsImmediately(t *testing.T) {
	server := localUDP(t)
	client := localUDP(t)
	w := &simpleWriter{conn: client}

	to := addrPortOf(server.LocalAddr().(*net.UDPAddr))
	want := []byte("hello")
	if !w.add(want, to) {
		t.Fatal("逐包写出口不该报批满")
	}
	if w.pending() != 0 {
		t.Fatalf("pending = %d，逐包模式必须立即发出", w.pending())
	}
	buf := make([]byte, 64)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("接收失败: %v", err)
	}
	if string(buf[:n]) != string(want) {
		t.Fatalf("收到 %q", buf[:n])
	}
	if n, ferr := w.flush(); n != 0 || ferr != nil {
		t.Fatalf("逐包模式 flush 应是空操作: %d %v", n, ferr)
	}
}

// 平台不支持批量时必须降级到逐包，并在 setup 里留下可读的原因。
// 静默降级会让人对着「改了没效果」查半天。
func TestNewUDPIORespectsPlatformSupport(t *testing.T) {
	conn := localUDP(t)
	r, w, setup := newUDPIO(conn, true, false, false)
	if batchSupported() {
		if !setup.Batch || setup.Mode != "batch" {
			t.Fatalf("Linux 上应启用批量: %+v", setup)
		}
		if _, ok := r.(*batchReader); !ok {
			t.Fatalf("读源类型 = %T", r)
		}
		if _, ok := w.(*batchWriter); !ok {
			t.Fatalf("写出口类型 = %T", w)
		}
	} else {
		if setup.Batch || setup.Mode != "simple" {
			t.Fatalf("非 Linux 必须降级: %+v", setup)
		}
		if len(setup.Notes) == 0 {
			t.Fatal("降级必须留下原因，否则无法解释「批量没生效」")
		}
		if _, ok := r.(*simpleReader); !ok {
			t.Fatalf("读源类型 = %T", r)
		}
	}
}

// io_mode=simple 明确关闭批量：这是回退开关，必须无条件生效且不留降级说明
// （那是用户的选择，不是能力受限）。
func TestNewUDPIOHonorsSimpleMode(t *testing.T) {
	conn := localUDP(t)
	r, w, setup := newUDPIO(conn, false, true, true)
	if setup.Batch || setup.GRO || setup.GSO || setup.Mode != "simple" {
		t.Fatalf("io_mode=simple 必须关闭全部批量能力: %+v", setup)
	}
	if len(setup.Notes) != 0 {
		t.Fatalf("显式选择 simple 不该产出降级说明: %v", setup.Notes)
	}
	if _, ok := r.(*simpleReader); !ok {
		t.Fatalf("读源类型 = %T", r)
	}
	if _, ok := w.(*simpleWriter); !ok {
		t.Fatalf("写出口类型 = %T", w)
	}
}

func TestConfigWantBatchIO(t *testing.T) {
	for mode, want := range map[string]bool{
		"":       true, // Defaults 会填 batch
		"batch":  true,
		"BATCH":  true,
		"simple": false,
		"Simple": false,
		"其它":     true, // 未知值按默认（批量）处理，不要静默变成 simple
	} {
		c := Config{IOMode: mode}
		if got := c.wantBatchIO(); got != want {
			t.Errorf("io_mode=%q wantBatchIO = %v, 期望 %v", mode, got, want)
		}
	}
	c := Config{}
	c.Defaults()
	if c.IOMode != "batch" {
		t.Fatalf("默认 io_mode = %q，期望 batch", c.IOMode)
	}
}

// 特性位必须由服务端配置决定并对称下发：一端发 FEC 另一端不认，那些校验包
// 会被当未知类型静默丢弃，表现成「开了纠错反而更卡」。
func TestConfigFeatures(t *testing.T) {
	if got := (&Config{}).features(); got != 0 {
		t.Fatalf("默认应无特性位，得到 %d", got)
	}
	if got := (&Config{FEC: true}).features(); got != tunnel.FeatFEC {
		t.Fatalf("FEC 位 = %d", got)
	}
	if got := (&Config{TailDup: true}).features(); got != tunnel.FeatTailDup {
		t.Fatalf("TailDup 位 = %d", got)
	}
	if got := (&Config{FEC: true, TailDup: true}).features(); got != tunnel.FeatFEC|tunnel.FeatTailDup {
		t.Fatalf("两项同时开启 = %d", got)
	}
}

// 开启 FEC 必须让出校验包的额外开销：不让的话校验包自己会被 IP 分片，而分片
// 丢一片等于整包全损——正是 FEC 想解决的问题。
func TestNegotiateTunMTUReservesFECOverhead(t *testing.T) {
	plain := negotiateTunMTU(Config{})
	withFEC := negotiateTunMTU(Config{FEC: true})
	if plain <= 0 || withFEC <= 0 {
		t.Fatalf("MTU 必须为正: %d / %d", plain, withFEC)
	}
	if plain-withFEC != tunnel.FECOverhead {
		t.Fatalf("开启 FEC 后应让出 %d 字节，实际 %d", tunnel.FECOverhead, plain-withFEC)
	}
	if plain > tunnel.MaxTunMTU {
		t.Fatalf("MTU %d 超出协议上限 %d", plain, tunnel.MaxTunMTU)
	}
}

// GSO 的等长约束：除末段外各段必须等长，否则内核会切出长度错乱的包（不报错）。
func TestSegRunEnforcesEqualSegments(t *testing.T) {
	// 首包 1000，第二个同长 → 可合并，段长定为 1000。
	r := segRun{total: 1000}
	if !r.canAppend(1000) {
		t.Fatal("等长包应可合并")
	}
	r = r.append(1000)
	if r.segSize != 1000 || r.total != 2000 || r.closed {
		t.Fatalf("状态 = %+v", r)
	}
	if r.controlSize() != 1000 {
		t.Fatalf("controlSize = %d", r.controlSize())
	}
	// 更长的包不能合并（会被按 1000 切开）。
	if r.canAppend(1200) {
		t.Fatal("超过段长的包不得合并")
	}
	// 更短的包可以作为末段，但之后必须封口。
	if !r.canAppend(400) {
		t.Fatal("短尾段应可合并")
	}
	r = r.append(400)
	if !r.closed {
		t.Fatal("短尾段之后必须封口")
	}
	if r.canAppend(400) {
		t.Fatal("封口后不得再合并")
	}
	// 单包消息不需要 GSO 控制数据。
	single := segRun{total: 800}
	if single.controlSize() != 0 {
		t.Fatalf("单包 controlSize = %d，应为 0", single.controlSize())
	}
	// 空消息不能被合并进去（没有段长基准）。
	if (segRun{}).canAppend(100) {
		t.Fatal("空消息不该报可合并")
	}
}

// 突发上限：一条 GSO 消息不能无限攒，否则会撞上内核的段数上限（EINVAL）。
func TestSegRunRespectsBurstLimit(t *testing.T) {
	r := segRun{total: gsoMaxBurst - 100, segSize: 100}
	if !r.canAppend(100) {
		t.Fatal("未超上限应可合并")
	}
	r = r.append(100)
	if r.canAppend(100) {
		t.Fatal("达到突发上限后不得再合并")
	}
}

// GRO 拆包边界：聚合消息按内核给出的段长切分，末段可以短；没有聚合时按单包。
func TestGROSegmentation(t *testing.T) {
	cases := []struct {
		total, segSize, wantN int
	}{
		{1400, 0, 1},    // 未聚合
		{1400, 1400, 1}, // 段长等于总长 = 单包
		{1400, 2000, 1}, // 段长大于总长（不该出现，按单包兜底）
		{2800, 1400, 2}, // 两个满段
		{3000, 1400, 3}, // 两个满段 + 200 字节末段
	}
	for _, c := range cases {
		if got := groSegments(c.total, c.segSize); got != c.wantN {
			t.Errorf("groSegments(%d,%d) = %d, 期望 %d", c.total, c.segSize, got, c.wantN)
		}
	}
	// 逐段边界必须无缝拼回原始缓冲，且末段不越界。
	total, seg := 3000, 1400
	prevEnd := 0
	for i := 0; i < groSegments(total, seg); i++ {
		start, end := groSegmentAt(total, seg, i)
		if start != prevEnd {
			t.Fatalf("第 %d 段起点 %d 与上一段终点 %d 不连续", i, start, prevEnd)
		}
		if end > total {
			t.Fatalf("第 %d 段终点 %d 越界（总长 %d）", i, end, total)
		}
		prevEnd = end
	}
	if prevEnd != total {
		t.Fatalf("拆分未覆盖全部字节: %d/%d", prevEnd, total)
	}
	// 未聚合时整条消息就是一个包。
	if start, end := groSegmentAt(1400, 0, 0); start != 0 || end != 1400 {
		t.Fatalf("未聚合切分 = [%d,%d)", start, end)
	}
}

// 会话表的查表键必须归一 v4-in-v6：同一个客户端占两个键会让换端口重连后
// 包发到旧地址（而旧地址上的会话密钥已经废弃）。
func TestAddrPortNormalization(t *testing.T) {
	v4 := addrPortOf(&net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1234})
	mapped := addrPortOf(&net.UDPAddr{IP: net.ParseIP("::ffff:203.0.113.9"), Port: 1234})
	if v4 != mapped {
		t.Fatalf("v4 与 v4-in-v6 应归一成同一个键: %v vs %v", v4, mapped)
	}
	if v4.Addr().Is4In6() {
		t.Fatal("归一后不该仍是映射地址")
	}
	if addrPortOf(nil).IsValid() {
		t.Fatal("nil 地址应返回无效 AddrPort")
	}
	// 还原回 *net.UDPAddr 供写 API 使用时不得丢信息。
	back := udpAddrOf(v4)
	if !back.IP.Equal(net.ParseIP("203.0.113.9")) || back.Port != 1234 {
		t.Fatalf("还原后 = %v", back)
	}
	if got := normalizeAddrPort(netip.MustParseAddrPort("[::ffff:1.2.3.4]:99")); got.Addr().Is4In6() {
		t.Fatalf("normalizeAddrPort 未归一: %v", got)
	}
}
