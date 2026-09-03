package forward

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go.uber.org/zap"
)

// freeUDPAddr 取一个当前空闲的 loopback UDP 地址（先占后放，供后续 bind）。
func freeUDPAddr(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	addr := conn.LocalAddr().(*net.UDPAddr)
	_ = conn.Close()
	return addr
}

// listenUDP 分配一个存活的 loopback UDP socket（后端/玩家口），测试结束自动关闭。
func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// testFwd 构造仅带规则与回程出口的转发器骨架（不 Start；注册表只用到
// rule.Name / targetAddr / conn / bytesOut）。
func testFwd(t *testing.T, id string, target *net.UDPAddr) *UDPForwarder {
	t.Helper()
	f := &UDPForwarder{
		rule:       &models.ForwardRule{ID: id, Name: "rule-" + id, Protocol: models.ProtocolUDP, Transparent: true},
		targetAddr: target,
	}
	if target != nil {
		f.conn = listenUDP(t) // 回程出口：真 socket 才能收断言包
	}
	return f
}

func recvUDP(t *testing.T, conn *net.UDPConn, want string, wantSrcPort int) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, src, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read %q: %v", want, err)
	}
	if string(buf[:n]) != want {
		t.Fatalf("payload = %q, want %q", string(buf[:n]), want)
	}
	if wantSrcPort > 0 && src.Port != wantSrcPort {
		t.Fatalf("src port = %d, want %d", src.Port, wantSrcPort)
	}
}

func assertNoUDP(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 128)
	if n, _, err := conn.ReadFromUDP(buf); err == nil {
		t.Fatalf("unexpected packet %q", string(buf[:n]))
	}
}

func registryEntriesLocked(reg *tupleRegistry) int {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return len(reg.entries)
}

// TestMakeUDPAddrKeyNormalizesV4Mapped 回归锁：net.ParseIP/ResolveUDPAddr 产出
// v4-mapped 16 字节表示，ReadFromUDP 产出 4 字节表示——同一地址必须同键，
// 否则回程分发（后端源 → 订阅）永远 miss（透明共享注册表曾因此全灭回程）。
func TestMakeUDPAddrKeyNormalizesV4Mapped(t *testing.T) {
	mapped := net.ParseIP("10.66.0.4") // 16 字节 v4-mapped
	bare := net.IP(append([]byte(nil), mapped.To4()...)) // 4 字节（ReadFromUDP 形式）
	kA := makeUDPAddrKey(&net.UDPAddr{IP: mapped, Port: 58618})
	kB := makeUDPAddrKey(&net.UDPAddr{IP: bare, Port: 58618})
	if kA != kB {
		t.Fatal("v4-mapped 与 4 字节表示必须归一化为同一 key")
	}
	k6 := makeUDPAddrKey(&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 1})
	if k6.len != 16 {
		t.Fatalf("IPv6 key 长度 = %d, want 16", k6.len)
	}
}

// TestTupleRegistrySharedBindingRefCountAndRebind 锁共享绑定的核心不变量：
// 同元组只 bind 一次、引用归零才关、归零后立即重建必成功（无 EADDRINUSE 窗口）。
func TestTupleRegistrySharedBindingRefCountAndRebind(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	bindTuple := freeUDPAddr(t) // 模拟 IP_TRANSPARENT 绑定的玩家对外元组
	calls := &atomic.Int64{}
	reg := newTupleRegistry(func(src *net.UDPAddr) (*net.UDPConn, error) {
		calls.Add(1)
		return net.ListenUDP("udp", bindTuple)
	})
	t.Cleanup(reg.Close)

	f1 := testFwd(t, "r1", nil)
	f2 := testFwd(t, "r2", nil)
	src := freeUDPAddr(t) // 会话源（注册表键）

	h1, err := reg.acquire(f1, src)
	if err != nil {
		t.Fatalf("acquire f1: %v", err)
	}
	h2, err := reg.acquire(f2, src)
	if err != nil {
		t.Fatalf("第二条规则共享绑定失败: %v（旧实现此处为 bind: address already in use）", err)
	}
	if h1.conn() != h2.conn() {
		t.Fatal("两条规则必须共享同一个透明 socket")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("factory 调用次数 = %d, want 1（共享即不再绑定）", got)
	}

	// 引用计数：h1 释放后 conn 必须仍存活（h2 还在用）
	h1.release()
	if _, err := h2.conn().WriteToUDP([]byte("x"), bindTuple); err != nil {
		t.Fatalf("h1 释放后共享 socket 被提前关闭: %v", err)
	}

	// 全部释放 → 条目摘除 + fd 关闭
	h2.release()
	waitFor(t, time.Second, func() bool { return registryEntriesLocked(reg) == 0 })
	if _, err := h2.conn().WriteToUDP([]byte("x"), bindTuple); err == nil {
		t.Fatal("全部释放后共享 socket 应已关闭")
	}

	// 关闭握手：归零后立即重取同一元组必须 bind 成功——「条目已删、fd 还绑着」
	// 的窗口会让这里撞 EADDRINUSE（回归锁）
	h3, err := reg.acquire(f1, src)
	if err != nil {
		t.Fatalf("归零后立即重建绑定失败: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("factory 调用次数 = %d, want 2", got)
	}
	h3.release()
}

// TestTupleRegistryDispatchByBackendSource 锁回程按源地址（后端元组）精确分流：
// 后端 A 的回包只经规则 1 的转发口回玩家，后端 B 同理。
func TestTupleRegistryDispatchByBackendSource(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	backendA := listenUDP(t)
	backendB := listenUDP(t)
	player := listenUDP(t) // 回程投递口（clientAddr）

	bindTuple := freeUDPAddr(t)
	reg := newTupleRegistry(func(src *net.UDPAddr) (*net.UDPConn, error) {
		return net.ListenUDP("udp", bindTuple)
	})
	t.Cleanup(reg.Close)

	f1 := testFwd(t, "r1", backendA.LocalAddr().(*net.UDPAddr))
	f2 := testFwd(t, "r2", backendB.LocalAddr().(*net.UDPAddr))
	src := freeUDPAddr(t)

	h1, err := reg.acquire(f1, src)
	if err != nil {
		t.Fatalf("acquire f1: %v", err)
	}
	defer h1.release()
	h1.attach(&udpSession{}, player.LocalAddr().(*net.UDPAddr))
	h2, err := reg.acquire(f2, src)
	if err != nil {
		t.Fatalf("acquire f2: %v", err)
	}
	defer h2.release()
	h2.attach(&udpSession{}, player.LocalAddr().(*net.UDPAddr))

	// 后端 A 回包 → 只应经 f1 的转发口到玩家
	if _, err := backendA.WriteToUDP([]byte("from-a"), bindTuple); err != nil {
		t.Fatalf("backendA write: %v", err)
	}
	recvUDP(t, player, "from-a", f1.conn.LocalAddr().(*net.UDPAddr).Port)
	assertNoUDP(t, player)

	// 后端 B 回包 → f2
	if _, err := backendB.WriteToUDP([]byte("from-b"), bindTuple); err != nil {
		t.Fatalf("backendB write: %v", err)
	}
	recvUDP(t, player, "from-b", f2.conn.LocalAddr().(*net.UDPAddr).Port)
}

// TestTupleRegistryBroadcastOnSameBackend 锁存量「同后端端口重复配置」的广播
// 兜底：两条规则同 target 时回程无法按源区分，广播给全部订阅者（各自经自己
// 的转发口发回，NAT 映射各自成立）。
func TestTupleRegistryBroadcastOnSameBackend(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	backend := listenUDP(t)
	player := listenUDP(t)
	bindTuple := freeUDPAddr(t)
	reg := newTupleRegistry(func(src *net.UDPAddr) (*net.UDPConn, error) {
		return net.ListenUDP("udp", bindTuple)
	})
	t.Cleanup(reg.Close)

	f1 := testFwd(t, "r1", backend.LocalAddr().(*net.UDPAddr))
	f2 := testFwd(t, "r2", backend.LocalAddr().(*net.UDPAddr))
	src := freeUDPAddr(t)

	h1, err := reg.acquire(f1, src)
	if err != nil {
		t.Fatalf("acquire f1: %v", err)
	}
	defer h1.release()
	h1.attach(&udpSession{}, player.LocalAddr().(*net.UDPAddr))
	h2, err := reg.acquire(f2, src)
	if err != nil {
		t.Fatalf("acquire f2: %v", err)
	}
	defer h2.release()
	h2.attach(&udpSession{}, player.LocalAddr().(*net.UDPAddr))

	if _, err := backend.WriteToUDP([]byte("dup"), bindTuple); err != nil {
		t.Fatalf("backend write: %v", err)
	}
	recvUDP(t, player, "dup", f1.conn.LocalAddr().(*net.UDPAddr).Port)
	recvUDP(t, player, "dup", f2.conn.LocalAddr().(*net.UDPAddr).Port)
}

// TestTupleRegistryFactoryFailureNoResidue：工厂失败（外部进程真占用玩家元组）
// 必须上抛且不残留条目（fail-closed 维持现状语义）。
func TestTupleRegistryFactoryFailureNoResidue(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	reg := newTupleRegistry(func(src *net.UDPAddr) (*net.UDPConn, error) {
		return nil, errors.New("bind: address already in use (simulated)")
	})
	t.Cleanup(reg.Close)

	f := testFwd(t, "r1", nil)
	if _, err := reg.acquire(f, freeUDPAddr(t)); err == nil {
		t.Fatal("工厂失败必须上抛")
	}
	if n := registryEntriesLocked(reg); n != 0 {
		t.Fatalf("失败后条目应清空，剩 %d", n)
	}
}

// TestTupleRegistryCloseDuringCreation：创建中途关停，等待与创建路径都必须
// 立即失败返回，不得卡死（铁律 3：先关 fd 再等 goroutine）。
func TestTupleRegistryCloseDuringCreation(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	release := make(chan struct{})
	entered := &atomic.Bool{}
	reg := newTupleRegistry(func(src *net.UDPAddr) (*net.UDPConn, error) {
		entered.Store(true)
		<-release
		return nil, errors.New("aborted")
	})
	t.Cleanup(reg.Close)

	f := testFwd(t, "r1", nil)
	src := freeUDPAddr(t)
	done := make(chan error, 1)
	go func() {
		_, err := reg.acquire(f, src)
		done <- err
	}()
	waitFor(t, 2*time.Second, func() bool { return entered.Load() })
	reg.Close()           // 创建中途关停
	close(release)        // 放行工厂
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("关停后 acquire 必须失败")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acquire 未在关停后返回（创建/等待路径卡死）")
	}
}

// TestTupleRegistryConcurrentAcquireRelease：多 goroutine 并发 acquire/release
// 同一玩家元组，全部成功、无错误（引用计数与创建占位不得产生 EADDRINUSE）、
// 结束后无条目泄漏。本机无 -race（无 cgo），以计数断言代替竞态检测。
func TestTupleRegistryConcurrentAcquireRelease(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	bindTuple := freeUDPAddr(t)
	calls := &atomic.Int64{}
	reg := newTupleRegistry(func(src *net.UDPAddr) (*net.UDPConn, error) {
		calls.Add(1)
		return net.ListenUDP("udp", bindTuple)
	})
	t.Cleanup(reg.Close)

	src := freeUDPAddr(t)
	const workers, iters = 8, 50
	fwds := make([]*UDPForwarder, workers)
	for i := range fwds {
		fwds[i] = testFwd(t, fmt.Sprintf("r%d", i), nil)
	}
	var wg sync.WaitGroup
	var okCount atomic.Int64
	errCh := make(chan error, workers*iters)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(f *UDPForwarder) {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				h, err := reg.acquire(f, src)
				if err != nil {
					errCh <- err
					continue
				}
				okCount.Add(1)
				h.release()
			}
		}(fwds[i])
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("并发 acquire 失败: %v", err)
	}
	if got := okCount.Load(); got != workers*iters {
		t.Fatalf("成功 acquire = %d, want %d", got, workers*iters)
	}
	if n := registryEntriesLocked(reg); n != 0 {
		t.Fatalf("全部释放后条目应清空，剩 %d", n)
	}
	if calls.Load() < 1 {
		t.Fatal("factory 未被调用")
	}
}
