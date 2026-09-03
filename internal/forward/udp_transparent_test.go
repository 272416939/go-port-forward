package forward

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go.uber.org/zap"
)

// transparentFixture 构建两条透明规则 + 两个后端 + 一个「玩家」收包口 +
// 共享绑定注册表。bindTuple 模拟 IP_TRANSPARENT 绑定的「玩家对外元组」——
// 与回程投递口（clientAddr=player）解耦：生产中两者是同一个玩家，测试里
// 分开绑定以便在 loopback 上断言（共享 socket 占住绑定元组，玩家口另用地址）。
type transparentFixture struct {
	reg       *tupleRegistry
	calls     *atomic.Int64
	f1, f2    *UDPForwarder
	b1, b2    *net.UDPConn // 后端（游戏服）
	player    *net.UDPConn // 玩家收包口（= 会话源 / clientAddr）
	bindTuple *net.UDPAddr
}

func newTransparentFixture(t *testing.T, timeoutSec int) *transparentFixture {
	t.Helper()
	b1 := listenUDP(t)
	b2 := listenUDP(t)
	player := listenUDP(t)
	bindTuple := freeUDPAddr(t)
	calls := &atomic.Int64{}
	reg := newTupleRegistry(func(src *net.UDPAddr) (*net.UDPConn, error) {
		// 固定绑定 bindTuple（生产由 transparentUDPFactory 以 IP_TRANSPARENT
		// 绑定玩家源元组完成同等工作）
		calls.Add(1)
		return net.ListenUDP("udp", bindTuple)
	})
	t.Cleanup(reg.Close)

	mk := func(id string, target *net.UDPConn) *UDPForwarder {
		f := newUDPForwarder(&models.ForwardRule{
			ID:          id,
			Name:        "透明-" + id,
			ListenAddr:  "127.0.0.1",
			ListenPort:  0,
			Protocol:    models.ProtocolUDP,
			Transparent: true,
			TargetAddr:  "127.0.0.1",
			TargetPort:  target.LocalAddr().(*net.UDPAddr).Port,
		}, timeoutSec)
		// 最小 svc：guard/sessions/logs 全走 nil-safe 链（见 acl.go）
		f.svc = &forwardServices{tuples: reg}
		if err := f.Start(); err != nil {
			t.Fatalf("start %s: %v", id, err)
		}
		t.Cleanup(f.Stop)
		return f
	}
	return &transparentFixture{
		reg: reg, calls: calls,
		f1: mk("t1", b1), f2: mk("t2", b2),
		b1: b1, b2: b2, player: player, bindTuple: bindTuple,
	}
}

// roundTrip 模拟玩家从收包口发包经转发器 → 后端收到（源=绑定元组，源地址
// 保真）→ 后端回包 → 玩家收到（源端口=该转发器的监听端口）。
func (fx *transparentFixture) roundTrip(t *testing.T, f *UDPForwarder, backend *net.UDPConn, payload string) {
	t.Helper()
	fwdAddr := f.conn.LocalAddr().(*net.UDPAddr)
	if _, err := fx.player.WriteToUDP([]byte(payload), fwdAddr); err != nil {
		t.Fatalf("player write %q: %v", payload, err)
	}
	_ = backend.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, src, err := backend.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("backend read %q: %v", payload, err)
	}
	if string(buf[:n]) != payload {
		t.Fatalf("backend payload = %q, want %q", string(buf[:n]), payload)
	}
	if src.Port != fx.bindTuple.Port || !src.IP.Equal(fx.bindTuple.IP) {
		t.Fatalf("后端看到的源 = %v, want 绑定元组 %v（源地址保真被破坏）", src, fx.bindTuple)
	}
	if _, err := backend.WriteToUDP([]byte(payload), src); err != nil {
		t.Fatalf("backend reply %q: %v", payload, err)
	}
	_ = fx.player.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, src, err = fx.player.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("player read %q: %v", payload, err)
	}
	if string(buf[:n]) != payload {
		t.Fatalf("player payload = %q, want %q", string(buf[:n]), payload)
	}
	if src.Port != fwdAddr.Port {
		t.Fatalf("回程源端口 = %d, want 转发器监听端口 %d", src.Port, fwdAddr.Port)
	}
}

// TestUDPForwarderTransparentSharedBindingAcrossRules 端到端锁「同一玩家元组 ×
// 两条透明规则」互通。⚠️ 旧所有权模型下此用例必然失败：第二条规则直接 bind
// 同一玩家元组，内核 EADDRINUSE，会话建不出来（2026-09 两次现形）——先证旧
// 写法必败，再证修复通过。
func TestUDPForwarderTransparentSharedBindingAcrossRules(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	fx := newTransparentFixture(t, 5)

	// 玩家从同一源端口 ping/连两个透明端口（EIM NAT 复用形态）
	fx.roundTrip(t, fx.f1, fx.b1, "ping-1")
	fx.roundTrip(t, fx.f2, fx.b2, "ping-2")

	if got := fx.calls.Load(); got != 1 {
		t.Fatalf("绑定应共享（factory 调用 = %d, want 1；旧实现为各规则自行 bind）", got)
	}

	// 会话视图按规则隔离：两条规则各有自己的活跃会话（面板语义不变）
	if _, _, a1, _ := fx.f1.Stats(); a1 != 1 {
		t.Fatalf("f1 active = %d, want 1", a1)
	}
	if _, _, a2, _ := fx.f2.Stats(); a2 != 1 {
		t.Fatalf("f2 active = %d, want 1", a2)
	}
}

// TestUDPForwarderTransparentSwitchBetweenRules 锁「玩家频繁切服」语义：
// 同一玩家元组在两条规则间往返——切新服即时共享绑定（不再抢 bind）；旧会话
// 空闲回收后绑定仍被另一规则持有、其流量不受影响；回收后回切能重建会话。
func TestUDPForwarderTransparentSwitchBetweenRules(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	fx := newTransparentFixture(t, 1) // 1s 空闲超时，缩短回收等待

	// ① 在服 1 游戏
	fx.roundTrip(t, fx.f1, fx.b1, "game-1")
	// ② 切到服 2（同源端口复用）：即时共享绑定
	fx.roundTrip(t, fx.f2, fx.b2, "game-2")
	// ③ 快速回切服 1：会话 1 还活着，直接复用
	fx.roundTrip(t, fx.f1, fx.b1, "game-1b")
	// ④ 停止服 1 流量 → 会话 1 空闲回收；期间持续服 2 流量保温——
	// 回收后绑定必须仍被会话 2 持有（fd 不关，factory 不再调用）
	stop := make(chan struct{})
	done := make(chan struct{})
	buf := make([]byte, 128)
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = fx.player.WriteToUDP([]byte("keep-2"), fx.f2.conn.LocalAddr().(*net.UDPAddr))
			_ = fx.b2.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if n, src, err := fx.b2.ReadFromUDP(buf); err == nil {
				_, _ = fx.b2.WriteToUDP(buf[:n], src)
			}
			_ = fx.player.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, _, _ = fx.player.ReadFromUDP(buf) // 排空回包，防接收队列堆积
			time.Sleep(100 * time.Millisecond)
		}
	}()
	waitFor(t, 4*time.Second, func() bool {
		_, _, active, _ := fx.f1.Stats()
		return active == 0
	})
	close(stop)
	<-done
	fx.roundTrip(t, fx.f2, fx.b2, "game-2b") // 回归：单规则回收不得拆共享绑定
	// ⑤ 回切服 1：重建会话（共享既有绑定，factory 不再调用）
	fx.roundTrip(t, fx.f1, fx.b1, "game-1c")
	if got := fx.calls.Load(); got != 1 {
		t.Fatalf("整个切换过程 factory 应只绑定一次，实际 %d", got)
	}
}
