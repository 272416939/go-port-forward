package tunnelapp

import (
	"net"
	"testing"
	"time"
)

// 集合指纹必须与顺序无关：会话 IP 来自 map 遍历，顺序天然不稳定。
// 若指纹随顺序变化，每次推送都会被误判为「变更」并打一条 info——正是
// 这次要消掉的刷屏。
func TestSessionIPsSignatureIgnoresOrder(t *testing.T) {
	a := sessionIPsSignature([]string{"1.1.1.1", "2.2.2.2", "3.3.3.3"})
	b := sessionIPsSignature([]string{"3.3.3.3", "1.1.1.1", "2.2.2.2"})
	if a != b {
		t.Errorf("同一集合不同顺序指纹不同：\n  %q\n  %q", a, b)
	}
}

func TestSessionIPsSignatureDetectsChange(t *testing.T) {
	base := sessionIPsSignature([]string{"1.1.1.1", "2.2.2.2"})

	cases := map[string][]string{
		"新增": {"1.1.1.1", "2.2.2.2", "3.3.3.3"},
		"移除": {"1.1.1.1"},
		"替换": {"1.1.1.1", "9.9.9.9"},
		"清空": {},
	}
	for name, ips := range cases {
		if got := sessionIPsSignature(ips); got == base {
			t.Errorf("%s 后指纹未变化（%q），变更会被漏报", name, got)
		}
	}
}

// 不得就地修改入参：调用方传的是活跃会话快照，排序会打乱其它使用者看到的顺序。
func TestSessionIPsSignatureDoesNotMutateInput(t *testing.T) {
	ips := []string{"3.3.3.3", "1.1.1.1", "2.2.2.2"}
	sessionIPsSignature(ips)
	if ips[0] != "3.3.3.3" {
		t.Errorf("入参被就地排序了：%v", ips)
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
