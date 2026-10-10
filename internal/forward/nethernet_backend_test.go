package forward

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"go-port-forward/internal/config"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/nethernet"
	"go.uber.org/zap"
)

// 回归测试，锁真机症状（信令通、registered/learned 都有、约 15 秒后
// InitialConnection-83）：NetherNet 会话必须进入 forward 的会话注册表。
//
// 回程路由推送的数据源是 SessionIPsByCode，而它只统计会话注册表。NetherNet
// 会话不登记 → 推送列表恒为空（线上日志「回程路由 IP 已推送 count:0」）→
// Windows 客户端装不上 /32 回程路由 → BDS 的回包从后端机物理网卡漏出去
// （源地址变成后端自己的公网 IP）→ 玩家 ICE/DTLS 永远等不到应答。
func TestNetherSessionSinkFeedsReturnRoutePush(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	rule := &models.ForwardRule{
		ID:          "rule-nn",
		Name:        "bds26.51-1",
		UserID:      "u1",
		ListenAddr:  "0.0.0.0",
		ListenPort:  39042,
		Protocol:    models.ProtocolUDP,
		TargetAddr:  "10.66.0.3",
		TargetPort:  39042,
		Transparent: true,
		NetherNet:   true,
		Enabled:     false, // 不真起网关/多路复用器，只验证登记与推送数据源
	}
	mgr, err := NewManager(newCountingStore(rule), config.ForwardConfig{DialTimeout: 1, UDPTimeout: 30, BufferSize: 4096, PoolSize: 8})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer mgr.Shutdown()

	live, err := mgr.GetRule(rule.ID)
	if err != nil {
		t.Fatalf("get rule: %v", err)
	}
	sink := newNetherSessionSink(mgr.svc, live)
	client := &net.UDPAddr{IP: net.ParseIP("111.29.236.176"), Port: 3955}

	// 推送前没有任何活跃会话——这正是线上 count:0 的形态。
	if got := mgr.SessionIPsByCode(map[string]string{"10.66.0.3": "code-222"}); len(got) != 0 {
		t.Fatalf("before start: SessionIPsByCode = %v, want empty", got)
	}

	sink.NetherSessionStart("chJs", client)

	byCode := mgr.SessionIPsByCode(map[string]string{"10.66.0.3": "code-222"})
	if len(byCode["code-222"]) != 1 || byCode["code-222"][0] != "111.29.236.176" {
		t.Fatalf("after start: SessionIPsByCode = %v, want code-222 → [111.29.236.176]", byCode)
	}

	// 面板计数：增量字节要看得见（「包在往返但进不去游戏」首先看这里）。
	sink.NetherSessionBytes("chJs", client, 1200, 800)
	entries := mgr.SessionsForUser("")
	if len(entries) != 1 || entries[0].BytesIn != 1200 || entries[0].BytesOut != 800 {
		t.Fatalf("session view = %+v, want one entry with 1200/800 bytes", entries)
	}

	// 会话结束必须摘表：否则客户端一直为该 IP 保留 /32 主机路由，把该 IP 的
	// 全部回包都吸进隧道。
	sink.NetherSessionEnd("chJs", client)
	if got := mgr.SessionIPsByCode(map[string]string{"10.66.0.3": "code-222"}); len(got) != 0 {
		t.Fatalf("after end: SessionIPsByCode = %v, want empty", got)
	}
}

// 重复 end（规则重启时 Stop 与回收可能都走到）不得改动注册表。
func TestNetherSessionSinkEndIsIdempotent(t *testing.T) {
	svc := &forwardServices{sessions: newSessionRegistry()}
	rule := &models.ForwardRule{ID: "rule-nn", Name: "bds", TargetAddr: "10.66.0.3", Protocol: models.ProtocolUDP}
	sink := newNetherSessionSink(svc, rule)
	client := &net.UDPAddr{IP: net.ParseIP("111.29.236.176"), Port: 3955}

	sink.NetherSessionStart("chJs", client)
	sink.NetherSessionEnd("chJs", client)
	sink.NetherSessionEnd("chJs", client)

	if n := len(svc.sessions.snapshot()); n != 0 {
		t.Fatalf("registry has %d entries after duplicate end, want 0", n)
	}
}

// fakeNetherPlayerSocket 是实现 nethernet.PlayerSocket 的最小替身：记录出站包，
// Read 阻塞到 Close（readBackend goroutine 因此不会空转退出）。
type fakeNetherPlayerSocket struct {
	mu   sync.Mutex
	sent [][]byte
	done chan struct{}
}

func newFakeNetherPlayerSocket() *fakeNetherPlayerSocket {
	return &fakeNetherPlayerSocket{done: make(chan struct{})}
}

func (s *fakeNetherPlayerSocket) SendTo(packet []byte, dst *net.UDPAddr) error {
	s.mu.Lock()
	s.sent = append(s.sent, append([]byte(nil), packet...))
	s.mu.Unlock()
	return nil
}

func (s *fakeNetherPlayerSocket) Read(buf []byte) (int, error) {
	<-s.done
	return 0, net.ErrClosed
}

func (s *fakeNetherPlayerSocket) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return nil
}

// buildSTUNBindingRequest 构造只带单个 USERNAME 属性的最小 STUN binding request。
func buildSTUNBindingRequest(username string) []byte {
	attrLen := 4 + len(username)
	if pad := len(username) % 4; pad != 0 {
		attrLen += 4 - pad
	}
	p := make([]byte, 20+attrLen)
	binary.BigEndian.PutUint16(p[0:2], 0x0001)          // Binding Request
	binary.BigEndian.PutUint16(p[2:4], uint16(attrLen)) // Message Length
	binary.BigEndian.PutUint32(p[4:8], 0x2112A442)      // Magic Cookie
	copy(p[8:20], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	binary.BigEndian.PutUint16(p[20:22], 0x0006) // USERNAME
	binary.BigEndian.PutUint16(p[22:24], uint16(len(username)))
	copy(p[24:], []byte(username))
	return p
}

// 回归测试（真机症状：玩家已能进服，但面板规则行与仪表盘的流入/流出/连接数恒为
// 0 B）：NetherNet 规则的流量必须经 mergeStats 汇总进规则视图。
//
// 用真实 UDP socket 驱过多路复用器（只走公开 API）：RegisterSession + 一个带
// USERNAME 的 STUN binding request，足以让会话学到地址并计数。
func TestMergeStatsIncludesNetherNetMultiplexer(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("probe port: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	sock := newFakeNetherPlayerSocket()
	mux := nethernet.NewMultiplexer(fmt.Sprintf("127.0.0.1:%d", port),
		func(src *net.UDPAddr) (nethernet.PlayerSocket, error) { return sock, nil })
	if err := mux.Start(); err != nil {
		t.Fatalf("mux start: %v", err)
	}
	defer mux.Stop()
	mux.RegisterSession("chJs", net.ParseIP("10.66.0.3"), 39042)

	pc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatalf("dial mux: %v", err)
	}
	stun := buildSTUNBindingRequest("chJs:cli")
	if _, err := pc.Write(stun); err != nil {
		t.Fatalf("send stun: %v", err)
	}
	_ = pc.Close()

	waitFor(t, 2*time.Second, func() bool {
		_, _, active, _ := mux.Stats()
		return active == 1
	})

	sock.mu.Lock()
	sent := len(sock.sent)
	sock.mu.Unlock()
	if sent != 1 {
		t.Fatalf("forwarded %d packets through the player socket, want 1", sent)
	}

	bi, bo, a, tot := mergeStats(&entry{netherMux: mux})
	if bi != int64(len(stun)) || bo != 0 {
		t.Fatalf("mergeStats bytes = %d/%d, want %d/0", bi, bo, len(stun))
	}
	if a != 1 || tot != 1 {
		t.Fatalf("mergeStats conns = %d/%d, want 1/1", a, tot)
	}
}
