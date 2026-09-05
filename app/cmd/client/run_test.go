//go:build windows

package main

// 握手对「上一轮会话残留包」的容忍（2026-09-03 用户实测的根因）：
// 断开后服务端旧会话在 janitor 回收前（最长 3 分钟）仍向本地址发心跳与路由
// 推送，快速重连时 NAT（EIM 映射）与 OS 都可能复用刚释放的源端口，残留包
// 落进握手 socket 的接收队列。握手只认 Accept/Reject，其余一律排空——此前
// 它们掉进 Accept 解析失败，被误报成「接入码可能已失效，请在面板重新获取」，
// 把用户引去重置接入码。本测试在合法 Accept 前先塞残留包，锁住排空行为；
// 旧实现读到第一条残留包就报「接入码失效」，直接失败。

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"go-port-forward/pkg/tunnel"
)

func TestHandshakeDrainsStalePacketsBeforeAccept(t *testing.T) {
	secret := []byte("c2VjcmV0")
	uid, err := tunnel.ParseUID("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}

	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("假服务端监听: %v", err)
	}
	defer srv.Close()

	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := srv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			hello, perr := tunnel.ParseClientHello(secret, buf[:n])
			if perr != nil {
				continue
			}
			// 先塞两条「上一轮会话的残留包」（心跳/数据形态），再回合法 Accept。
			stale := make([]byte, 41)
			stale[0] = tunnel.TypePing
			_, _ = srv.WriteToUDP(stale, addr)
			stale[0] = tunnel.TypeData
			_, _ = srv.WriteToUDP(stale, addr)
			accept, _, aerr := tunnel.NewServerAccept(secret, hello.Eph,
				netip.AddrFrom4([4]byte{10, 66, 0, 4}),
				netip.AddrFrom4([4]byte{10, 66, 0, 1}), 16, 1400, 0)
			if aerr != nil {
				return
			}
			_, _ = srv.WriteToUDP(accept.Marshal(), addr)
		}
	}()

	e := NewEngine()
	conn, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("客户端 socket: %v", err)
	}
	defer conn.Close()

	var device [tunnel.FingerprintSize]byte
	done := make(chan struct{})
	var sess *tunnel.Session
	var addr tunnelAddressing
	var herr error
	go func() {
		defer close(done)
		sess, addr, herr = e.handshake(context.Background(), conn, uid, device, secret)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("握手 10 秒未完成")
	}
	if herr != nil {
		t.Fatalf("握手失败：%v（残留包必须被排空，而不是误报接入码失效）", herr)
	}
	if sess == nil || !addr.valid() {
		t.Fatalf("握手应返回会话与地址：sess=%v addr=%+v", sess, addr)
	}
}

// startHandshakeFakeServer 起一个假服务端：每收到一条合法 v4 Hello 就依次
// 发出 pre 回调给定的包，最后回一条用 secret 签发的合法 Accept。
func startHandshakeFakeServer(t *testing.T, secret []byte, pre func(hello *tunnel.ClientHello) [][]byte) *net.UDPAddr {
	t.Helper()
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("假服务端监听: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := srv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			hello, perr := tunnel.ParseClientHello(secret, buf[:n])
			if perr != nil {
				continue // v3 探测包等非 v4 握手：不应答
			}
			for _, pkt := range pre(hello) {
				_, _ = srv.WriteToUDP(pkt, addr)
			}
			accept, _, aerr := tunnel.NewServerAccept(secret, hello.Eph,
				netip.AddrFrom4([4]byte{10, 66, 0, 4}),
				netip.AddrFrom4([4]byte{10, 66, 0, 1}), 16, 1400, 0)
			if aerr != nil {
				return
			}
			_, _ = srv.WriteToUDP(accept.Marshal(), addr)
		}
	}()
	return srv.LocalAddr().(*net.UDPAddr)
}

// runHandshake 在独立 goroutine 里跑握手并等待完成。
func runHandshake(t *testing.T, e *Engine, conn *net.UDPConn, uid tunnel.UID,
	secret []byte) (sess *tunnel.Session, addr tunnelAddressing, herr error) {
	t.Helper()
	var device [tunnel.FingerprintSize]byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess, addr, herr = e.handshake(context.Background(), conn, uid, device, secret)
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("握手 60 秒未完成")
	}
	return sess, addr, herr
}

// TestHandshakeIgnoresForeignAccept 锁「同网多台客户端同时握手」的容忍：
// 同一 NAT 下多台机器同时握手时（EIM 端口复用/重映射），另一台机器的 Accept
// 会串进本机的握手窗口。Accept 的 MAC 绑定握手双方临时公钥，别人的 Accept
// 拿来必验签失败；而为本次握手签发的 Accept 数学上必然验签通过（同一密钥 +
// 同一临时公钥）——所以验签失败 ≠ 接入码失效，只可能是串线或损坏，必须排空
// 继续等本次自己的应答。旧实现在此中止本轮并误报「接入码可能已失效」。
func TestHandshakeIgnoresForeignAccept(t *testing.T) {
	secret := []byte("c2VjcmV0")
	foreignSecret := []byte("Zm9yZWlnbg==")
	uid, err := tunnel.ParseUID("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	srvAddr := startHandshakeFakeServer(t, secret, func(hello *tunnel.ClientHello) [][]byte {
		// 同网另一台客户端的 Accept：结构完整（78 字节）但 MAC 用别的密钥算
		foreign, _, ferr := tunnel.NewServerAccept(foreignSecret, hello.Eph,
			netip.AddrFrom4([4]byte{10, 66, 0, 9}),
			netip.AddrFrom4([4]byte{10, 66, 0, 1}), 16, 1400, 0)
		if ferr != nil {
			t.Errorf("构造外来 Accept: %v", ferr)
			return nil
		}
		return [][]byte{foreign.Marshal()}
	})

	e := NewEngine()
	conn, err := net.DialUDP("udp", nil, srvAddr)
	if err != nil {
		t.Fatalf("客户端 socket: %v", err)
	}
	defer conn.Close()

	sess, addr, herr := runHandshake(t, e, conn, uid, secret)
	if herr != nil {
		t.Fatalf("外来 Accept 必须被排空（而不是中止握手误报接入码失效）：%v", herr)
	}
	if sess == nil || !addr.valid() {
		t.Fatalf("握手应返回会话与地址：sess=%v addr=%+v", sess, addr)
	}
}

// TestHandshakeIgnoresShortAcceptShapedPacket 锁「截断/损坏的 Accept 形态包」：
// 0x02 开头但长度不足 78 字节（路径上被截断等），同样排空而不是报错。
func TestHandshakeIgnoresShortAcceptShapedPacket(t *testing.T) {
	secret := []byte("c2VjcmV0")
	uid, err := tunnel.ParseUID("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	srvAddr := startHandshakeFakeServer(t, secret, func(hello *tunnel.ClientHello) [][]byte {
		return [][]byte{{tunnel.TypeAccept, tunnel.Version, 0x00, 0x01}}
	})

	e := NewEngine()
	conn, err := net.DialUDP("udp", nil, srvAddr)
	if err != nil {
		t.Fatalf("客户端 socket: %v", err)
	}
	defer conn.Close()

	sess, addr, herr := runHandshake(t, e, conn, uid, secret)
	if herr != nil {
		t.Fatalf("截断的 Accept 形态包必须被排空：%v", herr)
	}
	if sess == nil || !addr.valid() {
		t.Fatalf("握手应返回会话与地址：sess=%v addr=%+v", sess, addr)
	}
}

// TestHandshakeForeignAcceptOnlyReportsNoReply 锁最终报错语义：整轮只收到
// 别人的 Accept 时，最终错误是「服务端无应答」类（提示检查接入码/地址/路由器），
// 而不是把串线误报成「接入码可能已失效」。
func TestHandshakeForeignAcceptOnlyReportsNoReply(t *testing.T) {
	secret := []byte("c2VjcmV0")
	foreignSecret := []byte("Zm9yZWlnbg==")
	uid, err := tunnel.ParseUID("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("假服务端监听: %v", err)
	}
	defer srv.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := srv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			hello, perr := tunnel.ParseClientHello(secret, buf[:n])
			if perr != nil {
				continue
			}
			// 永远只回「别人的 Accept」，从不回本次握手的合法应答
			foreign, _, ferr := tunnel.NewServerAccept(foreignSecret, hello.Eph,
				netip.AddrFrom4([4]byte{10, 66, 0, 9}),
				netip.AddrFrom4([4]byte{10, 66, 0, 1}), 16, 1400, 0)
			if ferr != nil {
				return
			}
			_, _ = srv.WriteToUDP(foreign.Marshal(), addr)
		}
	}()

	e := NewEngine()
	conn, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("客户端 socket: %v", err)
	}
	defer conn.Close()

	_, _, herr := runHandshake(t, e, conn, uid, secret)
	if herr == nil {
		t.Fatal("只收到外来 Accept 时握手必须失败")
	}
	for _, sub := range []string{"接入码可能已失效", "authentication failed", "malformed packet"} {
		if strings.Contains(herr.Error(), sub) {
			t.Fatalf("串线场景的最终报错不得指向接入码/报解析错误，得到：%v", herr)
		}
	}
}
