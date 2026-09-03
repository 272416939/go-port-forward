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
