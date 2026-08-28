package tunnel

import (
	"bytes"
	"testing"
)

func TestHandshakeAndSessionRoundTrip(t *testing.T) {
	psk := []byte("shared-secret-001")

	// 客户端构造 Hello，服务端解析
	hello, clientPriv, err := NewClientHello(psk)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseClientHello(psk, hello.Marshal())
	if err != nil {
		t.Fatalf("server parse hello: %v", err)
	}

	// 服务端应答，客户端解析
	accept, serverPriv, err := NewServerAccept(psk, parsed.Eph)
	if err != nil {
		t.Fatal(err)
	}
	acceptBack, err := ParseServerAccept(psk, accept.Marshal(), hello.Eph)
	if err != nil {
		t.Fatalf("client parse accept: %v", err)
	}

	// 双方派生会话密钥应一致
	cs := DeriveSessionKey(ECDHShared(&acceptBack.Eph, clientPriv), psk)
	ss := DeriveSessionKey(ECDHShared(&parsed.Eph, serverPriv), psk)
	if !bytes.Equal(cs[:], ss[:]) {
		t.Fatal("session keys mismatch")
	}

	// 数据往返 + 双向计数器独立
	csess := NewSession(cs)
	ssess := NewSession(ss)
	wire := csess.SealData([]byte{0x45, 0x00, 0x01, 0x02})
	plain, err := ssess.OpenData(wire)
	if err != nil || !bytes.Equal(plain, []byte{0x45, 0x00, 0x01, 0x02}) {
		t.Fatalf("data round trip failed: %v %x", err, plain)
	}
	if _, err := csess.OpenData(ssess.SealData([]byte("back"))); err != nil {
		t.Fatalf("reverse direction failed: %v", err)
	}
}

func TestWrongPSKRejected(t *testing.T) {
	hello, _, err := NewClientHello([]byte("right-psk"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseClientHello([]byte("wrong-psk"), hello.Marshal()); err == nil {
		t.Fatal("wrong PSK must be rejected")
	}
}

func TestReplayAndReorderWindow(t *testing.T) {
	s := NewSession(DeriveSessionKey(ECDHShared(&[32]byte{}, &[32]byte{}), []byte("k")))
	p1 := s.Seal([]byte("one"))
	p2 := s.Seal([]byte("two"))
	p3 := s.Seal([]byte("three"))

	if _, err := s.Open(p1); err != nil {
		t.Fatalf("open p1: %v", err)
	}
	if _, err := s.Open(p3); err != nil {
		t.Fatalf("open p3 (reorder ahead): %v", err)
	}
	if _, err := s.Open(p1); err == nil {
		t.Fatal("replayed p1 must be rejected")
	}
	if _, err := s.Open(p2); err != nil {
		t.Fatalf("p2 within window must open: %v", err)
	}
	if _, err := s.Open(p3); err == nil {
		t.Fatal("replayed p3 must be rejected")
	}
}

func TestCtrlMessageRoundTrip(t *testing.T) {
	s := NewSession(DeriveSessionKey(ECDHShared(&[32]byte{}, &[32]byte{}), []byte("k")))
	wire, err := s.SealCtrl(CtrlMessage{IPs: []string{"1.2.3.4", "5.6.7.8"}})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := s.OpenCtrl(wire)
	if err != nil {
		t.Fatalf("open ctrl: %v", err)
	}
	if len(msg.IPs) != 2 || msg.IPs[0] != "1.2.3.4" {
		t.Fatalf("ctrl = %+v", msg)
	}
	if s.IsPing(wire) {
		t.Fatal("ctrl must not be treated as ping")
	}
}

func TestTamperedPacketRejected(t *testing.T) {
	s := NewSession(DeriveSessionKey(ECDHShared(&[32]byte{}, &[32]byte{}), []byte("k")))
	wire := s.SealData([]byte("payload"))
	wire[len(wire)-1] ^= 0xFF
	if _, err := s.OpenData(wire); err == nil {
		t.Fatal("tampered packet must fail authentication")
	}
}
