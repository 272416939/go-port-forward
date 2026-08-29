package tunnel

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

var (
	testTunIP = netip.MustParseAddr("10.66.0.7")
	testGW    = netip.MustParseAddr("10.66.0.1")
)

func mustUID(t *testing.T, s string) UID {
	t.Helper()
	u, err := ParseUID(s)
	if err != nil {
		t.Fatalf("ParseUID(%q): %v", s, err)
	}
	return u
}

func TestHandshakeAndSessionRoundTrip(t *testing.T) {
	secret := []byte("per-user-secret-001")
	uid := mustUID(t, "3f2b1c4d-5e6f-4071-8293-a4b5c6d7e8f9")

	// 客户端构造 Hello，服务端解析
	hello, clientPriv, err := NewClientHello(secret, uid)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := PeekHello(hello.Marshal()); err != nil || got != uid {
		t.Fatalf("PeekHello = %v, %v; want %v", got, err, uid)
	}
	parsed, err := ParseClientHello(secret, hello.Marshal())
	if err != nil {
		t.Fatalf("server parse hello: %v", err)
	}
	if parsed.UID != uid {
		t.Fatalf("uid = %v, want %v", parsed.UID, uid)
	}

	// 服务端应答（携带分配的隧道地址），客户端解析
	accept, serverPriv, err := NewServerAccept(secret, parsed.Eph, testTunIP, testGW, 24)
	if err != nil {
		t.Fatal(err)
	}
	acceptBack, err := ParseServerAccept(secret, accept.Marshal(), hello.Eph)
	if err != nil {
		t.Fatalf("client parse accept: %v", err)
	}
	if acceptBack.TunAddr() != testTunIP || acceptBack.GatewayAddr() != testGW || acceptBack.Prefix != 24 {
		t.Fatalf("accept addressing = %v/%d gw %v", acceptBack.TunAddr(), acceptBack.Prefix, acceptBack.GatewayAddr())
	}

	// 双方派生会话密钥应一致
	cs := DeriveSessionKey(ECDHShared(&acceptBack.Eph, clientPriv), secret)
	ss := DeriveSessionKey(ECDHShared(&parsed.Eph, serverPriv), secret)
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

func TestWrongSecretRejected(t *testing.T) {
	uid := mustUID(t, "3f2b1c4d5e6f40718293a4b5c6d7e8f9")
	hello, _, err := NewClientHello([]byte("right-secret"), uid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseClientHello([]byte("wrong-secret"), hello.Marshal()); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong secret must be rejected with ErrAuth, got %v", err)
	}
}

// 隔离的第一道门：用户 A 的密钥不能开出 B 声称的会话。uid 明文可改，但
// 改了 uid 就对不上 MAC；换成 A 的密钥去签 B 的 uid，服务端查 B 的密钥验签必失败。
func TestCrossUserSecretRejected(t *testing.T) {
	secretA := []byte("secret-of-user-a")
	secretB := []byte("secret-of-user-b")
	uidA := mustUID(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	uidB := mustUID(t, "11111111-2222-3333-4444-555555555555")

	hello, _, err := NewClientHello(secretA, uidA)
	if err != nil {
		t.Fatal(err)
	}
	// A 把自己的 uid 换成 B 的：服务端会用 B 的密钥验签。
	wire := hello.Marshal()
	copy(wire[2:2+UIDSize], uidB[:])
	if got, _ := PeekHello(wire); got != uidB {
		t.Fatalf("peek after tamper = %v", got)
	}
	if _, err := ParseClientHello(secretB, wire); !errors.Is(err, ErrAuth) {
		t.Fatalf("cross-user hello must fail: %v", err)
	}
	// 用 A 自己的密钥也不行——uid 已进 MAC。
	if _, err := ParseClientHello(secretA, wire); !errors.Is(err, ErrAuth) {
		t.Fatalf("tampered uid must fail even with original secret: %v", err)
	}
}

// 下发地址进了 MAC：中间人改掉隧道 IP 会被客户端识破，否则可以把客户端
// 配成别人的地址、绕过服务端按 IP 做的隔离检查。
func TestTamperedAcceptAddressRejected(t *testing.T) {
	secret := []byte("s")
	uid := mustUID(t, "3f2b1c4d5e6f40718293a4b5c6d7e8f9")
	hello, _, err := NewClientHello(secret, uid)
	if err != nil {
		t.Fatal(err)
	}
	accept, _, err := NewServerAccept(secret, hello.Eph, testTunIP, testGW, 24)
	if err != nil {
		t.Fatal(err)
	}
	wire := accept.Marshal()
	wire[2+32+3] ^= 0x01 // 隧道 IP 的最后一个字节
	if _, err := ParseServerAccept(secret, wire, hello.Eph); !errors.Is(err, ErrAuth) {
		t.Fatalf("tampered tun ip must fail: %v", err)
	}
}

// v1 客户端必须被识别成「版本过旧」而不是「认证失败」——否则运维只会看到
// 一条查不出原因的 auth failed。
func TestV1HelloReportedAsOldVersion(t *testing.T) {
	v1 := make([]byte, 0, 73)
	v1 = append(v1, TypeHello)
	v1 = append(v1, bytes.Repeat([]byte{0xAB}, 32)...) // eph
	v1 = append(v1, bytes.Repeat([]byte{0x00}, 8)...)  // ts
	v1 = append(v1, bytes.Repeat([]byte{0xCD}, 32)...) // mac
	if _, err := PeekHello(v1); !errors.Is(err, ErrOldVersion) {
		t.Fatalf("v1 hello must report ErrOldVersion, got %v", err)
	}
	if _, err := ParseClientHello([]byte("any"), v1); !errors.Is(err, ErrOldVersion) {
		t.Fatalf("v1 hello parse must report ErrOldVersion, got %v", err)
	}
}

func TestHelloRejectsShortPacket(t *testing.T) {
	if _, err := PeekHello([]byte{TypeHello, Version, 0x01}); !errors.Is(err, ErrBadPacket) {
		t.Fatal("short hello must be ErrBadPacket")
	}
	if _, err := ParseServerAccept([]byte("s"), []byte{TypeAccept, Version}, [32]byte{}); !errors.Is(err, ErrBadPacket) {
		t.Fatal("short accept must be ErrBadPacket")
	}
}

func TestUIDRoundTrip(t *testing.T) {
	const text = "3f2b1c4d-5e6f-4071-8293-a4b5c6d7e8f9"
	u, err := ParseUID(text)
	if err != nil {
		t.Fatal(err)
	}
	if u.String() != text {
		t.Fatalf("uid text = %q, want %q", u.String(), text)
	}
	if u.IsZero() {
		t.Fatal("uid must not be zero")
	}
	if _, err := ParseUID("not-a-uuid"); err == nil {
		t.Fatal("invalid uid must fail")
	}
	var zero UID
	if !zero.IsZero() {
		t.Fatal("zero uid must report IsZero")
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
	wire, err := s.SealCtrl(CtrlMessage{Kind: CtrlKindRoutes, IPs: []string{"1.2.3.4", "5.6.7.8"}})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := s.OpenCtrl(wire)
	if err != nil {
		t.Fatalf("open ctrl: %v", err)
	}
	if msg.Kind != CtrlKindRoutes || len(msg.IPs) != 2 || msg.IPs[0] != "1.2.3.4" {
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
