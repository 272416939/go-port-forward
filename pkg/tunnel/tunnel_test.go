package tunnel

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

var (
	testTunIP  = netip.MustParseAddr("10.66.0.7")
	testGW     = netip.MustParseAddr("10.66.0.1")
	testDevice = [FingerprintSize]byte{0xA1, 0xB2, 0xC3, 0xD4}
	otherDevice = [FingerprintSize]byte{0x11, 0x22, 0x33, 0x44}
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
	hello, clientPriv, err := NewClientHello(secret, uid, testDevice)
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
	hello, _, err := NewClientHello([]byte("right-secret"), uid, testDevice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseClientHello([]byte("wrong-secret"), hello.Marshal()); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong secret must be rejected with ErrAuth, got %v", err)
	}
}

// 隔离的第一道门：访问码 A 的密钥不能开出 B 声称的会话。uid 明文可改，但
// 改了 uid 就对不上 MAC；换成 A 的密钥去签 B 的 uid，服务端查 B 的密钥验签必失败。
func TestCrossUserSecretRejected(t *testing.T) {
	secretA := []byte("secret-of-user-a")
	secretB := []byte("secret-of-user-b")
	uidA := mustUID(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	uidB := mustUID(t, "11111111-2222-3333-4444-555555555555")

	hello, _, err := NewClientHello(secretA, uidA, testDevice)
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
	hello, _, err := NewClientHello(secret, uid, testDevice)
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

// 旧版客户端必须被识别成「版本过旧」而不是「认证失败」——否则运维只会看到
// 一条查不出原因的 auth failed。v1 与 v2 的包长各自唯一，靠长度先行判定。
func TestOldHelloReportedAsOldVersion(t *testing.T) {
	v1 := make([]byte, 0, 73)
	v1 = append(v1, TypeHello)
	v1 = append(v1, bytes.Repeat([]byte{0xAB}, 32)...) // eph
	v1 = append(v1, bytes.Repeat([]byte{0x00}, 8)...)  // ts
	v1 = append(v1, bytes.Repeat([]byte{0xCD}, 32)...) // mac

	v2 := make([]byte, 0, 90)
	v2 = append(v2, TypeHello, 0x02)
	v2 = append(v2, bytes.Repeat([]byte{0xEE}, UIDSize)...)
	v2 = append(v2, bytes.Repeat([]byte{0xAB}, 32)...)
	v2 = append(v2, bytes.Repeat([]byte{0x00}, 8)...)
	v2 = append(v2, bytes.Repeat([]byte{0xCD}, 32)...)

	for name, pkt := range map[string][]byte{"v1": v1, "v2": v2} {
		if _, err := PeekHello(pkt); !errors.Is(err, ErrOldVersion) {
			t.Fatalf("%s hello must report ErrOldVersion, got %v", name, err)
		}
		if _, err := ParseClientHello([]byte("any"), pkt); !errors.Is(err, ErrOldVersion) {
			t.Fatalf("%s hello parse must report ErrOldVersion, got %v", name, err)
		}
	}
}

// 设备指纹进了 MAC：换一台设备重放同一个 Hello 会被识破。
func TestTamperedDeviceRejected(t *testing.T) {
	secret := []byte("s")
	uid := mustUID(t, "3f2b1c4d5e6f40718293a4b5c6d7e8f9")
	hello, _, err := NewClientHello(secret, uid, testDevice)
	if err != nil {
		t.Fatal(err)
	}
	wire := hello.Marshal()
	copy(wire[2+UIDSize:2+UIDSize+FingerprintSize], otherDevice[:])
	if _, perr := ParseClientHello(secret, wire); !errors.Is(perr, ErrAuth) {
		t.Fatalf("tampered device fingerprint must fail: %v", perr)
	}
	// 原包仍然可解析，确认上面失败的原因确实是指纹而不是别的。
	if parsed, perr := ParseClientHello(secret, hello.Marshal()); perr != nil {
		t.Fatalf("untampered hello must parse: %v", perr)
	} else if parsed.Device != testDevice {
		t.Fatalf("device = %x", parsed.Device)
	}
}

// Reject 必须验 MAC：不验的话任何人都能伪造一个拒绝应答让客户端停止重连，
// 那是一个单包就能生效的拒绝服务。
func TestRejectRequiresValidMAC(t *testing.T) {
	secret := []byte("s")
	uid := mustUID(t, "3f2b1c4d5e6f40718293a4b5c6d7e8f9")
	hello, _, err := NewClientHello(secret, uid, testDevice)
	if err != nil {
		t.Fatal(err)
	}
	wire := NewServerReject(secret, hello.Eph, RejectDeviceMismatch).Marshal()

	got, perr := ParseServerReject(secret, wire, hello.Eph)
	if perr != nil {
		t.Fatalf("valid reject must parse: %v", perr)
	}
	if got.Reason != RejectDeviceMismatch {
		t.Fatalf("reason = %v", got.Reason)
	}
	if !got.Reason.Terminal() {
		t.Fatal("device mismatch must be a terminal reason（客户端不该继续重试）")
	}

	if _, perr := ParseServerReject([]byte("wrong-secret"), wire, hello.Eph); !errors.Is(perr, ErrAuth) {
		t.Fatalf("reject signed with another secret must fail: %v", perr)
	}
	// 换一个 clientEph（重放到另一次握手上）也必须失败。
	var otherEph [32]byte
	otherEph[0] = 0x99
	if _, perr := ParseServerReject(secret, wire, otherEph); !errors.Is(perr, ErrAuth) {
		t.Fatalf("replayed reject must fail: %v", perr)
	}
	tampered := append([]byte(nil), wire...)
	tampered[2] = byte(RejectTunnelLimit)
	if _, perr := ParseServerReject(secret, tampered, hello.Eph); !errors.Is(perr, ErrAuth) {
		t.Fatalf("tampered reason must fail: %v", perr)
	}
}

// tunnel_limit 是暂时状态（对端可能马上下线），必须继续重试；其余是终态。
func TestRejectTerminalClassification(t *testing.T) {
	if RejectTunnelLimit.Terminal() {
		t.Fatal("并发上限是暂时状态，应继续重试")
	}
	for _, r := range []RejectReason{RejectDeviceMismatch, RejectCodeDisabled, RejectUserDisabled, RejectAddrInvalid} {
		if !r.Terminal() {
			t.Fatalf("%v 需要人工介入，应停止重试", r)
		}
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
