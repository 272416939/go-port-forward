package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"
)

var (
	testTunIP   = netip.MustParseAddr("10.66.0.7")
	testGW      = netip.MustParseAddr("10.66.0.1")
	testDevice  = [FingerprintSize]byte{0xA1, 0xB2, 0xC3, 0xD4}
	otherDevice = [FingerprintSize]byte{0x11, 0x22, 0x33, 0x44}
)

func mustUID(t testing.TB, s string) UID {
	t.Helper()
	u, err := ParseUID(s)
	if err != nil {
		t.Fatalf("ParseUID(%q): %v", s, err)
	}
	return u
}

// mustSession 建一个自环会话（收发同一把密钥）：它能打开自己封的包，用于
// 只关心重放窗口与封装格式的用例。方向隔离由 TestDirectionKeysAreIsolated
// 单独锁定，两者不要混在一个 fixture 里。
func mustSession(t testing.TB, feats uint32) *Session {
	t.Helper()
	var k [32]byte
	k[0] = 0x5A
	s, err := newSession(&k, &k, feats, MaxTunMTU)
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}
	return s
}

// sessionPair 走完整握手并返回两端会话（方向密钥各自反接）。
func sessionPair(t testing.TB, feats uint8) (client, server *Session) {
	t.Helper()
	secret := []byte("per-code-secret")
	uid := mustUID(t, "3f2b1c4d-5e6f-4071-8293-a4b5c6d7e8f9")

	hello, clientPriv, err := NewClientHello(secret, uid, testDevice)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseClientHello(secret, hello.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	accept, serverPriv, err := NewServerAccept(secret, parsed.Eph, testTunIP, testGW, 24, MaxTunMTU, feats)
	if err != nil {
		t.Fatal(err)
	}
	acceptBack, err := ParseServerAccept(secret, accept.Marshal(), hello.Eph)
	if err != nil {
		t.Fatal(err)
	}

	cC2S, cS2C, err := DeriveSessionKeys(ECDHShared(&acceptBack.Eph, clientPriv), secret, hello.Eph, acceptBack.Eph)
	if err != nil {
		t.Fatal(err)
	}
	sC2S, sS2C, err := DeriveSessionKeys(ECDHShared(&parsed.Eph, serverPriv), secret, parsed.Eph, accept.Eph)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cC2S[:], sC2S[:]) || !bytes.Equal(cS2C[:], sS2C[:]) {
		t.Fatal("两端派生的方向密钥必须一致")
	}
	client, err = NewClientSession(cC2S, cS2C, uint32(acceptBack.Feats), acceptBack.TunMTU())
	if err != nil {
		t.Fatal(err)
	}
	server, err = NewServerSession(sC2S, sS2C, uint32(accept.Feats), accept.TunMTU())
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func sealBuf() []byte { return make([]byte, 0, MaxPacket+NonceSize) }

func TestHandshakeAndSessionRoundTrip(t *testing.T) {
	secret := []byte("per-user-secret-001")
	uid := mustUID(t, "3f2b1c4d-5e6f-4071-8293-a4b5c6d7e8f9")

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

	// 服务端应答（携带分配的隧道地址、MTU 与特性位），客户端解析
	accept, serverPriv, err := NewServerAccept(secret, parsed.Eph, testTunIP, testGW, 24, 1380, FeatFEC)
	if err != nil {
		t.Fatal(err)
	}
	if len(accept.Marshal()) != acceptLen {
		t.Fatalf("accept 长度 = %d，期望 %d", len(accept.Marshal()), acceptLen)
	}
	acceptBack, err := ParseServerAccept(secret, accept.Marshal(), hello.Eph)
	if err != nil {
		t.Fatalf("client parse accept: %v", err)
	}
	if acceptBack.TunAddr() != testTunIP || acceptBack.GatewayAddr() != testGW || acceptBack.Prefix != 24 {
		t.Fatalf("accept addressing = %v/%d gw %v", acceptBack.TunAddr(), acceptBack.Prefix, acceptBack.GatewayAddr())
	}
	if acceptBack.TunMTU() != 1380 || acceptBack.Feats != FeatFEC {
		t.Fatalf("accept mtu/feats = %d/%d", acceptBack.TunMTU(), acceptBack.Feats)
	}

	// 双方派生的方向密钥应两两一致
	cC2S, cS2C, err := DeriveSessionKeys(ECDHShared(&acceptBack.Eph, clientPriv), secret, hello.Eph, acceptBack.Eph)
	if err != nil {
		t.Fatal(err)
	}
	sC2S, sS2C, err := DeriveSessionKeys(ECDHShared(&parsed.Eph, serverPriv), secret, parsed.Eph, accept.Eph)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cC2S[:], sC2S[:]) || !bytes.Equal(cS2C[:], sS2C[:]) {
		t.Fatal("direction keys mismatch")
	}

	csess, err := NewClientSession(cC2S, cS2C, 0, acceptBack.TunMTU())
	if err != nil {
		t.Fatal(err)
	}
	ssess, err := NewServerSession(sC2S, sS2C, 0, accept.TunMTU())
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x45, 0x00, 0x01, 0x02}
	wire := csess.SealData(sealBuf(), want)
	plain, err := ssess.OpenData(sealBuf(), wire)
	if err != nil || !bytes.Equal(plain, want) {
		t.Fatalf("data round trip failed: %v %x", err, plain)
	}
	if _, err := csess.OpenData(sealBuf(), ssess.SealData(sealBuf(), []byte("back"))); err != nil {
		t.Fatalf("reverse direction failed: %v", err)
	}
	// 封装开销必须恰好是 25 字节：MTU 计算与缓冲规格都按它算。
	if got := len(wire) - len(want); got != SealOverhead {
		t.Fatalf("封装开销 = %d，期望 %d", got, SealOverhead)
	}
}

// v3 的致命缺陷：两个方向共用一把密钥且计数各自从 1 开始，于是客户端第 N 包
// 与服务端第 N 包用完全相同的 (key, nonce)。流密码 nonce 重用 = 密钥流重用，
// 机密性与可伪造性同时失效。v4 拆成两把方向密钥，这条测试锁死它。
func TestDirectionKeysAreIsolated(t *testing.T) {
	client, server := sessionPair(t, 0)

	// 两把密钥必须不同：拿客户端的会话去解客户端自己发的包必须失败。
	wire := client.SealData(sealBuf(), []byte("client to server"))
	if _, err := client.OpenData(sealBuf(), wire); err == nil {
		t.Fatal("客户端不得解开自己方向的包（说明两个方向共用了一把密钥）")
	}
	if _, err := server.OpenData(sealBuf(), wire); err != nil {
		t.Fatalf("服务端必须能解开客户端的包: %v", err)
	}

	// 反向同理。
	back := server.SealData(sealBuf(), []byte("server to client"))
	if _, err := server.OpenData(sealBuf(), back); err == nil {
		t.Fatal("服务端不得解开自己方向的包")
	}
	if _, err := client.OpenData(sealBuf(), back); err != nil {
		t.Fatalf("客户端必须能解开服务端的包: %v", err)
	}

	// 同序号的两个方向的包，密文必须不同（v3 下它们的密钥流完全相同）。
	c2, s2 := sessionPair(t, 0)
	same := []byte("identical plaintext for both directions")
	cw := c2.SealData(sealBuf(), same)
	sw := s2.SealData(sealBuf(), same)
	if binary.BigEndian.Uint64(cw[1:9]) != binary.BigEndian.Uint64(sw[1:9]) {
		t.Fatal("两个方向的首包计数应相同（这正是 v3 出问题的前提）")
	}
	if bytes.Equal(cw, sw) {
		t.Fatal("同计数的两个方向密文相同：nonce 与密钥流被复用")
	}
}

// KDF 的 info 绑定了双方临时公钥：改了公钥的中间人即使伪造出合法 MAC，
// 也派生不出同一把会话密钥。
func TestSessionKeysBindEphemerals(t *testing.T) {
	var shared [32]byte
	shared[0] = 0x11
	psk := []byte("psk")
	var cEph, sEph, otherEph [32]byte
	cEph[0], sEph[0], otherEph[0] = 1, 2, 3

	a, _, err := DeriveSessionKeys(&shared, psk, cEph, sEph)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := DeriveSessionKeys(&shared, psk, cEph, otherEph)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a[:], b[:]) {
		t.Fatal("临时公钥变化后派生密钥必须不同（transcript binding 失效）")
	}
	// 同一组输入必须稳定复现，否则两端派生不出同一把密钥。
	again, _, err := DeriveSessionKeys(&shared, psk, cEph, sEph)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a[:], again[:]) {
		t.Fatal("KDF 必须确定性")
	}
}

// 类型字节进 AAD：v3 的 type 在加密盒之外未受认证，一个合法 Data 盒重标成
// Ctrl 仍能解开。v4 之后类型混淆必须失败。
func TestTypeByteIsAuthenticated(t *testing.T) {
	s := mustSession(t, 0)
	wire := s.SealData(sealBuf(), []byte{0x45, 0x00, 0x00, 0x14})
	tampered := append([]byte(nil), wire...)
	tampered[0] = TypeCtrl
	if _, _, err := s.OpenInto(sealBuf(), tampered); !errors.Is(err, ErrAuth) {
		t.Fatalf("篡改类型字节必须认证失败，得到 %v", err)
	}
}

// 计数进 nonce 也就进了认证：改计数的包解不开，因此重放检查放在认证之后是
// 安全的（被改过计数的包根本走不到窗口）。
func TestCounterIsAuthenticated(t *testing.T) {
	s := mustSession(t, 0)
	wire := s.SealData(sealBuf(), []byte("payload"))
	tampered := append([]byte(nil), wire...)
	tampered[1+CounterSize-1] ^= 0x01
	if _, err := s.OpenData(sealBuf(), tampered); !errors.Is(err, ErrAuth) {
		t.Fatalf("篡改计数必须认证失败，得到 %v", err)
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
// 配成别人的地址、绕过服务端按 IP 做的隔离检查。MTU 与特性位同理——能改 MTU
// 的中间人可以把隧道压到不可用的小值，能改特性位的可以单向关掉纠错。
func TestTamperedAcceptFieldsRejected(t *testing.T) {
	secret := []byte("s")
	uid := mustUID(t, "3f2b1c4d5e6f40718293a4b5c6d7e8f9")
	hello, _, err := NewClientHello(secret, uid, testDevice)
	if err != nil {
		t.Fatal(err)
	}
	accept, _, err := NewServerAccept(secret, hello.Eph, testTunIP, testGW, 24, MaxTunMTU, FeatFEC|FeatTailDup)
	if err != nil {
		t.Fatal(err)
	}
	base := accept.Marshal()
	if _, perr := ParseServerAccept(secret, base, hello.Eph); perr != nil {
		t.Fatalf("原包必须可解析: %v", perr)
	}
	for name, off := range map[string]int{
		"隧道 IP": 2 + 32 + 3,
		"前缀":    2 + 32 + 4,
		"网关":    2 + 32 + 5 + 3,
		"MTU":   2 + 32 + 4 + 1 + 4 + 1,
		"特性位":   2 + 32 + 4 + 1 + 4 + 2,
	} {
		wire := append([]byte(nil), base...)
		wire[off] ^= 0x01
		if _, perr := ParseServerAccept(secret, wire, hello.Eph); !errors.Is(perr, ErrAuth) {
			t.Fatalf("篡改 %s 必须认证失败: %v", name, perr)
		}
	}
}

// 旧版客户端必须被识别成「版本过旧」而不是「认证失败」——否则运维只会看到
// 一条查不出原因的 auth failed。v1 与 v2 的包长各自唯一，靠长度先行判定；
// v3 的包长与 v4 相同，靠版本字节判定。
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

	// v3 Hello：字段布局与 v4 完全一致，只有版本字节是 0x03。
	v3 := make([]byte, helloLen)
	v3[0], v3[1] = TypeHello, 0x03

	for name, pkt := range map[string][]byte{"v1": v1, "v2": v2, "v3": v3} {
		if _, err := PeekHello(pkt); !errors.Is(err, ErrOldVersion) {
			t.Fatalf("%s hello must report ErrOldVersion, got %v", name, err)
		}
		if _, err := ParseClientHello([]byte("any"), pkt); !errors.Is(err, ErrOldVersion) {
			t.Fatalf("%s hello parse must report ErrOldVersion, got %v", name, err)
		}
	}
}

// 反向互操作：v4 客户端连 v3 服务端时，75 字节的旧 Accept 必须被报成
// ErrOldVersion 而不是 ErrBadPacket——后者的文案会让用户去查网络。
func TestOldAcceptReportedAsOldVersion(t *testing.T) {
	v3 := make([]byte, 75)
	v3[0], v3[1] = TypeAccept, 0x03
	if _, err := ParseServerAccept([]byte("s"), v3, [32]byte{}); !errors.Is(err, ErrOldVersion) {
		t.Fatalf("v3 accept must report ErrOldVersion, got %v", err)
	}
	v3r := make([]byte, rejectLen)
	v3r[0], v3r[1] = TypeReject, 0x03
	if _, err := ParseServerReject([]byte("s"), v3r, [32]byte{}); !errors.Is(err, ErrOldVersion) {
		t.Fatalf("v3 reject must report ErrOldVersion, got %v", err)
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
	s := mustSession(t, 0)
	p1 := append([]byte(nil), s.SealData(sealBuf(), []byte("one"))...)
	p2 := append([]byte(nil), s.SealData(sealBuf(), []byte("two"))...)
	p3 := append([]byte(nil), s.SealData(sealBuf(), []byte("three"))...)

	if _, err := s.OpenData(sealBuf(), p1); err != nil {
		t.Fatalf("open p1: %v", err)
	}
	if _, err := s.OpenData(sealBuf(), p3); err != nil {
		t.Fatalf("open p3 (reorder ahead): %v", err)
	}
	if _, err := s.OpenData(sealBuf(), p1); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed p1 must be rejected: %v", err)
	}
	if _, err := s.OpenData(sealBuf(), p2); err != nil {
		t.Fatalf("p2 within window must open: %v", err)
	}
	if _, err := s.OpenData(sealBuf(), p3); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed p3 must be rejected: %v", err)
	}
	// 乱序被单独计数：高乱序链路上它会很大而丢包率很低，两个数必须分得开。
	if v := s.Stats().View(); v.RxReordered == 0 || v.RxReplayed != 2 {
		t.Fatalf("stats = %+v（期望 reordered>0、replayed=2）", v)
	}
}

func TestCtrlMessageRoundTrip(t *testing.T) {
	s := mustSession(t, 0)
	wire, err := s.SealCtrl(sealBuf(), CtrlMessage{Kind: CtrlKindRoutes, IPs: []string{"1.2.3.4", "5.6.7.8"}})
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
	if _, _, err := s.OpenPing(wire); !errors.Is(err, ErrBadPacket) {
		t.Fatalf("ctrl 不得被当成心跳: %v", err)
	}
}

// Ping/Pong 走 AEAD 且带探测载荷：服务端此前对 Pong 完全不解密就刷新活跃
// 时间，任何人伪造一个 0x06 字节就能给别人的会话续命。
func TestPingPongRoundTrip(t *testing.T) {
	client, server := sessionPair(t, 0)

	ping := client.SealPing(sealBuf(), 0, 0)
	id, plainLen, err := server.OpenPing(ping)
	if err != nil || id != 0 || plainLen != 1 {
		t.Fatalf("OpenPing = %d/%d/%v", id, plainLen, err)
	}
	pong := server.SealPong(sealBuf(), id, plainLen)
	gotID, observed, err := client.OpenPong(pong)
	if err != nil || gotID != 0 || observed != 1 {
		t.Fatalf("OpenPong = %d/%d/%v", gotID, observed, err)
	}

	// 带 padding 的探测包：Pong 必须回显实际收到的明文长度。
	probe := client.SealPing(sealBuf(), 3, 700)
	id, plainLen, err = server.OpenPing(probe)
	if err != nil || id != 3 || plainLen != 701 {
		t.Fatalf("探测 Ping = %d/%d/%v", id, plainLen, err)
	}
	pong = server.SealPong(sealBuf(), id, plainLen)
	if gotID, observed, err = client.OpenPong(pong); err != nil || gotID != 3 || observed != 701 {
		t.Fatalf("探测 Pong = %d/%d/%v", gotID, observed, err)
	}

	// 伪造的 Pong（没有有效 AEAD 标签）必须被拒。
	forged := []byte{TypePong, 0, 0, 0, 0, 0, 0, 0, 9}
	forged = append(forged, bytes.Repeat([]byte{0xAA}, TagSize+3)...)
	if _, _, err := client.OpenPong(forged); err == nil {
		t.Fatal("伪造的 Pong 必须被拒绝")
	}
}

func TestTamperedPacketRejected(t *testing.T) {
	s := mustSession(t, 0)
	wire := s.SealData(sealBuf(), []byte("payload"))
	wire[len(wire)-1] ^= 0xFF
	if _, err := s.OpenData(sealBuf(), wire); !errors.Is(err, ErrAuth) {
		t.Fatalf("tampered packet must fail authentication: %v", err)
	}
	if v := s.Stats().View(); v.RxAuthFail != 1 {
		t.Fatalf("认证失败必须被计数: %+v", v)
	}
}

// 零分配路径的缓冲约定：容量不足必须显式报错而不是偷偷分配一块新的——
// 偷偷分配会让「0 allocs/op」的基准在真实负载下悄悄失效。
func TestOpenIntoRejectsShortBuffer(t *testing.T) {
	s := mustSession(t, 0)
	wire := s.SealData(sealBuf(), bytes.Repeat([]byte{0x41}, 200))
	if _, _, err := s.OpenInto(make([]byte, 0, 32), wire); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("缓冲不足必须返回 ErrShortBuffer，得到 %v", err)
	}
}

func TestClampTunMTU(t *testing.T) {
	for in, want := range map[int]int{
		0: MaxTunMTU, 1: MaxTunMTU, MinTunMTU - 1: MaxTunMTU,
		MinTunMTU: MinTunMTU, 1300: 1300, MaxTunMTU: MaxTunMTU,
		MaxTunMTU + 1: MaxTunMTU, 9000: MaxTunMTU,
	} {
		if got := ClampTunMTU(in); got != want {
			t.Fatalf("ClampTunMTU(%d) = %d, want %d", in, got, want)
		}
	}
}

// 热路径必须零分配：SealData/OpenData 各一次，缓冲由调用方复用。
func BenchmarkSealData1400(b *testing.B) {
	s := mustSession(b, 0)
	plain := bytes.Repeat([]byte{0x42}, 1400)
	dst := sealBuf()
	b.SetBytes(int64(len(plain)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.SealData(dst[:0], plain)
	}
}

func BenchmarkOpenData1400(b *testing.B) {
	s := mustSession(b, 0)
	plain := bytes.Repeat([]byte{0x42}, 1400)
	// 每次都要新计数，否则第二次就被重放窗口拒了。预生成一批包。
	const n = 1024
	wires := make([][]byte, n)
	for i := range wires {
		wires[i] = append([]byte(nil), s.SealData(sealBuf(), plain)...)
	}
	dst := sealBuf()
	b.SetBytes(int64(len(plain)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.OpenData(dst[:0], wires[i%n]); err != nil && i < n {
			b.Fatalf("open: %v", err)
		}
	}
}

// 服务端有三个并发发送者（数据泵、心跳、路由推送），所以发送计数必须原子且
// 绝不重复——重复的计数就是重复的 nonce，AEAD 下等于把密钥流交出去。
//
// 本机没有 C 编译器（-race 需要 cgo），所以这条用「计数唯一性」直接验证不变量
// 而不是靠竞态检测器。
func TestConcurrentSealCountersAreUnique(t *testing.T) {
	s := mustSession(t, 0)
	const writers, perWriter = 4, 2000

	seen := make([][]uint64, writers)
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			buf := sealBuf()
			out := make([]uint64, 0, perWriter)
			for i := 0; i < perWriter; i++ {
				wire := s.SealData(buf[:0], []byte("payload"))
				out = append(out, binary.BigEndian.Uint64(wire[1:1+CounterSize]))
			}
			seen[w] = out
		}(w)
	}
	wg.Wait()

	all := make(map[uint64]bool, writers*perWriter)
	for w, list := range seen {
		if len(list) != perWriter {
			t.Fatalf("writer %d 只产出 %d 个计数", w, len(list))
		}
		for _, c := range list {
			if c == 0 {
				t.Fatal("计数不得为 0（0 只可能是伪造）")
			}
			if all[c] {
				t.Fatalf("计数 %d 被重复分配：nonce 重用", c)
			}
			all[c] = true
		}
		// 同一个 goroutine 内必须严格递增。
		for i := 1; i < len(list); i++ {
			if list[i] <= list[i-1] {
				t.Fatalf("writer %d 的计数非递增：%d 之后是 %d", w, list[i-1], list[i])
			}
		}
	}
	if len(all) != writers*perWriter {
		t.Fatalf("唯一计数 %d 个，期望 %d", len(all), writers*perWriter)
	}
	if v := s.Stats().View(); v.TxPackets != uint64(writers*perWriter) {
		t.Fatalf("TxPackets = %d，期望 %d", v.TxPackets, writers*perWriter)
	}
}
