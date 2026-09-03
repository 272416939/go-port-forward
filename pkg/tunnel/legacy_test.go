package tunnel

// 跨版本握手兼容的用例（legacy.go）。
//
// 每条都对着一个具体的失效模式：探测包必须被 v3 服务端当作合法 Hello 处理
// （否则探测永远超时，客户端依旧显示「无应答」）；跨版本拒绝必须能被 v3 客户端
// 验证（否则旧客户端还是「无应答」）；MAC 无效必须静默（否则引入访问码存在性
// 探测口子）。

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"testing"
)

// v3HelloMAC 按旧版域标签手工计算 Hello MAC（测试参照物，不经过新代码）。
func v3HelloMAC(secret []byte, ver byte, uid UID, device, eph [32]byte, ts uint64) [32]byte {
	return macPSK(secret, helloDomainV3, []byte{ver}, uid[:], device[:], eph[:], u64be(ts))
}

// 探测包必须是 v3 服务端认识的合法 Hello：版本字节 0x03、当前 PeekHello 报
// ErrOldVersion（这正是版本不匹配被静默的原因）、字段布局与 v3 完全一致。
func TestLegacyProbeHelloIsWellFormedV3(t *testing.T) {
	secret := []byte("per-code-secret")
	uid := mustUID(t, "3f2b1c4d-5e6f-4071-8293-a4b5c6d7e8f9")

	wire, err := NewLegacyProbeHello(secret, uid, testDevice)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != helloLen {
		t.Fatalf("探测包长度 = %d，期望 %d", len(wire), helloLen)
	}
	if _, err := PeekHello(wire); !errors.Is(err, ErrOldVersion) {
		t.Fatalf("v4 服务端应把探测包报成 ErrOldVersion，得到 %v", err)
	}
	gotUID, ok := PeekLegacyHelloUID(wire)
	if !ok || gotUID != uid {
		t.Fatalf("PeekLegacyHelloUID = %v, %v", gotUID, ok)
	}
	// MAC 必须与旧版算法逐字节一致，否则 v3 服务端会当认证失败静默丢弃。
	want := v3HelloMAC(secret, VersionV3, uid, testDevice, [32]byte(wire[50:82]),
		uint64(wire[82])<<56|uint64(wire[83])<<48|uint64(wire[84])<<40|uint64(wire[85])<<32|
			uint64(wire[86])<<24|uint64(wire[87])<<16|uint64(wire[88])<<8|uint64(wire[89]))
	if !hmac.Equal(want[:], wire[90:122]) {
		t.Fatal("探测包 MAC 与 v3 算法不一致：v3 服务端会静默丢弃，探测永远超时")
	}
	// 它也必须能被 InspectLegacyHello 验证（服务端跨版本应答的前提）。
	if _, ver, ok := InspectLegacyHello(secret, wire); !ok || ver != VersionV3 {
		t.Fatalf("InspectLegacyHello = %v, ver=%d", ok, ver)
	}
}

// MAC 验证失败的 Hello 必须静默：跨版本应答只发给持有密钥的对端，否则等于
// 新增一个「访问码是否存在」的探测口子。
func TestLegacyInspectRejectsBadMAC(t *testing.T) {
	secret := []byte("right")
	wire, err := NewLegacyProbeHello(secret, mustUID(t, "3f2b1c4d-5e6f-4071-8293-a4b5c6d7e8f9"), testDevice)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := InspectLegacyHello([]byte("wrong"), wire); ok {
		t.Fatal("密钥不符必须验证失败")
	}
	tampered := append([]byte(nil), wire...)
	tampered[20] ^= 0x01 // 篡改 device 字段
	if _, _, ok := InspectLegacyHello(secret, tampered); ok {
		t.Fatal("篡改后的 Hello 必须验证失败")
	}
	if _, _, ok := InspectLegacyHello(secret, wire[:100]); ok {
		t.Fatal("截断的 Hello 必须验证失败")
	}
	// 时间戳超出容忍窗口（防重放）同样静默。
	stale := append([]byte(nil), wire...)
	stale[82], stale[83] = 0, 1 // ts ≈ 1970
	if _, _, ok := InspectLegacyHello(secret, stale); ok {
		t.Fatal("时间戳超出窗口必须验证失败")
	}
	// v1/v2 布局不同：静默。
	if _, ok := PeekLegacyHelloUID(make([]byte, 73)); ok {
		t.Fatal("v1 长度的包不应被识别")
	}
	if _, ok := PeekLegacyHelloUID(make([]byte, 90)); ok {
		t.Fatal("v2 长度的包不应被识别")
	}
}

// 跨版本拒绝应答必须能被 v3 客户端验证：版本字节 0x03 + v3 域标签的 MAC +
// reason 0（v3 词表没有版本语义，旧客户端落到「原因代码 0」的默认文案）。
func TestLegacyVersionRejectVerifiableByV3Client(t *testing.T) {
	secret := []byte("per-code-secret")
	hello, err := NewLegacyProbeHello(secret, mustUID(t, "3f2b1c4d-5e6f-4071-8293-a4b5c6d7e8f9"), testDevice)
	if err != nil {
		t.Fatal(err)
	}
	wire := LegacyVersionReject(secret, hello)
	if wire == nil {
		t.Fatal("合法 Hello 必须产出拒绝应答")
	}
	if len(wire) != rejectLen || wire[0] != TypeReject || wire[1] != VersionV3 {
		t.Fatalf("拒绝应答形态不符: len=%d [0]=%#x [1]=%#x", len(wire), wire[0], wire[1])
	}
	if wire[2] != byte(RejectUnknown) {
		t.Fatalf("reason = %d，期望 0（v3 词表的版本不匹配标记）", wire[2])
	}
	// 用旧版算法独立复算 MAC：v3 客户端的 ParseServerReject 就是这样验的。
	want := macPSK(secret, rejectDomainV3, []byte{VersionV3}, []byte{byte(RejectUnknown)}, hello[50:82])
	if !hmac.Equal(want[:], wire[3:]) {
		t.Fatal("拒绝应答 MAC 与 v3 算法不一致：旧客户端会显示「无法验证」而不是拒绝原因")
	}
	// MAC 复验失败的 Hello 不得产出应答。
	tampered := append([]byte(nil), hello...)
	tampered[60] ^= 0x01
	if LegacyVersionReject(secret, tampered) != nil {
		t.Fatal("MAC 无效时必须返回 nil（调用方静默）")
	}
}

func TestClassifyLegacyProbeReply(t *testing.T) {
	secret := []byte("s")
	hello, err := NewLegacyProbeHello(secret, mustUID(t, "3f2b1c4d-5e6f-4071-8293-a4b5c6d7e8f9"), testDevice)
	if err != nil {
		t.Fatal(err)
	}
	accept := make([]byte, 0, acceptLen)
	accept = append(accept, TypeAccept, VersionV3)
	accept = append(accept, bytes.Repeat([]byte{0xAB}, acceptLen-2)...)

	cases := []struct {
		name string
		pkt  []byte
		want ProbeVerdict
	}{
		{"v3 服务端的 Accept", accept, ProbeServerLegacy},
		{"v4 服务端的跨版本拒绝（reason 0）", LegacyVersionReject(secret, hello), ProbeVersionSkew},
		{"v3 服务端的业务拒绝（reason 2）", func() []byte {
			mac := macPSK(secret, rejectDomainV3, []byte{VersionV3}, []byte{byte(RejectCodeDisabled)}, hello[50:82])
			out := []byte{TypeReject, VersionV3, byte(RejectCodeDisabled)}
			return append(out, mac[:]...)
		}(), ProbeServerLegacy},
		{"空应答", nil, ProbeNoReply},
		{"版本字节不是 v3", []byte{TypeAccept, Version, 0}, ProbeNoReply},
		{"未知类型", []byte{TypeHello, VersionV3, 0}, ProbeNoReply},
	}
	for _, c := range cases {
		if got := ClassifyLegacyProbeReply(c.pkt); got != c.want {
			t.Errorf("%s: verdict = %v, 期望 %v", c.name, got, c.want)
		}
	}
}

func TestRejectVersionMismatchClassification(t *testing.T) {
	if !RejectVersionMismatch.Terminal() {
		t.Fatal("版本不匹配必须终态：重试只会刷日志，升级后才会恢复")
	}
	if RejectVersionMismatch.String() != "version_mismatch" {
		t.Fatalf("String() = %q", RejectVersionMismatch.String())
	}
}
