package tunnel

// 跨版本握手兼容（v4 起）。
//
// 背景：协议硬切换，但「版本不匹配」此前在两端都是**静默**——服务端
// PeekHello 失败后只写日志，客户端只能等超时，最后显示「服务端无应答（请检查
// 地址、端口与中转机防火墙）」。一个纯粹的版本问题被误报成了网络问题，运维
// 会去白查防火墙（2026-09-03 用户实测踩中）。
//
// 这里的两块补丁让两端各自给出可读的原因，同时不放松任何一条安全约束：
//
//  1. **服务端**：对版本过旧但 **MAC 验证通过**的旧客户端，回一个用旧版本域
//     标签签名的拒绝应答（reason 0——v3 词表里没有「版本不匹配」的语义，0 在
//     旧客户端显示为「原因代码 0」的默认文案，比无应答强）。MAC 无效一律保持
//     静默：拒绝应答 35 字节 < Hello 122 字节，不构成反射放大；只应答持有
//     密钥的对端，不引入「访问码是否存在」的探测口子。
//  2. **客户端**：v4 握手全部无应答后，用一条 v3 格式的探测包再试一次。对端
//     若有应答即可区分「服务端不可达」与「服务端是旧版本/版本不一致」。
//     **探测包绝不用于建立会话**——按 v3 建会话等于回到 nonce 跨方向重用。
//     探测的副作用与一次正常的旧客户端连接相同（设备绑定、内存会话空闲回收）。

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// v3 的域分隔标签。只在跨版本应答/探测里使用，会话密钥派生永远用 v4 的。
var (
	helloDomainV3  = []byte("pfapp-hello-v3")
	rejectDomainV3 = []byte("pfapp-reject-v3")
)

// NewLegacyProbeHello 构造一条 v3 格式的握手包（探测专用）。
//
// 字段布局与 v4 完全一致，只有版本字节与 MAC 域标签不同——这正是 v3/v4 能靠
// 版本字节区分的原因。返回的包给「可能仍是 v3 的服务端」看，让它按老规矩处理
// 并应答；客户端只读应答的版本字节来判断对端版本，绝不解析 Accept 建会话。
func NewLegacyProbeHello(secret []byte, uid UID, device [FingerprintSize]byte) ([]byte, error) {
	return buildHello(secret, uid, device, VersionV3, helloDomainV3)
}

// buildHello 按指定版本组装 Hello。v4 的 NewClientHello 也走这里。
func buildHello(secret []byte, uid UID, device [FingerprintSize]byte, ver byte, domain []byte) ([]byte, error) {
	h := &ClientHello{UID: uid, Device: device, TS: uint64(time.Now().Unix())}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	h.Eph = *pub
	mac := macPSK(secret, domain, []byte{ver}, h.UID[:], h.Device[:], h.Eph[:], u64be(h.TS))
	out := make([]byte, 0, helloLen)
	out = append(out, TypeHello, ver)
	out = append(out, h.UID[:]...)
	out = append(out, h.Device[:]...)
	out = append(out, h.Eph[:]...)
	out = append(out, u64be(h.TS)...)
	out = append(out, mac[:]...)
	_ = priv // 探测包不需要私钥；签名仅用于让对端愿意处理
	return out, nil
}

// PeekLegacyHelloUID 从一个「版本过旧但格式可识别」的 Hello 里取出声称的
// 访问码 ID（v3 与 v4 的字段偏移相同）。只做长度与版本字节检查，不验证 MAC。
// v1/v2 的布局不同，一律返回 false。
func PeekLegacyHelloUID(b []byte) (UID, bool) {
	var uid UID
	if len(b) < helloLen || b[0] != TypeHello {
		return uid, false
	}
	if b[1] != VersionV3 && b[1] != Version {
		return uid, false
	}
	copy(uid[:], b[2:2+UIDSize])
	return uid, true
}

// InspectLegacyHello 用对应版本的域标签验证一条旧版 Hello 的 MAC。
// 通过则返回客户端临时公钥与它的协议版本；失败一律 ok=false（调用方保持静默）。
// 时间窗检查与当前版本一致（防重放）。
func InspectLegacyHello(secret, b []byte) (clientEph [32]byte, ver byte, ok bool) {
	if len(b) < helloLen || b[0] != TypeHello {
		return clientEph, 0, false
	}
	ver = b[1]
	var domain []byte
	switch ver {
	case VersionV3:
		domain = helloDomainV3
	case Version:
		domain = helloDomain
	default:
		return clientEph, 0, false
	}
	ts := binary.BigEndian.Uint64(b[82:90])
	age := time.Since(time.Unix(int64(ts), 0))
	if age < -helloMaxAge || age > helloMaxAge {
		return clientEph, 0, false
	}
	want := macPSK(secret, domain, []byte{ver}, b[2:18], b[18:50], b[50:82], b[82:90])
	if !hmac.Equal(want[:], b[90:122]) {
		return clientEph, 0, false
	}
	copy(clientEph[:], b[50:82])
	return clientEph, ver, true
}

// LegacyVersionReject 为一条已通过 InspectLegacyHello 的旧版 Hello 构造拒绝
// 应答：用**该客户端自己的协议版本**的域标签签名，所以旧客户端能验证并显示
// 出「被拒绝」而不是无应答。reason 固定 0（v3 词表没有版本语义；v4 Hello 在
// v5 服务端被**接受**（只动 Hello 的版本策略），因此 0x04 不会走到跨版本
// 应答；reason 6 留给未来真正拒收旧版 Hello 的版本使用）。
//
// 入参必须原样是收到的 Hello 报文；MAC 复验失败返回 nil（调用方静默）。
func LegacyVersionReject(secret, hello []byte) []byte {
	eph, ver, ok := InspectLegacyHello(secret, hello)
	if !ok {
		return nil
	}
	var domain []byte
	switch ver {
	case VersionV3:
		domain = rejectDomainV3
	case Version:
		domain = rejectDomain
	default:
		return nil
	}
	reason := byte(RejectUnknown)
	mac := macPSK(secret, domain, []byte{ver}, []byte{reason}, eph[:])
	out := make([]byte, 0, rejectLen)
	out = append(out, TypeReject, ver, reason)
	out = append(out, mac[:]...)
	return out
}

// ProbeVerdict 是对「v3 探测包」应答的判定。
type ProbeVerdict int

const (
	// ProbeNoReply 表示没有可识别的应答：对端不可达或静默丢弃。
	ProbeNoReply ProbeVerdict = iota
	// ProbeServerLegacy 表示对端按 v3 规则处理了探测包（回 Accept，或回了带
	// 具体原因的 Reject）——它就是一个 v3 服务端。
	ProbeServerLegacy
	// ProbeVersionSkew 表示对端认出了密钥、但标记了「版本不匹配」（reason 0，
	// 这是 v4 服务端的跨版本应答约定）——两端版本不一致，且对端不是 v3。
	ProbeVersionSkew
)

// ClassifyLegacyProbeReply 判定探测包的应答。应答不验 MAC：它只用于给用户
// 一条准确的诊断文案，不驱动任何状态变更——socket 是 connected 的，伪造者
// 本来就能随意阻塞这条链路，诊断文案不增加攻击面。
func ClassifyLegacyProbeReply(b []byte) ProbeVerdict {
	if len(b) < 3 || b[1] != VersionV3 {
		return ProbeNoReply
	}
	switch b[0] {
	case TypeAccept:
		return ProbeServerLegacy // v3 服务端处理了合法探测包后只可能是 Accept
	case TypeReject:
		if RejectReason(b[2]) == RejectUnknown {
			return ProbeVersionSkew // v4 服务端的跨版本应答约定（reason 0）
		}
		return ProbeServerLegacy // v3 服务端因业务原因拒绝（停用/绑定/上限）
	default:
		return ProbeNoReply
	}
}
