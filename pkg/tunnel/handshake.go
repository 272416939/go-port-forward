package tunnel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// 握手域分隔标签，避免不同方向的 MAC 互挪。版本后缀让新旧端天然互不认证。
var (
	helloDomain  = []byte("pfapp-hello-v4")
	acceptDomain = []byte("pfapp-accept-v4")
	rejectDomain = []byte("pfapp-reject-v4")
)

// 握手时间戳容忍窗口（防重放 + 容忍时钟偏差）。
const helloMaxAge = 10 * time.Minute

// 报文长度（含 1 字节类型前缀）。
const (
	helloLen  = 1 + 1 + UIDSize + FingerprintSize + 32 + 8 + 32 // 122
	acceptLen = 1 + 1 + 32 + 4 + 1 + 4 + 2 + 1 + 32             // 78
	rejectLen = 1 + 1 + 1 + 32                                  // 35
	// 旧版本 Hello 的长度，仅用于识别旧客户端。v3 与 v4 的 Hello 长度相同
	// （字段没变），v3 靠版本字节识别。
	helloLenV1 = 1 + 32 + 8 + 32               // 73
	helloLenV2 = 1 + 1 + UIDSize + 32 + 8 + 32 // 90
)

// macPSK 计算 HMAC-SHA256(secret, domain || parts...)。
func macPSK(secret []byte, domain []byte, parts ...[]byte) [32]byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(domain)
	for _, p := range parts {
		mac.Write(p)
	}
	return [32]byte(mac.Sum(nil))
}

// ClientHello 客户端握手包（明文传输，per-code secret HMAC 认证）。
//
// UID 明文传输是必要的：服务端要先知道对端声称是哪个访问码，才能取出对应的
// 密钥去验证 MAC。声称本身不构成认证——MAC 验证失败即拒绝。
//
// Device 是客户端的设备指纹（machineid 派生）。它进 MAC，所以中间人改不了；
// 但它由客户端自报，服务端只能保证「同一个访问码后续必须来自同一指纹」，
// 不能保证指纹对应真实硬件。
type ClientHello struct {
	UID    UID                   // 访问码 ID
	Device [FingerprintSize]byte // 设备指纹
	Eph    [32]byte              // 客户端临时 X25519 公钥
	TS     uint64                // 发起时间（unix 秒）
	MAC    [32]byte
}

// NewClientHello 生成客户端握手包，返回客户端临时私钥（用于派生会话密钥）。
func NewClientHello(secret []byte, uid UID, device [FingerprintSize]byte) (*ClientHello, *[32]byte, error) {
	h := &ClientHello{UID: uid, Device: device, TS: uint64(time.Now().Unix())}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	h.Eph = *pub
	h.MAC = h.mac(secret)
	return h, priv, nil
}

func (h *ClientHello) mac(secret []byte) [32]byte {
	return macPSK(secret, helloDomain,
		[]byte{Version}, h.UID[:], h.Device[:], h.Eph[:], u64be(h.TS))
}

// Marshal 序列化为 UDP 载荷：[0x01]ver||uid||device||eph||ts||mac。
func (h *ClientHello) Marshal() []byte {
	out := make([]byte, 0, helloLen)
	out = append(out, TypeHello, Version)
	out = append(out, h.UID[:]...)
	out = append(out, h.Device[:]...)
	out = append(out, h.Eph[:]...)
	out = append(out, u64be(h.TS)...)
	out = append(out, h.MAC[:]...)
	return out
}

// PeekHello 只做长度与版本检查并取出声称的访问码 ID，不做任何认证。
// 服务端用它决定去查哪个访问码的密钥，随后必须调用 ParseClientHello 验证。
func PeekHello(b []byte) (UID, error) {
	var uid UID
	if len(b) < 1 || b[0] != TypeHello {
		return uid, ErrBadPacket
	}
	// 长度先行：旧版 Hello 的版本字节位置落在临时公钥（v1）或长度不足（v2），
	// 直接读版本字节会把旧包误判成任意版本。
	if len(b) == helloLenV1 || len(b) == helloLenV2 {
		return uid, ErrOldVersion
	}
	if len(b) < helloLen {
		return uid, ErrBadPacket
	}
	if b[1] != Version {
		return uid, ErrOldVersion
	}
	copy(uid[:], b[2:2+UIDSize])
	return uid, nil
}

// ParseClientHello 解析并校验客户端握手包。
func ParseClientHello(secret, b []byte) (*ClientHello, error) {
	uid, err := PeekHello(b)
	if err != nil {
		return nil, err
	}
	h := &ClientHello{UID: uid}
	off := 2 + UIDSize
	copy(h.Device[:], b[off:off+FingerprintSize])
	off += FingerprintSize
	copy(h.Eph[:], b[off:off+32])
	off += 32
	h.TS = binary.BigEndian.Uint64(b[off : off+8])
	off += 8
	copy(h.MAC[:], b[off:off+32])

	age := time.Since(time.Unix(int64(h.TS), 0))
	if age < -helloMaxAge || age > helloMaxAge {
		return nil, ErrAuth
	}
	want := h.mac(secret)
	if !hmac.Equal(want[:], h.MAC[:]) {
		return nil, ErrAuth
	}
	return h, nil
}

// ServerAccept 服务端握手应答（明文传输，per-code secret HMAC 认证）。
//
// TunIP/Prefix/Gateway 是服务端为该访问码分配的隧道内地址，全部纳入 MAC——
// 否则中间人可以把客户端的隧道地址改成别人的，绕过服务端的隔离检查。
//
// MTU/Feats 同样进 MAC：能改 MTU 的中间人可以把隧道压到不可用的小值（静默的
// 吞吐攻击），能改 Feats 的可以单向关掉 FEC（一端发、一端不认，那些校验包会
// 被当未知类型丢弃，表现成「开了纠错反而更卡」）。
type ServerAccept struct {
	Eph     [32]byte // 服务端临时 X25519 公钥
	TunIP   [4]byte  // 分配给客户端的隧道内地址
	Prefix  uint8    // 隧道网段前缀长度
	Gateway [4]byte  // 隧道内网关（服务端的隧道地址）
	MTU     uint16   // 服务端算出的隧道 MTU（客户端据此设置 wintun）
	Feats   uint8    // 会话特性开关（FeatFEC / FeatTailDup）
	MAC     [32]byte
}

// NewServerAccept 生成服务端应答包，返回服务端临时私钥。
func NewServerAccept(secret []byte, clientEph [32]byte, tunIP, gateway netip.Addr,
	prefix, mtu int, feats uint8) (*ServerAccept, *[32]byte, error) {
	if !tunIP.Is4() || !gateway.Is4() {
		return nil, nil, ErrBadPacket
	}
	if prefix < 1 || prefix > 32 {
		return nil, nil, ErrBadPacket
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	a := &ServerAccept{
		Eph:     *pub,
		TunIP:   tunIP.As4(),
		Prefix:  uint8(prefix),
		Gateway: gateway.As4(),
		MTU:     uint16(ClampTunMTU(mtu)),
		Feats:   feats,
	}
	a.MAC = a.mac(secret, clientEph)
	return a, priv, nil
}

func (a *ServerAccept) mac(secret []byte, clientEph [32]byte) [32]byte {
	var mtuBE [2]byte
	binary.BigEndian.PutUint16(mtuBE[:], a.MTU)
	return macPSK(secret, acceptDomain,
		[]byte{Version}, a.Eph[:], clientEph[:], a.TunIP[:], []byte{a.Prefix},
		a.Gateway[:], mtuBE[:], []byte{a.Feats})
}

// TunAddr 返回分配到的隧道内地址。
func (a *ServerAccept) TunAddr() netip.Addr { return netip.AddrFrom4(a.TunIP) }

// GatewayAddr 返回隧道内网关地址。
func (a *ServerAccept) GatewayAddr() netip.Addr { return netip.AddrFrom4(a.Gateway) }

// TunMTU 返回下发的隧道 MTU（越界值回落到缺省）。
func (a *ServerAccept) TunMTU() int { return ClampTunMTU(int(a.MTU)) }

// ECDHShared 计算 X25519 共享密钥（box.Precompute 语义）。
func ECDHShared(peerPub, myPriv *[32]byte) *[32]byte {
	shared := new([32]byte)
	box.Precompute(shared, peerPub, myPriv)
	return shared
}

// Marshal 序列化为 UDP 载荷：[0x02]ver||eph||tunIP||prefix||gw||mtu||feats||mac。
func (a *ServerAccept) Marshal() []byte {
	out := make([]byte, 0, acceptLen)
	out = append(out, TypeAccept, Version)
	out = append(out, a.Eph[:]...)
	out = append(out, a.TunIP[:]...)
	out = append(out, a.Prefix)
	out = append(out, a.Gateway[:]...)
	out = binary.BigEndian.AppendUint16(out, a.MTU)
	out = append(out, a.Feats)
	out = append(out, a.MAC[:]...)
	return out
}

// ParseServerAccept 解析并校验服务端应答包。
func ParseServerAccept(secret, b []byte, clientEph [32]byte) (*ServerAccept, error) {
	if len(b) < 1 || b[0] != TypeAccept {
		return nil, ErrBadPacket
	}
	// 版本先判：v3 服务端的 Accept 是 75 字节，长度检查会先把它报成
	// ErrBadPacket，而真正的原因是版本不匹配（运维会去查密钥而不是查版本）。
	if len(b) >= 2 && b[1] != Version {
		return nil, ErrOldVersion
	}
	if len(b) < acceptLen {
		return nil, ErrBadPacket
	}
	a := &ServerAccept{}
	off := 2
	copy(a.Eph[:], b[off:off+32])
	off += 32
	copy(a.TunIP[:], b[off:off+4])
	off += 4
	a.Prefix = b[off]
	off++
	copy(a.Gateway[:], b[off:off+4])
	off += 4
	a.MTU = binary.BigEndian.Uint16(b[off : off+2])
	off += 2
	a.Feats = b[off]
	off++
	copy(a.MAC[:], b[off:off+32])

	want := a.mac(secret, clientEph)
	if !hmac.Equal(want[:], a.MAC[:]) {
		return nil, ErrAuth
	}
	if a.Prefix < 1 || a.Prefix > 32 {
		return nil, ErrBadPacket
	}
	return a, nil
}

// ServerReject 是服务端明确拒绝握手的应答。
//
// 为什么需要它：在此之前服务端拒绝握手一律静默丢包，客户端只能报「服务端
// 无应答」。设备绑定上线后最常见的失败（换了台电脑）会显示成一个指向错误
// 方向的提示，用户会去查防火墙和端口。
//
// 安全约束：**只在 MAC 校验通过之后才发送**。这样它只会发给确实持有密钥的
// 对端，不构成反射放大源（35 字节应答 < 122 字节请求）。访问码查不到时仍然
// 静默——那种情况下没有密钥可用来签名，能签的只有攻击者想让我们签的东西。
type ServerReject struct {
	Reason RejectReason
	MAC    [32]byte
}

// NewServerReject 生成拒绝应答。
func NewServerReject(secret []byte, clientEph [32]byte, reason RejectReason) *ServerReject {
	r := &ServerReject{Reason: reason}
	r.MAC = r.mac(secret, clientEph)
	return r
}

func (r *ServerReject) mac(secret []byte, clientEph [32]byte) [32]byte {
	return macPSK(secret, rejectDomain,
		[]byte{Version}, []byte{byte(r.Reason)}, clientEph[:])
}

// Marshal 序列化为 UDP 载荷：[0x07]ver||reason||mac。
func (r *ServerReject) Marshal() []byte {
	out := make([]byte, 0, rejectLen)
	out = append(out, TypeReject, Version, byte(r.Reason))
	out = append(out, r.MAC[:]...)
	return out
}

// ParseServerReject 解析并校验拒绝应答。
//
// 必须验 MAC：不验的话任何人都能伪造一个 Reject 让客户端停止重连——那是一个
// 单包就能生效的拒绝服务。
func ParseServerReject(secret, b []byte, clientEph [32]byte) (*ServerReject, error) {
	if len(b) < 1 || b[0] != TypeReject {
		return nil, ErrBadPacket
	}
	if len(b) >= 2 && b[1] != Version {
		return nil, ErrOldVersion
	}
	if len(b) < rejectLen {
		return nil, ErrBadPacket
	}
	r := &ServerReject{Reason: RejectReason(b[2])}
	copy(r.MAC[:], b[3:3+32])
	want := r.mac(secret, clientEph)
	if !hmac.Equal(want[:], r.MAC[:]) {
		return nil, ErrAuth
	}
	return r, nil
}

func u64be(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}
