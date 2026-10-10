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
//
// v5 硬切换：accept/reject 的域标签随全局 Version 一起升到 v5；Hello 因要
// 单独识别「旧客户端发来的旧版 Hello」（跨版本拒绝应答用），保留 v3/v4/v5
// 三个历史标签，当前 Hello 用 v6。
var (
	helloDomain   = []byte("pfapp-hello-v4")  // 旧：v4 形态 Hello（122B）
	helloDomain5  = []byte("pfapp-hello-v5")  // 旧：v5 形态 Hello（154B，指纹 v2）
	helloDomain6  = []byte("pfapp-hello-v6")  // 当前：v6 形态 Hello（154B）
	acceptDomain  = []byte("pfapp-accept-v5") // 当前：Accept
	rejectDomain  = []byte("pfapp-reject-v5") // 当前：Reject
	rejectDomainV4 = []byte("pfapp-reject-v4") // 旧：给 v4/v5 Hello 的客户端回拒绝用
)

// Hello 的版本字节单独管理：Accept/Reject/会话格式跟随全局 Version，而 Hello
// 的版本字节还要承担「识别旧客户端」的职责——服务端靠它决定用哪个域标签去
// 复验 MAC、回一个旧客户端能验证的拒绝应答。
const (
	helloVerV4 = 0x04 // 旧：122B，无指纹 v2
	helloVerV5 = 0x05 // 旧：154B，带指纹 v2
	helloVerV6 = 0x06 // 当前：154B，带指纹 v2
)

// 握手时间戳容忍窗口（防重放 + 容忍时钟偏差）。
const helloMaxAge = 10 * time.Minute

// 报文长度（含 1 字节类型前缀）。
const (
	helloLen   = 1 + 1 + UIDSize + FingerprintSize + 32 + 8 + 32           // 122
	helloLenV5 = helloLen + FingerprintSize                                // 154
	acceptLen  = 1 + 1 + 32 + 4 + 1 + 4 + 2 + 1 + 32                       // 78
	rejectLen  = 1 + 1 + 1 + 32                                            // 35
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
//
// Device2 是指纹 v2（v5 起携带）：主指纹掺入 SMBIOS 系统UUID 派生——克隆
// 虚拟机的宿主机会在克隆时更换该 UUID，两台克隆机由此可区分。本机没有可用
// 的第二指纹来源时 Device2 == Device（服务端迁移为 no-op）。Device2 为全零
// 表示 v4 形态（Marshal/Parse 据此分派）。
type ClientHello struct {
	UID     UID                   // 访问码 ID
	Device  [FingerprintSize]byte // 设备指纹（v1，兼容锚点）
	Device2 [FingerprintSize]byte // 设备指纹 v2（克隆去重；v4 包为零值）
	Eph     [32]byte              // 客户端临时 X25519 公钥
	TS      uint64                // 发起时间（unix 秒）
	MAC     [32]byte

	// ver 是这条 Hello 的线上版本字节，由构造函数设置，Marshal 依据它决定布局。
	//
	// 不能用 HasDevice2() 推断布局：机器上两个指纹来源都取不到时 Device2 是
	// 零值，但当前协议仍然必须发 154B 的 v6 形态——发 122B 会被服务端当旧版
	// 直接拒掉（ErrOldVersion），而那种「本机没指纹就连不上」的失败模式极难
	// 排查。零值指纹只是「没有第二指纹」，不是「退回旧协议」。
	ver byte
}

// NewClientHello 生成**旧版 v4 形态**握手包（122B，不携带指纹 v2）。
//
// 生产客户端不再调用它——v5 硬切换后当前形态是 NewClientHelloV6。保留它是
// 为了在测试里构造「旧客户端发来的包」，验证跨版本拒绝应答链路。
func NewClientHello(secret []byte, uid UID, device [FingerprintSize]byte) (*ClientHello, *[32]byte, error) {
	h := &ClientHello{UID: uid, Device: device, TS: uint64(time.Now().Unix()), ver: helloVerV4}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	h.Eph = *pub
	h.MAC = h.mac(secret, helloVerV4)
	return h, priv, nil
}

// NewClientHelloV6 生成当前的 v6 握手包（154B，携带指纹 v2）。
//
// **恒定发 154B 形态**：device2 为空表示本机没有可用的第二指纹来源（如 SMBIOS
// UUID 缺失），此时 Device2 回填为主指纹 Device（服务端迁移为 no-op）；两者都
// 取不到时 Device2 就是零值，但形态仍然是 v6——见 ClientHello.ver 的说明。
func NewClientHelloV6(secret []byte, uid UID, device, device2 [FingerprintSize]byte) (*ClientHello, *[32]byte, error) {
	var zero [FingerprintSize]byte
	if device2 == zero {
		device2 = device
	}
	h := &ClientHello{
		UID: uid, Device: device, Device2: device2,
		TS: uint64(time.Now().Unix()), ver: helloVerV6,
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	h.Eph = *pub
	h.MAC = h.mac(secret, helloVerV6)
	return h, priv, nil
}

func (h *ClientHello) mac(secret []byte, ver byte) [32]byte {
	// v5/v6 同为 154B 布局，字段集一致，只有域标签不同——旧客户端用 v5 标签，
	// 当前客户端用 v6 标签，服务端据此识别并分别处理。
	if ver == helloVerV5 || ver == helloVerV6 {
		return macPSK(secret, helloDomainFor(ver),
			[]byte{ver}, h.UID[:], h.Device[:], h.Device2[:], h.Eph[:], u64be(h.TS))
	}
	return macPSK(secret, helloDomain,
		[]byte{ver}, h.UID[:], h.Device[:], h.Eph[:], u64be(h.TS))
}

// helloDomainFor 返回某个 Hello 版本对应的域标签。
func helloDomainFor(ver byte) []byte {
	if ver == helloVerV5 {
		return helloDomain5
	}
	return helloDomain6
}

// HasDevice2：Device2 非零即视为携带指纹 v2（v5 形态）。指纹是 HMAC 输出，
// 全零概率可忽略；v4 形态的调用方 Device2 恒为零值。
func (h *ClientHello) HasDevice2() bool {
	var zero [FingerprintSize]byte
	return h.Device2 != zero
}

// Marshal 序列化为 UDP 载荷。v6：[0x01]0x06||uid||device||device2||eph||ts||mac；
// v4：[0x01]0x04||uid||device||eph||ts||mac。
//
// ⚠️ 两处版本字节都必须写 **Hello 自己的版本**（h.ver），不能写全局 Version：
// 二者曾经恒等（都是 0x04），全局 Version 升到 0x05 后若继续写全局值，就会
// 出现「线上版本字节 0x05、MAC 却按 0x04 域签」的自相矛盾包，对端必然验失败。
func (h *ClientHello) Marshal() []byte {
	if h.ver == helloVerV6 {
		out := make([]byte, 0, helloLenV5)
		out = append(out, TypeHello, helloVerV6)
		out = append(out, h.UID[:]...)
		out = append(out, h.Device[:]...)
		out = append(out, h.Device2[:]...)
		out = append(out, h.Eph[:]...)
		out = append(out, u64be(h.TS)...)
		out = append(out, h.MAC[:]...)
		return out
	}
	out := make([]byte, 0, helloLen)
	out = append(out, TypeHello, helloVerV4)
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
	uid, _, err := peekHello(b)
	return uid, err
}

// peekHello 校验长度与版本并取出 uid 与 Hello 的版本字节。
//
// v5 硬切换后**只有 v6（154B）是当前版本**，其余一律 ErrOldVersion：
//   - 73/90 字节 = v1/v2（长度先行，它们的版本字节位置落在公钥上，不能读）
//   - 122 字节 = v3/v4 旧版
//   - 154 字节但版本字节不是 0x06 = 旧版 v5
//   - 其他更大长度 = 来自更新版本的客户端
func peekHello(b []byte) (UID, byte, error) {
	var uid UID
	if len(b) < 1 || b[0] != TypeHello {
		return uid, 0, ErrBadPacket
	}
	// 长度先行：旧版 Hello 的版本字节位置落在临时公钥（v1）或长度不足（v2），
	// 直接读版本字节会把旧包误判成任意版本。
	if len(b) == helloLenV1 || len(b) == helloLenV2 {
		return uid, 0, ErrOldVersion
	}
	switch {
	case len(b) == helloLenV5:
		if b[1] != helloVerV6 {
			return uid, 0, ErrOldVersion
		}
	case len(b) >= helloLen:
		// 122B（v3/v4）以及任何未知的更大长度：旧版或来自更新版本的对端。
		// 注意下界是 >= 而不是 >：122 字节本身也是旧版，漏了它会掉进
		// default 报 ErrBadPacket，而那条文案会让运维去查网络而不是查版本。
		return uid, 0, ErrOldVersion
	default:
		return uid, 0, ErrBadPacket
	}
	copy(uid[:], b[2:2+UIDSize])
	return uid, b[1], nil
}

// ParseClientHello 解析并校验客户端握手包（当前仅 v6 形态；旧版一律
// ErrOldVersion，由服务端走跨版本拒绝应答）。
func ParseClientHello(secret, b []byte) (*ClientHello, error) {
	uid, ver, err := peekHello(b)
	if err != nil {
		return nil, err
	}
	h := &ClientHello{UID: uid, ver: ver}
	off := 2 + UIDSize
	copy(h.Device[:], b[off:off+FingerprintSize])
	off += FingerprintSize
	if ver == helloVerV6 {
		copy(h.Device2[:], b[off:off+FingerprintSize])
		off += FingerprintSize
	}
	copy(h.Eph[:], b[off:off+32])
	off += 32
	h.TS = binary.BigEndian.Uint64(b[off : off+8])
	off += 8
	copy(h.MAC[:], b[off:off+32])

	age := time.Since(time.Unix(int64(h.TS), 0))
	if age < -helloMaxAge || age > helloMaxAge {
		return nil, ErrAuth
	}
	want := h.mac(secret, ver)
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
