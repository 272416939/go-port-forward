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
	helloDomain  = []byte("pfapp-hello-v2")
	acceptDomain = []byte("pfapp-accept-v2")
)

// 握手时间戳容忍窗口（防重放 + 容忍时钟偏差）。
const helloMaxAge = 10 * time.Minute

// 报文长度（含 1 字节类型前缀）。
const (
	helloLen   = 1 + 1 + UIDSize + 32 + 8 + 32 // 90
	acceptLen  = 1 + 1 + 32 + 4 + 1 + 4 + 32   // 75
	helloLenV1 = 1 + 32 + 8 + 32               // 73，仅用于识别旧客户端
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

// ClientHello 客户端握手包（明文传输，per-user secret HMAC 认证）。
//
// UID 明文传输是必要的：服务端要先知道对端声称是谁，才能取出该用户的密钥去
// 验证 MAC。声称本身不构成认证——MAC 验证失败即拒绝。
type ClientHello struct {
	UID UID      // 隧道用户 ID
	Eph [32]byte // 客户端临时 X25519 公钥
	TS  uint64   // 发起时间（unix 秒）
	MAC [32]byte
}

// NewClientHello 生成客户端握手包，返回客户端临时私钥（用于派生会话密钥）。
func NewClientHello(secret []byte, uid UID) (*ClientHello, *[32]byte, error) {
	h := &ClientHello{UID: uid, TS: uint64(time.Now().Unix())}
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
		[]byte{Version}, h.UID[:], h.Eph[:], u64be(h.TS))
}

// Marshal 序列化为 UDP 载荷：[0x01]ver||uid||eph||ts||mac。
func (h *ClientHello) Marshal() []byte {
	out := make([]byte, 0, helloLen)
	out = append(out, TypeHello, Version)
	out = append(out, h.UID[:]...)
	out = append(out, h.Eph[:]...)
	out = append(out, u64be(h.TS)...)
	out = append(out, h.MAC[:]...)
	return out
}

// PeekHello 只做长度与版本检查并取出声称的用户 ID，不做任何认证。
// 服务端用它决定去查哪个用户的密钥，随后必须调用 ParseClientHello 验证。
func PeekHello(b []byte) (UID, error) {
	var uid UID
	if len(b) < 1 || b[0] != TypeHello {
		return uid, ErrBadPacket
	}
	// 长度先行：v1 Hello 的第 2 字节是临时公钥的一部分（随机值），
	// 直接读版本字节会把旧包误判成任意版本。
	if len(b) == helloLenV1 {
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

// ServerAccept 服务端握手应答（明文传输，per-user secret HMAC 认证）。
//
// TunIP/Prefix/Gateway 是服务端为该用户分配的隧道内地址，全部纳入 MAC——
// 否则中间人可以把客户端的隧道地址改成别人的，绕过服务端的隔离检查。
type ServerAccept struct {
	Eph     [32]byte // 服务端临时 X25519 公钥
	TunIP   [4]byte  // 分配给客户端的隧道内地址
	Prefix  uint8    // 隧道网段前缀长度
	Gateway [4]byte  // 隧道内网关（服务端的隧道地址）
	MAC     [32]byte
}

// NewServerAccept 生成服务端应答包，返回服务端临时私钥。
func NewServerAccept(secret []byte, clientEph [32]byte, tunIP, gateway netip.Addr, prefix int) (*ServerAccept, *[32]byte, error) {
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
	a := &ServerAccept{Eph: *pub, TunIP: tunIP.As4(), Prefix: uint8(prefix), Gateway: gateway.As4()}
	a.MAC = a.mac(secret, clientEph)
	return a, priv, nil
}

func (a *ServerAccept) mac(secret []byte, clientEph [32]byte) [32]byte {
	return macPSK(secret, acceptDomain,
		[]byte{Version}, a.Eph[:], clientEph[:], a.TunIP[:], []byte{a.Prefix}, a.Gateway[:])
}

// TunAddr 返回分配到的隧道内地址。
func (a *ServerAccept) TunAddr() netip.Addr { return netip.AddrFrom4(a.TunIP) }

// GatewayAddr 返回隧道内网关地址。
func (a *ServerAccept) GatewayAddr() netip.Addr { return netip.AddrFrom4(a.Gateway) }

// ECDHShared 计算 X25519 共享密钥（box.Precompute 语义）。
func ECDHShared(peerPub, myPriv *[32]byte) *[32]byte {
	shared := new([32]byte)
	box.Precompute(shared, peerPub, myPriv)
	return shared
}

// Marshal 序列化为 UDP 载荷：[0x02]ver||eph||tunIP||prefix||gw||mac。
func (a *ServerAccept) Marshal() []byte {
	out := make([]byte, 0, acceptLen)
	out = append(out, TypeAccept, Version)
	out = append(out, a.Eph[:]...)
	out = append(out, a.TunIP[:]...)
	out = append(out, a.Prefix)
	out = append(out, a.Gateway[:]...)
	out = append(out, a.MAC[:]...)
	return out
}

// ParseServerAccept 解析并校验服务端应答包。
func ParseServerAccept(secret, b []byte, clientEph [32]byte) (*ServerAccept, error) {
	if len(b) < 1 || b[0] != TypeAccept {
		return nil, ErrBadPacket
	}
	if len(b) < acceptLen {
		return nil, ErrBadPacket
	}
	if b[1] != Version {
		return nil, ErrOldVersion
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

func u64be(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}
