package tunnel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// 握手域分隔标签，避免不同方向的 MAC 互挪。
var (
	helloDomain  = []byte("pfapp-hello-v1")
	acceptDomain = []byte("pfapp-accept-v1")
)

// 握手时间戳容忍窗口（防重放 + 容忍时钟偏差）。
const helloMaxAge = 10 * time.Minute

// macPSK 计算 HMAC-SHA256(psk, domain || parts...)。
func macPSK(psk []byte, domain []byte, parts ...[]byte) [32]byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write(domain)
	for _, p := range parts {
		mac.Write(p)
	}
	return [32]byte(mac.Sum(nil))
}

// ClientHello 客户端握手包（明文传输，PSK-HMAC 认证）。
type ClientHello struct {
	Eph [32]byte // 客户端临时 X25519 公钥
	TS  uint64   // 发起时间（unix 秒）
	MAC [32]byte
}

// NewClientHello 生成客户端握手包，返回客户端临时私钥（用于派生会话密钥）。
func NewClientHello(psk []byte) (*ClientHello, *[32]byte, error) {
	h := &ClientHello{TS: uint64(time.Now().Unix())}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	h.Eph = *pub
	h.MAC = macPSK(psk, helloDomain, h.Eph[:], u64be(h.TS))
	return h, priv, nil
}

// Marshal 序列化为 UDP 载荷：[0x01]eph||ts||mac。
func (h *ClientHello) Marshal() []byte {
	out := make([]byte, 0, 1+32+8+32)
	out = append(out, TypeHello)
	out = append(out, h.Eph[:]...)
	out = append(out, u64be(h.TS)...)
	out = append(out, h.MAC[:]...)
	return out
}

// ParseClientHello 解析并校验客户端握手包。
func ParseClientHello(psk, b []byte) (*ClientHello, error) {
	if len(b) < 1+32+8+32 || b[0] != TypeHello {
		return nil, ErrBadPacket
	}
	h := &ClientHello{}
	copy(h.Eph[:], b[1:33])
	h.TS = binary.BigEndian.Uint64(b[33:41])
	copy(h.MAC[:], b[41:73])

	age := time.Since(time.Unix(int64(h.TS), 0))
	if age < -helloMaxAge || age > helloMaxAge {
		return nil, ErrAuth
	}
	want := macPSK(psk, helloDomain, h.Eph[:], u64be(h.TS))
	if !hmac.Equal(want[:], h.MAC[:]) {
		return nil, ErrAuth
	}
	return h, nil
}

// ServerAccept 服务端握手应答（明文传输，PSK-HMAC 认证）。
type ServerAccept struct {
	Eph [32]byte // 服务端临时 X25519 公钥
	MAC [32]byte // HMAC(psk, "accept" || serverEph || clientEph)
}

// NewServerAccept 生成服务端应答包，返回服务端临时私钥。
func NewServerAccept(psk []byte, clientEph [32]byte) (*ServerAccept, *[32]byte, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	a := &ServerAccept{Eph: *pub}
	a.MAC = macPSK(psk, acceptDomain, a.Eph[:], clientEph[:])
	return a, priv, nil
}

// ECDHShared 计算 X25519 共享密钥（box.Precompute 语义）。
func ECDHShared(peerPub, myPriv *[32]byte) *[32]byte {
	shared := new([32]byte)
	box.Precompute(shared, peerPub, myPriv)
	return shared
}

// Marshal 序列化为 UDP 载荷：[0x02]eph||mac。
func (a *ServerAccept) Marshal() []byte {
	out := make([]byte, 0, 1+32+32)
	out = append(out, TypeAccept)
	out = append(out, a.Eph[:]...)
	out = append(out, a.MAC[:]...)
	return out
}

// ParseServerAccept 解析并校验服务端应答包。
func ParseServerAccept(psk, b []byte, clientEph [32]byte) (*ServerAccept, error) {
	if len(b) < 1+32+32 || b[0] != TypeAccept {
		return nil, ErrBadPacket
	}
	a := &ServerAccept{}
	copy(a.Eph[:], b[1:33])
	copy(a.MAC[:], b[33:65])
	want := macPSK(psk, acceptDomain, a.Eph[:], clientEph[:])
	if !hmac.Equal(want[:], a.MAC[:]) {
		return nil, ErrAuth
	}
	return a, nil
}

func u64be(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}
