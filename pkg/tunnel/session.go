package tunnel

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"sync"

	"golang.org/x/crypto/nacl/secretbox"
)

// Session 是握手完成后的加密会话：发送 nonce 单调递增，接收端滑动窗口防重放。
// Seal/SealCtrl 可并发调用（内部锁保护计数器）；Open 建议仅在接收泵调用。
type Session struct {
	mu        sync.Mutex
	key       *[32]byte
	sendNonce uint64

	recvMu   sync.Mutex
	recvMax  uint64               // 已接受的最高包计数
	recvBase uint64               // 窗口下界（= recvMax-recvWindow+1，最小 1）
	recvBits [recvWindow / 8]byte // 环形位图：计数 c 的位下标 = c % recvWindow
}

// 接收重放窗口大小（可容忍的最大乱序包数）。
const recvWindow = 8192

// DeriveSessionKey 从 X25519 共享密钥与 PSK 派生会话密钥。
// shared 来自 box.Precompute(对端公钥, 己方私钥)。
func DeriveSessionKey(shared *[32]byte, psk []byte) *[32]byte {
	out := sha256.Sum256(append(shared[:], psk...))
	return &out
}

// NewSession 基于派生密钥建立会话。
func NewSession(key *[32]byte) *Session {
	return &Session{
		key:      key,
		recvBase: 1,
	}
}

// nextNonce 消耗一个发送计数并返回 24 字节 nonce（8 字节计数 + 16 字节零）。
func (s *Session) nextNonce() [NonceSize]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendNonce++
	var n [NonceSize]byte
	binary.BigEndian.PutUint64(n[:8], s.sendNonce)
	return n
}

// Seal 加密任意载荷：返回 24 字节 nonce 前缀 + secretbox 密文。
func (s *Session) Seal(plain []byte) []byte {
	nonce := s.nextNonce()
	return secretbox.Seal(nonce[:], plain, &nonce, s.key)
}

// Open 解密封包并做重放检查。返回明文。
func (s *Session) Open(p []byte) ([]byte, error) {
	if len(p) < NonceSize+secretbox.Overhead {
		return nil, ErrBadPacket
	}
	var nonce [NonceSize]byte
	copy(nonce[:], p[:NonceSize])
	counter := binary.BigEndian.Uint64(nonce[:8])

	plain, ok := secretbox.Open(nil, p[NonceSize:], &nonce, s.key)
	if !ok {
		return nil, ErrAuth
	}
	if !s.acceptCounter(counter) {
		return nil, ErrReplay
	}
	return plain, nil
}

// SealData 封装 Data 包：[0x03]box(ipPacket)。
func (s *Session) SealData(ipPacket []byte) []byte {
	out := make([]byte, 0, 1+len(ipPacket)+NonceSize+secretbox.Overhead)
	out = append(out, TypeData)
	out = append(out, s.Seal(ipPacket)...)
	return out
}

// OpenData 打开 Data 包。
func (s *Session) OpenData(p []byte) ([]byte, error) {
	if len(p) < 1 || p[0] != TypeData {
		return nil, ErrBadPacket
	}
	return s.Open(p[1:])
}

// SealCtrl 封装控制消息：[0x04]box(json)。
func (s *Session) SealCtrl(msg CtrlMessage) ([]byte, error) {
	plain, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(plain)+NonceSize+secretbox.Overhead)
	out = append(out, TypeCtrl)
	out = append(out, s.Seal(plain)...)
	return out, nil
}

// OpenCtrl 打开控制消息。
func (s *Session) OpenCtrl(p []byte) (CtrlMessage, error) {
	var msg CtrlMessage
	if len(p) < 1 || p[0] != TypeCtrl {
		return msg, ErrBadPacket
	}
	plain, err := s.Open(p[1:])
	if err != nil {
		return msg, err
	}
	if err := json.Unmarshal(plain, &msg); err != nil {
		return msg, ErrBadPacket
	}
	return msg, nil
}

// SealPing 封装心跳。
func (s *Session) SealPing() []byte {
	out := make([]byte, 0, 1+NonceSize+secretbox.Overhead)
	out = append(out, TypePing)
	out = append(out, s.Seal(nil)...)
	return out
}

// IsPing 判断是否心跳包（内部完成解密与重放检查）。
func (s *Session) IsPing(p []byte) bool {
	if len(p) < 1 || p[0] != TypePing {
		return false
	}
	_, err := s.Open(p[1:])
	return err == nil
}

// acceptCounter 滑动窗口重放检查：接受单调递增与窗口内的未见计数。
//
// 用「计数对窗口取模」的环形位图实现 O(1) 判定：位下标 = c % recvWindow。
// 窗口宽恰好等于位图长，窗口 [recvBase, recvMax] 内的计数与位一一对应；
// 窗口前移时幸存计数的位**原地不动**（含义不漂移），只需清掉滑出区间
// [recvBase, newBase) 的位——顺序流量下每包清 1 位。语义与旧 map 实现
// 逐条等价：窗口 [max-recvWindow+1, max]、下界之下拒绝、重复拒绝、大跳变
// 接受。旧实现窗口每次前移都全表扫描（顺序流量下每包 O(8192) 次 map
// 迭代），是隧道热路径上最大的单项 CPU 开销（两端都要付）。
func (s *Session) acceptCounter(c uint64) bool {
	if c == 0 {
		return false // 发送端计数从 1 开始，0 只能是伪造
	}
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	if c > s.recvMax {
		newBase := uint64(1)
		if c > recvWindow {
			newBase = c - recvWindow + 1
		}
		if newBase > s.recvBase {
			n := newBase - s.recvBase // 待淘汰的计数个数（按下标取模可能绕回）
			if n > recvWindow {
				n = recvWindow // 跨度超过一个窗口时等价全清
			}
			start := s.recvBase % recvWindow
			for i := uint64(0); i < n; i++ {
				off := (start + i) % recvWindow
				s.recvBits[off/8] &^= 1 << (off % 8)
			}
		}
		s.recvBase = newBase
		s.recvMax = c
	}
	if c < s.recvBase {
		return false // 窗口下界之前，一律拒绝
	}
	off := c % recvWindow
	if s.recvBits[off/8]&(1<<(off%8)) != 0 {
		return false // 重放
	}
	s.recvBits[off/8] |= 1 << (off % 8)
	return true
}
