package tunnel

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// 接收重放窗口大小（可容忍的最大乱序包数）。
const recvWindow = 8192

// KDF 标签。方向分离靠它，两端必须同时改——改一端等于整条隧道解不开。
var (
	kdfLabelC2S = []byte("pf-tunnel-v4 c2s")
	kdfLabelS2C = []byte("pf-tunnel-v4 s2c")
)

// Session 是握手完成后的加密会话。
//
// 收发各用一把密钥（方向分离，理由见 protocol.go 的 v4 说明）；发送计数原子
// 递增，接收端用环形位图滑动窗口防重放。
//
// 并发约定：Seal* 可并发调用（服务端有数据泵、心跳、路由推送三个发送者）；
// Open* / HandleFEC / Recover **只允许在接收泵的单 goroutine 里调用**——它们
// 共用 ctrlBuf 暂存与 FEC 接收状态，没有额外加锁。
type Session struct {
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD
	sendCtr  atomic.Uint64
	feats    uint32 // 构造后只读

	recvMu   sync.Mutex
	recvMax  uint64               // 已接受的最高包计数
	recvBase uint64               // 窗口下界（= recvMax-recvWindow+1，最小 1）
	recvBits [recvWindow / 8]byte // 环形位图：计数 c 的位下标 = c % recvWindow

	stats Stats
	mtu   atomic.Int64 // 协商后的隧道 MTU（FEC 成员上限依赖它）

	// ctrlBuf 是 Ctrl/Ping/Pong 的解密暂存。仅接收泵单 goroutine 使用，
	// 因此不加锁；Data 走调用方缓冲（零分配路径），不碰这里。
	ctrlBuf []byte

	fec *fecState // nil = 该会话未启用 FEC

	dupMu     sync.Mutex
	lastDupAt time.Time
}

// DeriveSessionKeys 从 X25519 共享密钥与 PSK 派生两把方向密钥。
//
// shared 来自 box.Precompute(对端公钥, 己方私钥)；clientEph/serverEph 是本次
// 握手双方的临时公钥，它们进 HKDF 的 info 做 transcript binding：即使某天
// 握手 MAC 被绕过，改了公钥的中间人也派生不出同一把会话密钥。成本为零。
//
// 返回 (c2s, s2c)：客户端发送用 c2s、接收用 s2c，服务端反接。
func DeriveSessionKeys(shared *[32]byte, psk []byte, clientEph, serverEph [32]byte) (c2s, s2c *[32]byte, err error) {
	ikm := make([]byte, 0, 32+len(psk))
	ikm = append(ikm, shared[:]...)
	ikm = append(ikm, psk...)
	prk, err := hkdf.Extract(sha256.New, ikm, nil)
	if err != nil {
		return nil, nil, err
	}
	info := make([]byte, 0, len(kdfLabelC2S)+64)
	derive := func(label []byte) (*[32]byte, error) {
		info = info[:0]
		info = append(info, label...)
		info = append(info, clientEph[:]...)
		info = append(info, serverEph[:]...)
		out, kerr := hkdf.Expand(sha256.New, prk, string(info), KeySize)
		if kerr != nil {
			return nil, kerr
		}
		var k [32]byte
		copy(k[:], out)
		return &k, nil
	}
	if c2s, err = derive(kdfLabelC2S); err != nil {
		return nil, nil, err
	}
	if s2c, err = derive(kdfLabelS2C); err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

// NewClientSession 建立客户端侧会话（发 c2s、收 s2c）。
func NewClientSession(c2s, s2c *[32]byte, feats uint32, mtu int) (*Session, error) {
	return newSession(c2s, s2c, feats, mtu)
}

// NewServerSession 建立服务端侧会话（发 s2c、收 c2s）。
func NewServerSession(c2s, s2c *[32]byte, feats uint32, mtu int) (*Session, error) {
	return newSession(s2c, c2s, feats, mtu)
}

func newSession(sendKey, recvKey *[32]byte, feats uint32, mtu int) (*Session, error) {
	// AEAD 在会话建立时各构造一次并缓存。绝不每包 New——内部要做密钥展开与
	// 一次堆分配，那正是热路径上最不该有的东西。
	sendAEAD, err := chacha20poly1305.New(sendKey[:])
	if err != nil {
		return nil, err
	}
	recvAEAD, err := chacha20poly1305.New(recvKey[:])
	if err != nil {
		return nil, err
	}
	s := &Session{
		sendAEAD: sendAEAD,
		recvAEAD: recvAEAD,
		feats:    feats,
		recvBase: 1,
		ctrlBuf:  make([]byte, MaxPacket),
	}
	s.mtu.Store(int64(ClampTunMTU(mtu)))
	if feats&FeatFEC != 0 {
		s.fec = newFECState()
	}
	return s, nil
}

// Features 返回本会话协商启用的特性位。
func (s *Session) Features() uint32 { return s.feats }

// MTU 返回协商后的隧道 MTU。
func (s *Session) MTU() int { return int(s.mtu.Load()) }

// SetMTU 更新隧道 MTU（路径探测下调时调用）。
func (s *Session) SetMTU(mtu int) { s.mtu.Store(int64(ClampTunMTU(mtu))) }

// SealSize 返回封装 n 字节明文所需的缓冲容量。
func SealSize(n int) int { return n + SealOverhead }

// nextCounter 消耗一个发送计数。计数从 1 开始（0 只可能是伪造）。
func (s *Session) nextCounter() uint64 { return s.sendCtr.Add(1) }

// grow 保证 dst 至少有 need 字节容量（长度不变）。
func grow(dst []byte, need int) []byte {
	if cap(dst) >= need {
		return dst
	}
	out := make([]byte, len(dst), need)
	copy(out, dst)
	return out
}

// SealInto 把 [type][counter][密文][tag] 追加进 dst 并返回结果切片。
//
// 调用方应传入 buf[:0]（buf 容量 ≥ SealSize(len(plain))+NonceSize），这样整条
// 发送路径零分配。容量不足时会分配一次新缓冲——正确性优先，但那条路径不该在
// 热路径上出现。
func (s *Session) SealInto(dst []byte, typ byte, plain []byte) []byte {
	return s.sealCounter(dst, typ, s.nextCounter(), plain)
}

// sealCounter 用指定计数封装（FEC 与副本重发需要复用同一个计数）。
func (s *Session) sealCounter(dst []byte, typ byte, counter uint64, plain []byte) []byte {
	base := len(dst)
	// 末尾额外留 NonceSize：nonce 借用缓冲的「长度之外、容量之内」区域组装。
	// 用栈上数组会因为传给 cipher.AEAD 接口方法而逃逸，那就是每包一次分配。
	need := base + SealOverhead + len(plain) + NonceSize
	dst = grow(dst, need)

	nonce := dst[need-NonceSize : need]
	clear(nonce)
	binary.BigEndian.PutUint64(nonce[NonceSize-CounterSize:], counter)

	out := append(dst, typ)
	out = binary.BigEndian.AppendUint64(out, counter)
	// AAD = 类型字节。v3 的类型字节在盒外未受认证，一个合法 Data 盒重标成
	// Ctrl 仍能解开；进 AAD 后类型混淆彻底关闭。取输出缓冲里的那一字节而不是
	// 新建切片，同样是为了不分配。
	aad := out[base : base+1]
	out = s.sendAEAD.Seal(out, nonce, plain, aad)
	s.stats.txPackets.Add(1)
	return out
}

// OpenInto 解密一个密文包，明文写入 dst（dst 需为 buf[:0] 形态且容量足够）。
// 返回明文切片与包类型。
func (s *Session) OpenInto(dst, p []byte) (plain []byte, typ byte, err error) {
	if len(p) < SealOverhead {
		s.stats.rxBad.Add(1)
		return nil, 0, ErrBadPacket
	}
	typ = p[0]
	counter := binary.BigEndian.Uint64(p[1 : 1+CounterSize])
	body := p[1+CounterSize:]

	base := len(dst)
	need := base + len(body) - TagSize + NonceSize
	if cap(dst) < need {
		return nil, typ, ErrShortBuffer
	}
	nonce := dst[need-NonceSize : need]
	clear(nonce)
	binary.BigEndian.PutUint64(nonce[NonceSize-CounterSize:], counter)

	out, oerr := s.recvAEAD.Open(dst, nonce, body, p[0:1])
	if oerr != nil {
		s.stats.rxAuthFail.Add(1)
		return nil, typ, ErrAuth
	}
	// 重放检查必须在认证之后：计数经 nonce 参与认证，被篡改的计数根本解不开。
	if !s.acceptCounter(counter) {
		return nil, typ, ErrReplay
	}
	if s.fec != nil && typ == TypeData {
		s.fec.cacheBox(counter, body, &s.stats)
	}
	return out[base:], typ, nil
}

// SealData 封装 Data 包（[0x03] + 加密的完整 IP 包）。
func (s *Session) SealData(dst, ipPacket []byte) []byte {
	return s.SealInto(dst, TypeData, ipPacket)
}

// OpenData 打开 Data 包，明文写入 dst。
func (s *Session) OpenData(dst, p []byte) ([]byte, error) {
	if len(p) < 1 || p[0] != TypeData {
		s.stats.rxBad.Add(1)
		return nil, ErrBadPacket
	}
	plain, _, err := s.OpenInto(dst, p)
	return plain, err
}

// SealCtrl 封装控制消息（[0x04] + 加密的 JSON）。
func (s *Session) SealCtrl(dst []byte, msg CtrlMessage) ([]byte, error) {
	plain, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	return s.SealInto(dst, TypeCtrl, plain), nil
}

// OpenCtrl 打开控制消息。明文解进会话内部暂存，仅在接收泵单 goroutine 调用。
func (s *Session) OpenCtrl(p []byte) (CtrlMessage, error) {
	var msg CtrlMessage
	if len(p) < 1 || p[0] != TypeCtrl {
		s.stats.rxBad.Add(1)
		return msg, ErrBadPacket
	}
	plain, _, err := s.OpenInto(s.ctrlBuf[:0], p)
	if err != nil {
		return msg, err
	}
	if jerr := json.Unmarshal(plain, &msg); jerr != nil {
		return msg, ErrBadPacket
	}
	return msg, nil
}

// SealPing 封装心跳包。明文 = [probeID(1)][padLen 字节零填充]。
//
// 填充用于被动探测路径 MTU：对端 Pong 回显它实际收到的明文长度，探测方据此
// 判断某个尺寸的隧道包能否穿过链路（分片丢失是整包全损，不探测就只能靠固定
// MTU 猜）。普通心跳传 padLen = 0。
func (s *Session) SealPing(dst []byte, probeID byte, padLen int) []byte {
	if padLen < 0 {
		padLen = 0
	}
	plain := s.stageProbe(&dst, 1+padLen)
	plain[0] = probeID
	return s.sealCounter(dst, TypePing, s.nextCounter(), plain)
}

// SealPong 封装心跳应答。明文 = [probeID(1)][observedLen(2 BE)]。
func (s *Session) SealPong(dst []byte, probeID byte, observedLen int) []byte {
	plain := s.stageProbe(&dst, 3)
	if observedLen < 0 {
		observedLen = 0
	}
	if observedLen > 0xFFFF {
		observedLen = 0xFFFF
	}
	plain[0] = probeID
	binary.BigEndian.PutUint16(plain[1:], uint16(observedLen))
	return s.sealCounter(dst, TypePong, s.nextCounter(), plain)
}

// stageProbe 在 dst 容量的尾部划出一块清零的明文区（不改变 dst 的长度）。
//
// 为什么不用会话内的暂存：Seal* 允许并发调用（服务端有数据泵、心跳、路由推送
// 三个发送者），而 ctrlBuf 是接收泵的解密暂存——心跳借它组装明文就会与接收泵
// 同时写同一块内存，症状是探测长度或控制消息偶发损坏，且两者都静默。
// 调用方缓冲是每个发送者各自持有的，借它的尾部天然无竞争。
//
// 尾部布局（沿用 sealCounter 的 nonce 借位手法）：
//
//	[base .. 密文输出 ..][nonce][明文]
//
// 三段互不重叠，Seal 写密文时不会踩到还没读完的明文。
func (s *Session) stageProbe(dst *[]byte, n int) []byte {
	base := len(*dst)
	need := base + SealOverhead + n + NonceSize + n
	*dst = grow(*dst, need)
	plain := (*dst)[need-n : need]
	clear(plain)
	return plain
}

// OpenPing 打开心跳包，返回 probeID 与明文长度。
func (s *Session) OpenPing(p []byte) (probeID byte, plainLen int, err error) {
	if len(p) < 1 || p[0] != TypePing {
		s.stats.rxBad.Add(1)
		return 0, 0, ErrBadPacket
	}
	plain, _, err := s.OpenInto(s.ctrlBuf[:0], p)
	if err != nil {
		return 0, 0, err
	}
	if len(plain) < 1 {
		return 0, 0, ErrBadPacket
	}
	return plain[0], len(plain), nil
}

// OpenPong 打开心跳应答。
func (s *Session) OpenPong(p []byte) (probeID byte, observedLen int, err error) {
	if len(p) < 1 || p[0] != TypePong {
		s.stats.rxBad.Add(1)
		return 0, 0, ErrBadPacket
	}
	plain, _, err := s.OpenInto(s.ctrlBuf[:0], p)
	if err != nil {
		return 0, 0, err
	}
	if len(plain) < 3 {
		return 0, 0, ErrBadPacket
	}
	return plain[0], int(binary.BigEndian.Uint16(plain[1:3])), nil
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
		s.stats.rxReplayed.Add(1)
		return false // 发送端计数从 1 开始，0 只能是伪造
	}
	s.recvMu.Lock()
	reordered := c <= s.recvMax
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
		s.recvMu.Unlock()
		s.stats.rxReplayed.Add(1)
		return false // 窗口下界之前，一律拒绝
	}
	off := c % recvWindow
	if s.recvBits[off/8]&(1<<(off%8)) != 0 {
		s.recvMu.Unlock()
		s.stats.rxReplayed.Add(1)
		return false // 重放
	}
	s.recvBits[off/8] |= 1 << (off % 8)
	high := s.recvMax
	s.recvMu.Unlock()

	s.stats.rxHigh.Store(high)
	s.stats.rxAccepted.Add(1)
	if reordered {
		s.stats.rxReordered.Add(1)
	}
	s.stats.observeArrival(time.Now().UnixNano())
	return true
}
