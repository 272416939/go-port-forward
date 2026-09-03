// Package tunnel 实现迷你加密隧道协议（UDP）。
//
// 包格式：[1 字节类型][payload]
//   - Hello (0x01, 明文): ver(1) || uid(16) || device(32) || clientEphPub(32)
//     || ts(8 BE) || HMAC(secret,"pfapp-hello-v4"||ver||uid||device||eph||ts)
//   - Accept(0x02, 明文): ver(1) || serverEphPub(32) || tunIP(4) || prefix(1)
//     || gwIP(4) || mtu(2 BE) || flags(1)
//     || HMAC(secret,"pfapp-accept-v4"||ver||sEph||cEph||tunIP||prefix||gw||mtu||flags)
//   - Reject(0x07, 明文): ver(1) || reason(1) || HMAC(secret,"pfapp-reject-v4"||ver||reason||cEph)
//   - 其余全部是 AEAD 密文，统一形态：
//     [type(1)][counter(8 BE)][ciphertext][tag(16)]
//     Data (0x03): 完整 IP 包
//     Ctrl (0x04): JSON 控制消息（回程路由同步 / 会话结束事件）
//     Ping/Pong (0x05/0x06): 心跳，载荷用于路径 MTU 探测
//     FEC  (0x08): 一组 Data 密文盒的 XOR 校验包（见 fec.go）
//
// v4 相对 v3 的密码学变化（三条都是必须的）：
//
//  1. **方向密钥拆分**。v3 用 SHA256(共享||psk) 给两个方向派生同一把 key，而
//     两端的发送计数器都从 1 开始——客户端第 N 包与服务端第 N 包使用完全相同
//     的 (key, nonce)。secretbox 底层是 XSalsa20 流密码，nonce 重用即密钥流
//     重用（C1⊕C2 = P1⊕P2），且 Poly1305 的一次性密钥取自密钥流首块，已知
//     明文即可恢复认证密钥进而伪造任一方向的包。v4 用 HKDF-SHA256 派生
//     c2s/s2c 两把密钥，info 里绑定双方临时公钥（transcript binding）。
//  2. **AEAD 换 ChaCha20-Poly1305**（RFC 8439）。纯软件实现恒定快（客户端是
//     用户的各种 Windows 机器，不能假设有 AES-NI），nonce 从 24 字节降到
//     12 字节，每包线上开销 41 → 25 字节。
//  3. **类型字节进 AAD**。v3 的 1 字节 type 在加密盒之外、未受认证，一个合法
//     Data 盒重标成 Ctrl 后仍能通过解密。v4 把 type 作为 AAD 传入 AEAD，
//     类型混淆彻底关闭。
//
// v3 相对 v2 的变化（保留记录）：uid 的语义从「用户 ID」变为「访问码 ID」
// （一个用户可以有多个访问码，各自独立的密钥与隧道地址）；Hello 携带设备指纹
// 用于绑定客户端；新增 Reject 让拒绝原因可被客户端看到，而不是退化成
// 「服务端无应答」。
package tunnel

import (
	"errors"
)

// 包类型常量。
const (
	TypeHello  = 0x01
	TypeAccept = 0x02
	TypeData   = 0x03
	TypeCtrl   = 0x04
	TypePing   = 0x05
	TypePong   = 0x06
	TypeReject = 0x07
	// TypeFEC 是前向纠错校验包（见 fec.go）。它是**内容类型**而不是协议版本
	// 变化：不认识它的对端按 switch default 丢弃即可，无需 bump 版本。
	TypeFEC = 0x08
)

// 协议常量。
const (
	KeySize = 32
	// NonceSize 是 AEAD nonce 长度。ChaCha20-Poly1305 固定 12 字节，构造为
	// 4 字节零 || 8 字节大端计数（TLS 式）：只有计数上线，前 4 字节恒零。
	NonceSize = 12
	// CounterSize 是线上传输的发送计数长度。
	CounterSize = 8
	// TagSize 是 Poly1305 认证标签长度。
	TagSize = 16
	// SealOverhead 是一个密文包相对明文的线上增量：type + counter + tag。
	SealOverhead = 1 + CounterSize + TagSize // 25
	// MaxPacket 是单个加密包上限。隧道 MTU 最大 1400，封装后 1425；留到 2000
	// 是给 FEC 包（组头 + 最长成员盒）与将来的扩展字段用。
	MaxPacket = 2000

	// MaxTunMTU 是隧道 TUN 的 MTU 上限，也是握手协商不到 mtu 字段时的缺省值。
	// 1400 + 25(封装) + 28(IP+UDP) = 1453 < 1500，不分片。
	MaxTunMTU = 1400
	// MinTunMTU 是协商与探测允许的下限。低于这个值游戏流量会被大量分片，
	// 与其偷偷降到不可用，不如拒绝并沿用缺省值。
	MinTunMTU = 1000
	// WireOverhead 是一个隧道包在物理链路上相对 TUN 明文的总增量：
	// IPv4 头 20 + UDP 头 8 + 封装 25。用于从链路 MTU 反算隧道 MTU。
	WireOverhead = 20 + 8 + SealOverhead // 53

	// UIDSize 是握手包携带的访问码 ID 长度（uuid 的 16 字节二进制形式）。
	UIDSize = 16
	// FingerprintSize 是设备指纹长度（machineid 的 HMAC-SHA256 派生值）。
	FingerprintSize = 32

	// Version 是当前握手协议版本。显式版本字节的用途不是协商——本项目
	// 硬切换、不保留旧通道——而是让「客户端过旧」能被识别成一条可读的
	// 升级提示，而不是一个查不出原因的认证失败。
	Version = 0x04
)

// 会话特性开关。服务端在 Accept 的 flags 字节里下发，两端据此对称启用——
// 客户端不自行决定：一端发 FEC 另一端不认，那些包会被当未知类型静默丢弃，
// 表现为「开了 FEC 反而更卡」。
const (
	// FeatFEC 启用前向纠错（每 8 个 Data 包附 1 个 XOR 校验包，冗余 12.5%）。
	FeatFEC = 1 << 0
	// FeatTailDup 启用小包冗余副本（组尾小包发两份，接收端靠重放窗口去重）。
	FeatTailDup = 1 << 1
)

// 错误定义。
var (
	ErrAuth      = errors.New("tunnel: authentication failed")
	ErrBadPacket = errors.New("tunnel: malformed packet")
	ErrReplay    = errors.New("tunnel: replayed or stale packet")
	// ErrOldVersion 表示对端使用旧版握手（v1 无身份字段 / v2 无设备指纹 /
	// v3 两个方向共用一把密钥）。单独一个错误而不是复用 ErrAuth：这样服务端
	// 能打出「请升级客户端」而不是让运维去查密钥。
	ErrOldVersion = errors.New("tunnel: peer speaks an outdated protocol version")
	// ErrShortBuffer 表示调用方提供的缓冲装不下结果。零分配收发路径要求调用
	// 方备好缓冲，装不下必须报错而不是偷偷分配——偷偷分配会让「0 allocs」的
	// 基准在真实负载下失效。
	ErrShortBuffer = errors.New("tunnel: destination buffer too small")
)

// RejectReason 是服务端拒绝握手的原因。
//
// 数值一旦发布就不能改动含义：客户端按数值翻译提示文案，改了会让旧客户端
// 显示出完全无关的错误。
type RejectReason uint8

const (
	RejectUnknown        RejectReason = 0
	RejectDeviceMismatch RejectReason = 1 // 访问码已绑定到另一台设备
	RejectCodeDisabled   RejectReason = 2 // 访问码已停用
	RejectUserDisabled   RejectReason = 3 // 账号已停用
	RejectTunnelLimit    RejectReason = 4 // 并发隧道数已达上限
	RejectAddrInvalid    RejectReason = 5 // 访问码的隧道地址无效（需管理员处理）
)

// String 返回原因的可读描述（服务端日志用；客户端有自己的中文文案）。
func (r RejectReason) String() string {
	switch r {
	case RejectDeviceMismatch:
		return "device_mismatch"
	case RejectCodeDisabled:
		return "code_disabled"
	case RejectUserDisabled:
		return "user_disabled"
	case RejectTunnelLimit:
		return "tunnel_limit"
	case RejectAddrInvalid:
		return "addr_invalid"
	default:
		return "unknown"
	}
}

// Terminal 报告该原因是否需要人工介入。
//
// 客户端据此决定是否继续自动重连：终态原因下重试只会刷日志，并把真正的原因
// 埋在一堆「握手失败」里。
func (r RejectReason) Terminal() bool {
	switch r {
	case RejectDeviceMismatch, RejectCodeDisabled, RejectUserDisabled, RejectAddrInvalid:
		return true
	default:
		// tunnel_limit 是暂时的（对端可能马上下线），继续重试。
		return false
	}
}

// 控制消息类型。
const (
	// CtrlKindRoutes 是回程路由 IP 全量同步（历史上唯一的控制消息，
	// 旧客户端不带 kind 字段，零值按此处理）。
	CtrlKindRoutes = "routes"
	// CtrlKindEnded 告知客户端这些来源 IP 已无活跃会话，可以尽快回收它们的
	// /32 回程路由。
	//
	// 为什么需要一个「结束」消息：routes 是活跃列表，它的「缺席」不能当作删除
	// 依据（推送周期 10s，短交互的 IP 在列表里一闪而过，按缺席删除会把正在
	// 进行的会话反复掐断）。但 /32 主机路由会吸走该 IP 的全部回包，残留太久
	// 会让玩家不经代理直连源站时也收不到回包。所以由服务端在 UDP 会话真正
	// 超时回收时发一条明确的结束事件——事件可信，缺席不可信。
	CtrlKindEnded = "ended"
)

// CtrlMessage 是加密控制通道上的 JSON 消息。
//
// Kind 为空等价于 CtrlKindRoutes：控制通道原本只有一种消息，加 Kind 是为了
// 后续消息不必再改结构。
type CtrlMessage struct {
	Kind string   `json:"kind,omitempty"`
	IPs  []string `json:"ips,omitempty"` // 目的 IP 列表（按 Kind 解释）
}

// ClampTunMTU 把任意 MTU 值收进 [MinTunMTU, MaxTunMTU]。0 与越界值一律回落到
// MaxTunMTU：宁可按缺省值工作（对端也是这个缺省），也不要按一个算错的小值
// 长期跑——那是静默的吞吐损失。
func ClampTunMTU(mtu int) int {
	if mtu < MinTunMTU || mtu > MaxTunMTU {
		return MaxTunMTU
	}
	return mtu
}
