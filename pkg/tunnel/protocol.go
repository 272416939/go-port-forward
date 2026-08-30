// Package tunnel 实现迷你加密隧道协议（UDP）。
//
// 包格式：[1 字节类型][payload]
//   - Hello (0x01, 明文): ver(1) || uid(16) || device(32) || clientEphPub(32)
//     || ts(8 BE) || HMAC(secret,"hello-v3"||ver||uid||device||eph||ts)
//   - Accept(0x02, 明文): ver(1) || serverEphPub(32) || tunIP(4) || prefix(1)
//     || gwIP(4) || HMAC(secret,"accept-v3"||ver||sEph||cEph||tunIP||prefix||gwIP)
//   - Data  (0x03, 密文): box(完整 IP 包)
//   - Ctrl  (0x04, 密文): box(JSON 控制消息，如回程路由 IP 同步)
//   - Ping/Pong (0x05/0x06, 密文): 心跳
//   - Reject(0x07, 明文): ver(1) || reason(1) || HMAC(secret,"reject-v3"||ver||reason||cEph)
//
// 会话密钥 = SHA256(X25519 共享 || secret)；每方向独立单调 nonce 计数器，
// 接收端滑动窗口防重放。
//
// v3 相对 v2 的变化：uid 的语义从「用户 ID」变为「访问码 ID」（一个用户可以有
// 多个访问码，各自独立的密钥与隧道地址）；Hello 携带设备指纹用于绑定客户端；
// 新增 Reject 让拒绝原因可被客户端看到，而不是退化成「服务端无应答」。
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
)

// 协议常量。
const (
	KeySize   = 32
	NonceSize = 24
	MaxPacket = 2000 // 单个加密包上限（tun MTU 1400 + 封装余量）

	// UIDSize 是握手包携带的访问码 ID 长度（uuid 的 16 字节二进制形式）。
	UIDSize = 16
	// FingerprintSize 是设备指纹长度（machineid 的 HMAC-SHA256 派生值）。
	FingerprintSize = 32

	// Version 是当前握手协议版本。显式版本字节的用途不是协商——本项目
	// 硬切换、不保留旧通道——而是让「客户端过旧」能被识别成一条可读的
	// 升级提示，而不是一个查不出原因的认证失败。
	Version = 0x03
)

// 错误定义。
var (
	ErrAuth      = errors.New("tunnel: authentication failed")
	ErrBadPacket = errors.New("tunnel: malformed packet")
	ErrReplay    = errors.New("tunnel: replayed or stale packet")
	// ErrOldVersion 表示对端使用旧版握手（v1 无身份字段 / v2 无设备指纹）。
	// 单独一个错误而不是复用 ErrAuth：这样服务端能打出「请升级客户端」而不是
	// 让运维去查密钥。
	ErrOldVersion = errors.New("tunnel: peer speaks an outdated protocol version")
)

// RejectReason 是服务端拒绝握手的原因。
//
// 数值一旦发布就不能改动含义：客户端按数值翻译提示文案，改了会让旧客户端
// 显示出完全无关的错误。
type RejectReason uint8

const (
	RejectUnknown       RejectReason = 0
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
