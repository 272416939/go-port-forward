// Package tunnel 实现迷你加密隧道协议（UDP）。
//
// 包格式：[1 字节类型][payload]
//   - Hello (0x01, 明文): ver(1) || uid(16) || clientEphPub(32) || ts(8 BE)
//     || HMAC(secret,"hello-v2"||ver||uid||eph||ts)
//   - Accept(0x02, 明文): ver(1) || serverEphPub(32) || tunIP(4) || prefix(1)
//     || gwIP(4) || HMAC(secret,"accept-v2"||ver||sEph||cEph||tunIP||prefix||gwIP)
//   - Data  (0x03, 密文): box(完整 IP 包)
//   - Ctrl  (0x04, 密文): box(JSON 控制消息，如回程路由 IP 同步)
//   - Ping/Pong (0x05/0x06, 密文): 心跳
//
// 会话密钥 = SHA256(X25519 共享 || secret)；每方向独立单调 nonce 计数器，
// 接收端滑动窗口防重放。
//
// v2 与 v1 的区别：Hello 携带明文用户 ID（服务端必须先知道对端是谁，才能取出
// 该用户的密钥验 MAC），认证密钥从全局 PSK 变为每用户独立 secret，隧道内地址
// 由服务端在 Accept 中下发。地址必须走 Accept 而不是握手后的 Ctrl 消息——
// 客户端要先拿到地址才能配置虚拟网卡。
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
)

// 协议常量。
const (
	KeySize   = 32
	NonceSize = 24
	MaxPacket = 2000 // 单个加密包上限（tun MTU 1400 + 封装余量）

	// UIDSize 是握手包携带的用户 ID 长度（uuid 的 16 字节二进制形式）。
	UIDSize = 16

	// Version 是当前握手协议版本。显式版本字节的用途不是协商——本项目
	// 硬切换、不保留 v1 通道——而是让「客户端过旧」能被识别成一条可读的
	// 升级提示，而不是一个查不出原因的认证失败。
	Version = 0x02
	// VersionV1 是无身份字段的旧版本（仅用于识别与报错）。
	VersionV1 = 0x01
)

// 错误定义。
var (
	ErrAuth      = errors.New("tunnel: authentication failed")
	ErrBadPacket = errors.New("tunnel: malformed packet")
	ErrReplay    = errors.New("tunnel: replayed or stale packet")
	// ErrOldVersion 表示对端使用不含身份字段的旧版握手（v1）。单独一个错误
	// 而不是复用 ErrAuth：这样服务端能打出「请升级客户端」而不是让运维去查密钥。
	ErrOldVersion = errors.New("tunnel: peer speaks an outdated protocol version")
)

// 控制消息类型。
const (
	// CtrlKindRoutes 是回程路由 IP 全量同步（历史上唯一的控制消息，
	// 旧客户端不带 kind 字段，零值按此处理）。
	CtrlKindRoutes = "routes"
)

// CtrlMessage 是加密控制通道上的 JSON 消息。
//
// Kind 为空等价于 CtrlKindRoutes：控制通道原本只有一种消息，加 Kind 是为了
// 后续消息不必再改结构。
type CtrlMessage struct {
	Kind string   `json:"kind,omitempty"`
	IPs  []string `json:"ips,omitempty"` // 需要回程路由的目的 IP 全量列表
}
