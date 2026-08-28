// Package tunnel 实现迷你加密隧道协议（UDP）。
//
// 包格式：[1 字节类型][payload]
//   - Hello (0x01, 明文): clientEphPub(32) || ts(8 BE) || HMAC(psk,"hello"||eph||ts)
//   - Accept(0x02, 明文): serverEphPub(32) || HMAC(psk,"accept"||sEph||cEph)
//   - Data  (0x03, 密文): box(完整 IP 包)
//   - Ctrl  (0x04, 密文): box(JSON 控制消息，如回程路由 IP 同步)
//   - Ping/Pong (0x05/0x06, 密文): 心跳
//
// 会话密钥 = SHA256(X25519 共享 || psk)；每方向独立单调 nonce 计数器，
// 接收端滑动窗口防重放。PSK 双端预共享（服务端配置文件 / 客户端内置默认）。
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
)

// 错误定义。
var (
	ErrAuth       = errors.New("tunnel: authentication failed")
	ErrBadPacket  = errors.New("tunnel: malformed packet")
	ErrReplay     = errors.New("tunnel: replayed or stale packet")
	ErrNoSession  = errors.New("tunnel: no established session")
)

// CtrlMessage 是加密控制通道上的 JSON 消息（目前仅回程路由 IP 全量同步）。
type CtrlMessage struct {
	IPs []string `json:"ips"` // 需要回程路由的目的 IP 全量列表
}
