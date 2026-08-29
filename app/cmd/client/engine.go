//go:build windows

package main

// 隧道引擎：把「建立/断开隧道」封装成可被 UI 反复启停的对象。
//
// 原先这些逻辑直接写在 main 的 for 循环里，进程生命周期 == 隧道生命周期。
// 有了 UI 之后用户可以在不退出程序的情况下反复连接/断开、切换中转机地址，
// 因此状态、日志、统计都要能被 HTTP 层随时读取。

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go-port-forward/pkg/tunnel"
	"pfapp/internal/syssetup"
)

// State 是隧道的对外状态。
type State string

const (
	StateIdle       State = "idle"       // 未连接
	StateConnecting State = "connecting" // 正在握手
	StateConnected  State = "connected"  // 隧道已建立
	StateError      State = "error"      // 上一次尝试失败
)

// tunnelAddressing 是服务端在握手应答里下发的隧道内地址。
//
// 多用户之前这三项是编译期常量（10.66.0.2/24，网关 10.66.0.1）。现在每个用户
// 有各自的地址，只能等握手成功才知道——网卡配置因此必须挪到握手之后。
type tunnelAddressing struct {
	ClientIP string // 本机隧道地址
	Mask     string // 点分十进制掩码
	Gateway  string // 隧道内网关（服务端地址）
}

func (a tunnelAddressing) valid() bool {
	return a.ClientIP != "" && a.Mask != "" && a.Gateway != ""
}

// Engine 持有一次隧道会话的全部资源。
type Engine struct {
	mu      sync.Mutex
	state   State
	conf    clientConfig // 当前/上次使用的连接凭据
	lastErr string
	// terminal 标记「上一次失败需要人工介入」（设备不匹配、访问码停用等）。
	// 置位后不再自动重连——继续重试只会刷日志，并把真正的原因埋在一堆
	// 「握手失败」里。
	terminal bool
	since    time.Time // 进入 connected 的时刻
	cancel   context.CancelFunc
	done     chan struct{} // 上一次 run 完全退出的信号

	logs   *logRing
	routes atomic.Pointer[routeManager]
	sess   atomic.Pointer[tunnel.Session]
	addr   atomic.Pointer[tunnelAddressing] // 服务端下发的隧道地址

	statTunToTunnel atomic.Int64 // TUN 读出 → 发往隧道（后端回包方向）
	statTunnelToTun atomic.Int64 // 隧道收到 → 写入 TUN（玩家入站方向）
	bytesUp         atomic.Int64 // 玩家 → 后端 累计字节
	bytesDown       atomic.Int64 // 后端 → 玩家 累计字节
	lastWriteErr    atomic.Int64 // 写 TUN 失败日志限频锚点（Unix 秒）
}

// session 返回当前会话；nil 表示尚未握手成功，此时数据包应丢弃。
func (e *Engine) session() *tunnel.Session { return e.sess.Load() }

func (e *Engine) setSession(s *tunnel.Session) { e.sess.Store(s) }

func (e *Engine) addressing() tunnelAddressing {
	if a := e.addr.Load(); a != nil {
		return *a
	}
	return tunnelAddressing{}
}

func NewEngine() *Engine {
	return &Engine{state: StateIdle, logs: newLogRing(400)}
}

// Snapshot 是 UI 轮询拿到的完整状态。
//
// 流量方向以玩家为参照：up = 玩家 → 后端，down = 后端 → 玩家。
type Snapshot struct {
	State     State        `json:"state"`
	Addr      string       `json:"addr"`
	CodeID    string       `json:"code_id"`
	HasCred   bool         `json:"has_cred"`
	LastError string       `json:"last_error"`
	Terminal  bool         `json:"terminal"`
	Device    string       `json:"device"`
	Elevated  bool         `json:"elevated"`
	TunIP     string       `json:"tun_ip"`
	Gateway   string       `json:"gateway"`
	UptimeSec int64        `json:"uptime_sec"`
	PktUp     int64        `json:"pkt_up"`
	PktDown   int64        `json:"pkt_down"`
	BytesUp   int64        `json:"bytes_up"`
	BytesDown int64        `json:"bytes_down"`
	Routes    []RouteEntry `json:"routes"`
	Logs      []string     `json:"logs"`
}

func (e *Engine) Snapshot() Snapshot {
	e.mu.Lock()
	conf := e.conf
	s := Snapshot{
		State:     e.state,
		Addr:      conf.Addr,
		CodeID:    conf.CodeID,
		HasCred:   conf.complete(),
		LastError: e.lastErr,
		Terminal:  e.terminal,
		Device:    deviceLabel(),
		Elevated:  syssetup.IsElevated(),
		PktUp:     e.statTunToTunnel.Load(),
		PktDown:   e.statTunnelToTun.Load(),
		BytesUp:   e.bytesUp.Load(),
		BytesDown: e.bytesDown.Load(),
	}
	if e.state == StateConnected && !e.since.IsZero() {
		s.UptimeSec = int64(time.Since(e.since).Seconds())
	}
	e.mu.Unlock()

	addressing := e.addressing()
	s.TunIP = addressing.ClientIP
	s.Gateway = addressing.Gateway

	if rm := e.routes.Load(); rm != nil {
		s.Routes = rm.view()
	}
	if s.Routes == nil {
		s.Routes = []RouteEntry{}
	}
	s.Logs = e.logs.all()
	return s
}

func (e *Engine) logf(format string, a ...any) {
	e.logs.add(fmt.Sprintf(format, a...))
}

func (e *Engine) setState(st State, errMsg string) {
	e.mu.Lock()
	e.state = st
	e.lastErr = errMsg
	if st == StateConnected {
		e.since = time.Now()
	} else {
		e.since = time.Time{}
	}
	if st != StateError {
		e.terminal = false
	}
	e.mu.Unlock()
}

// setTerminal 置为「需要人工介入」的错误态：不再自动重连。
func (e *Engine) setTerminal(errMsg string) {
	e.mu.Lock()
	e.state = StateError
	e.lastErr = errMsg
	e.terminal = true
	e.since = time.Time{}
	e.mu.Unlock()
}

// Start 建立隧道。已在运行时返回错误而不是悄悄重连——UI 应先调 Stop。
func (e *Engine) Start(conf clientConfig) error {
	if !syssetup.IsElevated() {
		return fmt.Errorf("需要管理员权限：虚拟网卡与路由无法配置")
	}
	if _, err := deviceFingerprint(); err != nil {
		// 设备指纹是握手的必要输入（服务端要靠它绑定客户端）。取不到就直接
		// 报错，而不是带一个零值指纹去握手——那会绑定出一个所有机器都相同的
		// "空指纹"，把设备绑定变成一个假功能。
		return err
	}
	conf = conf.normalized()
	if !conf.complete() {
		return fmt.Errorf("缺少接入凭据，请粘贴接入码")
	}
	if _, _, err := net.SplitHostPort(conf.Addr); err != nil {
		return fmt.Errorf("地址格式应为 IP:端口")
	}
	if _, err := tunnel.ParseUID(conf.CodeID); err != nil {
		return fmt.Errorf("接入码中的访问码 ID 无效")
	}

	e.mu.Lock()
	if e.cancel != nil {
		e.mu.Unlock()
		return fmt.Errorf("隧道已在运行，请先断开")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	e.cancel, e.done, e.conf = cancel, done, conf
	e.state, e.lastErr = StateConnecting, ""
	e.mu.Unlock()

	saveConfig(conf)
	e.statTunToTunnel.Store(0)
	e.statTunnelToTun.Store(0)
	e.bytesUp.Store(0)
	e.bytesDown.Store(0)

	go func() {
		defer close(done)
		e.run(ctx, conf)
	}()
	return nil
}

// Stop 断开隧道并等待资源释放（路由、防火墙规则都会被清理）。
func (e *Engine) Stop() {
	e.mu.Lock()
	cancel, done := e.cancel, e.done
	e.cancel, e.done = nil, nil
	e.mu.Unlock()

	if cancel == nil {
		return
	}
	cancel()
	<-done
	e.setState(StateIdle, "")
	e.addr.Store(nil)
	e.logf("已断开连接。")
}
