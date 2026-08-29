//go:build windows

package main

// /32 回程路由的生命周期管理。
//
// 两条硬约束决定了这里的形态：
//
//  1. 安装必须发生在「把入站包写入 TUN」之前。后端的回包可能在微秒级产生，
//     路由晚一步，回包就按默认路由从物理网卡发出去了（源地址变成后端自己
//     的公网 IP，对方直接丢弃）。RakNet unconnected ping 这类一来一回的
//     交互没有第二次机会，所以安装是同步的——代价是每个新来源 IP 会让隧道
//     读循环停顿一次 route.exe 的时间（几十毫秒）。
//
//  2. 删除不能跟着服务端推送列表走。服务端每 10 秒推一次活跃会话 IP，
//     UDP 会话 30 秒超时，短交互的 IP 在列表里一闪而过；严格按列表删除会让
//     同一个 IP 反复增删，而每次删除都会掐断正在进行的会话——这正是
//     「探测正常但进不去游戏」的原因。所以删除要求「不在推送列表」且
//     「已空闲超过宽限期」，并且交给后台 worker（删除从不影响时延）。

import (
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"pfapp/internal/syssetup"
)

const (
	// routeIdleGrace 是路由在空闲后的保留时长；收到该 IP 的包即视为活跃。
	// 需明显长于服务端推送周期（10s）与 UDP 会话超时（30s）。
	routeIdleGrace = 5 * time.Minute
	// maxReturnRoutes 限制路由条数，防止源地址伪造洪泛撑爆系统路由表。
	maxReturnRoutes = 512
	// removeQueue 是待删除队列深度。
	removeQueue = 256
)

// routeState 是一条回程路由的本地视图。
//
// 字节方向以玩家为参照：up = 玩家 → 后端，down = 后端 → 玩家。这与主模块
// internal/forward 的 bytes_in/bytes_out 恰好相反——那边站在中转机视角，
// bytes_in 是"客户端流向目标"。客户端在链路另一端，沿用 in/out 会读反，
// 所以这里改用 up/down。
type routeState struct {
	lastSeen  time.Time    // 最近一次收到该 IP 的入站包，或被服务端确认活跃
	removing  bool         // 已入删除队列
	bytesUp   atomic.Int64 // 玩家 → 后端
	bytesDown atomic.Int64 // 后端 → 玩家
}

// RouteEntry 是单个来源 IP 的流量视图（供 UI 展示）。
type RouteEntry struct {
	IP        string `json:"ip"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
}

// routeManager 维护全部 /32 回程路由。
type routeManager struct {
	mu       sync.Mutex
	states   map[string]*routeState
	removals chan string
	// relayIP 是中转机地址。绝不能为它安装回程路由——那会把隧道自己的
	// UDP 流量导进 TUN 形成环路，整条隧道立刻断掉。
	relayIP string
	// addressing 是服务端下发的隧道内地址。网关是 /32 路由的下一跳；本机与
	// 网关地址都必须排除在可安装地址之外（同上，会形成环路）。
	// 多用户之前这两个地址是编译期常量，现在每个用户各不相同。
	addressing tunnelAddressing
	logf       func(string, ...any)
}

func newRouteManager(relayIP string, addressing tunnelAddressing, logf func(string, ...any)) *routeManager {
	m := &routeManager{
		states:     make(map[string]*routeState),
		removals:   make(chan string, removeQueue),
		relayIP:    relayIP,
		addressing: addressing,
		logf:       logf,
	}
	go m.removeWorker()
	return m
}

// view 返回当前所有回程路由及其流量，按 IP 排序保证 1Hz 刷新时行不跳动。
func (m *routeManager) view() []RouteEntry {
	m.mu.Lock()
	out := make([]RouteEntry, 0, len(m.states))
	for ip, st := range m.states {
		out = append(out, RouteEntry{
			IP:        ip,
			BytesUp:   st.bytesUp.Load(),
			BytesDown: st.bytesDown.Load(),
		})
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// eligible 判断该地址是否可以安装 /32 回程路由。只接受公网单播 IPv4：
// 中转机自身、隧道网段、私网/回环/组播一律排除——任何一条误装都可能把
// 隧道流量或本机正常流量导进 TUN。
func (m *routeManager) eligible(ip string) bool {
	if ip == "" || ip == m.relayIP ||
		ip == m.addressing.Gateway || ip == m.addressing.ClientIP {
		return false
	}
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return false
	}
	return !v4.IsLoopback() && !v4.IsPrivate() && !v4.IsMulticast() &&
		!v4.IsLinkLocalUnicast() && !v4.IsUnspecified() && v4[0] != 255
}

// countInbound 记录一个玩家入站包（后端 → 玩家方向的回程路由由源 IP 决定），
// 并确保该 IP 的回程路由就位。必须在写入 TUN 之前调用（见文件头约束 1）。
func (m *routeManager) countInbound(pkt []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return
	}
	ip := net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15]).String()
	if st := m.ensure(ip); st != nil {
		st.bytesDown.Add(int64(len(pkt)))
	}
}

// countOutbound 记录一个后端发往玩家的回程包，按目的 IP 归属。
//
// 与 countInbound 不同，这里绝不安装路由：本函数在 TUN 读循环里对每个包调用，
// 而安装要起 route.exe 子进程（几十毫秒），放在这条高频路径上会拖垮吞吐。
// 回程包能走到 TUN，说明路由已经由入站方向装好了。
func (m *routeManager) countOutbound(pkt []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return
	}
	ip := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19]).String()
	m.mu.Lock()
	st := m.states[ip]
	m.mu.Unlock()
	if st != nil {
		st.bytesUp.Add(int64(len(pkt)))
	}
}

// ensure 刷新活跃时间；路由不存在时同步安装。返回该 IP 的状态条目
//（地址不合格或安装失败时返回 nil）。
func (m *routeManager) ensure(ip string) *routeState {
	if !m.eligible(ip) {
		return nil
	}
	now := time.Now()

	m.mu.Lock()
	if st, ok := m.states[ip]; ok {
		st.lastSeen = now
		st.removing = false // 又活跃了，取消可能已入队的删除
		m.mu.Unlock()
		return st
	}
	if len(m.states) >= maxReturnRoutes {
		m.mu.Unlock()
		return nil
	}
	// 先登记再解锁：route.exe 期间不持锁，同 IP 的后续包直接走上面的快路径。
	st := &routeState{lastSeen: now}
	m.states[ip] = st
	m.mu.Unlock()

	if err := syssetup.AddRoute(ip, m.addressing.Gateway); err != nil {
		m.mu.Lock()
		delete(m.states, ip) // 安装失败，下一个包会重试
		m.mu.Unlock()
		m.logf("[!] 回程路由添加失败：%s", ip)
		return nil
	}
	m.logf("[+] 回程路由已添加：%s", ip)
	return st
}

// sync 处理服务端推送的活跃会话 IP 全量列表：确认这些 IP 活跃（顺带补齐
// 尚未安装的），并把既不在列表中、又已空闲超过宽限期的路由排队删除。
func (m *routeManager) sync(ips []string) {
	pushed := make(map[string]bool, len(ips))
	for _, ip := range ips {
		if m.eligible(ip) {
			pushed[ip] = true
		}
	}
	for ip := range pushed {
		_ = m.ensure(ip)
	}

	now := time.Now()
	var stale []string
	m.mu.Lock()
	for ip, st := range m.states {
		if pushed[ip] || st.removing || now.Sub(st.lastSeen) <= routeIdleGrace {
			continue
		}
		st.removing = true
		stale = append(stale, ip)
	}
	m.mu.Unlock()

	for _, ip := range stale {
		select {
		case m.removals <- ip:
		default:
			m.mu.Lock()
			if st := m.states[ip]; st != nil {
				st.removing = false // 队列满，下一轮再删
			}
			m.mu.Unlock()
		}
	}
}

func (m *routeManager) removeWorker() {
	for ip := range m.removals {
		m.mu.Lock()
		st := m.states[ip]
		if st == nil || !st.removing {
			m.mu.Unlock()
			continue // 入队后又活跃了，放弃删除
		}
		delete(m.states, ip)
		m.mu.Unlock()

		_ = syssetup.RemoveRoute(ip)
		m.logf("[-] 回程路由已移除（空闲）：%s", ip)
	}
}

// cleanup 退出或重握手时删除全部路由。
func (m *routeManager) cleanup() {
	m.mu.Lock()
	ips := make([]string, 0, len(m.states))
	for ip := range m.states {
		ips = append(ips, ip)
	}
	m.states = make(map[string]*routeState)
	m.mu.Unlock()

	for _, ip := range ips {
		_ = syssetup.RemoveRoute(ip)
	}
}
