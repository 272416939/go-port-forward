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
//     「探测正常但进不去游戏」的原因。所以删除的唯一判据是「已空闲超过
//     宽限期」，并且交给后台 worker（删除从不影响时延）。
//
//  3. 回收必须由本地时间驱动，不能依赖服务端推送到达。/32 主机路由会吸走
//     该 IP 的**全部**回包，与是否经隧道无关——玩家一旦用过代理，残留路由
//     会让他之后直连源站 IP 也收不到回包。原先删除只在收到推送时才被触发，
//     而服务端在「该访问码没有任何活跃会话」时根本不推送，残留路由能活到
//     进程退出。现在由 pruneLoop 按本地空闲时间独立回收。

import (
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"pfapp/internal/syssetup"
)

const (
	// routeIdleGrace 是「没有任何外部确认」时的本地空闲保留时长。
	//
	// 这个值原先是 5 分钟，理由是「必须明显长于服务端推送周期（10s）与 UDP
	// 会话超时（30s）」——但在线 IP 每轮推送都会被 ensure 续期，宽限期只对
	// 已经安静下来的 IP 生效，长到 5 分钟只是把残留路由的危害窗口拉长。
	routeIdleGrace = 90 * time.Second
	// routeEndedGrace 是服务端已确认「该 IP 无活跃会话」之后的保留时长。
	//
	// 服务端的确认本身已经意味着该来源至少静默了一个 UDP 会话超时（30s），
	// 再叠加这里的 20s 才删除，短交互不会被掐断。
	routeEndedGrace = 20 * time.Second
	// prunePeriod 是本地回收扫描周期。回收不能只在收到推送时触发：服务端在
	// 「该访问码没有任何活跃会话」时不推送，而那恰好是最需要清掉残留路由的
	// 时刻（玩家已经不用代理了）。
	prunePeriod = 15 * time.Second
	// maxReturnRoutes 限制路由条数，防止源地址伪造洪泛撑爆系统路由表。
	maxReturnRoutes = 512
	// removeQueue 是待删除队列深度。
	removeQueue = 256
	// routeDeleteTries 是删除失败的重试次数上限。删除失败必须重试并最终告警：
	// 残留的 /32 主机路由会吸走该 IP 的全部回包，静默失败等于让玩家永久无法
	// 直连源站，且能活到进程退出。
	routeDeleteTries = 3
)

// routeState 是一条回程路由的本地视图。
//
// 字节方向以玩家为参照：up = 玩家 → 后端，down = 后端 → 玩家。这与主模块
// internal/forward 的 bytes_in/bytes_out 恰好相反——那边站在中转机视角，
// bytes_in 是"客户端流向目标"。客户端在链路另一端，沿用 in/out 会读反，
// 所以这里改用 up/down。
type routeState struct {
	lastSeen time.Time // 最近一次收到该 IP 的入站包，或被服务端确认活跃
	// endedAt 是服务端确认「该 IP 已无活跃会话」的时刻；零值表示未确认。
	// 有确认时走 routeEndedGrace（短），没有时只能靠 routeIdleGrace（长）。
	endedAt   time.Time
	removing  bool         // 已入删除队列
	delFails  int          // 连续删除失败次数
	bytesUp   atomic.Int64 // 玩家 → 后端
	bytesDown atomic.Int64 // 后端 → 玩家
}

// expired 报告该路由是否已过保留期。调用方需持锁。
func (st *routeState) expired(now time.Time) bool {
	if !st.endedAt.IsZero() && now.Sub(st.endedAt) > routeEndedGrace {
		return true
	}
	return now.Sub(st.lastSeen) > routeIdleGrace
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

	// addRoute/delRoute 默认打到 syssetup（route.exe）。抽成字段是为了让
	// 宽限期与删除重试这两段易错逻辑可以在没有管理员权限、不动系统路由表的
	// 情况下被测试覆盖。
	addRoute func(dest, gateway string) error
	delRoute func(dest string) error

	stop     chan struct{}
	stopOnce sync.Once
}

func newRouteManager(relayIP string, addressing tunnelAddressing, logf func(string, ...any)) *routeManager {
	m := &routeManager{
		states:     make(map[string]*routeState),
		removals:   make(chan string, removeQueue),
		relayIP:    relayIP,
		addressing: addressing,
		logf:       logf,
		addRoute:   syssetup.AddRoute,
		delRoute:   syssetup.RemoveRoute,
		stop:       make(chan struct{}),
	}
	go m.removeWorker()
	go m.pruneLoop()
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
		st.removing = false      // 又活跃了，取消可能已入队的删除
		st.endedAt = time.Time{} // 服务端说会话结束了，但包还在来，撤销该结论
		st.delFails = 0
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

	if err := m.addRoute(ip, m.addressing.Gateway); err != nil {
		m.mu.Lock()
		delete(m.states, ip) // 安装失败，下一个包会重试
		m.mu.Unlock()
		m.logf("[!] 回程路由添加失败：%s", ip)
		return nil
	}
	m.logf("[+] 回程路由已添加：%s", ip)
	return st
}

// sync 处理服务端推送的活跃会话 IP 全量列表：确认这些 IP 活跃（顺带补齐尚未
// 安装的），随后按本地时间回收过期路由。
//
// ⚠️ 「不在推送列表里」不构成删除依据（铁律 5）：推送每 10 秒一次，短交互的
// IP 在列表里一闪而过，按列表删除会把正在进行的会话反复掐断。列表的作用只是
// 「确认活跃」这一个正向语义。
func (m *routeManager) sync(ips []string) {
	for _, ip := range ips {
		_ = m.ensure(ip)
	}
	m.prune()
}

// markEnded 记录服务端确认「这些来源已无活跃会话」。
//
// 这是唯一可信的「可以删了」事件：中转机侧 UDP 会话已按超时回收，意味着该来源
// 至少静默了一个会话超时周期。收到后走较短的 routeEndedGrace，让残留的 /32
// 主机路由尽快消失——它会吸走该 IP 的全部回包，玩家不用代理直连源站时同样被
// 吸进隧道，表现为「用过代理之后直连就进不去了」。
func (m *routeManager) markEnded(ips []string) {
	if len(ips) == 0 {
		return
	}
	now := time.Now()
	m.mu.Lock()
	for _, ip := range ips {
		if st := m.states[ip]; st != nil && st.endedAt.IsZero() {
			st.endedAt = now
		}
	}
	m.mu.Unlock()
	m.prune()
}

// pruneLoop 按本地时间独立回收过期路由。
//
// 回收不能只挂在 sync 上：服务端在「该访问码没有任何活跃会话」时根本不推送
// （pushSessionIPs 对空列表 continue），而那正是最需要清掉残留路由的时刻。
func (m *routeManager) pruneLoop() {
	tick := time.NewTicker(prunePeriod)
	defer tick.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-tick.C:
			m.prune()
		}
	}
}

// prune 把已过保留期的路由排队删除。
func (m *routeManager) prune() {
	now := time.Now()
	var stale []string
	m.mu.Lock()
	for ip, st := range m.states {
		if st.removing || !st.expired(now) {
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
	for {
		select {
		case <-m.stop:
			return
		case ip := <-m.removals:
			m.processRemoval(ip)
		}
	}
}

// processRemoval 执行一次删除，并按结果决定「摘掉条目 / 立即重装 / 交回重试 /
// 放弃告警」。
//
// ⚠️ 「删除期间该 IP 又活跃了」这条分支是一个真实故障的根因，不能省：删除要起
// route.exe（几十毫秒），这期间到达的入站包会走 ensure 的快路径——它看到条目还在
// 就认为路由就位，不会重装。旧实现在调用 route.exe **之前**就摘掉了条目，于是
// 「新条目 + AddRoute 成功」与随后的 RemoveRoute 撞在一起，留下「条目在、路由没了」
// 的状态；而入站包（玩家 → 后端方向）不需要回程路由就能到，lastSeen 被持续刷新，
// 条目永不过期，该玩家就永久收不到回包。表现正是「断开后有概率连不上，等几分钟
// 才好」——几分钟就是玩家放弃重试后条目终于超时。
func (m *routeManager) processRemoval(ip string) {
	m.mu.Lock()
	st := m.states[ip]
	if st == nil || !st.removing {
		m.mu.Unlock()
		return // 入队后又活跃了，放弃删除
	}
	m.mu.Unlock()

	err := m.delRoute(ip)

	m.mu.Lock()
	st = m.states[ip]
	fails := 0
	// removing 被 ensure 复位，说明删除期间该 IP 又活跃了。
	reactivated := st != nil && !st.removing
	switch {
	case reactivated:
		// 保留条目。删除成功的话下面立刻重装——不能等下一个包：一来一回的
		// 探测交互（RakNet unconnected ping）没有第二次机会。删除失败的话
		// 路由本来就还在，什么都不用做，更不能记失败次数（记满会摘掉条目，
		// 而系统里的路由仍在，成了没人管的残留）。
	case err == nil:
		delete(m.states, ip)
	case st == nil:
	default:
		st.delFails++
		fails = st.delFails
		if fails >= routeDeleteTries {
			delete(m.states, ip)
		} else {
			st.removing = false // 交回 prune，下一轮重试
		}
	}
	m.mu.Unlock()

	switch {
	case reactivated && err != nil:
		// 删除失败 + 重新活跃：路由还在原处，正是想要的结果。
	case reactivated:
		if aerr := m.addRoute(ip, m.addressing.Gateway); aerr != nil {
			// 重装失败就摘掉条目，让下一个入站包重新走完整安装路径。
			m.mu.Lock()
			delete(m.states, ip)
			m.mu.Unlock()
			m.logf("[!] 回程路由重装失败：%s", ip)
			return
		}
		m.logf("[~] 回程路由已重装（删除期间重新活跃）：%s", ip)
	case err == nil:
		m.logf("[-] 回程路由已移除：%s", ip)
	case fails >= routeDeleteTries:
		// 静默的删除失败会留下一条能活到进程退出的残留路由，而残留路由会让
		// 该玩家直连源站也收不到回包。必须让用户看到。
		m.logf("[!] 回程路由删除失败 %d 次，已放弃：%s（如该地址无法直连，请手动执行 route delete %s）：%v",
			fails, ip, ip, err)
	}
}

// cleanup 删除全部路由但保持管理器可用（重握手拿到同一地址时会继续复用）。
func (m *routeManager) cleanup() {
	m.mu.Lock()
	ips := make([]string, 0, len(m.states))
	for ip := range m.states {
		ips = append(ips, ip)
	}
	m.states = make(map[string]*routeState)
	m.mu.Unlock()

	for _, ip := range ips {
		if err := m.delRoute(ip); err != nil {
			m.logf("[!] 回程路由删除失败：%s（如该地址无法直连，请手动执行 route delete %s）：%v", ip, ip, err)
		}
	}
}

// close 清理路由并停掉后台 goroutine；管理器被丢弃时调用。
//
// 只关 stop、不关 removals：removeWorker 正阻塞在两者的 select 上，关闭
// removals 会让它在关闭通道上空转。
func (m *routeManager) close() {
	m.stopOnce.Do(func() { close(m.stop) })
	m.cleanup()
}
