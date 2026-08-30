//go:build windows

package main

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeRoutes 替身系统路由表：不碰 route.exe，因此测试无需管理员权限。
type fakeRoutes struct {
	mu      sync.Mutex
	present map[string]bool
	adds    []string
	dels    []string
	// failDel 指定某个地址前 n 次删除失败，用于覆盖重试与放弃路径。
	failDel map[string]int
}

func newFakeRoutes() *fakeRoutes {
	return &fakeRoutes{present: map[string]bool{}, failDel: map[string]int{}}
}

func (f *fakeRoutes) add(dest, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.present[dest] = true
	f.adds = append(f.adds, dest)
	return nil
}

func (f *fakeRoutes) del(dest string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n := f.failDel[dest]; n > 0 {
		f.failDel[dest] = n - 1
		f.dels = append(f.dels, dest+"!")
		return fmt.Errorf("模拟删除失败")
	}
	delete(f.present, dest)
	f.dels = append(f.dels, dest)
	return nil
}

func (f *fakeRoutes) has(dest string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.present[dest]
}

func (f *fakeRoutes) delCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dels)
}

// testRouteManager 造一个不起后台 goroutine 的管理器：回收与删除都由测试
// 显式驱动，避免时序竞争。
func testRouteManager(t *testing.T, f *fakeRoutes) *routeManager {
	t.Helper()
	return &routeManager{
		states:   map[string]*routeState{},
		removals: make(chan string, removeQueue),
		relayIP:  "203.0.113.1",
		addressing: tunnelAddressing{
			ClientIP: "10.66.0.2", Mask: "255.255.0.0", Gateway: "10.66.0.1",
		},
		logf:     func(string, ...any) {},
		addRoute: f.add,
		delRoute: f.del,
		stop:     make(chan struct{}),
	}
}

// drainRemovals 同步执行一遍 removeWorker 的循环体，把队列排空。
func drainRemovals(m *routeManager) {
	for {
		select {
		case ip := <-m.removals:
			m.processRemoval(ip)
		default:
			return
		}
	}
}

// 中转机地址、本机隧道地址、网关都不能装 /32 路由——给它们装会把隧道自身的
// UDP 流量或本机流量导进 TUN，整条隧道立刻断。
func TestEligibleExcludesTunnelAndPrivate(t *testing.T) {
	m := testRouteManager(t, newFakeRoutes())
	for _, ip := range []string{
		"", "203.0.113.1", "10.66.0.1", "10.66.0.2",
		"192.168.1.10", "127.0.0.1", "224.0.0.1", "169.254.1.1",
		"0.0.0.0", "255.255.255.255", "not-an-ip", "2001:db8::1",
	} {
		if m.eligible(ip) {
			t.Errorf("%q 不应被判为可安装", ip)
		}
	}
	for _, ip := range []string{"1.2.3.4", "198.51.100.7"} {
		if !m.eligible(ip) {
			t.Errorf("%q 应被判为可安装", ip)
		}
	}
}

// 服务端确认会话结束后走短宽限期（routeEndedGrace），不必等满
// routeIdleGrace。残留的 /32 路由会吸走该 IP 的全部回包，包括玩家不经代理
// 直连源站的流量，所以要尽快回收。
func TestMarkEndedUsesShortGrace(t *testing.T) {
	f := newFakeRoutes()
	m := testRouteManager(t, f)

	if st := m.ensure("1.2.3.4"); st == nil {
		t.Fatal("安装应成功")
	}
	m.markEnded([]string{"1.2.3.4"})
	drainRemovals(m)
	if !f.has("1.2.3.4") {
		t.Fatal("刚确认结束就删除会掐断短交互，必须等过 routeEndedGrace")
	}

	// 把结束时刻回拨到超过短宽限期。
	m.mu.Lock()
	m.states["1.2.3.4"].endedAt = time.Now().Add(-routeEndedGrace - time.Second)
	m.mu.Unlock()

	m.prune()
	drainRemovals(m)
	if f.has("1.2.3.4") {
		t.Fatal("过了 routeEndedGrace 应已删除")
	}
	if _, ok := m.states["1.2.3.4"]; ok {
		t.Fatal("删除成功后必须摘掉条目，否则 ensure 会走快路径不重装")
	}
}

// 收到结束通知后包又来了：说明会话其实还活着，必须撤销「已结束」的结论，
// 否则短宽限期一到就把正在用的路由删掉。
func TestEnsureCancelsEnded(t *testing.T) {
	f := newFakeRoutes()
	m := testRouteManager(t, f)
	m.ensure("1.2.3.4")
	m.markEnded([]string{"1.2.3.4"})

	m.ensure("1.2.3.4") // 又收到入站包

	m.mu.Lock()
	ended := m.states["1.2.3.4"].endedAt
	m.mu.Unlock()
	if !ended.IsZero() {
		t.Fatal("重新活跃后必须清掉 endedAt")
	}

	m.prune()
	drainRemovals(m)
	if !f.has("1.2.3.4") {
		t.Fatal("重新活跃的路由被误删")
	}
}

// 「不在推送列表里」不构成删除依据（铁律 5）：推送每 10 秒一次，短交互的 IP
// 在列表里一闪而过，按缺席删除会把正在进行的会话反复掐断。
func TestSyncDoesNotDeleteMerelyAbsentIP(t *testing.T) {
	f := newFakeRoutes()
	m := testRouteManager(t, f)
	m.ensure("1.2.3.4")

	m.sync([]string{"5.6.7.8"}) // 1.2.3.4 缺席
	drainRemovals(m)

	if !f.has("1.2.3.4") {
		t.Fatal("仅因缺席就删除，会掐断短交互会话")
	}
	if !f.has("5.6.7.8") {
		t.Fatal("推送列表里的新 IP 应被补齐")
	}
}

// 本地空闲宽限期到了必须删除，且不依赖任何推送到达——服务端在「该访问码没有
// 任何活跃会话」时不推送 routes，而那恰是最需要清残留路由的时刻。
func TestPruneRemovesIdleWithoutPush(t *testing.T) {
	f := newFakeRoutes()
	m := testRouteManager(t, f)
	m.ensure("1.2.3.4")

	m.mu.Lock()
	m.states["1.2.3.4"].lastSeen = time.Now().Add(-routeIdleGrace - time.Second)
	m.mu.Unlock()

	m.prune()
	drainRemovals(m)
	if f.has("1.2.3.4") {
		t.Fatal("空闲超过 routeIdleGrace 的路由应被回收")
	}
}

// 删除失败要重试，连续失败到上限才放弃并告警。静默的删除失败会留下一条活到
// 进程退出的残留路由，让该地址永久无法直连。
func TestRemovalRetriesThenGivesUp(t *testing.T) {
	f := newFakeRoutes()
	f.failDel["1.2.3.4"] = 1 // 第一次失败，第二次成功
	m := testRouteManager(t, f)
	m.ensure("1.2.3.4")
	expire(m, "1.2.3.4")

	m.prune()
	drainRemovals(m)
	if !f.has("1.2.3.4") {
		t.Fatal("第一次删除本应失败")
	}
	m.mu.Lock()
	st := m.states["1.2.3.4"]
	if st == nil || st.removing {
		t.Fatal("失败后应交回 prune 重试（removing 复位、条目保留）")
	}
	m.mu.Unlock()

	m.prune()
	drainRemovals(m)
	if f.has("1.2.3.4") {
		t.Fatal("重试应删除成功")
	}
}

func TestRemovalGivesUpAfterMaxTries(t *testing.T) {
	f := newFakeRoutes()
	f.failDel["1.2.3.4"] = 99 // 永远失败
	m := testRouteManager(t, f)
	m.ensure("1.2.3.4")
	expire(m, "1.2.3.4")

	for i := 0; i < routeDeleteTries+2; i++ {
		m.prune()
		drainRemovals(m)
	}
	m.mu.Lock()
	_, still := m.states["1.2.3.4"]
	m.mu.Unlock()
	if still {
		t.Fatal("连续失败到上限后应放弃并摘掉条目，不能无限重试刷日志")
	}
	if f.delCount() != routeDeleteTries {
		t.Fatalf("删除尝试次数 = %d，应为 %d", f.delCount(), routeDeleteTries)
	}
}

// expire 把某条路由的空闲时间推到宽限期之外。
func expire(m *routeManager, ip string) {
	m.mu.Lock()
	if st := m.states[ip]; st != nil {
		st.lastSeen = time.Now().Add(-routeIdleGrace - time.Second)
	}
	m.mu.Unlock()
}

// 删除期间该 IP 又活跃了：删除已经执行，条目必须留下并**立刻重装**路由。
//
// 这是「断开后有概率连不上、等几分钟才好」的根因分支。删除要起 route.exe
// （几十毫秒），这期间到达的入站包走 ensure 快路径，看到条目还在就不重装；
// 若删除后把条目也摘掉/留着但不重装，就会出现「条目在、系统路由没了」，
// 而入站方向不需要回程路由就能到，lastSeen 被持续刷新导致条目永不过期，
// 该玩家永久收不到回包。
func TestRemovalReinstallsWhenReactivated(t *testing.T) {
	f := newFakeRoutes()
	m := testRouteManager(t, f)
	m.ensure("1.2.3.4")
	expire(m, "1.2.3.4")
	m.prune() // 标记 removing 并入队

	// 模拟「删除执行期间又收到入站包」：ensure 会把 removing 复位。
	m.delRoute = func(dest string) error {
		m.ensure("1.2.3.4")
		return f.del(dest)
	}
	drainRemovals(m)

	m.mu.Lock()
	st := m.states["1.2.3.4"]
	m.mu.Unlock()
	if st == nil {
		t.Fatal("删除期间重新活跃，条目不应被摘掉")
	}
	if !f.has("1.2.3.4") {
		t.Fatal("路由必须被立刻重装，否则该玩家收不到任何回包")
	}
}

// 重装失败要摘掉条目，让下一个入站包重新走完整安装路径，而不是留一个
// 「条目在、路由没了」的永久黑洞。
func TestReinstallFailureDropsEntry(t *testing.T) {
	f := newFakeRoutes()
	m := testRouteManager(t, f)
	m.ensure("1.2.3.4")
	expire(m, "1.2.3.4")
	m.prune()

	m.delRoute = func(dest string) error {
		m.ensure("1.2.3.4")
		return f.del(dest)
	}
	m.addRoute = func(string, string) error { return fmt.Errorf("模拟安装失败") }
	drainRemovals(m)

	m.mu.Lock()
	_, still := m.states["1.2.3.4"]
	m.mu.Unlock()
	if still {
		t.Fatal("重装失败必须摘掉条目，否则 ensure 走快路径永不重装")
	}
}

// 删除失败 + 期间又活跃：路由本来就还在原处，正是想要的结果。此时**不能**
// 累计失败次数——累满会摘掉条目，而系统里的路由仍在，就成了没人管的残留。
func TestRemovalFailureWithReactivationKeepsEntry(t *testing.T) {
	f := newFakeRoutes()
	f.failDel["1.2.3.4"] = 99
	m := testRouteManager(t, f)
	m.ensure("1.2.3.4")
	expire(m, "1.2.3.4")
	m.prune()

	m.delRoute = func(dest string) error {
		m.ensure("1.2.3.4")
		return f.del(dest)
	}
	drainRemovals(m)

	m.mu.Lock()
	st := m.states["1.2.3.4"]
	m.mu.Unlock()
	if st == nil {
		t.Fatal("路由还在系统里，条目不能被摘掉")
	}
	if st.delFails != 0 {
		t.Fatalf("delFails = %d，重新活跃时不应累计失败", st.delFails)
	}
	if !f.has("1.2.3.4") {
		t.Fatal("删除失败意味着路由仍在，替身状态不符")
	}
}

// cleanup 必须清空全部路由：重握手/退出时残留任何一条都会污染直连。
func TestCleanupRemovesAll(t *testing.T) {
	f := newFakeRoutes()
	m := testRouteManager(t, f)
	m.ensure("1.2.3.4")
	m.ensure("5.6.7.8")

	m.cleanup()
	if f.has("1.2.3.4") || f.has("5.6.7.8") {
		t.Fatal("cleanup 后系统路由表应为空")
	}
	if len(m.states) != 0 {
		t.Fatal("cleanup 后本地状态应清空")
	}
}

// countOutbound 只计流量、不刷新活跃时间。否则玩家直连源站时后端回包被残留
// 路由吸进隧道，反而会给这条残留路由续命，永远不会自愈。
func TestCountOutboundDoesNotRefreshLastSeen(t *testing.T) {
	f := newFakeRoutes()
	m := testRouteManager(t, f)
	m.ensure("1.2.3.4")
	expire(m, "1.2.3.4")

	m.mu.Lock()
	before := m.states["1.2.3.4"].lastSeen
	m.mu.Unlock()

	m.countOutbound(ipv4Packet("10.66.0.2", "1.2.3.4"))

	m.mu.Lock()
	st := m.states["1.2.3.4"]
	after, up := st.lastSeen, st.bytesUp.Load()
	m.mu.Unlock()
	if !after.Equal(before) {
		t.Fatal("countOutbound 不得续期，否则残留路由被自己吸来的包永久续命")
	}
	if up == 0 {
		t.Fatal("字节数应被计入")
	}
}

// countInbound 要按源 IP 装路由并计入 down 方向。
func TestCountInboundInstallsRoute(t *testing.T) {
	f := newFakeRoutes()
	m := testRouteManager(t, f)
	m.countInbound(ipv4Packet("1.2.3.4", "10.66.0.2"))

	if !f.has("1.2.3.4") {
		t.Fatal("入站包应即时安装回程路由")
	}
	m.mu.Lock()
	down := m.states["1.2.3.4"].bytesDown.Load()
	m.mu.Unlock()
	if down == 0 {
		t.Fatal("字节数应计入 down 方向")
	}
}

// ipv4Packet 造一个最小 IPv4 头（20 字节）。
func ipv4Packet(src, dst string) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	copy(pkt[12:16], parse4(src))
	copy(pkt[16:20], parse4(dst))
	return pkt
}

func parse4(s string) []byte {
	var b [4]byte
	fmt.Sscanf(s, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3])
	return b[:]
}
