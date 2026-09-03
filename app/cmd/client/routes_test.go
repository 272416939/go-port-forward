//go:build windows

package main

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
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

// tunRecorder 替身 TUN 写出口：记录安装器代写的缓冲包及其顺序。
type tunRecorder struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (r *tunRecorder) write(p []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pkts = append(r.pkts, append([]byte(nil), p...))
	return nil
}

func (r *tunRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pkts)
}

func (r *tunRecorder) all() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.pkts))
	copy(out, r.pkts)
	return out
}

// testRouteManager 造一个不起后台 goroutine 的管理器：回收、删除与安装都由
// 测试显式驱动，避免时序竞争。
func testRouteManager(t *testing.T, f *fakeRoutes) (*routeManager, *tunRecorder) {
	t.Helper()
	w := &tunRecorder{}
	m := &routeManager{
		states:      map[netip.Addr]*routeState{},
		removals:    make(chan netip.Addr, removeQueue),
		installWake: make(chan struct{}, 1),
		relayIP:     ra("203.0.113.1"),
		clientIP:    ra("10.66.0.2"),
		gateway:     ra("10.66.0.1"),
		gatewayStr:  "10.66.0.1",
		logf:        t.Logf,
		addRoute:    f.add,
		delRoute:    f.del,
		writeTun:    w.write,
		stop:        make(chan struct{}),
	}
	m.publish()
	return m, w
}

// staleRouteLister 造一个残留路由列表替身（newRouteManager 之外手动装配）。
func staleRouteLister(dests ...string) func(string) ([]string, error) {
	return func(string) ([]string, error) { return dests, nil }
}

// ra 把点分十进制转成数据面用的键形态。
func ra(s string) netip.Addr {
	a, _ := netip.ParseAddr(s)
	return a.Unmap()
}

// ensureIP / stateOf 是 ensure / states 查表的字符串入口，只在测试里用——
// 数据面全程用 netip.Addr，这两个壳只是保留用例的可读性。
func ensureIP(m *routeManager, s string) *routeState { return m.ensure(ra(s), time.Now()) }

func stateOf(m *routeManager, s string) *routeState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.states[ra(s)]
}

// stateCount 返回当前条目数（states 只在 mu 下访问）。
func stateCount(m *routeManager) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.states)
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

// drainInstalls 同步跑一遍安装器循环体，把当前到期的安装任务处理完。
func drainInstalls(m *routeManager) {
	m.installDue()
}

// 中转机地址、本机隧道地址、网关都不能装 /32 路由——给它们装会把隧道自身的
// UDP 流量或本机流量导进 TUN，整条隧道立刻断。
func TestEligibleExcludesTunnelAndPrivate(t *testing.T) {
	m, _ := testRouteManager(t, newFakeRoutes())
	for _, ip := range []string{
		"", "203.0.113.1", "10.66.0.1", "10.66.0.2",
		"192.168.1.10", "127.0.0.1", "224.0.0.1", "169.254.1.1",
		"0.0.0.0", "255.255.255.255", "not-an-ip", "2001:db8::1",
	} {
		if m.eligibleStr(ip) {
			t.Errorf("%q 不应被判为可安装", ip)
		}
	}
	for _, ip := range []string{"1.2.3.4", "198.51.100.7"} {
		if !m.eligibleStr(ip) {
			t.Errorf("%q 应被判为可安装", ip)
		}
	}
}

// 服务端确认会话结束后走短宽限期（routeEndedGrace），不必等满
// routeIdleGrace。残留的 /32 路由会吸走该 IP 的全部回包，包括玩家不经代理
// 直连源站的流量，所以要尽快回收。
func TestMarkEndedUsesShortGrace(t *testing.T) {
	f := newFakeRoutes()
	m, _ := testRouteManager(t, f)

	ensureIP(m, "1.2.3.4")
	drainInstalls(m)
	m.markEnded([]string{"1.2.3.4"})
	drainRemovals(m)
	if !f.has("1.2.3.4") {
		t.Fatal("刚确认结束就删除会掐断短交互，必须等过 routeEndedGrace")
	}

	// 把结束时刻回拨到超过短宽限期。
	stateOf(m, "1.2.3.4").endedAt.Store(time.Now().Add(-routeEndedGrace - time.Second).UnixNano())

	m.prune()
	drainRemovals(m)
	if f.has("1.2.3.4") {
		t.Fatal("过了 routeEndedGrace 应已删除")
	}
	if stateOf(m, "1.2.3.4") != nil {
		t.Fatal("删除成功后必须摘掉条目，否则 ensure 会走快路径不重装")
	}
	if m.lookup(ra("1.2.3.4")) != nil {
		t.Fatal("索引快照未同步摘除，数据面会继续走快路径")
	}
}

// 收到结束通知后包又来了：说明会话其实还活着，必须撤销「已结束」的结论，
// 否则短宽限期一到就把正在用的路由删掉。
func TestEnsureCancelsEnded(t *testing.T) {
	f := newFakeRoutes()
	m, _ := testRouteManager(t, f)
	ensureIP(m, "1.2.3.4")
	drainInstalls(m)
	m.markEnded([]string{"1.2.3.4"})

	ensureIP(m, "1.2.3.4") // 又收到入站包

	if stateOf(m, "1.2.3.4").endedAt.Load() != 0 {
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
	m, _ := testRouteManager(t, f)
	ensureIP(m, "1.2.3.4")
	drainInstalls(m)

	m.sync([]string{"5.6.7.8"}) // 1.2.3.4 缺席
	drainInstalls(m)
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
	m, _ := testRouteManager(t, f)
	ensureIP(m, "1.2.3.4")
	drainInstalls(m)

	expire(m, "1.2.3.4")

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
	m, _ := testRouteManager(t, f)
	ensureIP(m, "1.2.3.4")
	drainInstalls(m)
	expire(m, "1.2.3.4")

	m.prune()
	drainRemovals(m)
	if !f.has("1.2.3.4") {
		t.Fatal("第一次删除本应失败")
	}
	if st := stateOf(m, "1.2.3.4"); st == nil || st.removing.Load() {
		t.Fatal("失败后应交回 prune 重试（removing 复位、条目保留）")
	}

	m.prune()
	drainRemovals(m)
	if f.has("1.2.3.4") {
		t.Fatal("重试应删除成功")
	}
}

func TestRemovalGivesUpAfterMaxTries(t *testing.T) {
	f := newFakeRoutes()
	f.failDel["1.2.3.4"] = 99 // 永远失败
	m, _ := testRouteManager(t, f)
	ensureIP(m, "1.2.3.4")
	drainInstalls(m)
	expire(m, "1.2.3.4")

	for i := 0; i < routeDeleteTries+2; i++ {
		m.prune()
		drainRemovals(m)
	}
	if stateOf(m, "1.2.3.4") != nil {
		t.Fatal("连续失败到上限后应放弃并摘掉条目，不能无限重试刷日志")
	}
	if f.delCount() != routeDeleteTries {
		t.Fatalf("删除尝试次数 = %d，应为 %d", f.delCount(), routeDeleteTries)
	}
}

// dueNow 把退避时刻推到过去，让下一次 installDue 立刻处理该条目。
func dueNow(m *routeManager, st *routeState) {
	m.mu.Lock()
	st.nextTry = time.Now().Add(-time.Second)
	m.mu.Unlock()
}

func expire(m *routeManager, ip string) {
	if st := stateOf(m, ip); st != nil {
		st.lastSeen.Store(time.Now().Add(-routeIdleGrace - time.Second).UnixNano())
	}
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
	m, _ := testRouteManager(t, f)
	ensureIP(m, "1.2.3.4")
	drainInstalls(m)
	expire(m, "1.2.3.4")
	m.prune() // 标记 removing 并入队

	// 模拟「删除执行期间又收到入站包」：ensure 会把 removing 复位。
	m.delRoute = func(dest string) error {
		ensureIP(m, "1.2.3.4")
		return f.del(dest)
	}
	drainRemovals(m)
	drainInstalls(m)

	st := stateOf(m, "1.2.3.4")
	installing := st != nil && st.installing.Load()
	if st == nil {
		t.Fatal("删除期间重新活跃，条目不应被摘掉")
	}
	if installing {
		t.Fatal("重装完成后不得仍处于 installing 状态")
	}
	if !f.has("1.2.3.4") {
		t.Fatal("路由必须被立刻重装，否则该玩家收不到任何回包")
	}
}

// 重装失败不能摘掉条目：条目在而路由没装上时保持 installing，由安装器按
// 指数退避重试直至成功。摘掉条目 + 后续包反复重演 route.exe 是旧实现的
// 逐包重演病根；直接放弃则留下「条目在、路由没了」的永久黑洞。
func TestReinstallFailureBacksOff(t *testing.T) {
	f := newFakeRoutes()
	m, _ := testRouteManager(t, f)
	ensureIP(m, "1.2.3.4")
	drainInstalls(m)
	expire(m, "1.2.3.4")
	m.prune()

	m.delRoute = func(dest string) error {
		ensureIP(m, "1.2.3.4")
		return f.del(dest)
	}
	m.addRoute = func(string, string) error { return fmt.Errorf("模拟安装失败") }
	drainRemovals(m)
	drainInstalls(m)

	st := stateOf(m, "1.2.3.4")
	installing := st != nil && st.installing.Load()
	if st == nil {
		t.Fatal("重装失败条目必须保留，交回安装器退避重试")
	}
	if !installing {
		t.Fatal("路由没装上必须保持 installing，否则后续包会在无路由时直写 TUN")
	}

	// 退避到期 + 安装恢复后自愈。
	dueNow(m, st)
	m.addRoute = f.add
	drainInstalls(m)
	if !f.has("1.2.3.4") {
		t.Fatal("退避到期后应重装成功")
	}
}

// 删除失败 + 期间又活跃：路由本来就还在原处，正是想要的结果。此时**不能**
// 累计失败次数——累满会摘掉条目，而系统里的路由仍在，就成了没人管的残留。
func TestRemovalFailureWithReactivationKeepsEntry(t *testing.T) {
	f := newFakeRoutes()
	f.failDel["1.2.3.4"] = 99
	m, _ := testRouteManager(t, f)
	ensureIP(m, "1.2.3.4")
	drainInstalls(m)
	expire(m, "1.2.3.4")
	m.prune()

	m.delRoute = func(dest string) error {
		ensureIP(m, "1.2.3.4")
		return f.del(dest)
	}
	drainRemovals(m)

	st := stateOf(m, "1.2.3.4")
	installing := st != nil && st.installing.Load()
	if st == nil {
		t.Fatal("路由还在系统里，条目不能被摘掉")
	}
	if n := st.delFails.Load(); n != 0 {
		t.Fatalf("delFails = %d，重新活跃时不应累计失败", n)
	}
	if installing {
		t.Fatal("删除失败意味着路由仍在，不得再走安装流程")
	}
	if !f.has("1.2.3.4") {
		t.Fatal("删除失败意味着路由仍在，替身状态不符")
	}
}

// cleanup 必须清空全部路由：重握手/退出时残留任何一条都会污染直连。
func TestCleanupRemovesAll(t *testing.T) {
	f := newFakeRoutes()
	m, _ := testRouteManager(t, f)
	ensureIP(m, "1.2.3.4")
	ensureIP(m, "5.6.7.8")
	drainInstalls(m)

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
	m, _ := testRouteManager(t, f)
	ensureIP(m, "1.2.3.4")
	drainInstalls(m)
	expire(m, "1.2.3.4")

	before := stateOf(m, "1.2.3.4").lastSeen.Load()

	m.countOutbound(ipv4Packet("10.66.0.2", "1.2.3.4"))

	st := stateOf(m, "1.2.3.4")
	after, up := st.lastSeen.Load(), st.bytesUp.Load()
	if after != before {
		t.Fatal("countOutbound 不得续期，否则残留路由被自己吸来的包永久续命")
	}
	if up == 0 {
		t.Fatal("字节数应被计入")
	}
}

// 新 IP 的入站包必须缓冲等安装，绝不能在无路由时直写 TUN（回包会从物理网卡
// 漏出去），也绝不能同步起 route.exe 阻塞读循环——后者正是旧实现「一个玩家
// 进服全服卡一下」的病根。
func TestDeliverInboundBuffersUntilInstalled(t *testing.T) {
	f := newFakeRoutes()
	m, w := testRouteManager(t, f)
	pkt := ipv4Packet("1.2.3.4", "10.66.0.2")

	if m.deliverInbound(pkt) {
		t.Fatal("新 IP 的首包应被缓冲，不能直接放行写 TUN")
	}
	if f.has("1.2.3.4") {
		t.Fatal("deliverInbound 不得同步安装路由（那会阻塞读循环）")
	}
	if w.count() != 0 {
		t.Fatal("路由未就绪前不得写入 TUN")
	}

	drainInstalls(m)
	if !f.has("1.2.3.4") {
		t.Fatal("安装器应完成安装")
	}
	if w.count() != 1 {
		t.Fatalf("缓冲的首包应由安装器代写一次，实际写了 %d 个", w.count())
	}
	if down := stateOf(m, "1.2.3.4").bytesDown.Load(); down == 0 {
		t.Fatal("字节数应计入 down 方向（缓冲期间也要计数）")
	}
}

// 安装完成后的后续包走快路径直接放行，安装器不再代写。
func TestDeliverInboundFastPathAfterInstall(t *testing.T) {
	f := newFakeRoutes()
	m, w := testRouteManager(t, f)
	m.deliverInbound(ipv4Packet("1.2.3.4", "10.66.0.2"))
	drainInstalls(m)

	if !m.deliverInbound(ipv4Packet("1.2.3.4", "10.66.0.2")) {
		t.Fatal("路由就位后应直接放行")
	}
	if w.count() != 1 {
		t.Fatalf("快路径的包由 pump 写，安装器不应代写，实际代写 %d 个", w.count())
	}
}

// 不合格地址（私网/中转机/网关等）直接放行且不登记状态。
func TestDeliverInboundIneligiblePassesThrough(t *testing.T) {
	m, _ := testRouteManager(t, newFakeRoutes())
	if !m.deliverInbound(ipv4Packet("192.168.1.10", "10.66.0.2")) {
		t.Fatal("不合格地址应直接放行")
	}
	if len(m.states) != 0 {
		t.Fatal("不合格地址不应登记状态条目")
	}
}

// 缓冲有上限：溢出的包被丢弃（RakNet 会重传），不会撑爆内存；安装恢复后
// 补写的数量不超过上限。
func TestDeliverInboundDropsOverflow(t *testing.T) {
	f := newFakeRoutes()
	m, w := testRouteManager(t, f)
	m.addRoute = func(string, string) error { return fmt.Errorf("模拟安装失败") }

	for i := 0; i < installPendingCap+3; i++ {
		if m.deliverInbound(ipv4Packet("1.2.3.4", "10.66.0.2")) {
			t.Fatal("安装未完成期间包应被缓冲或丢弃，不得放行")
		}
	}
	m.mu.Lock()
	pending := len(m.states[ra("1.2.3.4")].pending)
	m.mu.Unlock()
	if pending != installPendingCap {
		t.Fatalf("缓冲深度 = %d，应封顶在 %d", pending, installPendingCap)
	}

	// 安装恢复后退避到期，补写恰好上限个包。
	dueNow(m, stateOf(m, "1.2.3.4"))
	m.addRoute = f.add
	drainInstalls(m)
	if w.count() != installPendingCap {
		t.Fatalf("补写包数 = %d，应为上限 %d", w.count(), installPendingCap)
	}
}

// 缓冲包按到达顺序补写，不能乱序。
func TestDeliverInboundPreservesOrder(t *testing.T) {
	f := newFakeRoutes()
	m, w := testRouteManager(t, f)
	for i := 0; i < 3; i++ {
		pkt := ipv4Packet("1.2.3.4", "10.66.0.2")
		pkt[4] = byte(i) // 包内一个可区分的字节（仅测试用）
		m.deliverInbound(pkt)
	}
	drainInstalls(m)
	all := w.all()
	if len(all) != 3 {
		t.Fatalf("应补写 3 个包，实际 %d 个", len(all))
	}
	for i, p := range all {
		if p[4] != byte(i) {
			t.Fatalf("第 %d 个补写包顺序错乱", i)
		}
	}
}

// 安装失败不删除条目、不逐包重演 route.exe：退避期内后续包只进缓冲，
// 不触发新的安装尝试。
func TestInstallFailureBacksOffWithoutPerPacketExec(t *testing.T) {
	f := newFakeRoutes()
	m, _ := testRouteManager(t, f)
	calls := 0
	m.addRoute = func(dest, gateway string) error {
		calls++
		return fmt.Errorf("模拟安装失败")
	}

	m.deliverInbound(ipv4Packet("1.2.3.4", "10.66.0.2"))
	drainInstalls(m)
	if calls != 1 {
		t.Fatalf("首包只应尝试一次安装，实际 %d 次", calls)
	}

	m.deliverInbound(ipv4Packet("1.2.3.4", "10.66.0.2"))
	drainInstalls(m) // nextTry 在未来，不应触发重试
	if calls != 1 {
		t.Fatalf("退避期内不得重试安装，实际已尝试 %d 次", calls)
	}

	// 条目必须保留且仍为 installing（旧实现失败即删条目，后续每包重演）。
	st := stateOf(m, "1.2.3.4")
	installing := st != nil && st.installing.Load()
	if st == nil || !installing {
		t.Fatal("安装失败后条目必须保留并保持 installing")
	}

	// 退避到期后恢复安装。
	dueNow(m, st)
	m.addRoute = f.add
	drainInstalls(m)
	if !f.has("1.2.3.4") {
		t.Fatal("退避到期后应安装成功")
	}
}

// 安装执行期间条目被回收（prune/cleanup）：刚装上的路由必须立刻撤销，
// 否则留下一条没有状态条目的孤儿 /32，吸走该 IP 全部回包且无人再管。
func TestOrphanRouteRolledBack(t *testing.T) {
	f := newFakeRoutes()
	m, _ := testRouteManager(t, f)
	m.addRoute = func(dest, gateway string) error {
		m.mu.Lock()
		delete(m.states, ra(dest))
		m.publish() // 模拟安装执行期间条目被回收
		m.mu.Unlock()
		return f.add(dest, gateway)
	}
	ensureIP(m, "1.2.3.4")
	drainInstalls(m)

	if f.has("1.2.3.4") {
		t.Fatal("条目已消失时装上的路由必须被撤销（孤儿 /32）")
	}
}

// installBackoff 指数退避并封顶。
func TestInstallBackoffCaps(t *testing.T) {
	cases := map[int]time.Duration{
		0: time.Second, 1: time.Second, 2: 2 * time.Second,
		3: 4 * time.Second, 10: installBackoffMax, 100: installBackoffMax,
	}
	for fails, want := range cases {
		if got := installBackoff(fails); got != want {
			t.Errorf("installBackoff(%d) = %v，应为 %v", fails, got, want)
		}
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

// 缓冲的入站包必须被拷贝：调用方传进来的是解密输出缓冲，下一个包就会覆盖它。
// 不拷贝的话安装完成后代写出去的是「最后一个包重复 N 次」——这类 bug 在
// 单包测试里完全看不出来。
func TestDeliverInboundCopiesBufferedPackets(t *testing.T) {
	f := newFakeRoutes()
	m, w := testRouteManager(t, f)
	m.addRoute = func(string, string) error { return fmt.Errorf("先失败一次，制造缓冲窗口") }

	// 复用同一块缓冲（模拟 pump 的解密输出缓冲）逐包改写内容。
	shared := ipv4Packet("1.2.3.4", "10.66.0.2")
	for i := 0; i < 3; i++ {
		shared[4] = byte(i)
		m.deliverInbound(shared)
	}
	shared[4] = 0xFF // 缓冲被后续包覆盖

	dueNow(m, stateOf(m, "1.2.3.4"))
	m.addRoute = f.add
	drainInstalls(m)

	all := w.all()
	if len(all) != 3 {
		t.Fatalf("应补写 3 个包，实际 %d 个", len(all))
	}
	for i, p := range all {
		if p[4] != byte(i) {
			t.Fatalf("第 %d 个包内容被覆盖成 0x%02X：缓冲未拷贝", i, p[4])
		}
	}
}

// 全局字节闸门：单 IP 上限挡不住伪造源地址洪泛（512 条目 × 32 包 × 1400B
// 可以攒到 20MB+）。达到总量上限后新包一律丢弃，内存占用有确定上界。
func TestPendingBytesGlobalCap(t *testing.T) {
	f := newFakeRoutes()
	m, _ := testRouteManager(t, f)
	m.addRoute = func(string, string) error { return fmt.Errorf("模拟安装失败") }

	// 造足够多的公网源 IP 并各自塞满缓冲。上限 8MB / (32 包 × 1400 字节)
	// ≈ 187 个 IP，所以 250 个必然越过全局闸门。
	big := make([]byte, 1400)
	big[0] = 0x45
	copy(big[16:20], parse4("10.66.0.2"))
	for a := 1; a <= 250; a++ {
		copy(big[12:16], []byte{198, 51, byte(a), 7})
		for i := 0; i < installPendingCap; i++ {
			m.deliverInbound(big)
		}
	}
	if got := m.pendingBytes.Load(); got > pendingBytesMax {
		t.Fatalf("缓冲总字节 %d 超出上限 %d", got, pendingBytesMax)
	}
	if m.PendingDrops() == 0 {
		t.Fatal("达到上限后必须计数丢弃，否则这次卡顿完全不可观测")
	}
}

// 溢出丢弃要按 IP 计数并透出到面板：非零就意味着这个玩家进服时确实卡过。
func TestPendingDropsAreObservable(t *testing.T) {
	f := newFakeRoutes()
	m, _ := testRouteManager(t, f)
	m.addRoute = func(string, string) error { return fmt.Errorf("模拟安装失败") }

	for i := 0; i < installPendingCap+5; i++ {
		m.deliverInbound(ipv4Packet("1.2.3.4", "10.66.0.2"))
	}
	if got := stateOf(m, "1.2.3.4").pendingDrops.Load(); got != 5 {
		t.Fatalf("per-IP 丢弃计数 = %d，期望 5", got)
	}
	if m.PendingDrops() != 5 {
		t.Fatalf("总丢弃计数 = %d，期望 5", m.PendingDrops())
	}
	found := false
	for _, e := range m.view() {
		if e.IP == "1.2.3.4" {
			found = true
			if e.Drops != 5 {
				t.Fatalf("view 里的 drops = %d，期望 5", e.Drops)
			}
		}
	}
	if !found {
		t.Fatal("view 未包含该条目")
	}
}

// 缓冲配额必须在包被写出/丢弃后归还，否则跑一段时间就永久卡在上限上
// （表现为「运行几小时后新玩家进服必卡」）。
func TestPendingBytesReleasedAfterInstall(t *testing.T) {
	f := newFakeRoutes()
	m, _ := testRouteManager(t, f)
	m.addRoute = func(string, string) error { return fmt.Errorf("先失败") }
	for i := 0; i < 4; i++ {
		m.deliverInbound(ipv4Packet("1.2.3.4", "10.66.0.2"))
	}
	if m.pendingBytes.Load() == 0 {
		t.Fatal("缓冲期间应占用配额")
	}
	dueNow(m, stateOf(m, "1.2.3.4"))
	m.addRoute = f.add
	drainInstalls(m)
	if got := m.pendingBytes.Load(); got != 0 {
		t.Fatalf("排空后配额未归还：%d", got)
	}

	// cleanup 路径同样要归还。
	m.addRoute = func(string, string) error { return fmt.Errorf("再失败") }
	m.deliverInbound(ipv4Packet("5.6.7.8", "10.66.0.2"))
	if m.pendingBytes.Load() == 0 {
		t.Fatal("第二轮缓冲应占用配额")
	}
	m.cleanup()
	if got := m.pendingBytes.Load(); got != 0 {
		t.Fatalf("cleanup 后配额未归还：%d", got)
	}
}

// 热路径必须走无锁索引快照：条目增删之后快照要同步，否则数据面看到的是旧表
// （新玩家的包一直走「未登记」慢路径，或已删条目继续被计数）。
func TestIndexSnapshotTracksStates(t *testing.T) {
	f := newFakeRoutes()
	m, _ := testRouteManager(t, f)
	if m.lookup(ra("1.2.3.4")) != nil {
		t.Fatal("未登记的 IP 不该出现在快照里")
	}
	ensureIP(m, "1.2.3.4")
	if m.lookup(ra("1.2.3.4")) == nil {
		t.Fatal("登记后快照必须立即可见（否则每包都走慢路径）")
	}
	drainInstalls(m)
	expire(m, "1.2.3.4")
	m.prune()
	drainRemovals(m)
	if m.lookup(ra("1.2.3.4")) != nil {
		t.Fatal("删除后快照必须同步摘除")
	}
}

// 限频锚点写成 `now-last < sec && !CAS(...)` 会短路跳过 CAS，锚点永不更新，
// 于是每次调用都放行——等于没有限频。这条锁住正确的语义。
func TestThrottleLogActuallyThrottles(t *testing.T) {
	var anchor atomic.Int64
	if !throttleLog(&anchor, 5) {
		t.Fatal("首次应放行")
	}
	if anchor.Load() == 0 {
		t.Fatal("放行后必须更新锚点，否则限频永远不生效")
	}
	for i := 0; i < 3; i++ {
		if throttleLog(&anchor, 5) {
			t.Fatal("窗口内不应再放行")
		}
	}
	// 锚点回拨到窗口之外后应重新放行。
	anchor.Store(time.Now().Unix() - 6)
	if !throttleLog(&anchor, 5) {
		t.Fatal("超过窗口应重新放行")
	}
}

// 快路径（路由已就位）必须零分配：两条数据泵每包都要过这里。
func BenchmarkDeliverInboundFastPath(b *testing.B) {
	f := newFakeRoutes()
	m := &routeManager{
		states:      map[netip.Addr]*routeState{},
		removals:    make(chan netip.Addr, removeQueue),
		installWake: make(chan struct{}, 1),
		relayIP:     ra("203.0.113.1"),
		clientIP:    ra("10.66.0.2"),
		gateway:     ra("10.66.0.1"),
		gatewayStr:  "10.66.0.1",
		logf:        func(string, ...any) {},
		addRoute:    f.add,
		delRoute:    f.del,
		stop:        make(chan struct{}),
	}
	m.states[ra("1.2.3.4")] = newRouteState(time.Now())
	m.publish()

	pkt := ipv4Packet("1.2.3.4", "10.66.0.2")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.deliverInbound(pkt)
	}
}

func BenchmarkCountOutbound(b *testing.B) {
	f := newFakeRoutes()
	m := &routeManager{
		states:      map[netip.Addr]*routeState{},
		removals:    make(chan netip.Addr, removeQueue),
		installWake: make(chan struct{}, 1),
		relayIP:     ra("203.0.113.1"),
		clientIP:    ra("10.66.0.2"),
		gateway:     ra("10.66.0.1"),
		logf:        func(string, ...any) {},
		addRoute:    f.add,
		delRoute:    f.del,
		stop:        make(chan struct{}),
	}
	m.states[ra("1.2.3.4")] = newRouteState(time.Now())
	m.publish()

	pkt := ipv4Packet("10.66.0.2", "1.2.3.4")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.countOutbound(pkt)
	}
}

// 启动清扫：上一轮被强杀留下的 /32 路由必须在任何 ensure 之前删掉。
// 不清扫的话，这些路由吸走该 IP 的全部回包且无人再管——再也不会回来的玩家
// 之后不经代理直连源站也收不到回包。
func TestSweepRemovesStaleRoutesAtStartup(t *testing.T) {
	f := newFakeRoutes()
	m, _ := testRouteManager(t, f)
	swept := []string{}
	m.listStaleRoutes = func(gateway string) ([]string, error) {
		if gateway != "10.66.0.1" {
			t.Errorf("清扫用了错误的网关 %q", gateway)
		}
		return []string{"111.29.236.135", "8.8.8.8"}, nil
	}
	m.delRoute = func(dest string) error {
		swept = append(swept, dest)
		return f.del(dest)
	}

	m.sweepStaleRoutes()

	if len(swept) != 2 || swept[0] != "111.29.236.135" || swept[1] != "8.8.8.8" {
		t.Fatalf("清扫目标 = %v", swept)
	}
	if len(m.states) != 0 {
		t.Fatal("清扫不得创建任何路由状态条目")
	}
	// 清扫后的 ensure 必须照常工作（路由已不在系统里，重新安装是正确行为）。
	ensureIP(m, "111.29.236.135")
	drainInstalls(m)
	if !f.has("111.29.236.135") {
		t.Fatal("清扫后同 IP 的路由应能重新安装")
	}
}

// 清扫是防线的第一道，route add 的幂等收编是兜底：列举失败（权限/解析）时
// 清扫放弃但不能 panic，后续安装照常。
func TestSweepToleratesListingFailure(t *testing.T) {
	f := newFakeRoutes()
	m, _ := testRouteManager(t, f)
	calls := 0
	m.listStaleRoutes = func(string) ([]string, error) {
		calls++
		return nil, fmt.Errorf("模拟 route print 失败")
	}
	m.delRoute = func(dest string) error {
		t.Fatal("列举失败时不得尝试删除")
		return nil
	}

	m.sweepStaleRoutes()
	if calls != 1 {
		t.Fatalf("列举次数 = %d", calls)
	}
}

// 删除失败的单条残留不得阻断其余清扫。
func TestSweepContinuesOnSingleDeleteFailure(t *testing.T) {
	f := newFakeRoutes()
	// 先把两条残留「装进」替身系统：f.has 跟踪的就是这份状态。
	f.add("111.29.236.135", "10.66.0.1")
	f.add("8.8.8.8", "10.66.0.1")
	f.failDel["8.8.8.8"] = 99
	m, _ := testRouteManager(t, f)
	m.listStaleRoutes = staleRouteLister("111.29.236.135", "8.8.8.8")

	m.sweepStaleRoutes()

	if !f.has("8.8.8.8") {
		t.Fatal("删除失败的残留应仍在系统里（替身状态）")
	}
	if f.has("111.29.236.135") {
		t.Fatal("单条失败不应阻断其余清扫")
	}
}

// 清扫时机约束：newRouteManager 里是同步调用，此用例锁「清扫不创建状态、
// 不唤醒安装器」——它只删系统里的东西，与 states 完全解耦。
func TestSweepDoesNotTouchManagerState(t *testing.T) {
	f := newFakeRoutes()
	m, w := testRouteManager(t, f)
	m.listStaleRoutes = staleRouteLister("1.2.3.4")

	m.sweepStaleRoutes()

	if w.count() != 0 {
		t.Fatal("清扫不得经 writeTun 代写任何东西")
	}
	if m.pendingBytes.Load() != 0 || m.PendingDrops() != 0 {
		t.Fatal("清扫不得影响缓冲状态")
	}
}
