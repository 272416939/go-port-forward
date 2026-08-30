package tunnelapp

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"go-port-forward/pkg/tunnel"
)

func testSession() *tunnel.Session {
	return tunnel.NewSession(tunnel.DeriveSessionKey(tunnel.ECDHShared(&[32]byte{}, &[32]byte{}), []byte("k")))
}

func udpAddr(t *testing.T, s string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// mkPS 造一个测试会话：codeID 决定槽位，userID 决定并发隧道计数的归属。
func mkPS(t *testing.T, codeID, codeName, userID, userName string, tunIP netip.Addr, addr string) *peerSession {
	t.Helper()
	ident := Identity{
		CodeID: codeID, CodeName: codeName,
		UserID: userID, UserName: userName,
		TunIP: tunIP,
	}
	return newPeerSession(ident, testSession(), udpAddr(t, addr))
}

// 多访问码的核心保证：一个访问码握手不得影响另一个访问码的会话——即使它们
// 属于同一个用户。单会话时代 A 接入就会覆盖唯一槽位，B 的密钥立即失效且它
// 自己不知道。
func TestRegistryIsolatesCodes(t *testing.T) {
	r := newRegistry()
	a := mkPS(t, "code-a", "a", "u-alice", "alice", netip.MustParseAddr("10.66.0.2"), "203.0.113.5:1000")
	b := mkPS(t, "code-b", "b", "u-alice", "alice", netip.MustParseAddr("10.66.0.3"), "203.0.113.6:1001")

	if prev := r.upsert(a); prev != nil {
		t.Fatal("首次 upsert 不应返回旧会话")
	}
	if prev := r.upsert(b); prev != nil {
		t.Fatal("同一用户另一个访问码的 upsert 不应返回旧会话")
	}
	if r.count() != 2 {
		t.Fatalf("count = %d, want 2（同一用户的两个访问码必须并存）", r.count())
	}
	if got := r.byAddress(udpAddr(t, "203.0.113.5:1000")); got != a {
		t.Fatal("A 的地址索引被破坏")
	}
	if got := r.byAddress(udpAddr(t, "203.0.113.6:1001")); got != b {
		t.Fatal("B 的地址索引被破坏")
	}
	if got := r.byTunnelIP(netip.MustParseAddr("10.66.0.3")); got != b {
		t.Fatal("B 的隧道地址索引被破坏")
	}
}

// 并发隧道上限的数据源：按用户统计在线数。同一用户的多个访问码各计一个。
func TestCountByUser(t *testing.T) {
	r := newRegistry()
	r.upsert(mkPS(t, "code-a", "a", "u-alice", "alice", netip.MustParseAddr("10.66.0.2"), "203.0.113.5:1000"))
	r.upsert(mkPS(t, "code-b", "b", "u-alice", "alice", netip.MustParseAddr("10.66.0.3"), "203.0.113.6:1001"))
	r.upsert(mkPS(t, "code-c", "c", "u-bob", "bob", netip.MustParseAddr("10.66.0.4"), "203.0.113.7:1002"))

	if got := r.countByUser("u-alice"); got != 2 {
		t.Fatalf("alice 在线数 = %d, want 2", got)
	}
	if got := r.countByUser("u-bob"); got != 1 {
		t.Fatalf("bob 在线数 = %d, want 1", got)
	}
	if got := r.countByUser("nobody"); got != 0 {
		t.Fatalf("未知用户在线数 = %d, want 0", got)
	}
}

func TestRegistryOnline(t *testing.T) {
	r := newRegistry()
	r.upsert(mkPS(t, "code-a", "a", "u1", "u", netip.MustParseAddr("10.66.0.2"), "203.0.113.5:1000"))
	if !r.online("code-a") {
		t.Fatal("code-a 应显示在线")
	}
	if r.online("code-z") {
		t.Fatal("未知访问码不应显示在线")
	}
}

// 同一访问码重握手（常见于 NAT 端口漂移）必须替换自己的槽位，并且不留下
// 指向旧密钥的僵尸地址索引——旧索引会让服务端拿废弃会话去解密新包。
func TestRegistryReplacesSameCodeAndDropsStaleAddr(t *testing.T) {
	r := newRegistry()
	tunIP := netip.MustParseAddr("10.66.0.2")
	old := mkPS(t, "code-a", "a", "u1", "u", tunIP, "203.0.113.5:1000")
	r.upsert(old)

	fresh := mkPS(t, "code-a", "a", "u1", "u", tunIP, "203.0.113.5:2000")
	prev := r.upsert(fresh)
	if prev != old {
		t.Fatal("重握手应返回被取代的旧会话")
	}
	if r.count() != 1 {
		t.Fatalf("count = %d, want 1", r.count())
	}
	if got := r.byAddress(udpAddr(t, "203.0.113.5:1000")); got != nil {
		t.Fatal("旧来源地址索引未清理，会留下僵尸会话")
	}
	if got := r.byAddress(udpAddr(t, "203.0.113.5:2000")); got != fresh {
		t.Fatal("新来源地址索引未建立")
	}
	if got := r.byTunnelIP(tunIP); got != fresh {
		t.Fatal("隧道地址索引未指向新会话")
	}
}

// 一个访问码重握手时另一个访问码必须毫发无损。
func TestRegistryRehandshakeDoesNotEvictOthers(t *testing.T) {
	r := newRegistry()
	a := mkPS(t, "code-a", "a", "u1", "u", netip.MustParseAddr("10.66.0.2"), "203.0.113.5:1000")
	b := mkPS(t, "code-b", "b", "u2", "v", netip.MustParseAddr("10.66.0.3"), "203.0.113.6:1001")
	r.upsert(a)
	r.upsert(b)

	r.upsert(mkPS(t, "code-a", "a", "u1", "u", netip.MustParseAddr("10.66.0.2"), "203.0.113.5:3000"))

	if got := r.byAddress(udpAddr(t, "203.0.113.6:1001")); got != b {
		t.Fatal("B 的会话被 A 的重握手挤掉了")
	}
	if got := r.byTunnelIP(netip.MustParseAddr("10.66.0.3")); got != b {
		t.Fatal("B 的隧道地址索引被 A 的重握手破坏")
	}
}

// 解绑设备时要能精确踢掉那个访问码的会话，且不影响其它会话。
func TestRegistryEvictCode(t *testing.T) {
	r := newRegistry()
	a := mkPS(t, "code-a", "a", "u1", "u", netip.MustParseAddr("10.66.0.2"), "203.0.113.5:1000")
	b := mkPS(t, "code-b", "b", "u1", "u", netip.MustParseAddr("10.66.0.3"), "203.0.113.6:1001")
	r.upsert(a)
	r.upsert(b)

	if r.evict("code-nothing") != nil {
		t.Fatal("踢不存在的会话应返回 nil")
	}
	if got := r.evict("code-a"); got != a {
		t.Fatal("应返回被踢掉的会话")
	}
	if r.count() != 1 || r.byTunnelIP(netip.MustParseAddr("10.66.0.3")) != b {
		t.Fatal("踢掉 code-a 影响了 code-b")
	}
	// 再踢一次是空操作（幂等）。
	if r.evict("code-a") != nil {
		t.Fatal("重复踢应是空操作")
	}
}

// 空闲回收：只有时间能删除会话，且必须同时清掉三个索引。
func TestRegistryReapIdle(t *testing.T) {
	r := newRegistry()
	tunIP := netip.MustParseAddr("10.66.0.2")
	ps := mkPS(t, "code-a", "a", "u1", "u", tunIP, "203.0.113.5:1000")
	r.upsert(ps)

	now := time.Now()
	if dead := r.reap(now, time.Minute); len(dead) != 0 {
		t.Fatal("刚活跃的会话不应被回收")
	}
	// 把 lastSeen 推回 10 分钟前。
	ps.lastSeen.Store(now.Add(-10 * time.Minute).Unix())
	dead := r.reap(now, 3*time.Minute)
	if len(dead) != 1 || dead[0] != ps {
		t.Fatalf("空闲会话未被回收：%v", dead)
	}
	if r.count() != 0 || r.byAddress(udpAddr(t, "203.0.113.5:1000")) != nil || r.byTunnelIP(tunIP) != nil {
		t.Fatal("回收后索引未清空")
	}
}

// touch 之后不应再被回收（收到任何有效包即视为活跃）。
func TestRegistryTouchKeepsAlive(t *testing.T) {
	r := newRegistry()
	ps := mkPS(t, "code-a", "a", "u1", "u", netip.MustParseAddr("10.66.0.2"), "203.0.113.5:1000")
	r.upsert(ps)
	ps.lastSeen.Store(time.Now().Add(-10 * time.Minute).Unix())
	ps.touch()
	if dead := r.reap(time.Now(), 3*time.Minute); len(dead) != 0 {
		t.Fatal("touch 后的会话被误回收")
	}
}

// 回收只针对当前生效的会话：重握手后旧对象已不在表里，reap 不能因为它空闲
// 就把接替它的新会话一起摘掉。
func TestReapIgnoresReplacedSession(t *testing.T) {
	r := newRegistry()
	tunIP := netip.MustParseAddr("10.66.0.2")
	old := mkPS(t, "code-a", "a", "u1", "u", tunIP, "203.0.113.5:1000")
	r.upsert(old)
	fresh := mkPS(t, "code-a", "a", "u1", "u", tunIP, "203.0.113.5:2000")
	r.upsert(fresh)

	// 旧对象空闲很久，但它已被替换、不在表里。
	old.lastSeen.Store(time.Now().Add(-time.Hour).Unix())
	if dead := r.reap(time.Now(), 3*time.Minute); len(dead) != 0 {
		t.Fatalf("已被替换的会话不应影响回收：%v", dead)
	}
	if r.byTunnelIP(tunIP) != fresh {
		t.Fatal("当前会话被误删")
	}
}

// 来源地址必须复制：ReadFromUDP 返回的 *UDPAddr 会被后续读操作复用，
// 直接存进会话表会让已保存的 peer 地址被下一个包篡改。
func TestPeerSessionClonesAddr(t *testing.T) {
	shared := udpAddr(t, "203.0.113.5:1000")
	ps := mkPS(t, "code-a", "a", "u1", "u", netip.MustParseAddr("10.66.0.2"), "203.0.113.5:1000")
	shared.IP = net.ParseIP("198.51.100.9")
	shared.Port = 65000
	if ps.addr.String() != "203.0.113.5:1000" {
		t.Fatalf("会话地址被外部修改污染：%v", ps.addr)
	}
}

// 落盘活跃时间的限频：60 秒内只放行一次，否则每个包都会触发一次 bbolt 写。
func TestPeerSessionPersistTouchThrottle(t *testing.T) {
	ps := mkPS(t, "code-a", "a", "u1", "u", netip.MustParseAddr("10.66.0.2"), "203.0.113.5:1000")
	if !ps.shouldPersistTouch(60) {
		t.Fatal("首次应放行")
	}
	if ps.shouldPersistTouch(60) {
		t.Fatal("60 秒内第二次应被限频")
	}
}

func TestIPHeaderHelpers(t *testing.T) {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	copy(pkt[12:16], []byte{10, 66, 0, 2})
	copy(pkt[16:20], []byte{203, 0, 113, 7})

	if src, ok := srcIP4(pkt); !ok || src != netip.MustParseAddr("10.66.0.2") {
		t.Fatalf("srcIP4 = %v, %v", src, ok)
	}
	if dst, ok := dstIP4(pkt); !ok || dst != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("dstIP4 = %v, %v", dst, ok)
	}
	if _, ok := srcIP4(pkt[:19]); ok {
		t.Fatal("过短的包必须被拒")
	}
	pkt[0] = 0x60 // IPv6
	if _, ok := dstIP4(pkt); ok {
		t.Fatal("非 IPv4 必须被拒")
	}
}

// 推送记录按访问码各记一份：A 的 IP 集合变化不应让 B 被误判为「已变更」。
func TestPushSigPerCode(t *testing.T) {
	s := &Server{pushPrev: make(map[string][]string)}
	if _, changed := s.diffPushed("code-a", []string{"1.1.1.1"}); !changed {
		t.Fatal("首次记录应判为变化")
	}
	if _, changed := s.diffPushed("code-a", []string{"1.1.1.1"}); changed {
		t.Fatal("相同集合应判为未变化")
	}
	if _, changed := s.diffPushed("code-b", []string{"1.1.1.1"}); !changed {
		t.Fatal("另一个访问码的首次记录应判为变化")
	}
	if _, changed := s.diffPushed("code-a", []string{"1.1.1.1"}); changed {
		t.Fatal("B 的记录不应影响 A 的判定")
	}
	// 重握手后必须重推：新会话对端的路由表是空的。
	s.forgetPushed("code-a")
	if _, changed := s.diffPushed("code-a", []string{"1.1.1.1"}); !changed {
		t.Fatal("重握手后应重新判为变化")
	}
}

// 顺序不同不算变化：会话 IP 来自 map 遍历，顺序天然不稳定，不归一化会让每轮
// 推送都被误判为「变更」并打一条 info（正是要消掉的刷屏）。
func TestDiffPushedIgnoresOrder(t *testing.T) {
	s := &Server{pushPrev: make(map[string][]string)}
	s.diffPushed("c", []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"})
	gone, changed := s.diffPushed("c", []string{"3.3.3.3", "1.1.1.1", "2.2.2.2"})
	if changed || len(gone) > 0 {
		t.Fatalf("同一集合不同顺序被判为变化：gone=%v changed=%v", gone, changed)
	}
}

// 「上轮在、本轮不在」才是可信的会话结束事件——客户端据此走短宽限期回收
// /32 路由。首次推送不得产出 gone（对端路由表本来就是空的）。
func TestDiffPushedReportsGone(t *testing.T) {
	s := &Server{pushPrev: make(map[string][]string)}

	if gone, _ := s.diffPushed("c", []string{"1.1.1.1", "2.2.2.2"}); len(gone) > 0 {
		t.Fatalf("首次推送不应产出结束集合：%v", gone)
	}
	gone, changed := s.diffPushed("c", []string{"1.1.1.1"})
	if !changed {
		t.Fatal("集合缩小应判为变化")
	}
	if len(gone) != 1 || gone[0] != "2.2.2.2" {
		t.Fatalf("结束集合 = %v，应为 [2.2.2.2]", gone)
	}

	// 全部结束（空列表）同样要产出——这正是最需要客户端清残留路由的时刻。
	gone, changed = s.diffPushed("c", nil)
	if !changed || len(gone) != 1 || gone[0] != "1.1.1.1" {
		t.Fatalf("清空后 gone = %v changed = %v", gone, changed)
	}
	// 已经空了，再推一轮不应重复通知。
	if gone, changed := s.diffPushed("c", nil); changed || len(gone) > 0 {
		t.Fatalf("重复的空集合不应再通知：gone=%v changed=%v", gone, changed)
	}
}

// 新增来源不产出 gone：那是「活跃」正向语义，删除只由缺席差集与本地时间驱动。
func TestDiffPushedGrowthHasNoGone(t *testing.T) {
	s := &Server{pushPrev: make(map[string][]string)}
	s.diffPushed("c", []string{"1.1.1.1"})
	gone, changed := s.diffPushed("c", []string{"1.1.1.1", "2.2.2.2"})
	if !changed {
		t.Fatal("集合新增应判为变化")
	}
	if len(gone) > 0 {
		t.Fatalf("新增来源不应产出结束集合：%v", gone)
	}
}

// 不得就地修改入参：调用方传的是活跃会话快照，排序会打乱其它使用者看到的顺序。
func TestDiffPushedDoesNotMutateInput(t *testing.T) {
	s := &Server{pushPrev: make(map[string][]string)}
	ips := []string{"3.3.3.3", "1.1.1.1", "2.2.2.2"}
	s.diffPushed("c", ips)
	if ips[0] != "3.3.3.3" {
		t.Errorf("入参被就地排序了：%v", ips)
	}
}

func TestParseTunAddr(t *testing.T) {
	pool, gw, err := parseTunAddr("10.66.0.1/16")
	if err != nil {
		t.Fatal(err)
	}
	if pool.String() != "10.66.0.0/16" || gw != netip.MustParseAddr("10.66.0.1") {
		t.Fatalf("pool=%v gw=%v", pool, gw)
	}
	if !pool.Contains(netip.MustParseAddr("10.66.0.200")) {
		t.Fatal("网段应包含 10.66.0.200")
	}
	if _, _, err := parseTunAddr("nonsense"); err == nil {
		t.Fatal("非法网段必须报错")
	}
	if _, _, err := parseTunAddr("fd00::1/64"); err == nil {
		t.Fatal("IPv6 网段必须被拒")
	}
}

func TestThrottle(t *testing.T) {
	var anchor atomic.Int64
	if !throttle(&anchor, 5) {
		t.Fatal("首次应放行")
	}
	if throttle(&anchor, 5) {
		t.Fatal("5 秒内第二次应被限频")
	}
}
