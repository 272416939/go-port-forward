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

// 多用户的核心保证：用户 A 握手不得影响用户 B 的会话。
// 单会话时代 A 接入就会覆盖唯一槽位，B 的密钥立即失效且它自己不知道。
func TestRegistryIsolatesUsers(t *testing.T) {
	r := newRegistry()
	a := newPeerSession("uid-a", "alice", netip.MustParseAddr("10.66.0.2"), testSession(), udpAddr(t, "203.0.113.5:1000"))
	b := newPeerSession("uid-b", "bob", netip.MustParseAddr("10.66.0.3"), testSession(), udpAddr(t, "203.0.113.6:1001"))

	if prev := r.upsert(a); prev != nil {
		t.Fatal("首次 upsert 不应返回旧会话")
	}
	if prev := r.upsert(b); prev != nil {
		t.Fatal("另一个用户的 upsert 不应返回旧会话")
	}
	if r.count() != 2 {
		t.Fatalf("count = %d, want 2", r.count())
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

// 同一用户重握手（常见于 NAT 端口漂移）必须替换自己的槽位，并且不留下
// 指向旧密钥的僵尸地址索引——旧索引会让服务端拿废弃会话去解密新包。
func TestRegistryReplacesSameUserAndDropsStaleAddr(t *testing.T) {
	r := newRegistry()
	tunIP := netip.MustParseAddr("10.66.0.2")
	old := newPeerSession("uid-a", "alice", tunIP, testSession(), udpAddr(t, "203.0.113.5:1000"))
	r.upsert(old)

	fresh := newPeerSession("uid-a", "alice", tunIP, testSession(), udpAddr(t, "203.0.113.5:2000"))
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

// 一个用户重握手时另一个用户必须毫发无损。
func TestRegistryRehandshakeDoesNotEvictOthers(t *testing.T) {
	r := newRegistry()
	a := newPeerSession("uid-a", "alice", netip.MustParseAddr("10.66.0.2"), testSession(), udpAddr(t, "203.0.113.5:1000"))
	b := newPeerSession("uid-b", "bob", netip.MustParseAddr("10.66.0.3"), testSession(), udpAddr(t, "203.0.113.6:1001"))
	r.upsert(a)
	r.upsert(b)

	r.upsert(newPeerSession("uid-a", "alice", netip.MustParseAddr("10.66.0.2"), testSession(), udpAddr(t, "203.0.113.5:3000")))

	if got := r.byAddress(udpAddr(t, "203.0.113.6:1001")); got != b {
		t.Fatal("B 的会话被 A 的重握手挤掉了")
	}
	if got := r.byTunnelIP(netip.MustParseAddr("10.66.0.3")); got != b {
		t.Fatal("B 的隧道地址索引被 A 的重握手破坏")
	}
}

// 空闲回收：只有时间能删除会话，且必须同时清掉三个索引。
func TestRegistryReapIdle(t *testing.T) {
	r := newRegistry()
	tunIP := netip.MustParseAddr("10.66.0.2")
	ps := newPeerSession("uid-a", "alice", tunIP, testSession(), udpAddr(t, "203.0.113.5:1000"))
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
	ps := newPeerSession("uid-a", "alice", netip.MustParseAddr("10.66.0.2"), testSession(), udpAddr(t, "203.0.113.5:1000"))
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
	old := newPeerSession("uid-a", "alice", tunIP, testSession(), udpAddr(t, "203.0.113.5:1000"))
	r.upsert(old)
	fresh := newPeerSession("uid-a", "alice", tunIP, testSession(), udpAddr(t, "203.0.113.5:2000"))
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
	ps := newPeerSession("uid-a", "alice", netip.MustParseAddr("10.66.0.2"), testSession(), shared)
	shared.IP = net.ParseIP("198.51.100.9")
	shared.Port = 65000
	if ps.addr.String() != "203.0.113.5:1000" {
		t.Fatalf("会话地址被外部修改污染：%v", ps.addr)
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

// 推送指纹按用户各记一份：A 的 IP 集合变化不应让 B 被误判为「已变更」。
func TestPushSigPerUser(t *testing.T) {
	s := &Server{pushSigs: make(map[string]string)}
	if !s.recordPushSig("uid-a", "1.1.1.1") {
		t.Fatal("首次记录应判为变化")
	}
	if s.recordPushSig("uid-a", "1.1.1.1") {
		t.Fatal("相同指纹应判为未变化")
	}
	if !s.recordPushSig("uid-b", "1.1.1.1") {
		t.Fatal("另一个用户的首次记录应判为变化")
	}
	if s.recordPushSig("uid-a", "1.1.1.1") {
		t.Fatal("B 的记录不应影响 A 的判定")
	}
	// 重握手后必须重推：新会话对端的路由表是空的。
	s.forgetPushSig("uid-a")
	if !s.recordPushSig("uid-a", "1.1.1.1") {
		t.Fatal("重握手后应重新判为变化")
	}
}

func TestParseTunAddr(t *testing.T) {
	pool, gw, err := parseTunAddr("10.66.0.1/24")
	if err != nil {
		t.Fatal(err)
	}
	if pool.String() != "10.66.0.0/24" || gw != netip.MustParseAddr("10.66.0.1") {
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
