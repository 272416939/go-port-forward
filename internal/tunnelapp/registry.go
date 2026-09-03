package tunnelapp

// 多会话表。
//
// 单会话时代这里只有两个原子变量（sessPtr + peerValue），任何持 PSK 的客户端
// 握手都会覆盖它们——那正是「多客户端互相抢占、包在往返但进不去游戏」的根因。
//
// 键的语义是**访问码 ID**，不是用户 ID。一个用户可以有多个访问码，它们各自
// 独立、并存；按用户键会让同一用户的第二台机器把第一台顶掉。
//
// 三个索引各有明确用途，缺一不可：
//   - byCode：保证「一个访问码一条隧道」，重连时替换自己而不影响别的访问码；
//   - byAddr：收包时反查会话。加密数据包里没有会话 ID（协议如此），来源
//     地址是唯一可用的索引键；
//   - byTunIP：TUN 读到的包按目的地址找对应客户端。单会话时代这里是"直接
//     发给唯一 peer"，多会话下必须查表，否则 A 的回包会发给 B。
//
// peerSession 除 lastSeen 外全部字段不可变：重握手时整体替换对象而不是就地
// 改字段，这样数据面读到的快照永远自洽（地址与会话密钥必须成对，改一半会
// 让包发到新端口却用旧密钥加密）。
//
// 三张索引合成一个**不可变快照**，用 atomic.Pointer 发布（OPT-10 COW）：
//   - 读路径（每个入向包一次 byAddress、每个出向包一次 byTunnelIP）零锁零分配；
//   - 写路径（握手 / 踢人 / 30s 空闲扫描）在互斥锁下整体重建快照，成本
//     O(会话数)、频率极低。
//
// byAddr 的键是 netip.AddrPort 而不是 addr.String()（OPT-4）：字符串键要为
// **每个入向包**格式化一次 IP 字符串，那是除加解密外最热的一处分配。
// AddrPort 可比较、可作 map 键、构造零分配。

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"go-port-forward/pkg/tunnel"
)

// peerIdleTimeout 是会话的空闲回收阈值。
//
// 必须远大于客户端的重握手周期（10 秒无入站包即重握手）与心跳间隔（5 秒），
// 否则会把活着的会话回收掉；也不能无上限，否则换了网络的客户端会永久留下
// 一个僵尸槽位，占着它的隧道地址索引。
const peerIdleTimeout = 3 * time.Minute

// peerSession 是一个已握手的客户端会话。
type peerSession struct {
	codeID   string
	codeName string
	userID   string
	userName string
	tunIP    netip.Addr
	sess     *tunnel.Session
	addr     *net.UDPAddr
	// addrPort 是 addr 的可比较形态，构造时算一次。数据面只读它（查表键、
	// 批量发送的目的地址），*net.UDPAddr 只留给需要 net.Addr 的写 API。
	addrPort netip.AddrPort
	since    time.Time
	lastSeen atomic.Int64 // Unix 秒
	// lastTouch 是最近一次把活跃时间写回存储的时刻（Unix 秒），用于限频。
	lastTouch atomic.Int64
	// mtu 是本会话协商的隧道 MTU（出向超过它的包无法转发，计入统计）。
	mtu int
	// ctrlOut 是 Pong 应答的封装缓冲。Pong 只由入向泵单 goroutine 发出，
	// 可以安全复用；心跳与路由推送各有自己的缓冲。
	ctrlOut []byte
}

func newPeerSession(ident Identity, sess *tunnel.Session, addr *net.UDPAddr, mtu int) *peerSession {
	ps := &peerSession{
		codeID:   ident.CodeID,
		codeName: ident.CodeName,
		userID:   ident.UserID,
		userName: ident.UserName,
		tunIP:    ident.TunIP,
		sess:     sess,
		addr:     cloneUDPAddr(addr),
		addrPort: addrPortOf(addr),
		since:    time.Now(),
		mtu:      mtu,
		ctrlOut:  make([]byte, 0, 64+tunnel.NonceSize),
	}
	ps.touch()
	return ps
}

func (p *peerSession) touch() { p.lastSeen.Store(time.Now().Unix()) }

func (p *peerSession) idleFor(now time.Time) time.Duration {
	return now.Sub(time.Unix(p.lastSeen.Load(), 0))
}

// shouldPersistTouch 报告是否该把活跃时间写回存储（每 sec 秒最多一次）。
//
// 数据面上每个包都写 bbolt 会把 fsync 拖进转发热路径，所以这里必须限频。
func (p *peerSession) shouldPersistTouch(sec int64) bool {
	now := time.Now().Unix()
	last := p.lastTouch.Load()
	if now-last < sec {
		return false
	}
	return p.lastTouch.CompareAndSwap(last, now)
}

// cloneUDPAddr 复制来源地址。ReadFromUDP 返回的 *UDPAddr 可能被复用，
// 直接存进会话表会导致后续读操作篡改已保存的 peer 地址。
func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	out := &net.UDPAddr{Port: a.Port, Zone: a.Zone}
	if a.IP != nil {
		out.IP = append(net.IP(nil), a.IP...)
	}
	return out
}

// addrPortOf 把 *net.UDPAddr 转成可比较的 netip.AddrPort。
//
// Unmap 归一 v4-in-v6 映射：监听的是 "udp"（双栈），同一个 IPv4 客户端在不同
// 内核路径下可能以 ::ffff:1.2.3.4 或 1.2.3.4 的形态出现，不归一会让同一个
// 客户端在表里占两个键——症状是「换端口重连之后包发到旧地址」。
func addrPortOf(a *net.UDPAddr) netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip.Unmap().WithZone(a.Zone), uint16(a.Port))
}

// udpAddrOf 把 AddrPort 还原成 *net.UDPAddr（低频写路径用）。
func udpAddrOf(ap netip.AddrPort) *net.UDPAddr {
	return &net.UDPAddr{IP: ap.Addr().AsSlice(), Port: int(ap.Port()), Zone: ap.Addr().Zone()}
}

// peerIndex 是三张索引的不可变快照。写路径整体重建，读路径只 Load 不加锁。
type peerIndex struct {
	byCode  map[string]*peerSession
	byAddr  map[netip.AddrPort]*peerSession
	byTunIP map[netip.Addr]*peerSession
}

func (ix *peerIndex) clone() *peerIndex {
	out := &peerIndex{
		byCode:  make(map[string]*peerSession, len(ix.byCode)+1),
		byAddr:  make(map[netip.AddrPort]*peerSession, len(ix.byAddr)+1),
		byTunIP: make(map[netip.Addr]*peerSession, len(ix.byTunIP)+1),
	}
	for k, v := range ix.byCode {
		out.byCode[k] = v
	}
	for k, v := range ix.byAddr {
		out.byAddr[k] = v
	}
	for k, v := range ix.byTunIP {
		out.byTunIP[k] = v
	}
	return out
}

// registry 是会话表。
type registry struct {
	mu sync.Mutex // 只保护写路径（快照重建）
	ix atomic.Pointer[peerIndex]
}

func newRegistry() *registry {
	r := &registry{}
	r.ix.Store(&peerIndex{
		byCode:  make(map[string]*peerSession),
		byAddr:  make(map[netip.AddrPort]*peerSession),
		byTunIP: make(map[netip.Addr]*peerSession),
	})
	return r
}

// upsert 安装一个新会话，返回被它取代的旧会话（同一访问码的上一次握手）。
//
// 只动该访问码自己的槽位。附带清掉旧会话留在 byAddr/byTunIP 里的索引——
// 客户端换了 NAT 端口时旧地址键若不删除，会长期留下一个指向已废弃密钥的
// 僵尸条目。
func (r *registry) upsert(ps *peerSession) *peerSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	next := r.ix.Load().clone()
	prev := next.byCode[ps.codeID]
	if prev != nil {
		delete(next.byAddr, prev.addrPort)
		if cur, ok := next.byTunIP[prev.tunIP]; ok && cur == prev {
			delete(next.byTunIP, prev.tunIP)
		}
	}
	next.byCode[ps.codeID] = ps
	next.byAddr[ps.addrPort] = ps
	next.byTunIP[ps.tunIP] = ps
	r.ix.Store(next)
	return prev
}

// byAddress 按来源地址查会话（数据包解密入口）。零锁零分配。
func (r *registry) byAddress(ap netip.AddrPort) *peerSession {
	if !ap.IsValid() {
		return nil
	}
	return r.ix.Load().byAddr[ap]
}

// byTunnelIP 按隧道内地址查会话（TUN → 客户端 分流）。零锁零分配。
func (r *registry) byTunnelIP(ip netip.Addr) *peerSession {
	return r.ix.Load().byTunIP[ip]
}

// online 报告某访问码当前是否有在线会话。
func (r *registry) online(codeID string) bool {
	_, ok := r.ix.Load().byCode[codeID]
	return ok
}

// countByUser 返回某用户当前在线的隧道数（并发隧道上限判定用）。
func (r *registry) countByUser(userID string) int {
	n := 0
	for _, ps := range r.ix.Load().byCode {
		if ps.userID == userID {
			n++
		}
	}
	return n
}

// snapshot 返回全部会话（心跳与路由推送遍历用）。
func (r *registry) snapshot() []*peerSession {
	ix := r.ix.Load()
	out := make([]*peerSession, 0, len(ix.byCode))
	for _, ps := range ix.byCode {
		out = append(out, ps)
	}
	return out
}

// evict 摘除某访问码的会话（解绑设备、停用访问码时调用）。
//
// 解绑后必须立刻踢掉在线隧道：不踢的话旧设备还在跑，用户以为已经换到新机器，
// 结果两台机器抢同一个隧道地址。
func (r *registry) evict(codeID string) *peerSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.ix.Load()
	ps := cur.byCode[codeID]
	if ps == nil {
		return nil
	}
	next := cur.clone()
	delete(next.byCode, codeID)
	delete(next.byAddr, ps.addrPort)
	if got, ok := next.byTunIP[ps.tunIP]; ok && got == ps {
		delete(next.byTunIP, ps.tunIP)
	}
	r.ix.Store(next)
	return ps
}

// reap 回收空闲超时的会话，返回被摘除的列表。
//
// 遵循「事件负责建立、时间负责回收」：握手事件建立会话，只有时间能删除它。
// 反过来（按某个周期性推送的列表判定存活）会把短交互的会话反复掐断。
func (r *registry) reap(now time.Time, idle time.Duration) []*peerSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.ix.Load()
	var dead []*peerSession
	for _, ps := range cur.byCode {
		if ps.idleFor(now) > idle {
			dead = append(dead, ps)
		}
	}
	if len(dead) == 0 {
		return nil // 常态：不重建快照，避免每 30 秒制造一次垃圾
	}
	next := cur.clone()
	for _, ps := range dead {
		delete(next.byCode, ps.codeID)
		delete(next.byAddr, ps.addrPort)
		if got, ok := next.byTunIP[ps.tunIP]; ok && got == ps {
			delete(next.byTunIP, ps.tunIP)
		}
	}
	r.ix.Store(next)
	return dead
}

// count 返回在线会话数。
func (r *registry) count() int {
	return len(r.ix.Load().byCode)
}

// srcIP4 取 IPv4 包的源地址；非 IPv4 或长度不足返回无效地址。
func srcIP4(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}), true
}

// dstIP4 取 IPv4 包的目的地址。
func dstIP4(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}), true
}
