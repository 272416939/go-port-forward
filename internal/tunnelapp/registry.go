package tunnelapp

// 多用户会话表。
//
// 单会话时代这里只有两个原子变量（sessPtr + peerValue），任何持 PSK 的客户端
// 握手都会覆盖它们——那正是「多客户端互相抢占、包在往返但进不去游戏」的根因。
// 多用户下每个用户占一个独立槽位，握手只替换自己那一格。
//
// 三个索引各有明确用途，缺一不可：
//   - byUser：保证「一个用户一条隧道」，重连时替换自己而不影响别人；
//   - byAddr：收包时反查会话。加密数据包里没有会话 ID（协议如此），来源
//     地址是唯一可用的索引键；
//   - byTunIP：TUN 读到的包按目的地址找对应客户端。单会话时代这里是"直接
//     发给唯一 peer"，多用户下必须查表，否则 A 的回包会发给 B。
//
// peerSession 除 lastSeen 外全部字段不可变：重握手时整体替换对象而不是就地
// 改字段，这样数据面读到的快照永远自洽（地址与会话密钥必须成对，改一半会
// 让包发到新端口却用旧密钥加密）。

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
// 必须远大于客户端的重握手周期（30 秒无入站包即重握手）与心跳间隔（5 秒），
// 否则会把活着的会话回收掉；也不能无上限，否则换了网络的客户端会永久留下
// 一个僵尸槽位，占着它的隧道地址索引。
const peerIdleTimeout = 3 * time.Minute

// peerSession 是一个已握手的客户端会话。
type peerSession struct {
	userID   string
	userName string
	tunIP    netip.Addr
	sess     *tunnel.Session
	addr     *net.UDPAddr
	since    time.Time
	lastSeen atomic.Int64 // Unix 秒
}

func newPeerSession(userID, userName string, tunIP netip.Addr, sess *tunnel.Session, addr *net.UDPAddr) *peerSession {
	ps := &peerSession{
		userID:   userID,
		userName: userName,
		tunIP:    tunIP,
		sess:     sess,
		addr:     cloneUDPAddr(addr),
		since:    time.Now(),
	}
	ps.touch()
	return ps
}

func (p *peerSession) touch() { p.lastSeen.Store(time.Now().Unix()) }

func (p *peerSession) idleFor(now time.Time) time.Duration {
	return now.Sub(time.Unix(p.lastSeen.Load(), 0))
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

// registry 是会话表。
type registry struct {
	mu      sync.RWMutex
	byUser  map[string]*peerSession
	byAddr  map[string]*peerSession
	byTunIP map[netip.Addr]*peerSession
}

func newRegistry() *registry {
	return &registry{
		byUser:  make(map[string]*peerSession),
		byAddr:  make(map[string]*peerSession),
		byTunIP: make(map[netip.Addr]*peerSession),
	}
}

// upsert 安装一个新会话，返回被它取代的旧会话（同一用户的上一次握手）。
//
// 只动该用户自己的槽位。附带清掉旧会话留在 byAddr/byTunIP 里的索引——
// 客户端换了 NAT 端口时旧地址键若不删除，会长期留下一个指向已废弃密钥的
// 僵尸条目。
func (r *registry) upsert(ps *peerSession) *peerSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	prev := r.byUser[ps.userID]
	if prev != nil {
		delete(r.byAddr, prev.addr.String())
		if cur, ok := r.byTunIP[prev.tunIP]; ok && cur == prev {
			delete(r.byTunIP, prev.tunIP)
		}
	}
	r.byUser[ps.userID] = ps
	r.byAddr[ps.addr.String()] = ps
	r.byTunIP[ps.tunIP] = ps
	return prev
}

// byAddress 按来源地址查会话（数据包解密入口）。
func (r *registry) byAddress(addr *net.UDPAddr) *peerSession {
	if addr == nil {
		return nil
	}
	key := addr.String()
	r.mu.RLock()
	ps := r.byAddr[key]
	r.mu.RUnlock()
	return ps
}

// byTunnelIP 按隧道内地址查会话（TUN → 客户端 分流）。
func (r *registry) byTunnelIP(ip netip.Addr) *peerSession {
	r.mu.RLock()
	ps := r.byTunIP[ip]
	r.mu.RUnlock()
	return ps
}

// snapshot 返回全部会话（心跳与路由推送遍历用）。
func (r *registry) snapshot() []*peerSession {
	r.mu.RLock()
	out := make([]*peerSession, 0, len(r.byUser))
	for _, ps := range r.byUser {
		out = append(out, ps)
	}
	r.mu.RUnlock()
	return out
}

// reap 回收空闲超时的会话，返回被摘除的列表。
//
// 遵循「事件负责建立、时间负责回收」：握手事件建立会话，只有时间能删除它。
// 反过来（按某个周期性推送的列表判定存活）会把短交互的会话反复掐断。
func (r *registry) reap(now time.Time, idle time.Duration) []*peerSession {
	var dead []*peerSession
	r.mu.Lock()
	for _, ps := range r.byUser {
		if ps.idleFor(now) > idle {
			dead = append(dead, ps)
		}
	}
	for _, ps := range dead {
		delete(r.byUser, ps.userID)
		delete(r.byAddr, ps.addr.String())
		if cur, ok := r.byTunIP[ps.tunIP]; ok && cur == ps {
			delete(r.byTunIP, ps.tunIP)
		}
	}
	r.mu.Unlock()
	return dead
}

// count 返回在线会话数。
func (r *registry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byUser)
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
