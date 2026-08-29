// Package tunnelapp 内置隧道服务端：为 Windows 端 pf-client 提供加密隧道
// 与回程路径（TUN + 策略路由本机投递），并周期把 go-port-forward 活跃会话的
// 来源 IP 推送给客户端维护 /32 回程路由。开启 tunnel.enabled 后随主程序
// 常驻，无需单独的 pf-server 进程。
//
// 多用户：每个隧道用户有独立密钥与独立的隧道内地址，会话表按用户分槽
//（见 registry.go）。同一张 TUN 服务全部用户，出向按目的地址分流，入向
// 校验源地址必须等于该会话分配到的地址——这条校验是用户隔离的实际执行点。
package tunnelapp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/pkg/tunnel"
	"go-port-forward/pkg/tunnet"
)

// Config 隧道服务端配置（config.yaml 的 tunnel 段）。
type Config struct {
	Enabled bool   `mapstructure:"enabled"`
	Listen  string `mapstructure:"listen"`   // UDP 监听，默认 ":7947"
	TunName string `mapstructure:"tun_name"` // 默认 "pftun0"
	TunAddr string `mapstructure:"tun_addr"` // 如 "10.66.0.1/24"，同时是客户端地址池
	NAT     bool   `mapstructure:"nat"`      // 自动配置回程路径（ip_forward + 策略路由本机投递 + 放行）
}

// Defaults 填充零值配置。
func (c *Config) Defaults() {
	if c.Listen == "" {
		c.Listen = ":7947"
	}
	if c.TunName == "" {
		c.TunName = "pftun0"
	}
	if c.TunAddr == "" {
		c.TunAddr = "10.66.0.1/24"
	}
}

// Identity 是一个隧道用户的接入凭据与地址（由上层用户服务提供）。
type Identity struct {
	UserID   string
	UserName string
	Secret   []byte
	TunIP    netip.Addr
	Disabled bool
}

// IdentityFunc 按用户 ID 查询凭据；用户不存在返回 false。
//
// 服务端必须先知道对端声称是谁才能取密钥验 MAC，所以查询以明文 uid 为输入。
// 声称本身不构成认证——查到密钥后 MAC 验证失败一律拒绝。
type IdentityFunc func(userID string) (Identity, bool)

// SessionIPsFunc 返回「用户 ID → 该用户规则上的活跃来源 IP」。
//
// 单用户时代这里是一个全局 IP 列表。多用户下必须按用户切分：把全部玩家 IP
// 推给每个客户端等于让 A 为 B 的玩家安装回程路由，隔离在数据面就漏了。
type SessionIPsFunc func() map[string][]string

// Server 是运行中的隧道服务端实例。
type Server struct {
	cfg      Config
	udp      *net.UDPConn
	dev      *tunnet.Device
	peers    *registry
	identity IdentityFunc

	tunPool netip.Prefix
	gateway netip.Addr

	lastWriteErr atomic.Int64 // 写 TUN 失败日志限频锚点（Unix 秒）
	lastOldVer   atomic.Int64 // 旧版客户端告警限频锚点
	lastAuthErr  atomic.Int64 // 认证失败告警限频锚点
	lastNoRoute  atomic.Int64 // 出向找不到会话的告警限频锚点
	lastSpoof    atomic.Int64 // 源地址伪造告警限频锚点

	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}

	pushMu   sync.Mutex
	pushSigs map[string]string // 用户 ID → 上次推送的 IP 集合指纹
}

// Start 启动隧道服务端（TUN/NAT/UDP/泵/推送）。任一初始化失败返回错误。
func Start(cfg Config, identity IdentityFunc, sessionIPs SessionIPsFunc) (*Server, error) {
	cfg.Defaults()
	if identity == nil {
		return nil, errors.New("隧道服务端需要用户凭据查询函数 | identity lookup is required")
	}
	pool, gateway, err := parseTunAddr(cfg.TunAddr)
	if err != nil {
		return nil, err
	}

	dev, err := tunnet.Open(cfg.TunName, 1400)
	if err != nil {
		return nil, err
	}
	if err := configureInterface(cfg.TunName, cfg.TunAddr); err != nil {
		dev.Close()
		return nil, fmt.Errorf("配置 TUN 地址失败: %w", err)
	}
	if cfg.NAT {
		if err := setupReturnPath(cfg.TunName); err != nil {
			dev.Close()
			return nil, fmt.Errorf("配置回程路径失败: %w", err)
		}
	}
	udp, err := net.ListenPacket("udp", cfg.Listen)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("隧道 UDP 监听失败 %s: %w", cfg.Listen, err)
	}
	udpConn := udp.(*net.UDPConn)

	s := &Server{
		cfg:      cfg,
		udp:      udpConn,
		dev:      dev,
		peers:    newRegistry(),
		identity: identity,
		tunPool:  pool,
		gateway:  gateway,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		pushSigs: make(map[string]string),
	}

	go s.loop(dev, udpConn)         // 客户端 → TUN（含握手状态机）
	go s.pumpTunToClient(dev, udpConn) // TUN → 客户端（按目的地址分流）
	go s.heartbeat(udpConn)         // 心跳
	go s.janitor()                  // 空闲会话回收
	if sessionIPs != nil {
		go s.pushSessionIPs(sessionIPs, udpConn) // 回程路由同步（按用户过滤）
	}
	logger.S.Infow("隧道服务端已启动", "listen", cfg.Listen, "tun", cfg.TunName, "addr", cfg.TunAddr)
	return s, nil
}

// parseTunAddr 把 tun_addr 拆成客户端地址池与服务端隧道地址。
func parseTunAddr(cidr string) (netip.Prefix, netip.Addr, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("无效的隧道网段 %q: %w", cidr, err)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("隧道网段必须是 IPv4: %q", cidr)
	}
	return p.Masked(), p.Addr(), nil
}

// Stop 停止服务端并释放 TUN/UDP。
//
// 关闭顺序不能改：两个泵 goroutine 分别阻塞在 udpConn.ReadFromUDP 与
// dev.ReadPacket 上，只在拿到一个包之后才会去看 stop 通道。所以必须先关掉
// socket 与设备让阻塞读带错误返回，再等 goroutine 退出——反过来（先等再关）
// 会在没有流量时永久卡死，表现为 Ctrl+C 后进程不退出。
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.stop)
		if s.udp != nil {
			_ = s.udp.Close()
		}
		if s.dev != nil {
			_ = s.dev.Close()
		}

		// 即便如此也不无条件等待：读循环若卡在别处，宁可放它随进程退出，
		// 也不能让整个程序停不下来。
		select {
		case <-s.done:
		case <-time.After(3 * time.Second):
			logger.S.Warnw("隧道读循环未在 3 秒内退出，跳过等待")
		}

		if s.cfg.NAT {
			teardownReturnPath(s.cfg.TunName)
		}
	})
}

// PeerCount 返回当前在线的隧道客户端数（诊断用）。
func (s *Server) PeerCount() int { return s.peers.count() }

// PeerView 是一条在线隧道会话的只读视图。
type PeerView struct {
	UserID   string    `json:"user_id"`
	UserName string    `json:"user_name"`
	TunIP    string    `json:"tun_ip"`
	Addr     string    `json:"addr"`
	Since    time.Time `json:"since"`
	IdleSec  int64     `json:"idle_sec"`
}

// Peers 返回全部在线会话（按用户名排序，供面板展示）。
func (s *Server) Peers() []PeerView {
	now := time.Now()
	snap := s.peers.snapshot()
	out := make([]PeerView, 0, len(snap))
	for _, ps := range snap {
		out = append(out, PeerView{
			UserID:   ps.userID,
			UserName: ps.userName,
			TunIP:    ps.tunIP.String(),
			Addr:     ps.addr.String(),
			Since:    ps.since,
			IdleSec:  int64(ps.idleFor(now).Seconds()),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UserName < out[j].UserName })
	return out
}

// PeerUserIDs 返回当前有隧道在线的用户 ID 列表。
func (s *Server) PeerUserIDs() []string {
	snap := s.peers.snapshot()
	out := make([]string, 0, len(snap))
	for _, ps := range snap {
		out = append(out, ps.userID)
	}
	return out
}

// loop 客户端 → TUN 泵（含握手状态机）。
func (s *Server) loop(dev *tunnet.Device, udpConn *net.UDPConn) {
	defer close(s.done)
	buf := make([]byte, tunnel.MaxPacket+64)
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		n, from, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		if len(pkt) == 0 {
			continue
		}

		if pkt[0] == tunnel.TypeHello {
			s.handleHello(udpConn, pkt, from)
			continue
		}

		ps := s.peers.byAddress(from)
		if ps == nil {
			// 未握手的来源。丢弃即可——不回任何东西，避免成为反射放大源。
			continue
		}
		sess := ps.sess

		switch {
		case sess.IsPing(pkt):
			ps.touch()
			pong := make([]byte, 0, 1+tunnel.NonceSize+16)
			pong = append(pong, tunnel.TypePong)
			pong = append(pong, sess.Seal(nil)...)
			_, _ = udpConn.WriteToUDP(pong, ps.addr)
		case pkt[0] == tunnel.TypePong:
			ps.touch()
		case pkt[0] == tunnel.TypeData:
			plain, oerr := sess.OpenData(pkt)
			if oerr != nil {
				continue
			}
			ps.touch()
			// 用户隔离的执行点：包的源地址必须是该会话分配到的隧道地址。
			// 少了这一条，A 可以伪造 B 的源地址，让后端把回包发给 B 的玩家，
			// 也能借 conntrack 劫持 B 的透明会话——前面所有隔离都成了纸面的。
			src, ok := srcIP4(plain)
			if !ok || src != ps.tunIP {
				s.logSpoof(ps, src)
				continue
			}
			if werr := dev.WritePacket(plain); werr != nil {
				s.logWriteErr(werr)
			}
		}
	}
}

// handleHello 处理握手包（首次接入与重连走同一条路径）。
func (s *Server) handleHello(udpConn *net.UDPConn, pkt []byte, from *net.UDPAddr) {
	uid, err := tunnel.PeekHello(pkt)
	if err != nil {
		if errors.Is(err, tunnel.ErrOldVersion) {
			s.logOldVersion(from)
		}
		return
	}
	ident, found := s.identity(uid.String())
	if !found {
		s.logAuthFail(from, "未知用户 | unknown user", uid.String())
		return
	}
	if ident.Disabled {
		s.logAuthFail(from, "账号已停用 | user disabled", ident.UserName)
		return
	}
	if !ident.TunIP.IsValid() || !s.tunPool.Contains(ident.TunIP) || ident.TunIP == s.gateway {
		s.logAuthFail(from, "用户隧道地址无效 | invalid tunnel address", ident.UserName)
		return
	}

	hello, herr := tunnel.ParseClientHello(ident.Secret, pkt)
	if herr != nil {
		s.logAuthFail(from, "握手认证失败 | handshake authentication failed", ident.UserName)
		return
	}
	accept, priv, aerr := tunnel.NewServerAccept(ident.Secret, hello.Eph, ident.TunIP, s.gateway, s.tunPool.Bits())
	if aerr != nil {
		logger.S.Warnw("生成握手应答失败", "user", ident.UserName, "err", aerr)
		return
	}
	if _, werr := udpConn.WriteToUDP(accept.Marshal(), from); werr != nil {
		return
	}
	shared := tunnel.ECDHShared(&hello.Eph, priv)
	sess := tunnel.NewSession(tunnel.DeriveSessionKey(shared, ident.Secret))
	ps := newPeerSession(ident.UserID, ident.UserName, ident.TunIP, sess, from)
	prev := s.peers.upsert(ps)

	// 空闲 30 秒会触发客户端自动重握手，同一来源的重连是常态，只在首次接入
	// 或来源变化时记 info（换机器/换 NAT 端口才值得注意）。
	switch {
	case prev == nil:
		logger.S.Infow("隧道客户端已接入", "user", ident.UserName, "tun_ip", ident.TunIP, "src", from)
	case prev.addr.String() != from.String():
		logger.S.Infow("隧道客户端来源变更", "user", ident.UserName, "from", prev.addr, "to", from)
	default:
		logger.S.Debugw("隧道客户端重新握手", "user", ident.UserName, "src", from)
	}
	// 换会话意味着旧的推送指纹失效（新会话的对端路由表是空的，必须重推）。
	s.forgetPushSig(ident.UserID)
}

// logWriteErr 限频记录写 TUN 失败（每 5 秒最多一条）。
// 数据面写失败若静默丢弃，故障表现为「隧道通、业务不通」且毫无线索。
func (s *Server) logWriteErr(err error) {
	if !throttle(&s.lastWriteErr, 5) {
		return
	}
	logger.S.Warnw("写入 TUN 失败（玩家入站包被丢弃）", "err", err)
}

// logOldVersion 限频提示客户端版本过旧（每 30 秒最多一条）。
// 旧客户端会以固定周期重试，不限频会把日志刷满。
func (s *Server) logOldVersion(from *net.UDPAddr) {
	if !throttle(&s.lastOldVer, 30) {
		return
	}
	logger.S.Warnw("隧道客户端协议版本过旧，请升级 pf-client（多用户版握手不兼容旧版）", "src", from)
}

func (s *Server) logAuthFail(from *net.UDPAddr, reason, who string) {
	if !throttle(&s.lastAuthErr, 10) {
		return
	}
	logger.S.Warnw("隧道握手被拒绝", "reason", reason, "user", who, "src", from)
}

func (s *Server) logSpoof(ps *peerSession, src netip.Addr) {
	if !throttle(&s.lastSpoof, 10) {
		return
	}
	logger.S.Warnw("丢弃源地址不匹配的隧道包（疑似伪造）",
		"user", ps.userName, "expect", ps.tunIP, "got", src)
}

func (s *Server) logNoRoute(dst netip.Addr) {
	if !throttle(&s.lastNoRoute, 30) {
		return
	}
	logger.S.Debugw("TUN 出向包无对应在线客户端，已丢弃", "dst", dst)
}

// throttle 是限频锚点的通用实现：距上次记录不足 sec 秒则返回 false。
func throttle(anchor *atomic.Int64, sec int64) bool {
	now := time.Now().Unix()
	last := anchor.Load()
	if now-last < sec {
		return false
	}
	return anchor.CompareAndSwap(last, now)
}

// pumpTunToClient TUN → 客户端 泵：按目的地址分流到对应会话。
//
// 单读 goroutine 是硬约束（tunnet.Device.ReadPacket 内部有批读队列，不可并发）。
func (s *Server) pumpTunToClient(dev *tunnet.Device, udpConn *net.UDPConn) {
	buf := make([]byte, 1500)
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		n, err := dev.ReadPacket(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		dst, ok := dstIP4(buf[:n])
		if !ok {
			continue
		}
		ps := s.peers.byTunnelIP(dst)
		if ps == nil {
			s.logNoRoute(dst)
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if _, werr := udpConn.WriteToUDP(ps.sess.SealData(pkt), ps.addr); werr != nil {
			// 单个 peer 写失败不再终止整个泵——那会让一个客户端的网络问题
			// 掐断所有其它用户的隧道。
			s.logWriteErr(werr)
		}
	}
}

// heartbeat 周期心跳（对每个在线会话各发一次）。
func (s *Server) heartbeat(udpConn *net.UDPConn) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-tick.C:
			for _, ps := range s.peers.snapshot() {
				ping := make([]byte, 0, 1+tunnel.NonceSize+16)
				ping = append(ping, tunnel.TypePing)
				ping = append(ping, ps.sess.Seal(nil)...)
				_, _ = udpConn.WriteToUDP(ping, ps.addr)
			}
		}
	}
}

// janitor 回收空闲超时的会话。
//
// 会话的存活由「收到任何有效包」这个事件维持，回收由时间驱动。不做「按某个
// 周期性列表判定存活」——那会把短交互的会话反复掐断。
func (s *Server) janitor() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.stop:
			return
		case now := <-tick.C:
			for _, ps := range s.peers.reap(now, peerIdleTimeout) {
				logger.S.Infow("隧道会话已因空闲回收", "user", ps.userName, "tun_ip", ps.tunIP)
				s.forgetPushSig(ps.userID)
			}
		}
	}
}

// pushSessionIPs 周期把活跃会话来源 IP 推给各自的客户端（回程路由同步）。
//
// 推送每 10 秒一次且内容通常不变，逐次打 info 只会把日志刷满。所以只在某个
// 用户的 IP 集合发生变化时记一条 info，逐次推送降到 debug。
func (s *Server) pushSessionIPs(sessionIPs SessionIPsFunc, udpConn *net.UDPConn) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-tick.C:
			byUser := sessionIPs()
			for _, ps := range s.peers.snapshot() {
				ips := byUser[ps.userID]
				if len(ips) == 0 {
					continue
				}
				wire, err := ps.sess.SealCtrl(tunnel.CtrlMessage{Kind: tunnel.CtrlKindRoutes, IPs: ips})
				if err != nil {
					continue
				}
				if _, err := udpConn.WriteToUDP(wire, ps.addr); err != nil {
					continue
				}
				if s.recordPushSig(ps.userID, sessionIPsSignature(ips)) {
					logger.S.Infow("回程路由 IP 变更", "user", ps.userName, "count", len(ips), "ips", ips)
				} else {
					logger.S.Debugw("回程路由 IP 已推送", "user", ps.userName, "count", len(ips))
				}
			}
		}
	}
}

// recordPushSig 记录某用户的推送指纹，返回是否发生变化。
func (s *Server) recordPushSig(userID, sig string) bool {
	s.pushMu.Lock()
	defer s.pushMu.Unlock()
	if s.pushSigs[userID] == sig {
		return false
	}
	s.pushSigs[userID] = sig
	return true
}

// forgetPushSig 清掉某用户的推送指纹，让下一轮必然重推并记一条 info。
func (s *Server) forgetPushSig(userID string) {
	s.pushMu.Lock()
	delete(s.pushSigs, userID)
	s.pushMu.Unlock()
}

// sessionIPsSignature 生成与顺序无关的集合指纹，用于判断内容是否变化。
// 会话来源于 map 遍历，顺序本身不稳定，不排序会把同一集合误判为变更。
// 注意不得就地修改调用方传入的切片。
func sessionIPsSignature(ips []string) string {
	sorted := make([]string, len(ips))
	copy(sorted, ips)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}
