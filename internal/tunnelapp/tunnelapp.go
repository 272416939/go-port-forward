// Package tunnelapp 内置隧道服务端：为 Windows 端 pf-client 提供加密隧道
// 与回程路径（TUN + 策略路由本机投递），并周期把 go-port-forward 活跃会话的
// 来源 IP 推送给客户端维护 /32 回程路由。开启 tunnel.enabled 后随主程序
// 常驻，无需单独的 pf-server 进程。
//
// 多访问码：每个访问码是一份独立的隧道身份（自己的密钥、自己的隧道内地址、
// 绑定一台设备），会话表按访问码分槽（见 registry.go）。同一张 TUN 服务全部
// 访问码，出向按目的地址分流，入向校验源地址必须等于该会话分配到的地址——
// 这条校验是用户隔离的实际执行点。
package tunnelapp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
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

	// IOMode 选择 UDP 收发方式："batch"（recvmmsg/sendmmsg，默认）或
	// "simple"（逐包）。批量化把「每包 2 次 syscall」压到「每批 2 次」，
	// 但它是数据面上最脆弱的一处改动——保留开关，回退不需要换二进制。
	IOMode string `mapstructure:"io_mode"`
	// FEC 启用前向纠错（每 8 个数据包附 1 个校验包，上行冗余 12.5%）。
	// 默认关闭：丢包率低于 1% 的链路上这是纯浪费，还会掩盖真实的网络问题。
	FEC bool `mapstructure:"fec"`
	// TailDup 启用小包冗余副本（组尾小包发两份，接收端靠重放窗口去重）。
	TailDup bool `mapstructure:"tail_dup"`
	// UDPGRO / UDPGSO 是 Linux 的 UDP 聚合/分段卸载。默认关闭：收益要等
	// 观测数据证明「批量化之后单核仍是瓶颈」才成立。
	UDPGRO bool `mapstructure:"udp_gro"`
	UDPGSO bool `mapstructure:"udp_gso"`
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
		// /16：隧道地址按访问码分配，/24 的 253 个位置很快不够。
		c.TunAddr = "10.66.0.1/16"
	}
	if c.IOMode == "" {
		c.IOMode = "batch"
	}
}

// wantBatchIO 报告配置是否要求批量收发。
func (c *Config) wantBatchIO() bool { return !strings.EqualFold(c.IOMode, "simple") }

// features 把配置翻成协议特性位（在 Accept 里对称下发给客户端）。
//
// 必须由服务端下发而不是客户端自选：一端发 FEC 另一端不认，那些校验包会被
// 当未知类型静默丢弃，表现成「开了纠错反而更卡」。
func (c *Config) features() uint8 {
	var f uint8
	if c.FEC {
		f |= tunnel.FeatFEC
	}
	if c.TailDup {
		f |= tunnel.FeatTailDup
	}
	return f
}

// Identity 是一个访问码的接入凭据与约束（由上层用户服务提供）。
type Identity struct {
	CodeID   string
	CodeName string
	UserID   string
	UserName string
	Secret   []byte
	TunIP    netip.Addr
	// CodeDisabled / UserDisabled 分开，是为了给客户端一个准确的拒绝原因：
	// 「你的访问码被停了」与「你的账号被停了」要找的人不一样。
	CodeDisabled bool
	UserDisabled bool
	// Fingerprint 是已绑定的设备指纹（hex）；空串表示尚未绑定，首次握手成功
	// 时登记。
	Fingerprint string
	// MaxTunnels 是该用户的并发隧道上限（0 = 不限）。
	MaxTunnels int
}

// IdentityFunc 按访问码 ID 查询凭据；访问码不存在返回 false。
//
// 服务端必须先知道对端声称是哪个访问码才能取密钥验 MAC，所以查询以明文 uid
// 为输入。声称本身不构成认证——查到密钥后 MAC 验证失败一律拒绝。
type IdentityFunc func(codeID string) (Identity, bool)

// DeviceBinder 让隧道服务端登记/刷新访问码的设备绑定与活跃状态。
//
// 抽成接口是为了让 tunnelapp 不直接依赖用户服务：数据面只需要"记一下"，
// 不需要知道存储长什么样。
type DeviceBinder interface {
	// BindDevice 登记设备指纹。已绑定到别的设备时返回错误（调用方据此拒绝握手）。
	// 同一设备重连时只刷新活跃信息。
	BindDevice(codeID, fingerprint, label, addr string) error
	// TouchCode 刷新最近活跃时间。调用方已限频，实现无需再限。
	TouchCode(codeID, addr string)
}

// SessionIPsFunc 返回「访问码 ID → 该访问码对应规则上的活跃来源 IP」。
//
// 单用户时代这里是一个全局 IP 列表。多访问码下必须按访问码切分：把全部玩家
// IP 推给每个客户端等于让 A 为 B 的玩家安装回程路由，隔离在数据面就漏了。
type SessionIPsFunc func() map[string][]string

// Server 是运行中的隧道服务端实例。
type Server struct {
	cfg      Config
	udp      *net.UDPConn
	dev      *tunnet.Device
	peers    *registry
	identity IdentityFunc
	binder   DeviceBinder

	tunPool netip.Prefix
	gateway netip.Addr
	// tunMTU 是本机 TUN 的 MTU，也是握手时下发给客户端的值。
	tunMTU int
	// io 记录实际生效的收发配置（批量/GRO/GSO 与降级原因）。
	io ioSetup

	lastTunWrite  atomic.Int64 // 写 TUN 失败日志限频锚点（Unix 秒）
	lastUDPWrite  atomic.Int64 // 写 UDP 失败日志限频锚点
	lastOldVer    atomic.Int64 // 旧版客户端告警限频锚点
	lastAuthErr   atomic.Int64 // 认证失败告警限频锚点
	lastNoRoute   atomic.Int64 // 出向找不到会话的告警限频锚点
	lastSpoof     atomic.Int64 // 源地址伪造告警限频锚点
	lastNonIPv4   atomic.Int64 // 非 IPv4 隧道包丢弃的限频锚点
	lastInternal  atomic.Int64 // 隧道内互访告警限频锚点
	lastReject    atomic.Int64 // 拒绝握手告警限频锚点
	lastHelloDrop atomic.Int64 // 握手队列溢出丢弃的限频锚点
	lastOverMTU   atomic.Int64 // 出向包超出隧道 MTU 的限频锚点

	// kernelDrops 是内核 UDP 收缓冲溢出的累计丢包数（/proc/net/udp）。
	// 应用层对这类丢包完全无感——玩家进服的下行突发最容易打穿默认缓冲，
	// 而日志里一个字都没有。
	kernelDrops atomic.Uint64
	// tunDrops 是 TUN 读侧因超出缓冲而丢弃的包数（tunnet.Dropped 的镜像）。
	tunDrops atomic.Int64

	// helloQ 是握手包队列：握手要做存储读写（设备绑定要写库），放在唯一
	// 的入向泵里同步处理，重试风暴时每次 fsync 都会卡住全体玩家的包。
	// 单 worker 串行消费，兼而保证同一客户端的重传 Hello 按到达序处理。
	helloQ chan helloTask

	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}

	pushMu sync.Mutex
	// pushPrev 是每个访问码上次推送的活跃 IP 集合（已排序）。
	//
	// 存集合而不是指纹，是为了能算出「上次在、这次不在」的差集——那是唯一
	// 可信的「会话已结束」事件（见 sendEnded）。
	pushPrev map[string][]string
}

// Options 是隧道服务端的依赖注入。
type Options struct {
	Config     Config
	Identity   IdentityFunc
	Binder     DeviceBinder
	SessionIPs SessionIPsFunc
}

// Start 启动隧道服务端（TUN/NAT/UDP/泵/推送）。任一初始化失败返回错误。
func Start(opt Options) (*Server, error) {
	cfg := opt.Config
	cfg.Defaults()
	if opt.Identity == nil {
		return nil, errors.New("隧道服务端需要访问码凭据查询函数 | identity lookup is required")
	}
	if opt.Binder == nil {
		return nil, errors.New("隧道服务端需要设备绑定接口 | device binder is required")
	}
	pool, gateway, err := parseTunAddr(cfg.TunAddr)
	if err != nil {
		return nil, err
	}

	// 隧道 MTU 从物理出口反算：链路 MTU 减去封装开销（IP+UDP+AEAD），开启
	// FEC 时再让出校验包的额外开销。固定 1400 在 PPPoE(1492)/4G 这类链路上
	// 会贴上限，叠加企业 VPN 就超——而 IP 分片丢一片等于整个隧道包全损，
	// FEC 也救不回来（它看不到分片）。
	tunMTU := negotiateTunMTU(cfg)
	dev, err := tunnet.Open(cfg.TunName, tunMTU)
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
	// 默认 ~200KB 的读缓冲只够一百多个 MTU 包，玩家进服/重试风暴的突发会在
	// 内核层丢包，应用层毫无感知。实际生效值受 net.core.rmem_max 钳制，
	// 设置失败沿用系统默认，不影响转发。
	_ = udpConn.SetReadBuffer(tunnelSocketBuffer)
	_ = udpConn.SetWriteBuffer(tunnelSocketBuffer)

	reader, writer, ioSet := newUDPIO(udpConn, cfg.wantBatchIO(), cfg.UDPGRO, cfg.UDPGSO)

	s := &Server{
		cfg:      cfg,
		udp:      udpConn,
		dev:      dev,
		peers:    newRegistry(),
		identity: opt.Identity,
		binder:   opt.Binder,
		helloQ:   make(chan helloTask, helloQueueCap),
		tunPool:  pool,
		gateway:  gateway,
		tunMTU:   tunMTU,
		io:       ioSet,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		pushPrev: make(map[string][]string),
	}
	s.reportSocketBuffers()

	go s.loop(dev, reader)            // 客户端 → TUN（握手异步分发）
	go s.helloWorker(udpConn)         // 握手专用 worker（存储 I/O 不进数据泵）
	go s.pumpTunToClient(dev, writer) // TUN → 客户端（按目的地址分流）
	go s.heartbeat(udpConn)           // 心跳
	go s.janitor()                    // 空闲会话回收 + 内核丢包采样
	if cfg.NAT {
		go s.returnPathWatchdog() // 回程内核规则守护：被防火墙工具整表清空后自愈
	}
	if opt.SessionIPs != nil {
		go s.pushSessionIPs(opt.SessionIPs, udpConn) // 回程路由同步（按访问码过滤）
	}
	logger.S.Infow("隧道服务端已启动",
		"listen", cfg.Listen, "tun", cfg.TunName, "addr", cfg.TunAddr,
		"mtu", tunMTU, "io", ioSet.Mode, "fec", cfg.FEC, "tail_dup", cfg.TailDup)
	for _, note := range ioSet.Notes {
		logger.S.Warnw("隧道 UDP 收发能力受限", "detail", note)
	}
	return s, nil
}

// negotiateTunMTU 算出本机隧道 MTU。
//
// 取「物理出口 MTU - 封装开销」与协议上限的较小值；开启 FEC 时再让出校验包的
// 额外开销，否则校验包自己会被 IP 分片——而分片丢失是整包全损，正是 FEC 想
// 解决的问题。探测不到出口接口时按协议缺省值走（与客户端缺省一致）。
func negotiateTunMTU(cfg Config) int {
	mtu := tunnel.MaxTunMTU
	if link, ok := outboundLinkMTU(); ok {
		if v := link - tunnel.WireOverhead; v < mtu {
			mtu = v
		}
	}
	if cfg.FEC {
		mtu -= tunnel.FECOverhead
	}
	return tunnel.ClampTunMTU(mtu)
}

// outboundLinkMTU 探测默认出口网卡的 MTU。
//
// 用「连一个公网地址的 UDP socket」找出本机出口 IP（不发包），再按 IP 匹配
// 网卡。取不到就返回 false 让调用方用缺省值——MTU 探测失败不该阻止隧道启动。
func outboundLinkMTU() (int, bool) {
	c, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return 0, false
	}
	local, ok := c.LocalAddr().(*net.UDPAddr)
	_ = c.Close()
	if !ok || local.IP == nil {
		return 0, false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, false
	}
	for _, ifi := range ifaces {
		addrs, aerr := ifi.Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, isNet := a.(*net.IPNet)
			if isNet && ipnet.IP.Equal(local.IP) && ifi.MTU > 0 {
				return ifi.MTU, true
			}
		}
	}
	return 0, false
}

// reportSocketBuffers 核查内核实际生效的 socket 缓冲。
//
// SetReadBuffer(4MB) 受 net.core.rmem_max 钳制（多数发行版默认 212992），实际
// 生效可能只有 ~208KB ≈ 149 个 MTU 包——玩家进服的下行突发轻松打穿，内核层
// 丢包而应用层毫无感知。这里读回真实值并在被钳制时给出具体的 sysctl 做法。
func (s *Server) reportSocketBuffers() {
	rcv, snd, err := socketBufferSizes(s.udp)
	if err != nil {
		return // 非 Linux 或读取失败：不是错误，只是拿不到这项观测
	}
	logger.S.Debugw("隧道 socket 缓冲生效值", "rcvbuf", rcv, "sndbuf", snd, "want", tunnelSocketBuffer)
	if rcv*2 < tunnelSocketBuffer || snd*2 < tunnelSocketBuffer {
		logger.S.Warnw("隧道 socket 缓冲被内核上限钳制，突发流量会在内核层丢包（应用层无感知）",
			"rcvbuf", rcv, "sndbuf", snd, "want", tunnelSocketBuffer,
			"fix", sysctlHint(tunnelSocketBuffer))
	}
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

// returnPathWatchdog 周期校验透明回程的内核状态并自愈。
//
// ufw/宝塔等防火墙工具在 reload、enable 乃至增删单条规则时会整表 flush
// iptables，把 setupReturnPath 装配的规则连带清掉：控制面完全正常、玩家
// 入站照常、所有透明代理静默失联、日志零痕迹（2026-09-02 全代理失联事故
// 的根因）。这里每 30 秒幂等校验一次，缺失才补装，并且仅在确实修复时打
// 一条 info——它同时是「规则在何时被清」的时间戳。
func (s *Server) returnPathWatchdog() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
		}
		// 收敛关停竞态：Stop 会先关 stop 再 teardown，这里在发起任何修复
		// 前重读一次 stop，避免补装的规则逃过 teardown 留在内核里。
		select {
		case <-s.stop:
			return
		default:
		}
		repaired, err := verifyReturnPath(s.cfg.TunName)
		if err != nil {
			logger.S.Warnw("回程内核状态校验失败", "err", err)
			continue
		}
		if repaired {
			logger.S.Infow("回程内核规则缺失已自动补装（此前可能被防火墙工具整表清空）",
				"tun", s.cfg.TunName)
		}
	}
}

// PeerCount 返回当前在线的隧道客户端数（诊断用）。
func (s *Server) PeerCount() int { return s.peers.count() }

// PeerView 是一条在线隧道会话的只读视图。
type PeerView struct {
	CodeID   string    `json:"code_id"`
	CodeName string    `json:"code_name"`
	UserID   string    `json:"user_id"`
	UserName string    `json:"user_name"`
	TunIP    string    `json:"tun_ip"`
	Addr     string    `json:"addr"`
	Since    time.Time `json:"since"`
	IdleSec  int64     `json:"idle_sec"`
	MTU      int       `json:"mtu"`
	// Stats 是该会话的包级观测（丢包率/乱序率/抖动/RTT/纠错补回）。
	// 没有这组数据之前，丢包的归因全靠猜——公网丢包、内核缓冲丢包、应用层
	// 丢弃在日志里混成一团。
	Stats tunnel.StatsView `json:"stats"`
}

// Peers 返回全部在线会话（按用户名+访问码名排序，供面板展示）。
func (s *Server) Peers() []PeerView {
	now := time.Now()
	snap := s.peers.snapshot()
	out := make([]PeerView, 0, len(snap))
	for _, ps := range snap {
		out = append(out, PeerView{
			CodeID:   ps.codeID,
			CodeName: ps.codeName,
			UserID:   ps.userID,
			UserName: ps.userName,
			TunIP:    ps.tunIP.String(),
			Addr:     ps.addrPort.String(),
			Since:    ps.since,
			IdleSec:  int64(ps.idleFor(now).Seconds()),
			MTU:      ps.mtu,
			Stats:    ps.sess.Stats().View(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UserName != out[j].UserName {
			return out[i].UserName < out[j].UserName
		}
		return out[i].CodeName < out[j].CodeName
	})
	return out
}

// OnlineCodeIDs 返回当前有隧道在线的访问码 ID 列表。
func (s *Server) OnlineCodeIDs() []string {
	snap := s.peers.snapshot()
	out := make([]string, 0, len(snap))
	for _, ps := range snap {
		out = append(out, ps.codeID)
	}
	return out
}

// EvictCode 踢掉某访问码当前在线的隧道（解绑设备、停用访问码、删除时调用）。
//
// 必须踢：解绑后旧设备仍在跑，用户以为已经换到新机器，结果两台机器抢同一个
// 隧道地址；停用一个还在线的访问码若不踢，停用就只是界面上的一个状态。
func (s *Server) EvictCode(codeID string) bool {
	ps := s.peers.evict(codeID)
	if ps == nil {
		return false
	}
	s.forgetPushed(codeID)
	logger.S.Infow("隧道会话已被强制断开", "user", ps.userName, "code", ps.codeName, "tun_ip", ps.tunIP)
	return true
}

// tunnelSocketBuffer 是隧道 UDP socket 读写缓冲的目标值。
const tunnelSocketBuffer = 4 << 20 // 4MB

// helloQueueCap 是握手包队列深度。正常情况下握手频率极低（接入 + 空闲重握手），
// 队列的意义是把重试风暴的突发握手从数据泵上摘下来；满了就丢弃——客户端会
// 重发 Hello，不值得为它阻塞数据面。
const helloQueueCap = 128

// helloTask 是一条待处理的握手包。pkt 必须是拷贝：读循环的 buf 逐包复用。
type helloTask struct {
	pkt  []byte
	from netip.AddrPort
}

// queueHello 把握手包投递给专用 worker，绝不在数据泵里同步处理握手——
// 握手要做存储读写（设备绑定要写库），重试风暴时每次 fsync 都会把全体玩家
// 的入向包卡住（「有人疯狂重连全服卡顿」的服务端病根）。
func (s *Server) queueHello(pkt []byte, from netip.AddrPort) {
	task := helloTask{pkt: append([]byte(nil), pkt...), from: from}
	select {
	case s.helloQ <- task:
	default:
		now := time.Now().Unix()
		last := s.lastHelloDrop.Load()
		if now-last >= 5 && s.lastHelloDrop.CompareAndSwap(last, now) {
			logger.S.Warnw("握手队列已满，丢弃 Hello（客户端会重试）", "from", from)
		}
	}
}

// helloWorker 串行处理握手包。单 worker 既把存储 I/O 挪出数据泵，也天然保证
// 同一客户端的重传 Hello 按到达序处理——并发处理会为同一次握手生成两个不同的
// Accept 会话密钥，客户端与服务端可能各认一个，数据包互相解不开。
func (s *Server) helloWorker(udpConn *net.UDPConn) {
	for {
		select {
		case <-s.stop:
			return
		case task := <-s.helloQ:
			s.handleHello(udpConn, task.pkt, task.from)
		}
	}
}

// loop 客户端 → TUN 泵。握手包只入队，状态机的实际执行在 helloWorker。
//
// 批量化（OPT-6/7）只改了「包从哪来、写到哪去」：读源由 udpReader 提供（批量
// 时一次 recvmmsg 取多包再逐包交付），写出攒进 tunnet.Batch，读队列排空时一次
// 写入。逐包的判定逻辑——握手入队、源/目的两条隔离校验、活跃刷新——与逐包
// 时代逐条相同，一个字节都没动。
//
// 批的边界完全由「系统调用返回多少包」决定：reader.buffered()==0 就冲刷。
// 不定时、不等待、不凑批——为了合并几个包去等几毫秒，对游戏流量是纯损失。
func (s *Server) loop(dev *tunnet.Device, reader udpReader) {
	defer close(s.done)
	batch := dev.NewBatch(udpBatch)
	for {
		select {
		case <-s.stop:
			_ = batch.Flush()
			return
		default:
		}
		pkt, from, err := reader.read()
		if err != nil {
			_ = batch.Flush()
			return
		}
		if len(pkt) == 0 {
			continue
		}

		if pkt[0] == tunnel.TypeHello {
			s.queueHello(pkt, from)
			continue
		}

		ps := s.peers.byAddress(from)
		if ps == nil {
			// 未握手的来源。丢弃即可——不回任何东西，避免成为反射放大源。
			continue
		}
		s.handleSessionPacket(ps, pkt, batch)

		// 内核当前能给的包已全部消费完：把攒起来的写批冲刷出去。
		if reader.buffered() == 0 && batch.Len() > 0 {
			if werr := batch.Flush(); werr != nil {
				s.logTunWriteErr(werr)
			}
		}
	}
}

// handleSessionPacket 处理一个已知会话的入向包。
func (s *Server) handleSessionPacket(ps *peerSession, pkt []byte, batch *tunnet.Batch) {
	sess := ps.sess
	switch pkt[0] {
	case tunnel.TypePing:
		// Ping 载荷同时用于路径 MTU 探测：Pong 回显实际收到的明文长度，
		// 客户端据此判断某个尺寸能否穿过链路。
		probeID, plainLen, perr := sess.OpenPing(pkt)
		if perr != nil {
			return
		}
		s.markActive(ps)
		s.sendTo(ps, sess.SealPong(s.pongBuf(ps), probeID, plainLen))
	case tunnel.TypePong:
		// 必须解密验证：此前只看首字节就刷新活跃时间，任何人伪造一个 0x06
		// 字节就能给别人的会话续命（也就能让空闲回收永不触发）。
		if _, _, perr := sess.OpenPong(pkt); perr != nil {
			return
		}
		s.markActive(ps)
	case tunnel.TypeFEC:
		// 校验包本身不是数据。登记后循环取出被补回的包，走与普通 Data
		// 完全相同的路径——认证、重放窗口、源/目的校验一条不少。
		if !sess.HandleFEC(pkt) {
			return
		}
		s.markActive(ps)
		for {
			rec := sess.Recover()
			if rec == nil {
				return
			}
			s.deliverInbound(ps, rec, batch)
		}
	case tunnel.TypeData:
		s.deliverInbound(ps, pkt, batch)
	}
}

// deliverInbound 把一个 Data 包解密、校验并写进 TUN 批。
//
// 明文直接解进 TUN 写批的槽位（tunnet.Batch.Next），所以整条入向路径上既没有
// 明文分配也没有二次拷贝。
func (s *Server) deliverInbound(ps *peerSession, pkt []byte, batch *tunnet.Batch) {
	dst := batch.Next()
	if dst == nil {
		// 批满：先冲刷再取槽位。
		if werr := batch.Flush(); werr != nil {
			s.logTunWriteErr(werr)
		}
		dst = batch.Next()
		if dst == nil {
			return
		}
	}
	plain, oerr := ps.sess.OpenData(dst, pkt)
	if oerr != nil {
		return
	}
	s.markActive(ps)
	// 用户隔离的执行点：包的源地址必须是该会话分配到的隧道地址。
	// 少了这一条，A 可以伪造 B 的源地址，让后端把回包发给 B 的玩家，
	// 也能借 conntrack 劫持 B 的透明会话——前面所有隔离都成了纸面的。
	src, ok := srcIP4(plain)
	if !ok {
		// 解不出 IPv4 头：几乎必然是客户端网卡上的 Windows 后台流量
		// （IPv6 路由请求、组播等），不构成源地址伪造，降为 debug。
		s.logNonIPv4(ps, len(plain))
		return
	}
	if src != ps.tunIP {
		s.logSpoof(ps, src)
		return
	}
	// 用户隔离的第二条执行语句：目的地址不得落在隧道网段内（零例外，
	// 网关也不行——通用模式目标填隧道地址已整体禁用，网关上没有任何
	// 服务需要被隧道访问）。客户端掩码是 /16，整个网段在每台客户端
	// 机器上都是直连网段，不拦的话 A 可以直接访问 B 后端所有绑
	// 0.0.0.0 的服务。
	dstIP, ok := dstIP4(plain)
	if ok && s.isTunnelInternal(dstIP) {
		s.logTunnelInternal(ps, dstIP, "目的")
		return
	}
	batch.Commit(len(plain))
}

// pongBuf 取出该会话的应答缓冲。Pong 由入向泵单 goroutine 发出，可以安全复用
// 会话内的暂存。
func (s *Server) pongBuf(ps *peerSession) []byte { return ps.ctrlOut[:0] }

// sendTo 逐包发送一个已封装的包（低频路径：Pong、心跳、控制消息）。
func (s *Server) sendTo(ps *peerSession, wire []byte) {
	if _, err := s.udp.WriteToUDPAddrPort(wire, ps.addrPort); err != nil {
		ps.sess.Stats().AddTxDropped(1)
		s.logUDPWriteErr(err)
	}
}

// markActive 刷新会话活跃时间，并限频把它写回存储。
//
// 内存里的活跃时间每包都更新（回收判据要准），落盘每 60 秒最多一次——数据面
// 上每个包都写 bbolt 会把 fsync 拖进转发热路径。写盘还异步做，不让存储的抖动
// 影响转发延迟。
func (s *Server) markActive(ps *peerSession) {
	ps.touch()
	if !ps.shouldPersistTouch(60) {
		return
	}
	codeID, addr := ps.codeID, ps.addrPort.String()
	go s.binder.TouchCode(codeID, addr)
}

// replyVersionMismatch 对版本过旧的客户端回一个它能验证的拒绝应答。
//
// 此前这个分支完全静默：旧客户端只能等超时，最后显示「服务端无应答（请检查
// 地址、端口与中转机防火墙）」——一个纯粹的版本问题被误报成网络问题，运维去
// 白查防火墙。现在用**旧客户端自己的协议版本域标签**签名拒绝应答（reason 0），
// 旧客户端验证通过后会显示「服务端拒绝了连接」并指向管理员/服务端日志。
//
// 安全约束一条不放松：
//   - 只应答 **MAC 验证通过**的对端（InspectLegacyHello）——不引入「访问码
//     是否存在」的探测口子；伪造/重放的 Hello 依旧静默；
//   - 拒绝应答 35 字节 < Hello 122 字节，不构成反射放大；
//   - 成本与既有认证失败路径同类（uid 解析 + 身份查询 + 一次 HMAC），helloQ
//     深度 128 + 单 worker 串行已天然限流——垃圾包在队列就丢弃，数据泵不受影响。
func (s *Server) replyVersionMismatch(pkt []byte, from netip.AddrPort) {
	uid, ok := tunnel.PeekLegacyHelloUID(pkt)
	if !ok {
		return // v1/v2 布局不同，无法安全应答，保持静默
	}
	ident, found := s.identity(uid.String())
	if !found {
		return // 与正常握手一致：查无此码时连 Reject 都不回
	}
	wire := tunnel.LegacyVersionReject(ident.Secret, pkt)
	if wire == nil {
		return // MAC 复验失败：伪造或重放，静默
	}
	if _, err := s.udp.WriteToUDPAddrPort(wire, from); err != nil {
		return
	}
	logger.S.Debugw("已向旧协议客户端回复跨版本拒绝", "src", from, "code", ident.CodeName)
}

// handleHello 处理握手包（首次接入与重连走同一条路径）。
//
// 判定顺序是安全约束，不能重排：**必须先验 MAC 才允许回 Reject**。在认证之前
// 回任何应答，服务端就成了一个可被伪造源地址驱动的反射放大源。访问码查不到时
// 连 Reject 都不能回——那种情况下没有密钥可用来签名。
func (s *Server) handleHello(udpConn *net.UDPConn, pkt []byte, from netip.AddrPort) {
	uid, err := tunnel.PeekHello(pkt)
	if err != nil {
		if errors.Is(err, tunnel.ErrOldVersion) {
			s.replyVersionMismatch(pkt, from)
			s.logOldVersion(from)
		}
		return
	}
	ident, found := s.identity(uid.String())
	if !found {
		s.logAuthFail(from, "未知访问码 | unknown access code", uid.String())
		return
	}

	// --- 认证分界线：以下才可以回应答 ---
	hello, herr := tunnel.ParseClientHello(ident.Secret, pkt)
	if herr != nil {
		s.logAuthFail(from, "握手认证失败 | handshake authentication failed", ident.UserName)
		return
	}

	reject := func(reason tunnel.RejectReason) {
		wire := tunnel.NewServerReject(ident.Secret, hello.Eph, reason).Marshal()
		_, _ = udpConn.WriteToUDPAddrPort(wire, from)
		s.logReject(from, ident, reason)
	}

	switch {
	case ident.CodeDisabled:
		reject(tunnel.RejectCodeDisabled)
		return
	case ident.UserDisabled:
		reject(tunnel.RejectUserDisabled)
		return
	}
	if !ident.TunIP.IsValid() || !s.tunPool.Contains(ident.TunIP) || ident.TunIP == s.gateway {
		// 地址无效通常是管理员改小了 tunnel.tun_addr 网段，把已分配的地址甩在
		// 网段外面。这是个需要人处理的配置问题，给客户端一个明确原因。
		reject(tunnel.RejectAddrInvalid)
		return
	}

	// 设备绑定：首次握手登记指纹，之后其它设备一律拒绝。
	// 指纹未变化（重握手是常态）时直接短路：每次握手都写库会把 fsync 拖进
	// 握手路径，重试风暴下就是持续卡顿。活跃地址已由 TouchCode 异步刷新，
	// 无需借这里重写。
	fp := hex.EncodeToString(hello.Device[:])
	if ident.Fingerprint != fp {
		if err := s.binder.BindDevice(ident.CodeID, fp, models.FingerprintLabel(fp), from.String()); err != nil {
			reject(tunnel.RejectDeviceMismatch)
			return
		}
	}

	// 并发隧道上限：本访问码已在线时是重连，不占新配额。
	if ident.MaxTunnels > 0 && !s.peers.online(ident.CodeID) {
		if s.peers.countByUser(ident.UserID) >= ident.MaxTunnels {
			reject(tunnel.RejectTunnelLimit)
			return
		}
	}

	// MTU 与特性位由服务端下发（都进 MAC）。特性必须对称启用：一端发 FEC
	// 另一端不认，那些校验包会被当未知类型静默丢弃，表现成「开了纠错反而更卡」。
	feats := s.cfg.features()
	accept, priv, aerr := tunnel.NewServerAccept(ident.Secret, hello.Eph,
		ident.TunIP, s.gateway, s.tunPool.Bits(), s.tunMTU, feats)
	if aerr != nil {
		logger.S.Warnw("生成握手应答失败", "user", ident.UserName, "code", ident.CodeName, "err", aerr)
		return
	}
	if _, werr := udpConn.WriteToUDPAddrPort(accept.Marshal(), from); werr != nil {
		return
	}
	shared := tunnel.ECDHShared(&hello.Eph, priv)
	c2s, s2c, kerr := tunnel.DeriveSessionKeys(shared, ident.Secret, hello.Eph, accept.Eph)
	if kerr != nil {
		logger.S.Warnw("派生会话密钥失败", "user", ident.UserName, "code", ident.CodeName, "err", kerr)
		return
	}
	sess, serr := tunnel.NewServerSession(c2s, s2c, uint32(feats), s.tunMTU)
	if serr != nil {
		logger.S.Warnw("建立会话失败", "user", ident.UserName, "code", ident.CodeName, "err", serr)
		return
	}
	ps := newPeerSession(ident, sess, udpAddrOf(from), s.tunMTU)
	prev := s.peers.upsert(ps)

	// 空闲 10 秒会触发客户端自动重握手，同一来源的重连是常态，只在首次接入
	// 或来源变化时记 info（换机器/换 NAT 端口才值得注意）。
	switch {
	case prev == nil:
		logger.S.Infow("隧道客户端已接入",
			"user", ident.UserName, "code", ident.CodeName, "tun_ip", ident.TunIP,
			"src", from, "mtu", s.tunMTU)
	case prev.addrPort != from:
		logger.S.Infow("隧道客户端来源变更",
			"user", ident.UserName, "code", ident.CodeName, "from", prev.addrPort, "to", from)
	default:
		logger.S.Debugw("隧道客户端重新握手", "user", ident.UserName, "code", ident.CodeName, "src", from)
	}
	// 换会话意味着旧的推送指纹失效（新会话的对端路由表是空的，必须重推）。
	s.forgetPushed(ident.CodeID)
}

// logTunWriteErr 限频记录写 TUN 失败（每 5 秒最多一条）。
// 数据面写失败若静默丢弃，故障表现为「隧道通、业务不通」且毫无线索。
func (s *Server) logTunWriteErr(err error) {
	if !throttle(&s.lastTunWrite, 5) {
		return
	}
	logger.S.Warnw("写入 TUN 失败（玩家入站包被丢弃）", "err", err)
}

// logUDPWriteErr 限频记录写 UDP 失败（每 5 秒最多一条）。
//
// 与写 TUN 分开两个锚点两条文案：此前两者共用一条「写入 TUN 失败」，出向
// socket 缓冲满时打出的是一条指向错误方向的日志。
func (s *Server) logUDPWriteErr(err error) {
	if !throttle(&s.lastUDPWrite, 5) {
		return
	}
	logger.S.Warnw("发送隧道 UDP 包失败（该客户端的出向包被丢弃）", "err", err)
}

// logOverMTU 限频记录超出隧道 MTU 而无法转发的出向包。
//
// 此前这类包在 tunnet 读侧被静默丢弃（只加一个没人读的计数器），是「后端 MTU
// 大于隧道 MTU 时偶发大包全损」这类故障的黑盒来源。
func (s *Server) logOverMTU(ps *peerSession, size int) {
	if !throttle(&s.lastOverMTU, 30) {
		return
	}
	logger.S.Warnw("出向包超出隧道 MTU，已丢弃（请下调后端 MTU 或检查链路 MTU）",
		"user", ps.userName, "code", ps.codeName, "size", size, "mtu", ps.mtu)
}

// logOldVersion 限频提示客户端版本过旧（每 30 秒最多一条）。
// 旧客户端会以固定周期重试，不限频会把日志刷满。
func (s *Server) logOldVersion(from netip.AddrPort) {
	if !throttle(&s.lastOldVer, 30) {
		return
	}
	logger.S.Warnw("隧道客户端协议版本过旧，请升级 pf-client（当前版本要求 v4 握手：方向密钥分离 + AEAD）", "src", from)
}

func (s *Server) logAuthFail(from netip.AddrPort, reason, who string) {
	if !throttle(&s.lastAuthErr, 10) {
		return
	}
	logger.S.Warnw("隧道握手被拒绝", "reason", reason, "who", who, "src", from)
}

// logReject 限频记录已认证但被拒绝的握手。
//
// 这类拒绝多是运维需要知道的状态（有人换了机器、有人超了并发上限），但客户端
// 会持续重试，不限频会刷屏。
func (s *Server) logReject(from netip.AddrPort, ident Identity, reason tunnel.RejectReason) {
	if !throttle(&s.lastReject, 10) {
		return
	}
	logger.S.Warnw("隧道握手被拒绝",
		"reason", reason.String(), "user", ident.UserName, "code", ident.CodeName,
		"bound_device", models.FingerprintLabel(ident.Fingerprint), "src", from)
}

// logNonIPv4 限频记录解不出 IPv4 头的隧道包。TUN 是三层设备，这类包进不了
// 任何 IPv4 会话，丢弃即可；来源几乎必然是客户端网卡上的 Windows 后台流量
// （IPv6 路由请求等），周期性出现、无安全含义，降为 debug。
// （曾与真实源伪造共用一条「疑似伪造」warn，运维看到只会白紧张。）
func (s *Server) logNonIPv4(ps *peerSession, pktLen int) {
	if !throttle(&s.lastNonIPv4, 10) {
		return
	}
	logger.S.Debugw("丢弃非 IPv4 的隧道包（多为客户端网卡的 IPv6 后台流量）",
		"user", ps.userName, "code", ps.codeName, "tun_ip", ps.tunIP, "len", pktLen)
}

// logSpoof 限频记录「IPv4 头合法但源地址 ≠ 会话分配地址」的包——这才是值得
// 警惕的伪造嫌疑。非 IPv4 流量走 logNonIPv4（debug），两者共用一条日志会把
// 背景噪声升级成假警报。
func (s *Server) logSpoof(ps *peerSession, src netip.Addr) {
	if !throttle(&s.lastSpoof, 10) {
		return
	}
	logger.S.Warnw("丢弃源地址不匹配的隧道包（疑似伪造）",
		"user", ps.userName, "code", ps.codeName, "expect", ps.tunIP, "got", src)
}

// isTunnelInternal 报告该地址是否属于「隧道内部、不许互相访问」的地址：
// 网段内即命中，零例外。网关（中转机在 TUN 上的地址）同样命中——它上面的
// 服务对隧道用户不可达是 INPUT 收紧后的既定语义，这里在用户态对齐，别让
// 包先进内核再被丢。
func (s *Server) isTunnelInternal(ip netip.Addr) bool {
	return ip.IsValid() && s.tunPool.Contains(ip)
}

// logTunnelInternal 限频记录隧道内互访的拦截。direction 是被拦地址在 IP 头里
// 的位置（"源"/"目的"），方便对上排查方向。
func (s *Server) logTunnelInternal(ps *peerSession, ip netip.Addr, direction string) {
	if !throttle(&s.lastInternal, 10) {
		return
	}
	logger.S.Warnw("丢弃隧道内互访的包（用户隔离）",
		"direction", direction, "addr", ip,
		"user", ps.userName, "code", ps.codeName, "tun_ip", ps.tunIP)
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
//
// 批量化（OPT-6）：封装好的包攒进发送批，读队列排空时一次 sendmmsg 发出。
// 批边界仍是「一次系统调用返回多少包」——TUN 侧 Buffered()==0 就冲刷，
// 不定时、不等待、不凑批。
func (s *Server) pumpTunToClient(dev *tunnet.Device, writer udpWriter) {
	buf := make([]byte, dev.ReadBufSize())
	// 封装输出缓冲：一次 Seal 的结果在被 writer 拷走之前有效，所以单块即可。
	// 尾部多留 NonceSize 是零分配封装路径的要求（nonce 借用容量区组装）。
	out := make([]byte, 0, tunnel.MaxPacket+tunnel.NonceSize)
	for {
		select {
		case <-s.stop:
			s.flushWriter(writer)
			return
		default:
		}
		n, err := dev.ReadPacket(buf)
		if err != nil {
			s.flushWriter(writer)
			return
		}
		if n == 0 {
			continue
		}
		s.forwardOutbound(writer, out, buf[:n])
		if dev.Buffered() == 0 {
			s.flushWriter(writer)
		}
	}
}

// forwardOutbound 把一个 TUN 出向包分流、封装并加入发送批。
func (s *Server) forwardOutbound(writer udpWriter, out, pkt []byte) {
	dst, ok := dstIP4(pkt)
	if !ok {
		return
	}
	ps := s.peers.byTunnelIP(dst)
	if ps == nil {
		s.logNoRoute(dst)
		return
	}
	// 用户隔离的对称执行语句：发往客户端的包，源地址不得是隧道网段内的
	// 地址（零例外，含网关）。合法来源只有玩家公网 IP；出现隧道内地址
	// 说明有人正在隧道里访问别人，不能替他递送。
	if src, sok := srcIP4(pkt); sok && s.isTunnelInternal(src) {
		s.logTunnelInternal(ps, src, "源")
		return
	}
	// 超出协商 MTU 的包无法经隧道转发（封装后必然被 IP 分片，而分片丢一片
	// 等于整包全损）。此前这类包在 tunnet 读侧被静默丢弃，是黑盒丢包的来源。
	if len(pkt) > ps.mtu {
		ps.sess.Stats().AddTunDropped(1)
		s.logOverMTU(ps, len(pkt))
		return
	}
	// 直接用 buf 切片：封装在下一轮 ReadPacket 覆盖 buf 之前同步完成，
	// 逐包 make+copy 是纯浪费的分配。
	wire, extra := ps.sess.SealDataFEC(out[:0], pkt)
	s.enqueue(writer, ps, wire)
	if extra != nil {
		// FEC 校验包 / 冗余副本必须是**独立的数据报**：合并进同一个包等于
		// 让校验与数据同生共死，一次丢包同时带走两者，纠错就白做了。
		s.enqueue(writer, ps, extra)
	}
}

// enqueue 把一个已封装的包加入发送批，批满时先冲刷。
func (s *Server) enqueue(writer udpWriter, ps *peerSession, wire []byte) {
	if writer.add(wire, ps.addrPort) {
		return
	}
	s.flushWriter(writer)
	if !writer.add(wire, ps.addrPort) {
		ps.sess.Stats().AddTxDropped(1)
	}
}

// flushWriter 冲刷发送批。
//
// 单个 peer 写失败不终止整个泵——那会让一个客户端的网络问题掐断所有其它
// 用户的隧道。缓冲满（ENOBUFS/EWOULDBLOCK）时丢当前批并计数，绝不阻塞读 TUN。
func (s *Server) flushWriter(writer udpWriter) {
	if writer.pending() == 0 {
		return
	}
	if _, err := writer.flush(); err != nil {
		s.logUDPWriteErr(err)
	}
}

// heartbeat 周期心跳（对每个在线会话各发一次）。
//
// 心跳同时承担两件事：维持 NAT 映射与会话活跃判定，以及被动测量 RTT
// （Pong 回来时算差值）。逐包发送，低频路径不进批量化。
func (s *Server) heartbeat(udpConn *net.UDPConn) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	buf := make([]byte, 0, 64+tunnel.NonceSize)
	for {
		select {
		case <-s.stop:
			return
		case <-tick.C:
			for _, ps := range s.peers.snapshot() {
				wire := ps.sess.SealPing(buf[:0], 0, 0)
				if _, err := udpConn.WriteToUDPAddrPort(wire, ps.addrPort); err != nil {
					ps.sess.Stats().AddTxDropped(1)
				}
			}
		}
	}
}

// janitor 回收空闲超时的会话，并采样内核层丢包。
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
				logger.S.Infow("隧道会话已因空闲回收",
					"user", ps.userName, "code", ps.codeName, "tun_ip", ps.tunIP)
				s.forgetPushed(ps.codeID)
			}
			s.sampleKernelDrops()
			s.tunDrops.Store(s.dev.Dropped())
		}
	}
}

// sampleKernelDrops 读一次内核 UDP 收缓冲溢出计数。
//
// 只在**增量非零**时打日志：这类丢包应用层完全无感（日志里一个字都没有），
// 但它稳态下恒为 0，一旦增长就说明缓冲被打穿了——那是需要立刻知道的信号，
// 而不是每 30 秒复述一遍的噪声。
func (s *Server) sampleKernelDrops() {
	port := 0
	if la, ok := s.udp.LocalAddr().(*net.UDPAddr); ok {
		port = la.Port
	}
	if port == 0 {
		return
	}
	cur, ok := kernelUDPDrops(port)
	if !ok {
		return
	}
	prev := s.kernelDrops.Swap(cur)
	if cur > prev {
		logger.S.Warnw("内核 UDP 接收缓冲溢出丢包（突发流量打穿了 socket 缓冲）",
			"delta", cur-prev, "total", cur, "fix", sysctlHint(tunnelSocketBuffer))
	}
}

// KernelDrops 返回内核 UDP 收缓冲累计丢包数（0 = 无数据或非 Linux）。
func (s *Server) KernelDrops() uint64 { return s.kernelDrops.Load() }

// TunDrops 返回 TUN 读侧因超出缓冲而丢弃的包数。
func (s *Server) TunDrops() int64 { return s.tunDrops.Load() }

// IOMode 返回实际生效的 UDP 收发模式（诊断用）。
func (s *Server) IOMode() string { return s.io.Mode }

// pushSessionIPs 周期把活跃会话来源 IP 推给各自的客户端（回程路由同步），
// 并把「上一轮在、这一轮不在」的来源作为结束事件单独下发。
//
// 为什么要发结束事件：客户端的 /32 主机路由会吸走该 IP 的**全部**回包，包括
// 玩家不经代理直连源站的那条流。活跃列表的「缺席」不能当删除依据（铁律 5），
// 所以必须由服务端在会话真正结束时说一声，客户端才能及时回收。
//
// 推送每 10 秒一次且内容通常不变，逐次打 info 只会把日志刷满。所以只在某个
// 访问码的 IP 集合发生变化时记一条 info，逐次推送降到 debug。
func (s *Server) pushSessionIPs(sessionIPs SessionIPsFunc, udpConn *net.UDPConn) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	buf := make([]byte, 0, tunnel.MaxPacket+tunnel.NonceSize)
	for {
		select {
		case <-s.stop:
			return
		case <-tick.C:
			byCode := sessionIPs()
			for _, ps := range s.peers.snapshot() {
				ips := byCode[ps.codeID]
				// 空列表也要走完这一轮：会话全部结束时（玩家都退了）恰好
				// 是最需要下发结束事件的时刻，提前 continue 会让客户端的
				// 残留路由等到本地宽限期才消失。
				if len(ips) > 0 {
					wire, err := ps.sess.SealCtrl(buf[:0], tunnel.CtrlMessage{Kind: tunnel.CtrlKindRoutes, IPs: ips})
					if err != nil {
						continue
					}
					if _, err := udpConn.WriteToUDPAddrPort(wire, ps.addrPort); err != nil {
						continue
					}
				}
				gone, changed := s.diffPushed(ps.codeID, ips)
				if len(gone) > 0 {
					s.sendEnded(udpConn, ps, gone)
				}
				if changed {
					logger.S.Infow("回程路由 IP 变更",
						"user", ps.userName, "code", ps.codeName, "count", len(ips), "ips", ips)
				} else {
					logger.S.Debugw("回程路由 IP 已推送", "code", ps.codeName, "count", len(ips))
				}
			}
		}
	}
}

// sendEnded 下发「这些来源已无活跃会话」。失败不重试：客户端还有本地空闲
// 宽限期兜底，只是回收得慢一些。
func (s *Server) sendEnded(udpConn *net.UDPConn, ps *peerSession, gone []string) {
	wire, err := ps.sess.SealCtrl(nil, tunnel.CtrlMessage{Kind: tunnel.CtrlKindEnded, IPs: gone})
	if err != nil {
		return
	}
	if _, err := udpConn.WriteToUDPAddrPort(wire, ps.addrPort); err != nil {
		return
	}
	logger.S.Infow("回程路由会话结束已通知",
		"user", ps.userName, "code", ps.codeName, "ips", gone)
}

// diffPushed 用本轮的活跃 IP 集合替换上一轮，返回「上轮在、本轮不在」的集合
// 与「集合是否发生变化」。
//
// 首次推送（该访问码没有上一轮记录）不产出 gone：新会话对端路由表是空的，
// 无从谈起「结束」。
func (s *Server) diffPushed(codeID string, ips []string) (gone []string, changed bool) {
	cur := make([]string, len(ips))
	copy(cur, ips)
	sort.Strings(cur)

	s.pushMu.Lock()
	prev, seen := s.pushPrev[codeID]
	s.pushPrev[codeID] = cur
	s.pushMu.Unlock()

	if !seen {
		return nil, len(cur) > 0
	}
	if slices.Equal(prev, cur) {
		return nil, false
	}
	now := make(map[string]bool, len(cur))
	for _, ip := range cur {
		now[ip] = true
	}
	for _, ip := range prev {
		if !now[ip] {
			gone = append(gone, ip)
		}
	}
	return gone, true
}

// forgetPushed 清掉某访问码的推送记录，让下一轮必然重推并记一条 info。
//
// 会话换了（重握手、被踢、空闲回收）之后对端的路由表是空的，上一轮的集合
// 不再代表对端状态，据它算出的结束事件也没有意义。
func (s *Server) forgetPushed(codeID string) {
	s.pushMu.Lock()
	delete(s.pushPrev, codeID)
	s.pushMu.Unlock()
}
