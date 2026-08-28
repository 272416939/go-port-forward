// Package tunnelapp 内置隧道服务端：为 Windows 端 pf-client 提供加密隧道
// 与回程路径（TUN + 策略路由本机投递），并周期把 go-port-forward 活跃会话的
// 来源 IP 推送给客户端维护 /32 回程路由。开启 tunnel.enabled 后随主程序
// 常驻，无需单独的 pf-server 进程。
package tunnelapp

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/pkg/tunnet"
	"go-port-forward/pkg/tunnel"

)

// Config 隧道服务端配置（config.yaml 的 tunnel 段）。
type Config struct {
	Enabled bool   `mapstructure:"enabled"`
	Listen  string `mapstructure:"listen"`  // UDP 监听，默认 ":7947"
	PSK     string `mapstructure:"psk"`     // 留空使用与客户端一致的内置默认
	TunName string `mapstructure:"tun_name"`
	TunAddr string `mapstructure:"tun_addr"` // 如 "10.66.0.1/24"
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

const defaultPSK = "pfapp-default-psk-v1" // 与客户端内置默认一致

// Server 是运行中的隧道服务端实例。
type Server struct {
	cfg          Config
	udp          *net.UDPConn
	dev          *tunnet.Device
	sessPtr      atomic.Pointer[tunnel.Session]
	peerValue    atomic.Value // *net.UDPAddr
	lastWriteErr atomic.Int64 // 写 TUN 失败日志限频锚点（Unix 秒）
	stop         chan struct{}
	stopOnce     sync.Once
	done         chan struct{}
}

// SessionIPsFunc 返回当前活跃会话的来源 IP 去重列表。
type SessionIPsFunc func() []string

// Start 启动隧道服务端（TUN/NAT/UDP/泵/推送）。任一初始化失败返回错误。
func Start(cfg Config, sessionIPs SessionIPsFunc) (*Server, error) {
	cfg.Defaults()
	psk := []byte(cfg.PSK)
	if cfg.PSK == "" {
		psk = []byte(defaultPSK)
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
		cfg:  cfg,
		udp:  udpConn,
		dev:  dev,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}

	go s.loop(dev, udpConn, psk)          // 客户端 → TUN（含握手状态机）
	go s.pumpTunToClient(dev, udpConn)    // TUN → 客户端
	go s.heartbeat(udpConn)               // 心跳
	if sessionIPs != nil {
		go s.pushSessionIPs(sessionIPs, udpConn) // 回程路由同步
	}
	logger.S.Infow("隧道服务端已启动", "listen", cfg.Listen, "tun", cfg.TunName, "addr", cfg.TunAddr)
	return s, nil
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

func (s *Server) peer() *net.UDPAddr {
	if v := s.peerValue.Load(); v != nil {
		return v.(*net.UDPAddr)
	}
	return nil
}

// loop 客户端 → TUN 泵（含握手状态机，最近接入的客户端胜出）。
func (s *Server) loop(dev *tunnet.Device, udpConn *net.UDPConn, psk []byte) {
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

		if sess := s.sessPtr.Load(); sess == nil {
			if hello, herr := tunnel.ParseClientHello(psk, pkt); herr == nil {
				accept, priv, aerr := tunnel.NewServerAccept(psk, hello.Eph)
				if aerr != nil {
					continue
				}
				if _, werr := udpConn.WriteToUDP(accept.Marshal(), from); werr != nil {
					continue
				}
				shared := tunnel.ECDHShared(&hello.Eph, priv)
				sess := tunnel.NewSession(tunnel.DeriveSessionKey(shared, psk))
				s.sessPtr.Store(sess)
				s.peerValue.Store(from)
				logger.S.Infow("隧道客户端已接入", "src", from)
			}
			continue
		}

		sess := s.sessPtr.Load()
		switch {
		case pkt[0] == tunnel.TypeHello:
			// 客户端重连：重新握手换新会话密钥
			if hello, herr := tunnel.ParseClientHello(psk, pkt); herr == nil {
				accept, priv, _ := tunnel.NewServerAccept(psk, hello.Eph)
				if _, werr := udpConn.WriteToUDP(accept.Marshal(), from); werr == nil {
					prev := s.peer()
					shared := tunnel.ECDHShared(&hello.Eph, priv)
					sess := tunnel.NewSession(tunnel.DeriveSessionKey(shared, psk))
					s.sessPtr.Store(sess)
					s.peerValue.Store(from)
					// 空闲 30 秒会触发客户端自动重握手，同一来源的重连是
					// 常态，只在来源变化时记 info（换机器/换 NAT 端口才值得注意）。
					if prev == nil || prev.String() != from.String() {
						logger.S.Infow("隧道客户端重新接入", "src", from)
					} else {
						logger.S.Debugw("隧道客户端重新握手", "src", from)
					}
				}
			}
		case sess.IsPing(pkt):
			if addr := s.peer(); addr != nil {
				pong := make([]byte, 0, 1+24+16)
				pong = append(pong, tunnel.TypePong)
				pong = append(pong, sess.Seal(nil)...)
				_, _ = udpConn.WriteToUDP(pong, addr)
			}
		case sess != nil:
			plain, oerr := sess.OpenData(pkt)
			if oerr == nil {
				if werr := dev.WritePacket(plain); werr != nil {
					s.logWriteErr(werr)
				}
			}
		}
	}
}

// logWriteErr 限频记录写 TUN 失败（每 5 秒最多一条）。
// 数据面写失败若静默丢弃，故障表现为「隧道通、业务不通」且毫无线索。
func (s *Server) logWriteErr(err error) {
	now := time.Now().Unix()
	last := s.lastWriteErr.Load()
	if now-last < 5 || !s.lastWriteErr.CompareAndSwap(last, now) {
		return
	}
	logger.S.Warnw("写入 TUN 失败（玩家入站包被丢弃）", "err", err)
}

// pumpTunToClient TUN → 客户端 泵。
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
		sess := s.sessPtr.Load()
		addr := s.peer()
		if sess == nil || addr == nil {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if _, werr := udpConn.WriteToUDP(sess.SealData(pkt), addr); werr != nil {
			return
		}
	}
}

// heartbeat 周期心跳。
func (s *Server) heartbeat(udpConn *net.UDPConn) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-tick.C:
			sess := s.sessPtr.Load()
			addr := s.peer()
			if sess == nil || addr == nil {
				continue
			}
			ping := make([]byte, 0, 1+24+16)
			ping = append(ping, tunnel.TypePing)
			ping = append(ping, sess.Seal(nil)...)
			_, _ = udpConn.WriteToUDP(ping, addr)
		}
	}
}

// pushSessionIPs 周期把活跃会话来源 IP 推给客户端（回程路由同步）。
//
// 推送每 10 秒一次且内容通常不变，逐次打 info 只会把日志刷满、把真正有用的
// 信息挤出屏幕。所以只在 IP 集合发生变化时记一条 info（这才是运维需要知道的
// 状态变更），逐次推送降到 debug。
func (s *Server) pushSessionIPs(sessionIPs SessionIPsFunc, udpConn *net.UDPConn) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	var lastSig string
	for {
		select {
		case <-s.stop:
			return
		case <-tick.C:
			sess := s.sessPtr.Load()
			addr := s.peer()
			if sess == nil || addr == nil {
				continue
			}
			ips := sessionIPs()
			if len(ips) == 0 {
				continue
			}
			wire, err := sess.SealCtrl(tunnel.CtrlMessage{IPs: ips})
			if err != nil {
				continue
			}
			if _, err := udpConn.WriteToUDP(wire, addr); err != nil {
				continue
			}
			if sig := sessionIPsSignature(ips); sig != lastSig {
				lastSig = sig
				logger.S.Infow("回程路由 IP 变更", "count", len(ips), "ips", ips)
			} else {
				logger.S.Debugw("回程路由 IP 已推送", "count", len(ips))
			}
		}
	}
}

// sessionIPsSignature 生成与顺序无关的集合指纹，用于判断内容是否变化。
// 会话来源于 map 遍历，顺序本身不稳定，不排序会把同一集合误判为变更。
func sessionIPsSignature(ips []string) string {
	sorted := make([]string, len(ips))
	copy(sorted, ips)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}
