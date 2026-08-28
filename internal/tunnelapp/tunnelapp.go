// Package tunnelapp 内置隧道服务端：为 Windows 端 pf-client 提供加密隧道
// 与回程路径（TUN + MASQUERADE），并周期把 go-port-forward 活跃会话的
// 来源 IP 推送给客户端维护 /32 回程路由。开启 tunnel.enabled 后随主程序
// 常驻，无需单独的 pf-server 进程。
package tunnelapp

import (
	"fmt"
	"net"
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
	NAT     bool   `mapstructure:"nat"`      // ip_forward + MASQUERADE + FORWARD 放行
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
	cfg       Config
	udp       *net.UDPConn
	dev       *tunnet.Device
	sessPtr   atomic.Pointer[tunnel.Session]
	peerValue atomic.Value // *net.UDPAddr
	stop      chan struct{}
	stopOnce  sync.Once
	done      chan struct{}
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
		if err := setupNAT(cfg.TunName, tunCIDR(cfg.TunAddr)); err != nil {
			dev.Close()
			return nil, fmt.Errorf("配置 NAT/转发失败: %w", err)
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
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.stop)
		<-s.done
		_ = s.udp.Close()
		_ = s.dev.Close()
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
					shared := tunnel.ECDHShared(&hello.Eph, priv)
					sess := tunnel.NewSession(tunnel.DeriveSessionKey(shared, psk))
					s.sessPtr.Store(sess)
					s.peerValue.Store(from)
					logger.S.Infow("隧道客户端重新接入", "src", from)
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
				_ = dev.WritePacket(plain)
			}
		}
	}
}

// pumpTunToClient TUN → 客户端 泵。
func (s *Server) pumpTunToClient(dev *tunnet.Device, udpConn *net.UDPConn) {
	buf := make([]byte, 1500+tunnet.Offset)
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
func (s *Server) pushSessionIPs(sessionIPs SessionIPsFunc, udpConn *net.UDPConn) {
	tick := time.NewTicker(10 * time.Second)
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
			ips := sessionIPs()
			if len(ips) == 0 {
				continue
			}
			wire, err := sess.SealCtrl(tunnel.CtrlMessage{IPs: ips})
			if err != nil {
				continue
			}
			if _, err := udpConn.WriteToUDP(wire, addr); err == nil {
				logger.S.Infow("回程路由 IP 已推送", "count", len(ips))
			}
		}
	}
}

// tunCIDR 从 "10.66.0.1/24" 提取网段。
func tunCIDR(addr string) string {
	_, ipnet, err := net.ParseCIDR(addr)
	if err != nil {
		return "10.66.0.0/24"
	}
	return ipnet.String()
}
