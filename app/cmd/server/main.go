//go:build linux

// pf-server —— Port Forward 隧道服务端（Linux，与 go-port-forward 同机部署）。
// 创建 TUN（默认 10.66.0.1/24），启用 IP 转发与 MASQUERADE，等待客户端接入；
// 周期拉取 go-port-forward 的活跃会话来源 IP，经加密控制通道推给客户端，
// 客户端据此维护 /32 回程路由（仅回程，不影响后端其它流量）。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"pfapp/internal/syssetup"
	"pfapp/internal/tunnet"
	"pfapp/internal/tunnel"

	"gopkg.in/yaml.v3"
)

const defaultPSK = "pfapp-default-psk-v1" // 与客户端内置默认一致；生产建议在配置中修改

type config struct {
	Listen string `yaml:"listen"` // UDP 监听，如 ":7947"
	PSK    string `yaml:"psk"`    // 预共享密钥；留空使用内置默认
	Tun    struct {
		Name string `yaml:"name"` // TUN 接口名
		Addr string `yaml:"addr"` // 服务端地址，如 "10.66.0.1/24"
	} `yaml:"tun"`
	NAT struct {
		Enabled bool `yaml:"enabled"` // 自动 ip_forward + MASQUERADE
	} `yaml:"nat"`
	Sessions struct {
		URL      string `yaml:"url"`      // go-port-forward 的 /api/sessions
		Username string `yaml:"username"` // 可选 Basic Auth
		Password string `yaml:"password"`
	} `yaml:"sessions"`
}

var sessPtr atomic.Pointer[tunnel.Session]

func main() {
	cfgPath := flag.String("config", "config.yaml", "配置文件路径 | config file path")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置错误 | config error: %v\n", err)
		os.Exit(1)
	}
	psk := []byte(cfg.PSK)
	if cfg.PSK == "" {
		psk = []byte(defaultPSK)
	}

	tunNet := tunCIDRMaskOf(cfg.Tun.Addr)

	dev, err := tunnet.Open(cfg.Tun.Name, 1400)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer dev.Close()
	if err := syssetup.ConfigureInterface(cfg.Tun.Name, cfg.Tun.Addr); err != nil {
		fmt.Fprintf(os.Stderr, "配置 TUN 地址失败 | configure tun: %v\n", err)
		os.Exit(1)
	}
	if cfg.NAT.Enabled {
		if err := syssetup.SetupNAT(tunNet); err != nil {
			fmt.Fprintf(os.Stderr, "配置 NAT 失败（回程将无法改写源地址）| nat: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("隧道服务端就绪：tun=%s(%s) udp=%s\n", cfg.Tun.Name, cfg.Tun.Addr, cfg.Listen)

	udp, err := net.ListenPacket("udp", cfg.Listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "监听失败 | listen: %v\n", err)
		os.Exit(1)
	}
	udpConn := udp.(*net.UDPConn)
	defer udpConn.Close()

	// TUN → 客户端 泵
	go func() {
		buf := make([]byte, 1500+tunnet.Offset)
		for {
			n, err := dev.ReadPacket(buf)
			if err != nil {
				return
			}
			if s := sessPtr.Load(); s != nil && n > 0 {
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				if _, addr := peerAddr(); err == nil {
					_, _ = udpConn.WriteToUDP(s.SealData(pkt), addr)
				}
			}
		}
	}()

	// 会话 IP 拉取 → 控制通道推送
	if cfg.Sessions.URL != "" {
		go func() {
			tick := time.NewTicker(10 * time.Second)
			defer tick.Stop()
			for range tick.C {
				s := sessPtr.Load()
				if s == nil {
					continue
				}
				ips, err := fetchSessionIPs(cfg)
				if err != nil {
					continue
				}
				if wire, err := s.SealCtrl(tunnel.CtrlMessage{IPs: ips}); err == nil {
					if _, addr := peerAddr(); addr != nil {
						_, _ = udpConn.WriteToUDP(wire, addr)
					}
				}
			}
		}()
	}

	// 心跳探测
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for range tick.C {
			if s := sessPtr.Load(); s != nil {
				if _, addr := peerAddr(); addr != nil {
					_, _ = udpConn.WriteToUDP(s.SealPing(), addr)
				}
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// 客户端 → TUN 泵（含握手状态机）
	go runServer(udpConn, dev, psk)

	<-sig
	fmt.Println("\n正在退出…")
}

// peerAddr 返回当前客户端地址（未连接时 addr 为 nil）。
func peerAddr() (bool, *net.UDPAddr) {
	if v := peerValue.Load(); v != nil {
		return true, v.(*net.UDPAddr)
	}
	return false, nil
}

var peerValue atomic.Value // 存 *net.UDPAddr

func loadConfig(path string) (*config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if cfg.Listen == "" {
		cfg.Listen = ":7947"
	}
	if cfg.Tun.Name == "" {
		cfg.Tun.Name = "pftun0"
	}
	if cfg.Tun.Addr == "" {
		cfg.Tun.Addr = "10.66.0.1/24"
	}
	return &cfg, nil
}

// tunCIDRMaskOf 从 "10.66.0.1/24" 提取网段 "10.66.0.0/24"。
func tunCIDRMaskOf(addr string) string {
	_, ipnet, err := net.ParseCIDR(addr)
	if err != nil {
		return "10.66.0.0/24"
	}
	return ipnet.String()
}

// fetchSessionIPs 拉取 go-port-forward 活跃会话的来源 IP（去重）。
func fetchSessionIPs(cfg *config) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, cfg.Sessions.URL, nil)
	if err != nil {
		return nil, err
	}
	if cfg.Sessions.Username != "" || cfg.Sessions.Password != "" {
		req.SetBasicAuth(cfg.Sessions.Username, cfg.Sessions.Password)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var parsed struct {
		Data struct {
			Sessions []struct {
				SrcIP string `json:"src_ip"`
			} `json:"sessions"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var ips []string
	for _, s := range parsed.Data.Sessions {
		if s.SrcIP != "" && !seen[s.SrcIP] {
			seen[s.SrcIP] = true
			ips = append(ips, s.SrcIP)
		}
	}
	return ips, nil
}

// 主循环：等待客户端握手（最近连接的客户端胜出）并泵 UDP→TUN。
func runServer(udpConn *net.UDPConn, dev *tunnet.Device, psk []byte) {
	buf := make([]byte, tunnel.MaxPacket+64)
	for {
		n, from, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]

		// 未建立会话：只接受 Hello
		if sessPtr.Load() == nil {
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
				sessPtr.Store(sess)
				peerValue.Store(from)
				fmt.Printf("客户端已接入：%s\n", from)
			}
			continue
		}

		sess := sessPtr.Load()
		switch {
		case pkt[0] == tunnel.TypeHello:
			// 客户端重连（服务端侧会话可能已过期）：重新握手
			sessPtr.Store(nil)
			if hello, herr := tunnel.ParseClientHello(psk, pkt); herr == nil {
				accept, priv, _ := tunnel.NewServerAccept(psk, hello.Eph)
				if _, werr := udpConn.WriteToUDP(accept.Marshal(), from); werr == nil {
					shared := tunnel.ECDHShared(&hello.Eph, priv)
					sess = tunnel.NewSession(tunnel.DeriveSessionKey(shared, psk))
					sessPtr.Store(sess)
					peerValue.Store(from)
					fmt.Printf("客户端重新接入：%s\n", from)
				}
			}
		case sess != nil && sess.IsPing(pkt):
			if _, addr := peerAddr(); addr != nil {
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
