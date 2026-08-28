//go:build windows

// pf-client —— Port Forward 隧道客户端（Windows）。
// 以管理员身份运行，提示输入中转机（代理）地址后建立加密隧道：
// 创建 "Port Forward" 虚拟网卡（10.66.0.2），并按服务端推送的
// 会话 IP 列表动态维护 /32 回程路由（仅回程，不影响其它流量）。
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"pfapp/internal/syssetup"
	"go-port-forward/pkg/tunnet"
	"go-port-forward/pkg/tunnel"
)

const (
	defaultPSK    = "pfapp-default-psk-v1" // 与服务端配置保持一致，可修改
	tunName       = "Port Forward"
	tunClientIP   = "10.66.0.2"
	tunServerIP   = "10.66.0.1"
	tunCIDRMask   = "255.255.255.0"
	handshakeTries = 8
)

var (
	sessPtr atomic.Pointer[tunnel.Session]
	peerPtr atomic.Pointer[net.UDPAddr]
	addedMu sync.Mutex
	added   = map[string]bool{} // 已添加回程路由的 IP

	// 数据面统计（每 5 秒打印，用于定位断点在隧道段还是 Windows 本地段）
	statTunToTunnel atomic.Int64 // TUN 读出 → 发往隧道（玩家回包方向）
	statTunnelToTun atomic.Int64 // 隧道收到 → 写入 TUN（玩家入站方向）

	serverIP net.IP // 中转机公网地址：回包源改写目标（10.66.0.2 → serverIP）
)

func main() {
	fmt.Println("════════ Port Forward 隧道客户端（Windows）════════")
	fmt.Println(t("请以管理员身份运行本程序（虚拟网卡与路由需要管理员权限）。", "Run as Administrator."))

	addr := promptWithDefault("Port Forward 代理地址 (IP:端口)", loadLastAddr())
	if !strings.Contains(addr, ":") {
		addr = addr + ":7947"
	}
	saveLastAddr(addr)
	fmt.Println(t("连接目标：", "Target: ") + addr)

	serverAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fatal("地址无效 | invalid address: %v", err)
	}
	if ra, rerr := net.ResolveIPAddr("ip4", serverAddr.IP.String()); rerr == nil {
		serverIP = ra.IP
	}

	udp, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		fatal("创建 UDP socket 失败: %v", err)
	}
	defer udp.Close()

	dev, err := tunnet.Open(tunName, 1400)
	if err != nil {
		fatal("%v", err)
	}
	defer dev.Close()
	if err := syssetup.ConfigureInterface(tunName, tunClientIP, tunCIDRMask); err != nil {
		fatal("配置虚拟网卡地址失败: %v", err)
	}
	fmt.Println(t("虚拟网卡就绪: ", "TUN ready: ") + tunClientIP)

	// 后台：TUN → 隧道
	go func() {
		buf := make([]byte, 1500+tunnet.Offset)
		for {
			n, err := dev.ReadPacket(buf)
			if err != nil {
				return
			}
			if s := sessPtr.Load(); s != nil {
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				statTunToTunnel.Add(1)
				if _, werr := udp.Write(s.SealData(pkt)); werr != nil {
					return
				}
			}
		}
	}()

	// 后台：数据面统计（隧道建立后每 5 秒一行）
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for range tick.C {
			if sessPtr.Load() == nil {
				continue
			}
			ti, to := statTunToTunnel.Load(), statTunnelToTun.Load()
			fmt.Printf("%s", fmt.Sprintf(t("[流量] 回程(TUN→隧道) %d 包 | 入站(隧道→TUN) %d 包\n", "[traffic] return(TUN->tunnel) %d pkts | inbound(tunnel->TUN) %d pkts\n"), ti, to))
		}
	}()

	// 后台：心跳
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for range tick.C {
			if s := sessPtr.Load(); s != nil {
				_, _ = udp.Write(s.SealPing())
			}
		}
	}()

	// Ctrl+C 清理路由
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n" + t("正在清理回程路由并退出…", "Cleaning up routes and exiting…"))
		cleanupRoutes()
		os.Exit(0)
	}()

	// 主循环：握手 → 泵；空闲超时自动重握手
	for {
		sess, err := handshake(udp, serverAddr)
		if err != nil {
			fmt.Println(t("握手失败：", "Handshake failed: ") + err.Error())
			cleanupRoutes()
			time.Sleep(3 * time.Second)
			continue
		}
		sessPtr.Store(sess)
		peerPtr.Store(serverAddr)
		fmt.Println(t("✔ 隧道已建立。按 Ctrl+C 退出。", "✔ Tunnel established. Ctrl+C to exit."))

		if err := pumpUDP(udp, dev, sess, serverAddr); err != nil {
			fmt.Println(t("隧道中断：", "Tunnel broken: ") + err.Error())
		}
		sessPtr.Store(nil)
		fmt.Println(t("30 秒无数据，重新握手…", "Idle 30s, re-handshaking…"))
		cleanupRoutes()
	}
}

// handshake 循环发送 Hello 直到收到 Accept。
func handshake(udp *net.UDPConn, server *net.UDPAddr) (*tunnel.Session, error) {
	for attempt := 1; attempt <= handshakeTries; attempt++ {
		hello, priv, err := tunnel.NewClientHello([]byte(defaultPSK))
		if err != nil {
			return nil, err
		}
		if _, err := udp.Write(hello.Marshal()); err != nil {
			return nil, err
		}
		buf := make([]byte, tunnel.MaxPacket+64)
		_ = udp.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		n, err := udp.Read(buf)
		if err != nil {
			fmt.Printf(t("  等待服务端应答 (%d/%d)…\n", "  waiting for server (%d/%d)…\n"), attempt, handshakeTries)
			continue
		}

		accept, err := tunnel.ParseServerAccept([]byte(defaultPSK), buf[:n], hello.Eph)
		if err != nil {
			return nil, fmt.Errorf("%v（请核对服务端 PSK 配置）", err)
		}
		_ = udp.SetReadDeadline(time.Time{})
		shared := tunnel.ECDHShared(&accept.Eph, priv)
		if serverIP == nil {
			if ra, rerr := net.ResolveIPAddr("ip4", server.IP.String()); rerr == nil {
				serverIP = ra.IP
				fmt.Println(t("服务器公网地址（回包源改写目标）：", "Server public IP (rewrite target): ") + serverIP.String())
			}
		}
		return tunnel.NewSession(tunnel.DeriveSessionKey(shared, []byte(defaultPSK))), nil
	}
	return nil, fmt.Errorf("服务端无应答（检查地址/端口/防火墙）")
}

// pumpUDP 收隧道包：Data→写 TUN，Ctrl→同步回程路由，Ping→Pong。
// 30 秒无任何入站包返回错误触发重握手。
func pumpUDP(udp *net.UDPConn, dev *tunnet.Device, sess *tunnel.Session, server *net.UDPAddr) error {
	buf := make([]byte, tunnel.MaxPacket+64)
	_ = udp.SetReadDeadline(time.Now().Add(30 * time.Second))
	for {
		n, err := udp.Read(buf)
		if err != nil {
			return err // 超时或错误 → 外层重握手
		}
		_ = udp.SetReadDeadline(time.Now().Add(30 * time.Second))
		switch {
		case n > 0 && buf[0] == tunnel.TypeData:
			if plain, oerr := sess.OpenData(buf[:n]); oerr == nil {
				statTunnelToTun.Add(1)
				rewriteSource(plain)
				_ = dev.WritePacket(plain)
			}
		case n > 0 && buf[0] == tunnel.TypeCtrl:
			if msg, cerr := sess.OpenCtrl(buf[:n]); cerr == nil {
				syncRoutes(msg.IPs)
			}
		case n > 0 && buf[0] == tunnel.TypePing:
			pong := make([]byte, 0, 1+24+16)
			pong = append(pong, tunnel.TypePong)
			pong = append(pong, sess.Seal(nil)...)
			_, _ = udp.Write(pong)
		}
	}
}

// syncRoutes 按服务端推送的全量 IP 列表增删 /32 回程路由。
func syncRoutes(ips []string) {
	desired := map[string]bool{}
	for _, ip := range ips {
		if net.ParseIP(ip) != nil {
			desired[ip] = true
		}
	}
	addedMu.Lock()
	defer addedMu.Unlock()
	for ip := range added {
		if !desired[ip] {
			if err := syssetup.RemoveRoute(ip); err == nil {
				fmt.Println(t("[-] 已移除回程路由:", "[-] route removed: ") + ip)
				delete(added, ip)
			}
		}
	}
	for ip := range desired {
		if !added[ip] {
			if err := syssetup.AddRoute(ip, tunServerIP); err == nil {
				added[ip] = true
				fmt.Println(t("[+] 已添加回程路由:", "[+] route added: ") + ip)
			} else {
				fmt.Println(t("[!] 回程路由添加失败:", "[!] route add failed: ") + ip)
			}
		}
	}
}

func cleanupRoutes() {
	addedMu.Lock()
	defer addedMu.Unlock()
	for ip := range added {
		_ = syssetup.RemoveRoute(ip)
		delete(added, ip)
	}
}

// --- 交互与本地配置 ---

func t(zh, en string) string { return zh } // 控制台客户端当前仅中文提示

func fatal(f string, a ...any) {
	fmt.Printf("错误: "+f+"\n", a...)
	fmt.Println(t("按回车退出…", "Press Enter to exit…"))
	var s string
	_, _ = fmt.Scanln(&s)
	os.Exit(1)
}

func confPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "pf-client.conf"
	}
	return filepath.Join(filepath.Dir(exe), "pf-client.conf")
}

func loadLastAddr() string {
	b, err := os.ReadFile(confPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func saveLastAddr(addr string) {
	_ = os.WriteFile(confPath(), []byte(strings.TrimSpace(addr)), 0o644)
}

func promptWithDefault(label, last string) string {
	if last != "" {
		fmt.Printf("%s（回车 = %s）：", label, last)
	} else {
		fmt.Printf("%s：", label)
	}
	var line string
	_, _ = fmt.Scanln(&line)
	line = strings.TrimSpace(line)
	if line == "" {
		if last == "" {
			fmt.Println("必须输入地址 | address is required")
			os.Exit(1)
		}
		return last
	}
	if _, _, err := net.SplitHostPort(line); err != nil {
		fmt.Println("地址格式应为 IP:端口 | expected IP:port")
		os.Exit(1)
	}
	return line
}
