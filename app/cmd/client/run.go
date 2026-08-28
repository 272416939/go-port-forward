//go:build windows

package main

// Engine.run —— 一次连接的完整生命周期：开网卡 → 握手 → 双向泵 → 清理。
// 与 UI 的交互全部通过 Engine 上的状态/日志/统计字段，这里不直接碰 HTTP。

import (
	"context"
	"fmt"
	"net"
	"time"

	"go-port-forward/pkg/tunnel"
	"go-port-forward/pkg/tunnet"
	"pfapp/internal/syssetup"
)

func (e *Engine) run(ctx context.Context, addr string) {
	serverAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		e.fail("地址无法解析：%v", err)
		return
	}

	udp, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		e.fail("创建 UDP socket 失败：%v", err)
		return
	}
	defer udp.Close()

	dev, err := tunnet.Open(tunName, 1400)
	if err != nil {
		e.fail("创建虚拟网卡失败（请确认以管理员运行）：%v", err)
		return
	}
	defer dev.Close()

	if err := syssetup.ConfigureInterface(tunName, tunClientIP, tunCIDRMask); err != nil {
		e.fail("配置虚拟网卡地址失败：%v", err)
		return
	}
	// 静态邻居：wintun 是三层设备，Windows 对它不做 ARP，这一项只是省掉
	// 边缘场景下的一次解析，失败不影响隧道。
	if err := syssetup.AddStaticNeighbor(tunName, tunServerIP, "aa-bb-cc-dd-ee-ff"); err != nil {
		e.logf("[!] 静态邻居添加失败（可忽略）：%v", err)
	}
	defer syssetup.RemoveStaticNeighbor(tunName, tunServerIP)

	// Windows 把新网卡归为公用网络并默认阻止入站，玩家包会被静默丢弃。
	if err := syssetup.AllowInboundOnInterface(tunName); err != nil {
		e.logf("[!] 防火墙放行失败（玩家流量可能被拦截）：%v", err)
	} else {
		e.logf("已为虚拟网卡添加防火墙入站放行。")
	}
	defer syssetup.RemoveInboundRule()

	e.logf("虚拟网卡就绪：%s", tunClientIP)

	rm := newRouteManager(serverAddr.IP.String(), e.logf)
	e.routes.Store(rm)
	defer func() {
		rm.cleanup()
		e.routes.Store(nil)
	}()

	// TUN → 隧道
	go func() {
		buf := make([]byte, 1500)
		for {
			n, rerr := dev.ReadPacket(buf)
			if rerr != nil {
				return
			}
			if n == 0 || ctx.Err() != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			sess := e.session()
			if sess == nil {
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			e.statTunToTunnel.Add(1)
			if _, werr := udp.Write(sess.SealData(pkt)); werr != nil {
				return
			}
		}
	}()

	// 心跳
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if sess := e.session(); sess != nil {
					_, _ = udp.Write(sess.SealPing())
				}
			}
		}
	}()

	// 主循环：握手 → 泵；断开后自动重握手，直到 ctx 取消。
	for ctx.Err() == nil {
		e.setState(StateConnecting, "")
		sess, herr := e.handshake(ctx, udp)
		if herr != nil {
			if ctx.Err() != nil {
				break
			}
			e.setState(StateError, herr.Error())
			e.logf("握手失败：%v（3 秒后重试）", herr)
			rm.cleanup()
			if sleepCtx(ctx, 3*time.Second) != nil {
				break
			}
			continue
		}

		e.setSession(sess)
		e.setState(StateConnected, "")
		e.logf("✔ 隧道已建立。")

		if perr := e.pump(ctx, udp, dev, sess, rm); perr != nil && ctx.Err() == nil {
			e.logf("隧道中断：%v", perr)
		}
		e.setSession(nil)
		rm.cleanup()
	}

	e.setSession(nil)
}

// fail 记录失败原因并置为错误态。
func (e *Engine) fail(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	e.logs.add(msg)
	e.setState(StateError, msg)
}

// handshake 循环发送 Hello 直到收到 Accept 或 ctx 取消。
func (e *Engine) handshake(ctx context.Context, udp *net.UDPConn) (*tunnel.Session, error) {
	for attempt := 1; attempt <= handshakeTries; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
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
			e.logf("等待服务端应答 (%d/%d)…", attempt, handshakeTries)
			continue
		}
		accept, err := tunnel.ParseServerAccept([]byte(defaultPSK), buf[:n], hello.Eph)
		if err != nil {
			return nil, fmt.Errorf("%v（请核对服务端 PSK 配置）", err)
		}
		_ = udp.SetReadDeadline(time.Time{})
		shared := tunnel.ECDHShared(&accept.Eph, priv)
		return tunnel.NewSession(tunnel.DeriveSessionKey(shared, []byte(defaultPSK))), nil
	}
	return nil, fmt.Errorf("服务端无应答（请检查地址、端口与中转机防火墙）")
}

// pump 收隧道包：Data→写 TUN，Ctrl→同步回程路由，Ping→Pong。
// 30 秒无任何入站包返回错误，交由外层重握手。
func (e *Engine) pump(ctx context.Context, udp *net.UDPConn, dev *tunnet.Device,
	sess *tunnel.Session, rm *routeManager) error {
	buf := make([]byte, tunnel.MaxPacket+64)
	_ = udp.SetReadDeadline(time.Now().Add(30 * time.Second))
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, err := udp.Read(buf)
		if err != nil {
			return err
		}
		_ = udp.SetReadDeadline(time.Now().Add(30 * time.Second))
		switch {
		case n > 0 && buf[0] == tunnel.TypeData:
			if plain, oerr := sess.OpenData(buf[:n]); oerr == nil {
				e.statTunnelToTun.Add(1)
				// 必须先装回程路由再写 TUN：后端回包可能在微秒内产生，
				// 路由晚一步，回包就从物理网卡漏出去了。
				rm.touchPacket(plain)
				if werr := dev.WritePacket(plain); werr != nil {
					e.logWriteErr(werr)
				}
			}
		case n > 0 && buf[0] == tunnel.TypeCtrl:
			if msg, cerr := sess.OpenCtrl(buf[:n]); cerr == nil {
				rm.sync(msg.IPs)
			}
		case n > 0 && buf[0] == tunnel.TypePing:
			pong := make([]byte, 0, 1+24+16)
			pong = append(pong, tunnel.TypePong)
			pong = append(pong, sess.Seal(nil)...)
			_, _ = udp.Write(pong)
		}
	}
}

// logWriteErr 限频记录写 TUN 失败（每 5 秒最多一条）。
// 数据面写失败若静默丢弃，故障只表现为「隧道已建立但进不去世界」，无从排查。
func (e *Engine) logWriteErr(err error) {
	now := time.Now().Unix()
	last := e.lastWriteErr.Load()
	if now-last < 5 || !e.lastWriteErr.CompareAndSwap(last, now) {
		return
	}
	e.logf("[!] 写入虚拟网卡失败（玩家入站包被丢弃）：%v", err)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
