//go:build windows

package main

// Engine.run —— 一次连接的完整生命周期：开网卡 → 握手 → 配地址 → 双向泵 → 清理。
// 与 UI 的交互全部通过 Engine 上的状态/日志/统计字段，这里不直接碰 HTTP。
//
// 次序说明（多用户改造的关键）：隧道内地址由服务端在握手应答里下发，所以
// 「配置网卡地址 / 静态邻居 / 防火墙 / 路由管理器」必须排在握手之后。改造前
// 这些用的是编译期常量，可以在握手前一次配好。

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"go-port-forward/pkg/tunnel"
	"go-port-forward/pkg/tunnet"
	"pfapp/internal/syssetup"
)

func (e *Engine) run(ctx context.Context, conf clientConfig) {
	serverAddr, err := net.ResolveUDPAddr("udp", conf.Addr)
	if err != nil {
		e.fail("地址无法解析：%v", err)
		return
	}
	uid, err := tunnel.ParseUID(conf.CodeID)
	if err != nil {
		e.fail("接入码中的访问码 ID 无效：%v", err)
		return
	}
	device, err := deviceFingerprintBytes()
	if err != nil {
		e.fail("%v", err)
		return
	}
	secret := []byte(conf.Secret)

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

	// 网卡就绪前 TUN 上不会有流量，出向泵起得早一点无害；它自己会在
	// sess 或路由管理器尚未就绪时丢包。
	var rmHolder atomic.Pointer[routeManager]
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
			rm := rmHolder.Load()
			if sess == nil || rm == nil {
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			e.statTunToTunnel.Add(1)
			e.bytesUp.Add(int64(n))
			rm.countOutbound(pkt)
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

	// configured 记录已按下发地址配好系统。重握手时正常拿到同一个地址
	//（隧道地址持久绑定用户），只有真的变了才重配。
	var configured tunnelAddressing
	cleanupSystem := func() {
		if !configured.valid() {
			return
		}
		syssetup.RemoveStaticNeighbor(tunName, configured.Gateway)
		syssetup.RemoveInboundRule()
		configured = tunnelAddressing{}
	}
	defer func() {
		if rm := rmHolder.Load(); rm != nil {
			rm.cleanup()
		}
		e.routes.Store(nil)
		rmHolder.Store(nil)
		cleanupSystem()
		e.addr.Store(nil)
	}()

	// 主循环：握手 → 配地址 → 泵；断开后自动重握手，直到 ctx 取消。
	for ctx.Err() == nil {
		e.setState(StateConnecting, "")
		sess, addressing, herr := e.handshake(ctx, udp, uid, device, secret)
		if herr != nil {
			if ctx.Err() != nil {
				break
			}
			if rm := rmHolder.Load(); rm != nil {
				rm.cleanup()
			}
			// 服务端明确拒绝且原因需要人工介入（换了设备、访问码被停用）时
			// 停止重连：继续每 3 秒试一次只会刷日志，并把真正的原因埋进一串
			// 「握手失败」里。
			var rej *rejectedError
			if errors.As(herr, &rej) && rej.reason.Terminal() {
				e.setTerminal(rej.Error())
				e.logf("✗ %v", rej)
				break
			}
			e.setState(StateError, herr.Error())
			e.logf("握手失败：%v（3 秒后重试）", herr)
			if sleepCtx(ctx, 3*time.Second) != nil {
				break
			}
			continue
		}

		if addressing != configured {
			cleanupSystem()
			if aerr := e.applyAddressing(addressing); aerr != nil {
				e.setState(StateError, aerr.Error())
				e.logf("%v（3 秒后重试）", aerr)
				if sleepCtx(ctx, 3*time.Second) != nil {
					break
				}
				continue
			}
			configured = addressing
			e.addr.Store(&addressing)

			// 路由管理器依赖隧道地址（网关是 /32 回程路由的下一跳，
			// 本机与网关地址必须排除在可安装地址之外）。
			if rm := rmHolder.Load(); rm != nil {
				rm.cleanup()
			}
			rm := newRouteManager(serverAddr.IP.String(), addressing, e.logf)
			rmHolder.Store(rm)
			e.routes.Store(rm)
		}

		e.setSession(sess)
		e.setState(StateConnected, "")
		e.logf("✔ 隧道已建立（本机隧道地址 %s）。", addressing.ClientIP)

		rm := rmHolder.Load()
		if perr := e.pump(ctx, udp, dev, sess, rm); perr != nil && ctx.Err() == nil {
			e.logf("隧道中断：%v", perr)
		}
		e.setSession(nil)
		if rm != nil {
			rm.cleanup()
		}
	}

	e.setSession(nil)
}

// applyAddressing 按服务端下发的地址配置虚拟网卡、静态邻居与防火墙放行。
func (e *Engine) applyAddressing(a tunnelAddressing) error {
	if err := syssetup.ConfigureInterface(tunName, a.ClientIP, a.Mask); err != nil {
		return fmt.Errorf("配置虚拟网卡地址失败：%v", err)
	}
	// 静态邻居：wintun 是三层设备，Windows 对它不做 ARP，这一项只是省掉
	// 边缘场景下的一次解析，失败不影响隧道。
	if err := syssetup.AddStaticNeighbor(tunName, a.Gateway, "aa-bb-cc-dd-ee-ff"); err != nil {
		e.logf("[!] 静态邻居添加失败（可忽略）：%v", err)
	}
	// Windows 把新网卡归为公用网络并默认阻止入站，玩家包会被静默丢弃。
	if err := syssetup.AllowInboundOnInterface(tunName); err != nil {
		e.logf("[!] 防火墙放行失败（玩家流量可能被拦截）：%v", err)
	} else {
		e.logf("已为虚拟网卡添加防火墙入站放行。")
	}
	e.logf("虚拟网卡就绪：%s（网关 %s）", a.ClientIP, a.Gateway)
	return nil
}

// fail 记录失败原因并置为错误态。
func (e *Engine) fail(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	e.logs.add(msg)
	e.setState(StateError, msg)
}

// handshake 循环发送 Hello 直到收到 Accept 或 ctx 取消，返回会话与服务端
// 下发的隧道地址。
func (e *Engine) handshake(ctx context.Context, udp *net.UDPConn,
	uid tunnel.UID, device [tunnel.FingerprintSize]byte, secret []byte) (*tunnel.Session, tunnelAddressing, error) {
	var none tunnelAddressing
	for attempt := 1; attempt <= handshakeTries; attempt++ {
		if ctx.Err() != nil {
			return nil, none, ctx.Err()
		}
		hello, priv, err := tunnel.NewClientHello(secret, uid, device)
		if err != nil {
			return nil, none, err
		}
		if _, err := udp.Write(hello.Marshal()); err != nil {
			return nil, none, err
		}
		buf := make([]byte, tunnel.MaxPacket+64)
		_ = udp.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		n, err := udp.Read(buf)
		if err != nil {
			e.logf("等待服务端应答 (%d/%d)…", attempt, handshakeTries)
			continue
		}
		// 服务端明确拒绝：必须验 MAC 才采信。不验的话任何人都能伪造一个
		// Reject 让客户端停止重连——单包就能做到的拒绝服务。
		if n > 0 && buf[0] == tunnel.TypeReject {
			rej, rerr := tunnel.ParseServerReject(secret, buf[:n], hello.Eph)
			if rerr != nil {
				e.logf("收到无法验证的拒绝应答，已忽略 (%d/%d)…", attempt, handshakeTries)
				continue
			}
			return nil, none, &rejectedError{reason: rej.Reason}
		}
		accept, err := tunnel.ParseServerAccept(secret, buf[:n], hello.Eph)
		if err != nil {
			return nil, none, fmt.Errorf("%v（接入码可能已失效，请在面板重新获取）", err)
		}
		_ = udp.SetReadDeadline(time.Time{})
		shared := tunnel.ECDHShared(&accept.Eph, priv)
		addressing := tunnelAddressing{
			ClientIP: accept.TunAddr().String(),
			Mask:     prefixToMask(int(accept.Prefix)),
			Gateway:  accept.GatewayAddr().String(),
		}
		return tunnel.NewSession(tunnel.DeriveSessionKey(shared, secret)), addressing, nil
	}
	return nil, none, fmt.Errorf("服务端无应答（请检查地址、端口与中转机防火墙）")
}

// prefixToMask 把前缀长度转成点分十进制掩码（netsh 只接受这种写法）。
func prefixToMask(bits int) string {
	if bits < 0 {
		bits = 0
	}
	if bits > 32 {
		bits = 32
	}
	mask := net.CIDRMask(bits, 32)
	return net.IP(mask).String()
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
				e.bytesDown.Add(int64(len(plain)))
				// 必须先装回程路由再写 TUN：后端回包可能在微秒内产生，
				// 路由晚一步，回包就从物理网卡漏出去了。
				rm.countInbound(plain)
				if werr := dev.WritePacket(plain); werr != nil {
					e.logWriteErr(werr)
				}
			}
		case n > 0 && buf[0] == tunnel.TypeCtrl:
			if msg, cerr := sess.OpenCtrl(buf[:n]); cerr == nil {
				if msg.Kind == "" || msg.Kind == tunnel.CtrlKindRoutes {
					rm.sync(msg.IPs)
				}
			}
		case n > 0 && buf[0] == tunnel.TypePing:
			pong := make([]byte, 0, 1+tunnel.NonceSize+16)
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
