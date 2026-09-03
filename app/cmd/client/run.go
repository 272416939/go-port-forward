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

const (
	// pumpIdleTimeout 是「多久收不到任何入站包就重握手」。
	//
	// 客户端 NAT 换端口（手机切网、运营商 UDP 会话老化）后，服务端在会话表里
	// 查不到新来源、按设计静默丢弃（防反射放大，正确，不能改）。客户端感知
	// 恢复的唯一途径就是这个读超时。
	//
	// 从 30s 降到 10s：服务端心跳 5 秒一个，10 秒 = 连续错过两个心跳 + 余量。
	// 误判的代价是多一次握手（一个 RTT + 两次 X25519，微秒级 CPU），收益是
	// 最差恢复时间从 30 秒压到 10 秒。
	pumpIdleTimeout = 10 * time.Second
	// probeStartDelay 是隧道建立后开始探测路径 MTU 的延迟。
	// 让进服的首波流量先过去，探测不与它抢。
	probeStartDelay = 2 * time.Second
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
	// 默认 ~200KB 的读缓冲只够一百多个 MTU 包，玩家进服的下行突发会在内核
	// 层丢包且应用层毫无感知。设置失败沿用系统默认，无害。
	_ = udp.SetReadBuffer(4 << 20)
	_ = udp.SetWriteBuffer(4 << 20)
	e.udp.Store(udp)
	defer e.udp.Store(nil)
	defer udp.Close()

	// 网卡按协议上限创建；服务端在握手应答里下发实际 MTU，若更小则在
	// applyAddressing 之后下调（只能往下调，网卡缓冲不必重建）。
	dev, err := tunnet.Open(tunName, tunnel.MaxTunMTU)
	if err != nil {
		e.fail("创建虚拟网卡失败（请确认以管理员运行）：%v", err)
		return
	}
	defer dev.Close()
	e.dev.Store(dev)
	defer e.dev.Store(nil)

	// 网卡就绪前 TUN 上不会有流量，出向泵起得早一点无害；它自己会在
	// sess 或路由管理器尚未就绪时丢包。
	var rmHolder atomic.Pointer[routeManager]
	go e.pumpTunToTunnel(ctx, udp, dev, &rmHolder)
	go e.heartbeat(ctx, udp)

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
			rm.close()
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
			// 旧管理器要 close 而不是 cleanup——它带着回收与安装 goroutine，
			// 只清路由会把 goroutine 泄漏到进程结束。
			if rm := rmHolder.Load(); rm != nil {
				rm.close()
			}
			rm := newRouteManager(serverAddr.IP.String(), addressing, dev.WritePacket, e.logf)
			rmHolder.Store(rm)
			e.routes.Store(rm)
		}
		// 服务端下发的 MTU 可能小于协议上限（链路 MTU 反算 / 开启纠错时让出
		// 校验包开销）。网卡 MTU 必须同步下调，否则本机应用会发出超过隧道
		// 承载能力的包——封装后被 IP 分片，而分片丢一片等于整包全损。
		e.applyMTU(dev, sess.MTU())

		e.setSession(sess)
		e.setState(StateConnected, "")
		e.logf("✔ 隧道已建立（本机隧道地址 %s，MTU %d%s）。",
			addressing.ClientIP, sess.MTU(), featureLabel(sess.Features()))

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

// featureLabel 把协商到的特性位翻成一句可读的后缀。
func featureLabel(feats uint32) string {
	switch {
	case feats&tunnel.FeatFEC != 0 && feats&tunnel.FeatTailDup != 0:
		return "，已启用前向纠错与小包冗余"
	case feats&tunnel.FeatFEC != 0:
		return "，已启用前向纠错"
	case feats&tunnel.FeatTailDup != 0:
		return "，已启用小包冗余"
	default:
		return ""
	}
}

// applyMTU 把协商到的 MTU 应用到虚拟网卡。
func (e *Engine) applyMTU(dev *tunnet.Device, mtu int) {
	if mtu <= 0 || mtu == dev.MTU() {
		return
	}
	dev.SetMTU(mtu)
	if err := syssetup.SetInterfaceMTU(tunName, mtu); err != nil {
		// 只影响本机应用发出的包尺寸，隧道本身照常工作，所以不算致命。
		e.logf("[!] 设置虚拟网卡 MTU 失败（大包可能被分片）：%v", err)
		return
	}
	e.logf("虚拟网卡 MTU 已调整为 %d。", mtu)
}

// pumpTunToTunnel 是出向泵：TUN 读出 → 封装 → 发往服务端。
//
// 零分配（OPT-3）：读缓冲与封装缓冲各一块，全生命周期复用；封装直接写进
// 输出缓冲，不再每包 make。
func (e *Engine) pumpTunToTunnel(ctx context.Context, udp *net.UDPConn,
	dev *tunnet.Device, rmHolder *atomic.Pointer[routeManager]) {
	buf := make([]byte, dev.ReadBufSize())
	out := make([]byte, 0, tunnel.MaxPacket+tunnel.NonceSize)
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
		// 直接用 buf 切片：countOutbound 只同步读头部，封装在下一轮
		// Read 之前同步消费完毕，逐包 make+copy 是纯浪费的分配。
		pkt := buf[:n]
		e.statTunToTunnel.Add(1)
		e.bytesUp.Add(int64(n))
		rm.countOutbound(pkt)
		wire, extra := sess.SealDataFEC(out[:0], pkt)
		if _, werr := udp.Write(wire); werr != nil {
			return
		}
		if extra != nil {
			// 纠错校验包 / 冗余副本必须是独立的数据报：合并进同一个包等于
			// 让校验与数据同生共死，一次丢包同时带走两者。
			if _, werr := udp.Write(extra); werr != nil {
				return
			}
		}
	}
}

// heartbeat 周期心跳，兼做路径 MTU 探测。
//
// 探测原理：Ping 的明文用零填充到目标尺寸，服务端 Pong 回显它实际收到的明文
// 长度。收不到回显说明这个尺寸过不了链路（封装后被分片且丢了片），据此下调
// 本机 MTU。固定 MTU 在 PPPoE(1492)/4G 这类链路上会贴上限，而分片丢失是整包
// 全损——FEC 也救不回来（它看不到分片）。
func (e *Engine) heartbeat(ctx context.Context, udp *net.UDPConn) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	// 探测包的明文与密文同时占用这块缓冲（明文借尾部组装），按两倍 MTU 备量。
	buf := make([]byte, 0, tunnel.ProbeBufSize)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			sess := e.session()
			if sess == nil {
				continue
			}
			e.probeSentAt.Store(time.Now().UnixNano())
			if _, err := udp.Write(sess.SealPing(buf[:0], 0, 0)); err != nil {
				continue
			}
			e.maybeProbeMTU(udp, sess, buf)
		}
	}
}

// maybeProbeMTU 在会话稳定后发一个满尺寸探测包。
//
// 只探一次「当前 MTU 能否穿过」：连续两轮心跳都收不到该探测的回显就下调。
// 不做逐档二分——那要么慢要么在弱网上误判，而实际链路 MTU 的档位很少
// （1500 / 1492 PPPoE / 1480 隧道 / 1400）。
func (e *Engine) maybeProbeMTU(udp *net.UDPConn, sess *tunnel.Session, buf []byte) {
	if e.probeDone.Load() {
		return
	}
	target := sess.MTU()
	// 探测包的明文尺寸 = 目标 MTU，封装后正好是该 MTU 下最大的隧道包。
	pad := target - 1
	if pad <= 0 {
		return
	}
	id := byte(e.probeID.Add(1))
	if id == 0 {
		id = byte(e.probeID.Add(1))
	}
	e.probeWant.Store(int64(id)<<32 | int64(target))
	if _, err := udp.Write(sess.SealPing(buf[:0], id, pad)); err != nil {
		return
	}
	e.probeTries.Add(1)
	if e.probeTries.Load() >= 3 {
		// 连续三轮探测都没有回显：链路装不下当前 MTU，退一档。
		if next := target - probeStep; next >= tunnel.MinTunMTU {
			e.logf("[!] 路径 MTU 探测失败，下调至 %d（链路可能有更小的 MTU）", next)
			sess.SetMTU(next)
			if dev := e.dev.Load(); dev != nil {
				e.applyMTU(dev, next)
			}
		} else {
			e.probeDone.Store(true)
		}
		e.probeTries.Store(0)
	}
}

// probeStep 是路径 MTU 探测每次下调的步长。
//
// 72 = 1400 → 1328，一步跨过 PPPoE(1492-53=1439) 与常见隧道封装（1480-53=1427）
// 之下的安全区。步长太小会探很多轮，太大会白损失吞吐。
const probeStep = 72

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
	buf := make([]byte, tunnel.MaxPacket+64)
	// 8 次尝试共用的「残留包已忽略」日志锚点：残留包在握手期间可能持续到达
	// （服务端旧会话的心跳 5 秒一个），只提示一次，别刷屏。
	staleLogged := false
attemptLoop:
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
		// 同一个 1.5 秒窗口内排空非应答包，只认 Accept 与 Reject：
		// 断开后服务端的旧会话在 janitor 回收前（最长 3 分钟）仍会向本地址发
		// 心跳与路由推送，而客户端快速重连时 NAT（EIM 映射）与 OS 都可能复用
		// 刚释放的源端口——残留包就这样落进握手 socket 的接收队列。它们不是
		// 应答，忽略后继续等；此前它们会掉进 Accept 解析失败，被误报成
		// 「接入码可能已失效，请在面板重新获取」，把用户引去重置接入码
		//（2026-09-03 用户实测：反复断开/连接后握手必报接入码失效）。
		deadline := time.Now().Add(1500 * time.Millisecond)
		for {
			_ = udp.SetReadDeadline(deadline)
			n, err := udp.Read(buf)
			if err != nil {
				e.logf("等待服务端应答 (%d/%d)…", attempt, handshakeTries)
				continue attemptLoop
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
			if n > 0 && buf[0] == tunnel.TypeAccept {
				accept, aerr := tunnel.ParseServerAccept(secret, buf[:n], hello.Eph)
				if aerr != nil {
					if errors.Is(aerr, tunnel.ErrOldVersion) {
						return nil, none, fmt.Errorf("中转机的服务端版本过旧（隧道协议已升级），请让管理员升级服务端后重试")
					}
					return nil, none, fmt.Errorf("%v（接入码可能已失效，请在面板重新获取）", aerr)
				}
				_ = udp.SetReadDeadline(time.Time{})
				shared := tunnel.ECDHShared(&accept.Eph, priv)
				// 方向密钥：客户端发 c2s、收 s2c，服务端反接。v3 两个方向共用一把
				// 密钥且计数都从 1 开始，等于每包都在重用 (key, nonce)。
				c2s, s2c, kerr := tunnel.DeriveSessionKeys(shared, secret, hello.Eph, accept.Eph)
				if kerr != nil {
					return nil, none, fmt.Errorf("派生会话密钥失败：%v", kerr)
				}
				sess, serr := tunnel.NewClientSession(c2s, s2c, uint32(accept.Feats), accept.TunMTU())
				if serr != nil {
					return nil, none, fmt.Errorf("建立会话失败：%v", serr)
				}
				addressing := tunnelAddressing{
					ClientIP: accept.TunAddr().String(),
					Mask:     prefixToMask(int(accept.Prefix)),
					Gateway:  accept.GatewayAddr().String(),
				}
				e.probeDone.Store(false)
				e.probeTries.Store(0)
				return sess, addressing, nil
			}
			if !staleLogged {
				staleLogged = true
				e.logf("忽略上一轮会话的残留包，继续等待握手应答 (%d/%d)…", attempt, handshakeTries)
			}
		}
	}

	// 8 次 v4 握手全部无应答：用一条 v3 格式的探测包再试一次。服务端对版本
	// 不匹配此前是**静默**的，客户端只能靠超时——把「服务端还是旧版本」误报成
	// 「请检查防火墙」。探测包能让对端按老规矩应答（v3 服务端会正常处理它），
	// 据此把两种原因分开。探测绝不建立会话：按 v3 建会话等于回到 nonce 跨方向
	// 重用的老路。
	if verdict := e.probeLegacyVersion(udp, uid, device, secret); verdict != tunnel.ProbeNoReply {
		if verdict == tunnel.ProbeServerLegacy {
			return nil, none, fmt.Errorf("中转机服务端隧道协议版本过旧（v3）：请让管理员先升级服务端，升级完成后本机会自动恢复连接")
		}
		return nil, none, fmt.Errorf("隧道协议版本不匹配：中转机服务端与本客户端的协议版本不一致，请确认两端都已升级到配套版本（会自动重试）")
	}
	return nil, none, fmt.Errorf("服务端无应答（请检查地址、端口与中转机防火墙）")
}

// probeLegacyVersion 发一条 v3 格式的握手包并按应答判定对端版本。
// 返回 ProbeNoReply 表示对端不可达（或拒绝应答），其余见 ProbeVerdict。
func (e *Engine) probeLegacyVersion(udp *net.UDPConn, uid tunnel.UID,
	device [tunnel.FingerprintSize]byte, secret []byte) tunnel.ProbeVerdict {
	wire, err := tunnel.NewLegacyProbeHello(secret, uid, device)
	if err != nil {
		return tunnel.ProbeNoReply
	}
	if _, err := udp.Write(wire); err != nil {
		return tunnel.ProbeNoReply
	}
	buf := make([]byte, tunnel.MaxPacket+64)
	_ = udp.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	n, err := udp.Read(buf)
	_ = udp.SetReadDeadline(time.Time{})
	if err != nil || n <= 0 {
		return tunnel.ProbeNoReply
	}
	return tunnel.ClassifyLegacyProbeReply(buf[:n])
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

// pump 收隧道包：Data→写 TUN，Ctrl→同步回程路由，Ping→Pong，FEC→补包。
// pumpIdleTimeout 内无任何入站包则返回错误，交由外层重握手。
//
// 零分配（OPT-3/7）：明文直接解进 TUN 写批的槽位，既没有明文分配也没有二次
// 拷贝。批的边界是「本轮 socket 读不到更多包」——不定时、不等待。
func (e *Engine) pump(ctx context.Context, udp *net.UDPConn, dev *tunnet.Device,
	sess *tunnel.Session, rm *routeManager) error {
	buf := make([]byte, tunnel.MaxPacket+64)
	out := make([]byte, 0, tunnel.MaxPacket+tunnel.NonceSize)
	batch := dev.NewBatch(0)
	deadline := time.Now().Add(pumpIdleTimeout)
	_ = udp.SetReadDeadline(deadline)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, err := udp.Read(buf)
		if err != nil {
			_ = batch.Flush()
			return err
		}
		// 只在超过一半窗口时才重设 deadline：此前每个入站包都要一次
		// SetReadDeadline 系统调用，高 pps 下那是白付的开销。
		if now := time.Now(); deadline.Sub(now) < pumpIdleTimeout/2 {
			deadline = now.Add(pumpIdleTimeout)
			_ = udp.SetReadDeadline(deadline)
		}
		if n == 0 {
			continue
		}
		switch buf[0] {
		case tunnel.TypeData:
			e.deliverInbound(sess, rm, batch, buf[:n])
		case tunnel.TypeFEC:
			// 校验包本身不是数据：登记后取出被补回的包，走与普通 Data 完全
			// 相同的路径（认证 + 重放窗口 + 回程路由门控一条不少）。
			if sess.HandleFEC(buf[:n]) {
				for {
					rec := sess.Recover()
					if rec == nil {
						break
					}
					e.deliverInbound(sess, rm, batch, rec)
				}
			}
		case tunnel.TypeCtrl:
			if msg, cerr := sess.OpenCtrl(buf[:n]); cerr == nil {
				switch msg.Kind {
				case "", tunnel.CtrlKindRoutes:
					rm.sync(msg.IPs)
				case tunnel.CtrlKindEnded:
					rm.markEnded(msg.IPs)
				}
			}
		case tunnel.TypePing:
			// 服务端心跳：回 Pong 并回显收到的明文长度（服务端侧的探测用）。
			if id, plainLen, perr := sess.OpenPing(buf[:n]); perr == nil {
				_, _ = udp.Write(sess.SealPong(out[:0], id, plainLen))
			}
		case tunnel.TypePong:
			e.handlePong(sess, buf[:n])
		}
		// 冲刷 TUN 写批。
		//
		// 客户端这里不攒批：wintun 的 BatchSize 恒为 1（底层 Write 内部也是
		// 逐包发送），攒批只会给入站包凭空加一轮延迟。批量接口在客户端的价值
		// 不是合并 syscall（合并不了），而是消灭每包的 make+copy 与明文分配。
		if batch.Len() > 0 {
			if werr := batch.Flush(); werr != nil {
				e.logWriteErr(werr)
			}
		}
	}
}

// deliverInbound 解密一个 Data 包并按回程路由状态决定直写还是缓冲。
func (e *Engine) deliverInbound(sess *tunnel.Session, rm *routeManager,
	batch *tunnet.Batch, wire []byte) {
	dst := batch.Next()
	if dst == nil {
		if werr := batch.Flush(); werr != nil {
			e.logWriteErr(werr)
		}
		dst = batch.Next()
		if dst == nil {
			return
		}
	}
	plain, oerr := sess.OpenData(dst, wire)
	if oerr != nil {
		return
	}
	e.statTunnelToTun.Add(1)
	e.bytesDown.Add(int64(len(plain)))
	// 路由未就绪时包由路由管理器缓冲、安装器装好后代写：
	// 新 IP 的 route.exe（几十毫秒）绝不能阻塞其他玩家的包，
	// 这是旧实现「一个玩家进服全服卡一下」的病根。
	if rm.deliverInbound(plain) {
		batch.Commit(len(plain))
	}
}

// handlePong 处理服务端心跳应答：更新 RTT 与路径 MTU 探测结果。
func (e *Engine) handlePong(sess *tunnel.Session, wire []byte) {
	id, observed, err := sess.OpenPong(wire)
	if err != nil {
		return
	}
	if sent := e.probeSentAt.Load(); sent > 0 {
		sess.Stats().ObserveRTT(time.Duration(time.Now().UnixNano() - sent))
	}
	if id == 0 {
		return // 普通心跳
	}
	want := e.probeWant.Load()
	if byte(want>>32) == id && observed >= int(want&0xFFFFFFFF) {
		// 该尺寸的包确实穿过了链路：探测结束，当前 MTU 可用。
		e.probeDone.Store(true)
		e.probeTries.Store(0)
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
