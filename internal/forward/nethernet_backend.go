package forward

import (
	"net"
	"sync"
	"time"

	"go-port-forward/internal/models"
	"go-port-forward/internal/nethernet"
)

// transparentPlayerSocket 把项目现有的「以玩家地址绑定 UDP socket」能力
// （transparentListenPacket，Linux 下走 IP_TRANSPARENT）包装成 nethernet 需要的
// PlayerSocket。放在 forward 包而不是 nethernet 包：透明 socket 的实现依赖
// 本包的平台分支，而 nethernet 不该知道平台细节（也避免 import 环）。
type transparentPlayerSocket struct {
	conn net.PacketConn
}

func (s *transparentPlayerSocket) SendTo(packet []byte, dst *net.UDPAddr) error {
	_, err := s.conn.WriteTo(packet, dst)
	return err
}

func (s *transparentPlayerSocket) Read(buf []byte) (int, error) {
	n, _, err := s.conn.ReadFrom(buf)
	return n, err
}

func (s *transparentPlayerSocket) Close() error { return s.conn.Close() }

// netherNetSocketFactory 返回 NetherNet 数据面的 socket 工厂。
//
// 非 Linux 平台 transparentListenPacket 直接返回错误，工厂因此也返回错误，
// 多路复用器据此退化为共享 socket 并告警——这条路径由规则预检（checkTransparent
// Support）提前挡住，正常不会走到。
func netherNetSocketFactory() nethernet.SocketFactory {
	return func(src *net.UDPAddr) (nethernet.PlayerSocket, error) {
		pc, err := transparentListenPacket(src.String())
		if err != nil {
			return nil, err
		}
		return &transparentPlayerSocket{conn: pc}, nil
	}
}

// netherSessionSink 把 NetherNet 数据面会话登记进 forward 的会话注册表。
//
// 回程路由推送（tunnelapp.pushSessionIPs → SessionIPsByCode）只认这张表：
// NetherNet 会话不登记，活跃玩家 IP 就推不出去（日志「回程路由 IP 已推送
// count:0」），Windows 客户端装不上 /32 回程路由，BDS 的回包从后端机物理网卡
// 漏出去——玩家卡在 InitialConnection-83（信令通、有 learned、无回程）。
// 登记同时让 Web 面板的会话列表与连接日志看得到 NetherNet 玩家。
type netherSessionSink struct {
	svc  *forwardServices
	rule *models.ForwardRule

	mu    sync.Mutex
	infos map[string]*sessionInfo // ufrag → 会话条目（Start 时拿到并缓存）
}

func newNetherSessionSink(svc *forwardServices, rule *models.ForwardRule) *netherSessionSink {
	return &netherSessionSink{svc: svc, rule: rule, infos: make(map[string]*sessionInfo)}
}

func (s *netherSessionSink) NetherSessionStart(ufrag string, client *net.UDPAddr) {
	if s.svc == nil || s.svc.sessions == nil || client == nil {
		return
	}
	key := sessionKey(models.ProtocolUDP, s.rule.ID, client)
	si := s.svc.sessions.obtain(key, &sessionInfo{
		key:      key,
		Protocol: models.ProtocolUDP,
		RuleID:   s.rule.ID,
		RuleName: s.rule.Name,
		UserID:   s.rule.UserID,
		SrcIP:    client.IP.String(),
		SrcPort:  client.Port,
		Since:    time.Now(),
	})
	s.svc.logEvent(models.ConnLogEntry{
		Protocol: models.ProtocolUDP,
		RuleID:   s.rule.ID,
		RuleName: s.rule.Name,
		UserID:   s.rule.UserID,
		SrcIP:    client.IP.String(),
		SrcPort:  client.Port,
		Event:    models.ConnEventJoin,
	})

	s.mu.Lock()
	s.infos[ufrag] = si
	s.mu.Unlock()
}

func (s *netherSessionSink) NetherSessionBytes(ufrag string, client *net.UDPAddr, in, out int) {
	s.mu.Lock()
	si := s.infos[ufrag]
	s.mu.Unlock()
	if si == nil {
		return
	}
	si.bytesIn.Add(int64(in))
	si.bytesOut.Add(int64(out))
}

func (s *netherSessionSink) NetherSessionEnd(ufrag string, client *net.UDPAddr) {
	s.mu.Lock()
	si := s.infos[ufrag]
	delete(s.infos, ufrag)
	s.mu.Unlock()
	if s.svc == nil || s.svc.sessions == nil || si == nil {
		return
	}
	// 必须摘表：否则推送一直认为该玩家活跃，客户端的 /32 主机路由会吸走该 IP
	// 的全部回包（含玩家不经代理的直连流量），只能等本地空闲宽限期才消失。
	s.svc.sessions.remove(si.key)
	si.finish(models.ConnEventLeave, s.svc.logs)
}
