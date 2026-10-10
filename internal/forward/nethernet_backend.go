package forward

import (
	"net"

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
