//go:build !linux

package forward

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// checkTransparentSupport 非 Linux 平台不支持透明模式（fail-closed）。
func checkTransparentSupport() error {
	return errors.New("透明模式仅支持 Linux（需 root/CAP_NET_ADMIN），且需配合隧道组件使用 | transparent mode requires Linux with root/CAP_NET_ADMIN and the tunnel app")
}

// 以下为非 Linux 平台的占位实现（规则预检已拦截，不会到达）。
func transparentControl(network, address string, c syscall.RawConn) error {
	return errors.New("transparent mode unsupported on this platform")
}

func transparentDialer(ctx context.Context, srcIP net.IP, base *net.Dialer) *net.Dialer {
	return base
}

func transparentListenPacket(srcAddr string) (net.PacketConn, error) {
	return nil, errors.New("transparent mode unsupported on this platform")
}

func dialUDPConnected(pc net.PacketConn, target *net.UDPAddr) (*net.UDPConn, error) {
	return nil, errors.New("transparent mode unsupported on this platform")
}
