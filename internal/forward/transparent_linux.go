//go:build linux

package forward

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// checkTransparentSupport 检查当前进程能否使用 IP_TRANSPARENT
// （需要 root 或 CAP_NET_ADMIN）。fail-closed：不满足则规则启动失败。
func checkTransparentSupport() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("透明模式需要 Linux 且当前环境无法创建 socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		return fmt.Errorf("透明模式需要 root/CAP_NET_ADMIN 权限（IP_TRANSPARENT 不可用）: %w", err)
	}
	return nil
}

// transparentControl 供 net.ListenConfig/Dialer 使用：对 socket 设置
// IP_TRANSPARENT（允许绑定非本机地址作为源）。
func transparentControl(network, address string, c syscall.RawConn) error {
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	}); err != nil {
		return err
	}
	if sockErr != nil {
		return fmt.Errorf("设置 IP_TRANSPARENT 失败（需 root）: %w", sockErr)
	}
	return nil
}

// transparentDialer 返回启用 IP_TRANSPARENT 的拨号器（TCP 透明绑定源地址）。
func transparentDialer(ctx context.Context, srcIP net.IP, base *net.Dialer) *net.Dialer {
	d := &net.Dialer{Timeout: base.Timeout, Deadline: base.Deadline, Control: transparentControl}
	if srcIP != nil {
		d.LocalAddr = &net.TCPAddr{IP: srcIP}
	}
	return d
}

// transparentListenPacket 以指定源地址（玩家 IP:端口）绑定 UDP socket。
func transparentListenPacket(srcAddr string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: transparentControl}
	return lc.ListenPacket(context.Background(), "udp", srcAddr)
}

// dialUDPConnected 在已绑定的 PacketConn 上连接目标并返回 *net.UDPConn。
func dialUDPConnected(pc net.PacketConn, target *net.UDPAddr) (*net.UDPConn, error) {
	udp, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("透明模式：上游 socket 类型异常 | unexpected packet conn type")
	}
	if err := udp.Connect(target); err != nil {
		udp.Close()
		return nil, err
	}
	return udp, nil
}
