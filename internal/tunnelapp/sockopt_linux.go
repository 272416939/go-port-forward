//go:build linux

package tunnelapp

// Linux 侧的 socket 细节：批量收发能力、缓冲生效值核查、UDP GRO/GSO、
// 内核层丢包读取。全部集中在这里，非 Linux 走 sockopt_other.go 的桩。

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// batchSupported 报告本平台是否真的能走 recvmmsg/sendmmsg。
// x/net 只为 Linux（及部分 BSD）实现了批量路径，其余平台会退化成单包——
// 那种情况下用「批量」这条码路只是多绕一层，不如直接降级。
func batchSupported() bool { return true }

// control 在 socket 的原始 fd 上执行 fn。
func control(conn *net.UDPConn, fn func(fd int) error) error {
	rc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	if cerr := rc.Control(func(fd uintptr) { inner = fn(int(fd)) }); cerr != nil {
		return cerr
	}
	return inner
}

// socketBufferSizes 读回内核实际生效的收发缓冲大小。
//
// Linux 的 SO_RCVBUF/SO_SNDBUF getsockopt 返回的是内核记账值（约为设置值的
// 两倍，多出来的部分留给 skb 元数据），这里折半还原成「可用于载荷」的口径，
// 与 SetReadBuffer 的入参可比。
func socketBufferSizes(conn *net.UDPConn) (rcv, snd int, err error) {
	err = control(conn, func(fd int) error {
		r, gerr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
		if gerr != nil {
			return gerr
		}
		s, gerr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
		if gerr != nil {
			return gerr
		}
		rcv, snd = r/2, s/2
		return nil
	})
	return rcv, snd, err
}

// sysctlHint 是缓冲被钳制时给运维的具体做法。
func sysctlHint(want int) string {
	return fmt.Sprintf("sysctl -w net.core.rmem_max=%d net.core.wmem_max=%d（写入 /etc/sysctl.conf 持久化）", want, want)
}

// enableUDPGRO 打开接收侧的 UDP 聚合（Linux ≥ 5.0）。
//
// 开启后单条 recvmmsg 消息可能携带多个背靠背的隧道包，需要按 cmsg 给出的
// 分段大小在用户态拆开（wireguard-go 同款做法）。
func enableUDPGRO(conn *net.UDPConn) error {
	return control(conn, func(fd int) error {
		return unix.SetsockoptInt(fd, unix.SOL_UDP, unix.UDP_GRO, 1)
	})
}

// oobBufSize 是每条消息的控制数据缓冲长度（只需容纳一个 uint16 分段大小）。
func oobBufSize() int { return unix.CmsgSpace(2) }

// groSegmentSize 从控制数据里取出 GRO 分段大小；0 表示这条消息没有被聚合。
func groSegmentSize(oob []byte) int {
	if len(oob) == 0 {
		return 0
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, m := range msgs {
		if m.Header.Level == unix.SOL_UDP && m.Header.Type == unix.UDP_GRO && len(m.Data) >= 2 {
			return int(binary.NativeEndian.Uint16(m.Data[:2]))
		}
	}
	return 0
}

// gsoControl 组装 UDP_SEGMENT 控制数据（发送侧分段卸载）。
//
// 内核要求除最后一段外各段等长，所以调用方只能合并「同目的、同长度」的连续
// 包（判定逻辑在 gso.go，与平台无关且有单测）。游戏流量的包长参差不齐，这一条
// 命中率天然很低——这也是 GSO 默认关闭的原因，它对本项目的收益远小于 GRO。
func gsoControl(dst []byte, segSize int) []byte {
	space := unix.CmsgSpace(2)
	if cap(dst) < space {
		dst = make([]byte, space)
	}
	dst = dst[:space]
	clear(dst)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&dst[0]))
	h.Level = unix.SOL_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(dst[unix.CmsgLen(0):], uint16(segSize))
	return dst
}

// kernelUDPDrops 读 /proc/net/udp 里本端口的 drops 列。
//
// 这是「内核收缓冲溢出」的唯一可观测出口：应用层对它完全无感，日志里一个字
// 都没有，而玩家进服的下行突发恰好最容易打穿默认的 ~200KB 缓冲。
func kernelUDPDrops(port int) (uint64, bool) {
	data, err := os.ReadFile("/proc/net/udp")
	if err != nil {
		return 0, false
	}
	want := strings.ToUpper(strconv.FormatInt(int64(port), 16))
	if len(want) < 4 {
		want = strings.Repeat("0", 4-len(want)) + want
	}
	var total uint64
	found := false
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 13 {
			continue
		}
		local := f[1]
		i := strings.LastIndexByte(local, ':')
		if i < 0 || !strings.EqualFold(local[i+1:], want) {
			continue
		}
		n, perr := strconv.ParseUint(f[12], 10, 64)
		if perr != nil {
			continue
		}
		total += n
		found = true
	}
	return total, found
}
