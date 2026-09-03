//go:build !linux

package tunnelapp

// 非 Linux 的 socket 细节桩。
//
// 服务端的通用代理模式在 Windows/macOS 上是支持的（只有透明模式与隧道服务端
// 限 Linux+root），所以这些桩不能报错——它们只是让「批量化 / GRO / 内核丢包
// 观测」这些 Linux 专属能力优雅缺席。

import (
	"errors"
	"net"
)

// batchSupported 报告本平台是否真的能走 recvmmsg/sendmmsg。
//
// x/net 的 ReadBatch/WriteBatch 在非 Linux 上退化为单包（Windows 直接不实现），
// 走那条码路只是多绕一层，所以这里直接返回 false 让上层用逐包实现。
func batchSupported() bool { return false }

var errNotSupported = errors.New("tunnelapp: 该 socket 选项仅在 Linux 可用")

func socketBufferSizes(*net.UDPConn) (int, int, error) { return 0, 0, errNotSupported }

func sysctlHint(int) string { return "" }

func enableUDPGRO(*net.UDPConn) error { return errNotSupported }

func oobBufSize() int { return 0 }

func groSegmentSize([]byte) int { return 0 }

func gsoControl(dst []byte, _ int) []byte { return dst[:0] }

func kernelUDPDrops(int) (uint64, bool) { return 0, false }
