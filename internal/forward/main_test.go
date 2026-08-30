package forward

// forwarders_test.go 等本包测试的后端都架在本机回环上，而生产策略拒绝回环
// 目标（域名目标 SSRF 修复的执行点）。测试进程在 TestMain 里换成「放行回环、
// 其余照旧」；target_test.go 直接测的 CheckTargetIP/CheckDialControl 不受影响，
// 锁住的仍是默认策略。

import (
	"net"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	TargetPolicy = func(ip net.IP) error {
		if ip.IsLoopback() {
			return nil
		}
		return CheckTargetIP(ip)
	}
	os.Exit(m.Run())
}
