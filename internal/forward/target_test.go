package forward

// 转发目标地址校验的回归测试（安全边界：域名目标解析到内网必须在拨号前被拒）。

import (
	"net"
	"testing"
)

func TestCheckTargetIPRejectsForbidden(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want bool // true = 必须拒绝
	}{
		{"回环", "127.0.0.1", true},
		{"内网 10/8", "10.1.2.3", true},
		{"内网 192.168", "192.168.1.1", true},
		{"内网 172.16", "172.16.0.9", true},
		{"CGNAT 100.64", "100.64.0.1", true},
		{"链路本地", "169.254.169.254", true},
		{"IPv6 回环", "::1", true},
		{"IPv6 私网", "fd00::1", true},
		{"未指定地址", "0.0.0.0", true},
		{"公网", "203.0.113.9", false},
		{"公网 IPv6", "2001:db8::1", false},
	}
	for _, c := range cases {
		err := CheckTargetIP(net.ParseIP(c.ip))
		if got := err != nil; got != c.want {
			t.Errorf("%s %s: rejected=%v, want %v (err=%v)", c.name, c.ip, got, c.want, err)
		}
	}
	// nil IP 一律拒绝。
	if err := CheckTargetIP(nil); err == nil {
		t.Error("nil IP 应被拒绝")
	}
}

// CheckDialControl 是 Dialer.Control 形态的入口：模拟「已解析、未连接」的
// 地址串，内网地址必须报错中止拨号。
func TestCheckDialControl(t *testing.T) {
	if err := CheckDialControl("tcp", "192.168.1.1:25565", nil); err == nil {
		t.Fatal("内网拨号地址应被拒绝")
	}
	if err := CheckDialControl("tcp", "203.0.113.9:25565", nil); err != nil {
		t.Fatalf("公网拨号地址不应被拒: %v", err)
	}
	if err := CheckDialControl("tcp", "not-an-ip:80", nil); err == nil {
		t.Fatal("无法解析的地址应被拒绝")
	}
}
