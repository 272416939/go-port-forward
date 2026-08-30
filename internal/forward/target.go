package forward

// 转发目标地址的安全校验。
//
// API 层（internal/web/rule_guard.go）在创建/修改规则时按目标做了一道预检，
// 但对「域名」目标只做存在性放行、不解析——把解析结果的校验放在这里（数据面
// 拨号点）才是边界的执行点：域名指向哪，只有拨号时才真正确定。少了这一层，
// 普通用户用一个自己控制的域名（解析结果随时可改成 169.254.169.254 或中转机
// 内网地址）就能把中转机变成对内网的跳板。
//
// 透明模式例外：其目标按协议锁定为访问码的隧道地址（10/8 内的私网地址），
// 属合法目标，不做本检查——调用方以 rule.Transparent 分流。

import (
	"fmt"
	"net"
	"sync"
	"syscall"
)

// IsForbiddenTargetIP 报告一个 IP 是否属于禁止作为转发目标的地址段。
func IsForbiddenTargetIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// CGNAT 100.64.0.0/10：IsPrivate 不覆盖，但它同样不是公网可达地址。
		if v4[0] == 100 && v4[1] >= 64 && v4[1] < 128 {
			return true
		}
	}
	return false
}

// IsLocalIP 报告 IP 是否为本机网卡地址（含中转机自己的公网 IP——指向它的
// 规则等于绕过防火墙直连本机服务）。网卡集合进程生命周期内不变，只查一次。
var (
	localIPOnce sync.Once
	localIPs    []net.IP
)

// RefreshLocalIPs 重置本机网卡地址缓存（测试用；生产进程内网卡集合不变）。
func RefreshLocalIPs() {
	localIPOnce = sync.Once{}
	localIPs = nil
}

func IsLocalIP(ip net.IP) bool {
	localIPOnce.Do(func() {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				localIPs = append(localIPs, ipnet.IP)
			}
		}
	})
	for _, l := range localIPs {
		if l.Equal(ip) {
			return true
		}
	}
	return false
}

// TargetPolicy 是「已解析目标 IP 是否允许转发」的策略函数，默认拒绝内网/
// 保留/本机地址。做成可替换变量是为了 test/ 集成测试：测试后端的标准落点是
// 本机回环，测试进程在 TestMain 里换成「放行回环、其余照旧」；生产代码不得改动。
var TargetPolicy = CheckTargetIP

// CheckTargetIP 校验一个「已确定」的目标 IP 是否允许转发，本机网卡地址一并拒绝。
func CheckTargetIP(ip net.IP) error {
	if ip == nil {
		return errForbiddenTarget("目标地址无效 | target address is invalid")
	}
	if IsForbiddenTargetIP(ip) || IsLocalIP(ip) {
		return errForbiddenTarget(fmt.Sprintf("目标地址 %s 属于内网、保留或本机地址，已拒绝转发（通用模式仅允许公网目标）| target %s is a private, reserved or host-local address; general mode only forwards to public addresses", ip, ip))
	}
	return nil
}

func errForbiddenTarget(msg string) error { return fmt.Errorf("%s", msg) }

// CheckDialControl 作为 net.Dialer.Control 使用：在域名已解析、连接尚未建立的
// 时机检查每个候选地址，命中黑名单立即中止拨号（不会向目标发出任何报文）。
// address 形如 "ip:port"。
func CheckDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("拨号地址无效 | invalid dial address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errForbiddenTarget(fmt.Sprintf("拨号地址 %q 无法解析为 IP | dial address %q is not an IP", address, address))
	}
	return TargetPolicy(ip)
}
