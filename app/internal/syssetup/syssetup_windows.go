//go:build windows

// Package syssetup 配置路由/接口（Windows 实现）。
package syssetup

import (
	"fmt"
	"os/exec"
	"strings"
)

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w — %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// ConfigureInterface 为 wintun 接口配置静态地址。
func ConfigureInterface(ifaceName, ip, mask string) error {
	_, err := run("netsh", "interface", "ip", "set", "address",
		"name="+ifaceName, "source=static", "addr="+ip, "mask="+mask)
	return err
}

// SetInterfaceMTU 设置接口 MTU。
//
// 为什么需要它：服务端在握手应答里下发协商后的隧道 MTU（按链路 MTU 反算，
// 开启前向纠错时还要让出校验包开销）。本机网卡若仍按更大的 MTU 工作，应用
// 就会发出隧道装不下的包——封装后被 IP 分片，而分片丢一片等于整包全损。
//
// wintun 驱动自身的 MTU 由创建时的参数决定，这里改的是 Windows IP 层对该
// 接口的 MTU 记账（决定本机 TCP MSS 与 UDP 分片行为），两者需要一致。
func SetInterfaceMTU(ifaceName string, mtu int) error {
	_, err := run("netsh", "interface", "ipv4", "set", "subinterface",
		ifaceName, fmt.Sprintf("mtu=%d", mtu), "store=active")
	return err
}

// AddRoute 添加 /32 回程路由（网关为隧道对端地址）。
//
// 幂等：路由已存在时按成功处理。触发场景是**客户端升级时进程被强制结束**——
// cleanup 没机会跑，上一轮装的 /32 路由留在系统里；新客户端的管理器不知道它，
// route add 会报「对象已存在」，安装器从此进入无限退避，该 IP 的入站包缓冲满后
// 全部丢弃（表现为：升级重启后，上一次接入的玩家全部连不上，新玩家正常）。
// 路由已存在恰好就是想要的状态（指向同一隧道网关），直接收编。
func AddRoute(destIP, gateway string) error {
	out, err := run("route", "add", destIP, "mask", "255.255.255.255", gateway, "metric", "1")
	if err == nil || isRouteAlreadyExists(out) {
		return nil
	}
	return err
}

// isRouteAlreadyExists 识别 route add 的「路由已存在」输出。
// route.exe 不给可区分的退出码，只能认文案；中英文系统各一套。
func isRouteAlreadyExists(out string) bool {
	low := strings.ToLower(out)
	for _, s := range []string{"already exist", "已存在"} {
		if strings.Contains(low, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// ListRoutesViaGateway 列出系统路由表中所有以 gateway 为网关的 /32 路由。
//
// 用于客户端启动时清扫残留：升级时进程被强杀（或断电、崩溃），cleanup 不会
// 运行，上一轮的 /32 路由会留在系统里吸走该 IP 的全部回包——没人再管它们，
// 玩家之后不经代理直连源站也收不到回包。解析按列做（目标 掩码 网关 接口 跃点数），
// 只认掩码恰为 /32 且网关等于隧道网关的行，表头与「在链路上」行天然不匹配。
func ListRoutesViaGateway(gateway string) ([]string, error) {
	out, err := run("route", "print", "-4")
	if err != nil {
		return nil, err
	}
	var dests []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 5 || f[1] != "255.255.255.255" || f[2] != gateway {
			continue
		}
		if !isIPv4(f[0]) {
			continue
		}
		dests = append(dests, f[0])
	}
	return dests, nil
}

// isIPv4 粗验四段点分十进制（route print 的列不会给非法 IP，防御解析边界即可）。
func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

// RemoveRoute 删除 /32 回程路由。
//
// 错误必须返回给调用方：残留的 /32 主机路由会吸走该目的 IP 的**全部**回包
// （与是否经隧道无关），一条删不掉的路由会让该地址永久无法直连。原先这里
// 吞掉错误恒返回 nil，删除失败完全静默。
//
// 「路由本来就不存在」不算失败：清理路径会对同一地址重复调用。
func RemoveRoute(destIP string) error {
	out, err := run("route", "delete", destIP)
	if err == nil || isRouteNotFound(out) {
		return nil
	}
	return err
}

// isRouteNotFound 识别 route.exe 的「找不到该路由」输出。
// route.exe 不给可区分的退出码，只能认文案；中英文系统各一套。
func isRouteNotFound(out string) bool {
	low := strings.ToLower(out)
	for _, s := range []string{"not found", "找不到", "元素没有找到"} {
		if strings.Contains(low, strings.ToLower(s)) {
			return true
		}
	}
	return false
}
