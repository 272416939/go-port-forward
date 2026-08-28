//go:build linux

package tunnelapp

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// 回程标记与专用路由表：把从 TUN 进来的包（Windows 后端发给玩家的回包）
// 强制走「本机投递」表，交给透明 socket 收取，而不是按目的地址转发出去。
const (
	returnMark  = "0x7947"
	returnTable = "7947"
	// cmdTimeout 是每条外部命令的上限。这些命令跑在启动与关停路径上，
	// 一旦 iptables 等待 xtables 锁挂住，整个进程就停不下来。
	cmdTimeout = 5 * time.Second
)

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("%s %s: 超过 %s 未返回", name, strings.Join(args, " "), cmdTimeout)
	}
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w — %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// configureInterface 为 TUN 接口配置地址并启用。
func configureInterface(ifaceName, cidr string) error {
	if _, err := run("ip", "addr", "add", cidr, "dev", ifaceName); err != nil {
		if !strings.Contains(err.Error(), "exists") {
			return err
		}
	}
	_, err := run("ip", "link", "set", ifaceName, "up")
	return err
}

// ensureRule 幂等添加一条 iptables 规则（先 -C 检查再 -A 追加）。
func ensureRule(table string, ruleSpec ...string) error {
	if _, err := run("iptables", append([]string{"-t", table, "-C"}, ruleSpec...)...); err == nil {
		return nil
	}
	_, err := run("iptables", append([]string{"-t", table, "-A"}, ruleSpec...)...)
	return err
}

// setupReturnPath 建立透明模式的回程路径（幂等）。
//
// 透明模式下 go-port-forward 用玩家真实 IP:端口 绑定上游 socket 发往隧道，
// 因此 Windows 后端的回包目的地址是玩家 IP——对中转机而言那是个「别人的」
// 地址，内核默认会尝试转发出去，永远不会交给等待它的透明 socket。
// 标准解法是策略路由：给 TUN 入向包打标记，让它查一张「全部视为本机地址」
// 的专用路由表，从而进入 INPUT 被 socket 收取。
//
// 这也是为什么服务端不需要（也不能用）NAT：回包源地址保持隧道内网地址，
// 由 conntrack 认作正向连接的 REPLY，最终由监听 socket 以中转机公网地址
// 发回玩家。
func setupReturnPath(tunName string) error {
	if _, err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	// rp_filter 放宽为 loose：TUN 入包的源地址在其它接口上也说得通。
	for _, key := range []string{
		"net.ipv4.conf.all.rp_filter",
		"net.ipv4.conf.default.rp_filter",
		"net.ipv4.conf." + tunName + ".rp_filter",
	} {
		_, _ = run("sysctl", "-w", key+"=2")
	}

	if err := ensureRule("mangle", "PREROUTING", "-i", tunName, "-p", "udp", "-j", "MARK", "--set-mark", returnMark); err != nil {
		return fmt.Errorf("标记 TUN 入向包失败: %w", err)
	}
	if err := ensureIPRule(); err != nil {
		return err
	}
	// local 类型的默认路由：命中此表的包一律按本机地址处理。
	if _, err := run("ip", "route", "replace", "local", "default", "dev", "lo", "table", returnTable); err != nil {
		return fmt.Errorf("配置本机投递路由表失败: %w", err)
	}
	// 回包进入 INPUT（目的是玩家 IP），云镜像的 INPUT 策略可能拦下它。
	if err := ensureRule("filter", "INPUT", "-i", tunName, "-j", "ACCEPT"); err != nil {
		return err
	}
	// 非透明规则或将来其它用途仍可能走转发路径（云镜像 FORWARD 常为 DROP）。
	if err := ensureRule("filter", "FORWARD", "-i", tunName, "-j", "ACCEPT"); err != nil {
		return err
	}
	return ensureRule("filter", "FORWARD", "-o", tunName, "-j", "ACCEPT")
}

// ensureIPRule 添加 fwmark → 专用路由表的策略路由规则。
// ip rule add 不幂等，重复执行会堆叠，必须先查。
func ensureIPRule() error {
	if out, err := run("ip", "rule", "show"); err == nil && strings.Contains(out, "lookup "+returnTable) {
		return nil
	}
	if _, err := run("ip", "rule", "add", "fwmark", returnMark, "lookup", returnTable); err != nil {
		return fmt.Errorf("添加策略路由规则失败: %w", err)
	}
	return nil
}

// teardownReturnPath 撤销 setupReturnPath 的改动（best-effort，不返回错误）。
func teardownReturnPath(tunName string) {
	_, _ = run("ip", "rule", "del", "fwmark", returnMark, "lookup", returnTable)
	_, _ = run("ip", "route", "flush", "table", returnTable)
	_, _ = run("iptables", "-t", "mangle", "-D", "PREROUTING", "-i", tunName, "-p", "udp", "-j", "MARK", "--set-mark", returnMark)
	_, _ = run("iptables", "-t", "filter", "-D", "INPUT", "-i", tunName, "-j", "ACCEPT")
	_, _ = run("iptables", "-t", "filter", "-D", "FORWARD", "-i", tunName, "-j", "ACCEPT")
	_, _ = run("iptables", "-t", "filter", "-D", "FORWARD", "-o", tunName, "-j", "ACCEPT")
}
