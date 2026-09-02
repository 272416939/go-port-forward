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
// cmdTimeout 是每条外部命令的上限。这些命令跑在启动与关停路径上，
// 一旦 iptables 等待 xtables 锁挂住，整个进程就停不下来。
// （回程标记与专用路由表常量、各条规则的 spec 在 returnpath.go：安装与
// 守护校验必须共用同一份，spec 漂移会让守护协程每轮误判缺失。）
const cmdTimeout = 5 * time.Second

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

// ensureRuleFirst 幂等地把一条规则**插入到链首**。
//
// hairpin DROP 必须排在 -A 追加的放行规则前面才有意义：用户态检查之外，
// 隧道里 A 访问 B 的包在内核里表现为 in=pftun0 out=pftun0 的转发，会被
// 「FORWARD -i pftun0 -j ACCEPT」直接放走，DROP 追加在它后面永远匹配不到。
func ensureRuleFirst(table string, ruleSpec ...string) error {
	if _, err := run("iptables", append([]string{"-t", table, "-C"}, ruleSpec...)...); err == nil {
		return nil
	}
	_, err := run("iptables", append([]string{"-t", table, "-I"}, ruleSpec...)...)
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

	if err := ensureRule("mangle", markRuleSpec(tunName)...); err != nil {
		return fmt.Errorf("标记 TUN 入向包失败: %w", err)
	}
	if err := ensureIPRule(); err != nil {
		return err
	}
	// local 类型的默认路由：命中此表的包一律按本机地址处理。
	if _, err := run("ip", "route", "replace", "local", "default", "dev", "lo", "table", returnTable); err != nil {
		return fmt.Errorf("配置本机投递路由表失败: %w", err)
	}
	// 回包进入 INPUT（目的是玩家 IP 或网关），云镜像的 INPUT 策略可能拦下它。
	//
	// ⚠️ 但**不能**全放行：TUN 上的地址对客户端是可达的（掩码 /16，网段全
	// on-link），全放行等于把中转机上所有绑 0.0.0.0 的服务（管理面板、sshd、
	// 数据库）暴露给隧道用户——访问 https://<网关>/login.html 就能摸到面板。
	// 只放行**既有连接的回包**：透明回程与通用模式的回包都是中转机主动发起
	// 的流的 REPLY（conntrack 状态 ESTABLISHED/RELATED），而客户端**主动**
	// 发起的新连接没有任何合法用途（隧道协议本身走公网 UDP，不经过 TUN），
	// 一律丢弃。
	//
	// 两条都必须 -I 插到链首：追加的话排在云镜像的 dport 放行规则（面板端口
	// 几乎必然有一条 ACCEPT）之后，等于没拦。先删后插：旧版本的「全放行」
	// 规则与可能错序的残留都要清掉，-C 判定「已存在」会保留错误顺序。
	if err := lockInputOnInterface(tunName); err != nil {
		return err
	}
	// 隧道内互访的内核兜底：用户态检查（tunnelapp.go isTunnelInternal）之外，
	// A 访问 B 的包在内核里是同一张 TUN 的进与出，直接丢弃。必须插在链首，
	// 否则会被下面的放行规则先匹配掉。
	if err := ensureRuleFirst("filter", hairpinRuleSpec(tunName)...); err != nil {
		return fmt.Errorf("配置隧道内互访拦截失败: %w", err)
	}
	// 非透明规则或将来其它用途仍可能走转发路径（云镜像 FORWARD 常为 DROP）。
	if err := ensureRule("filter", forwardInSpec(tunName)...); err != nil {
		return err
	}
	return ensureRule("filter", forwardOutSpec(tunName)...)
}

// lockInputOnInterface 把 TUN 接口的 INPUT 收紧为「只放行既有连接的回包」。
// 命令序列与说明见 returnpath.go 的 lockInputOnInterfaceWith。
func lockInputOnInterface(tunName string) error {
	return lockInputOnInterfaceWith(run, tunName)
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
	_, _ = run("iptables", append([]string{"-t", "mangle", "-D"}, markRuleSpec(tunName)...)...)
	est, drop := inputRuleSpecs(tunName)
	_, _ = run("iptables", append([]string{"-t", "filter", "-D", "INPUT"}, est...)...)
	_, _ = run("iptables", append([]string{"-t", "filter", "-D", "INPUT"}, drop...)...)
	_, _ = run("iptables", "-t", "filter", "-D", "INPUT", "-i", tunName, "-j", "ACCEPT") // 旧版全放行规则
	_, _ = run("iptables", append([]string{"-t", "filter", "-D"}, hairpinRuleSpec(tunName)...)...)
	_, _ = run("iptables", append([]string{"-t", "filter", "-D"}, forwardInSpec(tunName)...)...)
	_, _ = run("iptables", append([]string{"-t", "filter", "-D"}, forwardOutSpec(tunName)...)...)
}

// verifyReturnPath 用真实命令执行器校验并修复回程内核状态。
// 守护协程入口，判定逻辑见 returnpath.go 的 verifyReturnPathWith。
func verifyReturnPath(tunName string) (bool, error) {
	return verifyReturnPathWith(run, tunName)
}
