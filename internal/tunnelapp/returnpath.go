// 回程路径的内核状态装配与校验。
//
// 本文件不碰进程出口：安装走 setup_linux.go 的 run（带超时 exec），校验走
// verifyReturnPathWith 的可注入命令执行器。拆出中立文件是因为守护逻辑的
// 「在位不重装、缺失才补装、修复后收敛」语义需要跨平台用替身测试锁住——
// 与 routeManager 把 addRoute/delRoute 抽成可注入字段是同一套做法。
package tunnelapp

import (
	"fmt"
	"strings"
)

// 回程标记与专用路由表：把从 TUN 进来的包（Windows 后端发给玩家的回包）
// 强制走「本机投递」表，交给透明 socket 收取，而不是按目的地址转发出去。
const (
	returnMark  = "0x7947"
	returnTable = "7947"
)

// cmdRunner 是回程路径装配/校验用到的外部命令执行器抽象。
// 真实实现是 setup_linux.go 里带 5s 超时的 run；测试注入假实现。
type cmdRunner func(name string, args ...string) (string, error)

// 下列 spec 是「安装」与「检查」共用的唯一来源。iptables -C 与 -A/-I 必须
// 用完全相同的参数：一旦两边漂移，守护协程会每轮误判缺失、反复插规则，
// 三十分钟就能把链堆成灾难。改任何一条规则先改这里。
func markRuleSpec(tunName string) []string {
	return []string{"PREROUTING", "-i", tunName, "-p", "udp", "-j", "MARK", "--set-mark", returnMark}
}

// inputRuleSpecs 返回 INPUT 收紧的两条规则：回包放行与兜底 DROP。
func inputRuleSpecs(tunName string) (est, drop []string) {
	est = []string{"-i", tunName, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}
	drop = []string{"-i", tunName, "-j", "DROP"}
	return
}

func hairpinRuleSpec(tunName string) []string {
	return []string{"FORWARD", "-i", tunName, "-o", tunName, "-j", "DROP"}
}

func forwardInSpec(tunName string) []string {
	return []string{"FORWARD", "-i", tunName, "-j", "ACCEPT"}
}

func forwardOutSpec(tunName string) []string {
	return []string{"FORWARD", "-o", tunName, "-j", "ACCEPT"}
}

// lockInputOnInterfaceWith 把 TUN 接口的 INPUT 收紧为「只放行既有连接的回包」。
//
// 最终顺序（链首起）：ESTABLISHED,RELATED ACCEPT → DROP → 其余原有规则。
// 插入顺序是先 DROP(1) 再 ESTABLISHED(1)——后者把前者顶到 2。
// 旧版的全放行 ACCEPT 一并删除：它若还在（且位置靠前），新连接照样通。
func lockInputOnInterfaceWith(shell cmdRunner, tunName string) error {
	est, drop := inputRuleSpecs(tunName)

	_, _ = shell("iptables", append([]string{"-t", "filter", "-D", "INPUT"}, est...)...)
	_, _ = shell("iptables", append([]string{"-t", "filter", "-D", "INPUT"}, drop...)...)
	_, _ = shell("iptables", "-t", "filter", "-D", "INPUT", "-i", tunName, "-j", "ACCEPT")

	if _, err := shell("iptables", append([]string{"-t", "filter", "-I", "INPUT", "1"}, drop...)...); err != nil {
		return fmt.Errorf("收紧 TUN 入站（DROP）失败: %w", err)
	}
	if _, err := shell("iptables", append([]string{"-t", "filter", "-I", "INPUT", "1"}, est...)...); err != nil {
		return fmt.Errorf("收紧 TUN 入站（放行回包）失败: %w", err)
	}
	return nil
}

// verifyReturnPathWith 幂等校验回程路径的全部内核状态，缺失的补装。
//
// 服务器上的防火墙工具（ufw/宝塔/firewalld 等）在 reload、enable 乃至增删
// 单条规则时会整表 flush iptables，把 setupReturnPath 装配的规则连带清掉。
// 症状是控制面完全正常、玩家入站照常、所有透明代理静默失联、服务端日志
// 零痕迹（2026-09-02 全代理失联事故的根因）。守护协程周期调用本函数：
// 返回 repaired 表示本次确实修复了缺失项，调用方仅在变化时打日志——这条
// 日志同时是「规则在何时被清」的时间戳。
//
// 校验项必须与 setupReturnPath 的装配面一一对应：新增装配项时两处都要加。
func verifyReturnPathWith(shell cmdRunner, tunName string) (repaired bool, err error) {
	// sysctl：ip_forward 与 rp_filter（与 setupReturnPath 的取值一致）
	sysctls := []struct {
		key    string
		expect string
	}{
		{"net.ipv4.ip_forward", "1"},
		{"net.ipv4.conf.all.rp_filter", "2"},
		{"net.ipv4.conf.default.rp_filter", "2"},
		{"net.ipv4.conf." + tunName + ".rp_filter", "2"},
	}
	for _, sc := range sysctls {
		out, serr := shell("sysctl", "-n", sc.key)
		if serr == nil && strings.TrimSpace(out) == sc.expect {
			continue
		}
		if _, werr := shell("sysctl", "-w", sc.key+"="+sc.expect); werr != nil {
			return repaired, fmt.Errorf("恢复 %s=%s 失败: %w", sc.key, sc.expect, werr)
		}
		repaired = true
	}

	// 1. mangle MARK：回程本机投递的入口
	if _, cerr := shell("iptables", append([]string{"-t", "mangle", "-C"}, markRuleSpec(tunName)...)...); cerr != nil {
		if _, aerr := shell("iptables", append([]string{"-t", "mangle", "-A"}, markRuleSpec(tunName)...)...); aerr != nil {
			return repaired, fmt.Errorf("补装 TUN 入向标记失败: %w", aerr)
		}
		repaired = true
	}

	// 2. fwmark → 专用表的策略路由（ip rule add 不幂等，必须先查再加）
	out, rerr := shell("ip", "rule", "show")
	if rerr != nil {
		return repaired, fmt.Errorf("查询策略路由规则失败: %w", rerr)
	}
	if !strings.Contains(out, "lookup "+returnTable) {
		if _, aerr := shell("ip", "rule", "add", "fwmark", returnMark, "lookup", returnTable); aerr != nil {
			return repaired, fmt.Errorf("补装策略路由规则失败: %w", aerr)
		}
		repaired = true
	}

	// 3. local 类型的默认路由：命中此表的包一律按本机地址处理
	out, rerr = shell("ip", "route", "show", "table", returnTable)
	if rerr != nil {
		// 表不存在也会走到这里，replace 会连表一起建立
		out = ""
	}
	if !strings.Contains(out, "local default dev lo") {
		if _, aerr := shell("ip", "route", "replace", "local", "default", "dev", "lo", "table", returnTable); aerr != nil {
			return repaired, fmt.Errorf("补配本机投递路由失败: %w", aerr)
		}
		repaired = true
	}

	// 4. INPUT 两条：任一缺失就走一次先删后插，恢复链首顺序
	est, drop := inputRuleSpecs(tunName)
	_, cerr1 := shell("iptables", append([]string{"-t", "filter", "-C", "INPUT"}, est...)...)
	_, cerr2 := shell("iptables", append([]string{"-t", "filter", "-C", "INPUT"}, drop...)...)
	if cerr1 != nil || cerr2 != nil {
		if lerr := lockInputOnInterfaceWith(shell, tunName); lerr != nil {
			return repaired, fmt.Errorf("修复 TUN 入站规则失败: %w", lerr)
		}
		repaired = true
	}

	// 5. FORWARD 三条：hairpin DROP 必须插链首，两条放行追加即可
	forwards := []struct {
		spec   []string
		insert bool
	}{
		{hairpinRuleSpec(tunName), true},
		{forwardInSpec(tunName), false},
		{forwardOutSpec(tunName), false},
	}
	for _, fw := range forwards {
		op := "-A"
		if fw.insert {
			op = "-I"
		}
		if _, cerr := shell("iptables", append([]string{"-t", "filter", "-C"}, fw.spec...)...); cerr != nil {
			if _, aerr := shell("iptables", append([]string{"-t", "filter", op}, fw.spec...)...); aerr != nil {
				return repaired, fmt.Errorf("补装 FORWARD 规则 %v 失败: %w", fw.spec, aerr)
			}
			repaired = true
		}
	}
	return repaired, nil
}
