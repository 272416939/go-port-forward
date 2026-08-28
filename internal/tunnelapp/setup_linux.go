//go:build linux

package tunnelapp

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

// defaultOutInterface 返回默认路由出口接口名。
func defaultOutInterface() (string, error) {
	out, err := run("ip", "route", "show", "default")
	if err != nil {
		return "", err
	}
	for _, field := range strings.Fields(out) {
		if field != "default" && field != "via" && !strings.Contains(field, ".") && field != "dev" {
			return field, nil
		}
	}
	return "", fmt.Errorf("tunnelapp: 未找到默认路由接口: %s", strings.TrimSpace(out))
}

// setupNAT 启用 IP 转发、放行 TUN 转发、并对隧道网段做 MASQUERADE（幂等）。
// FORWARD 放行至关重要：云镜像普遍默认 DROP FORWARD，缺失会导致
// “隧道通但业务不通”（回包被内核静默丢弃）。
//
// 注意：iptables 的 -t <table> 必须位于 -A/-C 等命令之前，否则报
// Bad argument 'nat'。
func setupNAT(tunName, tunCIDR string) error {
	if _, err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	iface, err := defaultOutInterface()
	if err != nil {
		return err
	}
	ensure := func(table string, ruleSpec ...string) error {
		check := append([]string{"-t", table, "-C"}, ruleSpec...)
		if _, cerr := run("iptables", check...); cerr == nil {
			return nil // 规则已存在 | rule already present
		}
		add := append([]string{"-t", table, "-A"}, ruleSpec...)
		_, aerr := run("iptables", add...)
		return aerr
	}
	if err := ensure("nat", "POSTROUTING", "-s", tunCIDR, "-o", iface, "-j", "MASQUERADE"); err != nil {
		return err
	}
	if err := ensure("filter", "FORWARD", "-i", tunName, "-j", "ACCEPT"); err != nil {
		return err
	}
	return ensure("filter", "FORWARD", "-o", tunName, "-j", "ACCEPT")
}
