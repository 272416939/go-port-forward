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

// setupNetwork 启用 IP 转发、放行 TUN 转发并放宽 rp_filter（幂等）。
// 透明模式的回包源地址已被 pf-client 在 Windows 侧改写为服务器公网 IP，
// 因此这里不需要 MASQUERADE；FORWARD 放行至关重要（云镜像普遍默认 DROP）。
// rp_filter 放宽为 loose：TUN 入包的源地址（玩家 IP）的对称路由不在入接口上。
func setupNAT(tunName, tunCIDR string) error {
	if _, err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	for _, key := range []string{"net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter", "net.ipv4.conf." + tunName + ".rp_filter"} {
		_, _ = run("sysctl", "-w", key+"=2")
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
	if err := ensure("filter", "FORWARD", "-i", tunName, "-j", "ACCEPT"); err != nil {
		return err
	}
	return ensure("filter", "FORWARD", "-o", tunName, "-j", "ACCEPT")
}
