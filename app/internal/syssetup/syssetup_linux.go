//go:build linux

// Package syssetup 配置路由/NAT/接口（平台特定实现）。
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

// ConfigureInterface 为 TUN 接口配置地址并启用。
func ConfigureInterface(ifaceName, cidr string) error {
	if _, err := run("ip", "addr", "add", cidr, "dev", ifaceName); err != nil {
		// 地址已存在不算错误
		if !strings.Contains(err.Error(), "exists") {
			return err
		}
	}
	_, err := run("ip", "link", "set", ifaceName, "up")
	return err
}

// DefaultOutInterface 返回默认路由出口接口名。
func DefaultOutInterface() (string, error) {
	out, err := run("ip", "route", "show", "default")
	if err != nil {
		return "", err
	}
	for _, field := range strings.Fields(out) {
		// "default via x.x.x.x dev eth0 ..."
		if field != "default" && field != "via" && !strings.Contains(field, ".") && field != "dev" {
			return field, nil
		}
	}
	return "", fmt.Errorf("syssetup: 未找到默认路由接口: %s", strings.TrimSpace(out))
}

// SetupNAT 启用 IP 转发并对隧道网段做 MASQUERADE（幂等）。
func SetupNAT(tunCIDR string) error {
	if _, err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	iface, err := DefaultOutInterface()
	if err != nil {
		return err
	}
	args := []string{"-t", "nat", "-C", "POSTROUTING", "-s", tunCIDR, "-o", iface, "-j", "MASQUERADE"}
	if _, cerr := run("iptables", args...); cerr != nil {
		add := []string{"-t", "nat", "-A", "POSTROUTING", "-s", tunCIDR, "-o", iface, "-j", "MASQUERADE"}
		if _, aerr := run("iptables", add...); aerr != nil {
			return aerr
		}
	}
	return nil
}
