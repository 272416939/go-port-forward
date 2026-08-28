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

// AddRoute 添加 /32 回程路由（网关为隧道对端地址）。
func AddRoute(destIP, gateway string) error {
	_, err := run("route", "add", destIP, "mask", "255.255.255.255", gateway, "metric", "1")
	return err
}

// RemoveRoute 删除回程路由；不存在不报错。
func RemoveRoute(destIP string) error {
	_, _ = run("route", "delete", destIP)
	return nil
}
