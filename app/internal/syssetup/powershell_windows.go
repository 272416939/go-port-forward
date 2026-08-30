//go:build windows

package syssetup

import (
	"os/exec"
	"strings"
)

// execPowerShell 执行一段 PowerShell 命令（New/Remove-NetFirewallRule
// 等 cmdlet 无法用 netsh 表达）。
func execPowerShell(command string) (string, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", command).CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}

// psQuote 把值包成 PowerShell 单引号字符串字面量：单引号串里唯一需要转义的
// 是单引号本身（写成两个连续单引号）。当前调用点的入参都是编译期常量，这里
// 是防御性收口——参数一旦变成动态输入（如自定义网卡名），直接内插进 -Command
// 就是命令注入。
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
