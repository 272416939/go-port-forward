//go:build windows

package syssetup

import (
	"os/exec"
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
