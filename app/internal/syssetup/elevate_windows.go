//go:build windows

package syssetup

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// IsElevated 报告当前进程是否以管理员身份运行。
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// RelaunchElevated 以管理员身份重新启动自身（触发 UAC 提示）并返回。
// 调用方应在成功后立即退出，让提权后的新进程接管。
//
// 虚拟网卡、路由表、防火墙规则都需要管理员权限；GUI 模式下没有控制台可以
// 提示用户"请右键以管理员运行"，所以这里主动走 ShellExecute 的 runas 动词。
func RelaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := strings.Join(os.Args[1:], " ")

	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	var argPtr *uint16
	if args != "" {
		if argPtr, err = windows.UTF16PtrFromString(args); err != nil {
			return err
		}
	}
	cwd, _ := windows.UTF16PtrFromString(filepathDir(exe))

	return windows.ShellExecute(0, verb, file, argPtr, cwd, windows.SW_SHOWNORMAL)
}

// filepathDir 取目录部分（避免为此单独引入 path/filepath）。
func filepathDir(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i > 0 {
		return p[:i]
	}
	return "."
}
