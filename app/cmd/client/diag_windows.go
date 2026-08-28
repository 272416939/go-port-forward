//go:build windows

package main

// 启动期诊断与用户可见的错误提示。
//
// GUI 程序没有控制台，任何早期失败都是"双击没反应"。所以两件事必须做：
// 一是错误用原生 MessageBox 弹出来（不能依赖 mshta 这类外部宿主——Windows
// Server 精简安装里它可能被裁掉或被策略禁止，那就退化成完全静默）；
// 二是把启动过程写进 exe 同目录的日志文件，用户不必装任何工具就能反馈。

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	mbOK        = 0x00000000
	mbIconError = 0x00000010
)

var (
	logMu   sync.Mutex
	logFile *os.File
)

// startupLogPath 返回 exe 同目录下的日志路径。
func startupLogPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "pf-client.log"
	}
	return filepath.Join(filepath.Dir(exe), "pf-client.log")
}

// openStartupLog 打开（截断）启动日志。失败不影响程序运行——日志是诊断
// 手段，不能成为新的故障点（比如目录只读时）。
func openStartupLog() {
	f, err := os.Create(startupLogPath())
	if err != nil {
		return
	}
	logMu.Lock()
	logFile = f
	logMu.Unlock()
	diag("=== pf-client 启动 ===")
}

// diag 写一行启动诊断日志。
func diag(format string, a ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	if logFile == nil {
		return
	}
	fmt.Fprintf(logFile, "%s  %s\n", time.Now().Format("2006-01-02 15:04:05"),
		fmt.Sprintf(format, a...))
	_ = logFile.Sync()
}

func closeStartupLog() {
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		_ = logFile.Close()
		logFile = nil
	}
}

// messageBox 弹出原生消息框。user32 的 MessageBoxW 一定可用，不像 mshta
// 那样依赖外部宿主程序。
func messageBox(title, text string, flags uint32) int32 {
	t, err1 := windows.UTF16PtrFromString(text)
	c, err2 := windows.UTF16PtrFromString(title)
	if err1 != nil || err2 != nil {
		return 0
	}
	ret, _, _ := procMessageBoxW.Call(0, uintptr(unsafe.Pointer(t)),
		uintptr(unsafe.Pointer(c)), uintptr(flags))
	return int32(ret)
}

// fatalBox 记录并弹出致命错误，然后退出。
func fatalBox(title, text string) {
	diag("[致命] %s：%s", title, text)
	messageBox(title, text+"\n\n详细信息见程序目录下的 pf-client.log。", mbOK|mbIconError)
	closeStartupLog()
	os.Exit(1)
}

// rtlGetNtVersionNumbers 取真实系统版本。GetVersionEx 受兼容性清单影响会
// 谎报（未声明 Win10 支持的程序只会看到 6.2），诊断日志必须拿到真值。
func rtlGetNtVersionNumbers() (major, minor, build uint32) {
	proc := windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlGetNtVersionNumbers")
	proc.Call(uintptr(unsafe.Pointer(&major)), uintptr(unsafe.Pointer(&minor)),
		uintptr(unsafe.Pointer(&build)))
	return major, minor, build & 0x0FFFFFFF
}

func fmtVersion(major, minor, build uint32) string {
	name := ""
	switch {
	case major == 10 && build >= 22000:
		name = "Windows 11 / Server 2022+"
	case major == 10 && build >= 20348:
		name = "Windows Server 2022"
	case major == 10 && build >= 17763:
		name = "Windows 10 / Server 2019"
	case major == 10:
		name = "Windows 10 早期版本"
	case major == 6 && minor == 3:
		name = "Windows 8.1 / Server 2012 R2"
	default:
		name = "较旧版本"
	}
	return fmt.Sprintf("%d.%d.%d（%s）", major, minor, build, name)
}
