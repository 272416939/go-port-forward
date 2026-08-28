//go:build windows

// pf-client —— Port Forward 隧道客户端（Windows 桌面应用）。
//
// 界面是一个原生窗口，由系统自带的 Edge WebView2 渲染内嵌页面；页面与隧道
// 之间走本机回环上的一个受 token 保护的小 HTTP 服务。这样既是单窗口桌面程序，
// 又不必引入 CGO 或额外的 GUI 工具链——分发物仍是 exe + wintun.dll。
//
// 隧道本身需要管理员权限（虚拟网卡、路由表、防火墙规则），未提权时会主动
// 触发一次 UAC 重启自身。
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"pfapp/internal/syssetup"
)

const (
	defaultPSK     = "pfapp-default-psk-v1" // 与服务端配置保持一致，可修改
	tunName        = "Port Forward"
	tunClientIP    = "10.66.0.2"
	tunServerIP    = "10.66.0.1"
	tunCIDRMask    = "255.255.255.0"
	handshakeTries = 8
)

func main() {
	// WebView2 的消息循环必须固定在创建它的 OS 线程上。
	runtime.LockOSThread()

	// 未提权：请求 UAC 重启自身。用户拒绝时窗口照常打开，但会显示权限提示，
	// 避免用户以为程序没反应。
	if !syssetup.IsElevated() && os.Getenv("PF_NO_ELEVATE") == "" {
		if err := syssetup.RelaunchElevated(); err == nil {
			return
		}
	}

	if !webview2Available() {
		alert("缺少运行时组件", webview2Hint)
		os.Exit(1)
	}

	eng := NewEngine()
	url, quit, err := startUI(eng)
	if err != nil {
		alert("启动失败", err.Error())
		os.Exit(1)
	}

	if !syssetup.IsElevated() {
		eng.logf("[!] 当前未以管理员身份运行，无法建立隧道。")
	}

	// 自动连接上次使用的地址，正常使用无需任何输入。
	if last := loadLastAddr(); last != "" && syssetup.IsElevated() {
		eng.logf("正在连接上次使用的地址：%s", last)
		if err := eng.Start(last); err != nil {
			eng.logf("自动连接失败：%v", err)
		}
	}

	// 托盘菜单「退出程序」与界面上的退出按钮走同一条路径。
	go func() {
		<-quit
		quitApp()
	}()

	// 阻塞直到程序退出（关窗只是收进托盘）；随后清理路由与防火墙规则。
	err = runWindow(url, trayActions{
		Disconnect: eng.Stop,
		Quit:       quitApp,
	})
	if err != nil {
		alert("界面异常", err.Error())
	}
	eng.Stop()
}

// alert 弹出一个原生消息框（窗口尚未就绪时只能走系统对话框）。
func alert(title, msg string) {
	_ = exec.Command("mshta", fmt.Sprintf(
		`javascript:alert("%s\n\n%s");close()`,
		escapeJS(title), escapeJS(msg))).Run()
}

func escapeJS(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return strings.ReplaceAll(s, "\n", `\n`)
}

// --- 本地配置：记住上次使用的中转机地址 ---

func confPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "pf-client.conf"
	}
	return filepath.Join(filepath.Dir(exe), "pf-client.conf")
}

func loadLastAddr() string {
	b, err := os.ReadFile(confPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func saveLastAddr(addr string) {
	_ = os.WriteFile(confPath(), []byte(strings.TrimSpace(addr)), 0o644)
}
