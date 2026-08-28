//go:build windows

// pf-client —— Port Forward 隧道客户端（Windows，图形界面）。
//
// 界面用本机浏览器承载：程序在 127.0.0.1 的随机端口起一个带一次性 token
// 的本地服务，然后打开默认浏览器。这样不必引入 GUI 工具链或 WebView2 运行时，
// 单个 exe（加 wintun.dll）即可分发。
//
// 隧道本身需要管理员权限（虚拟网卡、路由表、防火墙规则），未提权时会主动
// 触发一次 UAC 重启自身。
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

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
	// 未提权：请求 UAC 重启自身。用户拒绝时（1223）静默退出，界面仍可打开
	// 但会显示权限提示，避免用户以为程序崩了。
	if !syssetup.IsElevated() && os.Getenv("PF_NO_ELEVATE") == "" {
		if err := syssetup.RelaunchElevated(); err == nil {
			return
		}
	}

	eng := NewEngine()
	url, quit, err := startUI(eng)
	if err != nil {
		alert("启动失败", err.Error())
		os.Exit(1)
	}
	eng.logf("界面已就绪：%s", url)
	// 从终端启动时打印入口地址（GUI 模式无控制台，写入静默失败）；
	// 浏览器没能自动弹出时用户也能手工打开。
	fmt.Println("界面地址：" + url)

	if !syssetup.IsElevated() {
		eng.logf("[!] 当前未以管理员身份运行，无法建立隧道。")
	}

	openBrowser(url)

	// 自动连接上次使用的地址，省掉重复输入。
	if last := loadLastAddr(); last != "" && syssetup.IsElevated() {
		eng.logf("正在连接上次使用的地址：%s", last)
		if err := eng.Start(last); err != nil {
			eng.logf("自动连接失败：%v", err)
		}
	}

	// 退出路径有两条：界面上的「退出程序」按钮，或 Ctrl+C / 系统终止信号。
	// 两者都要走 Stop()，否则 /32 路由和防火墙规则会残留在系统里。
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
	case <-quit:
	}
	eng.Stop()
	// 给 defer 中的系统命令（route delete / 防火墙规则移除）留出执行时间。
	time.Sleep(300 * time.Millisecond)
}

// openBrowser 用系统默认浏览器打开界面。
// rundll32 比 `cmd /c start` 稳妥：不会因 URL 中的 & 被 cmd 解析而截断。
func openBrowser(url string) {
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

// alert 弹出一个原生消息框（此时界面还没起来，只能走系统对话框）。
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
