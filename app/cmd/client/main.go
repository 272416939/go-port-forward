//go:build windows

// pf-client —— Port Forward 隧道客户端（Windows 桌面应用）。
//
// 界面是一个原生窗口，由系统自带的 Edge WebView2 渲染内嵌页面；页面与隧道
// 之间走本机回环上的一个受 token 保护的小 HTTP 服务。这样既是单窗口桌面程序，
// 又不必引入 CGO 或额外的 GUI 工具链——分发物仍是 exe + wintun.dll。
//
// 隧道本身需要管理员权限（虚拟网卡、路由表、防火墙规则），未提权时会主动
// 触发一次 UAC 重启自身。
//
// GUI 程序没有控制台，启动期任何失败在用户看来都是"双击没反应"。因此每个
// 关键步骤都写进 exe 同目录的 pf-client.log，失败一律用原生 MessageBox 报出来
//（见 diag_windows.go）。
package main

import (
	"os"
	"runtime"

	"pfapp/internal/syssetup"
)

const (
	tunName        = "Port Forward"
	handshakeTries = 8
	// defaultTunnelPort 是隧道服务端默认监听端口（与服务端 tunnel.listen 一致）。
	defaultTunnelPort = 7947
)

func main() {
	// WebView2 的消息循环必须固定在创建它的 OS 线程上。
	runtime.LockOSThread()

	// 软内存上限（GC 的节奏阀，不是缓冲上限——所有缓冲自身都有固定上界）。
	memLimitMB := applyMemoryLimit()

	openStartupLog()
	defer closeStartupLog()
	diag("可执行文件：%s", exePath())
	diag("软内存上限：%d MB", memLimitMB)
	diag("Windows 版本：%s", windowsVersion())
	diag("管理员权限：%v", syssetup.IsElevated())

	// 单实例保护：在提权之前先探测。提权会启动新进程、旧进程退出，若把检查
	// 放在提权之后，重复双击会先弹一次多余的 UAC 才发现自己该退出。
	//
	// 多用户版服务端已按用户分槽，同机多实例不再互相抢占隧道会话；但它们仍会
	// 撞在一批机器级的全局资源上——虚拟网卡名、按名删除的防火墙规则、系统
	// 路由表条目、pf-client.conf。任何一个实例退出都会连带删掉另一个的防火墙
	// 规则与路由，症状仍是「包在往返但进不去游戏」。所以单实例保留。
	if instanceRunning() {
		diag("已有实例在运行，唤起其窗口后退出")
		activateExistingInstance()
		return
	}

	// 未提权：请求 UAC 重启自身。
	if !syssetup.IsElevated() && os.Getenv("PF_NO_ELEVATE") == "" {
		diag("未提权，正在请求 UAC…")
		if err := syssetup.RelaunchElevated(); err == nil {
			diag("已启动提权实例，本进程退出")
			return
		} else {
			// 用户点了「否」，或系统禁用了 UAC 提权。继续以受限权限打开界面，
			// 界面上会显示权限提示。
			diag("UAC 提权未完成：%v（继续以受限权限运行）", err)
		}
	}

	// 真正占用所有权。走到这里已过提权环节，句柄保留到进程结束。
	if !claimSingleInstance() {
		diag("占用单实例锁失败（已被其它实例抢先），退出")
		activateExistingInstance()
		return
	}

	if v, err := webview2Version(); err != nil || v == "" {
		diag("WebView2 运行时检测失败：version=%q err=%v", v, err)
		fatalBox("缺少运行时组件", webview2Hint)
	} else {
		diag("WebView2 运行时版本：%s", v)
	}

	eng := NewEngine()
	url, quit, err := startUI(eng)
	if err != nil {
		fatalBox("启动失败", err.Error())
	}
	diag("本地界面服务已就绪：%s", url)

	if !syssetup.IsElevated() {
		eng.logf("[!] 当前未以管理员身份运行，无法建立隧道。")
	}

	// 自动连接上次使用的凭据，正常使用无需任何输入。
	if last := loadConfig(); last.complete() && syssetup.IsElevated() {
		eng.logf("正在连接上次使用的地址：%s", last.Addr)
		if err := eng.Start(last); err != nil {
			eng.logf("自动连接失败：%v", err)
		}
	} else if last.Addr != "" && !last.complete() {
		// 旧版配置只有地址。凭据缺失时不要静默停在「未连接」，否则用户会以为
		// 程序坏了。
		eng.logf("[!] 配置里没有接入凭据（可能是旧版本升级上来的）。请在面板的用户管理中复制接入码，粘贴到上方输入框。")
	}

	// 托盘菜单「退出程序」与界面上的退出按钮走同一条路径。
	go func() {
		<-quit
		quitApp()
	}()

	// 托盘退出与界面退出共用同一条顺序：**先同步停完隧道（路由清理在此完成），
	// 再关窗口**。窗口消失之后程序立即退出，exe 不再被锁定——用户「退出后复制
	// 新版本」不会撞上正在清理的隐形进程（2026-09-03 实测事故）。
	quitAfterStop := func() {
		eng.Stop()
		quitApp()
	}

	// 阻塞直到程序退出（关窗只是收进托盘）；随后清理路由与防火墙规则。
	diag("正在创建主窗口…")
	if err := runWindow(url, trayActions{Disconnect: eng.Stop, Quit: quitAfterStop}); err != nil {
		diag("主窗口创建失败：%v", err)
		fatalBox("界面异常", err.Error())
	}
	diag("窗口已关闭，正在清理…")
	eng.Stop() // 兜底：非退出路径关窗（断开/异常）时确保资源释放；Stop 幂等
	diag("已退出")
}

func exePath() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "(未知)"
}

// windowsVersion 返回可读的系统版本（诊断用：WebView2 的可用性与系统版本相关）。
func windowsVersion() string {
	major, minor, build := rtlGetNtVersionNumbers()
	return fmtVersion(major, minor, build)
}
