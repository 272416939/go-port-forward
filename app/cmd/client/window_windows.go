//go:build windows

package main

// 原生窗口：用系统自带的 WebView2 承载界面，程序自己就是一个桌面应用。
//
// 依赖 Edge WebView2 Runtime。Win11 与打过近年更新的 Win10 都预装了它；
// 缺失时给出可执行的指引（附下载地址）而不是静默失败。
//
// WebView2 的消息循环必须跑在创建它的那个 OS 线程上，所以调用方要负责
// runtime.LockOSThread。关窗行为由 tray_windows.go 的子类化窗口过程接管：
// 默认收进托盘，只有 requestQuit 才真正退出。

import (
	"embed"
	"fmt"
	"sync/atomic"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
	"github.com/jchv/go-webview2/webviewloader"
	"golang.org/x/sys/windows"
)

//go:embed assets/icon.ico
var assetFS embed.FS

// current 是当前窗口，供后台 goroutine 请求关闭。
var current atomic.Value // webview2.WebView

// webview2Version 返回已安装的 WebView2 运行时版本；未安装时返回空字符串。
func webview2Version() (string, error) {
	return webviewloader.GetInstalledVersion()
}

const webview2Hint = "本程序界面需要 Microsoft Edge WebView2 运行时，当前系统未安装。\n\n" +
	"Windows Server 2019 / 2016 以及部分精简版 Windows 10 不预装它，需要手动安装：\n\n" +
	"1. 打开 https://developer.microsoft.com/microsoft-edge/webview2/\n" +
	"2. 下载「常青版独立安装程序」（Evergreen Standalone Installer，x64）\n" +
	"3. 安装完成后重新运行本程序\n\n" +
	"直接下载地址：\n" +
	"https://go.microsoft.com/fwlink/p/?LinkId=2124703"

// windowTitle 同时用于创建窗口和单实例检查时按标题查找已有窗口，
// 必须是同一个常量。
const windowTitle = "Port Forward 隧道客户端"

// runWindow 打开原生窗口并阻塞直到程序退出（关窗只是隐藏到托盘）。
// 必须在已 LockOSThread 的 goroutine 中调用。
func runWindow(url string, actions trayActions) error {
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug: false,
		WindowOptions: webview2.WindowOptions{
			Title:  windowTitle,
			Width:  980,
			Height: 760,
			Center: true,
		},
	})
	if w == nil {
		return fmt.Errorf("创建窗口失败（WebView2 运行时可能已损坏）")
	}
	defer w.Destroy()
	current.Store(w)

	hwnd := windows.HWND(uintptr(unsafe.Pointer(w.Window())))
	if ico, err := assetFS.ReadFile("assets/icon.ico"); err == nil {
		if terr := installTray(hwnd, ico, actions); terr != nil {
			return fmt.Errorf("初始化托盘失败: %w", terr)
		}
	} else {
		return fmt.Errorf("读取图标资源失败: %w", err)
	}

	w.SetSize(860, 640, webview2.HintMin)
	w.Navigate(url)
	w.Run() // 直到 requestQuit 放行 WM_CLOSE
	current.Store(webview2.WebView(nil))
	return nil
}

// quitApp 请求整个程序退出；可从任意 goroutine 调用。
//
// 不能用 webview 的 Terminate()：它内部是 PostQuitMessage，只投递到**调用
// 线程**的消息队列，而主线程被 LockOSThread 钉住，后台 goroutine 永远不在
// 那个线程上——WM_QUIT 会落到错误的队列，窗口关不掉。PostMessageW 是按窗口
// 投递的，跨线程安全。
func quitApp() {
	if t := activeTray; t != nil {
		t.requestQuit()
	}
}

// showMainWindow 从托盘恢复窗口（供界面/托盘菜单调用）。
func showMainWindow() {
	if t := activeTray; t != nil {
		t.showWindow()
	}
}
