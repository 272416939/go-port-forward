//go:build windows

package main

// 原生窗口：用系统自带的 WebView2 承载界面，程序自己就是一个桌面应用，
// 不再借道外部浏览器。
//
// 依赖 Edge WebView2 Runtime。Win11 与打过近年更新的 Win10 都预装了它；
// 缺失时给出可执行的指引（附下载地址）而不是静默失败。
//
// WebView2 的消息循环必须跑在创建它的那个 OS 线程上，所以调用方要负责
// runtime.LockOSThread。

import (
	"fmt"
	"sync/atomic"

	webview2 "github.com/jchv/go-webview2"
	"github.com/jchv/go-webview2/webviewloader"
)

// current 是当前窗口，供后台 goroutine 请求关闭（Terminate 可跨线程调用）。
var current atomic.Value // webview2.WebView

// webview2Available 报告系统是否装有 WebView2 Runtime。
func webview2Available() bool {
	v, err := webviewloader.GetInstalledVersion()
	return err == nil && v != ""
}

const webview2Hint = "本程序界面需要 Microsoft Edge WebView2 运行时。\n\n" +
	"请访问以下地址下载「常青版独立安装程序」后重试：\n" +
	"https://developer.microsoft.com/microsoft-edge/webview2/"

// runWindow 打开原生窗口并阻塞直到用户关闭它（或 terminateWindow 被调用）。
// 必须在已 LockOSThread 的 goroutine 中调用。
func runWindow(url string) error {
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug: false,
		WindowOptions: webview2.WindowOptions{
			Title:  "Port Forward 隧道客户端",
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
	w.SetSize(860, 640, webview2.HintMin)
	w.Navigate(url)
	w.Run() // 窗口关闭 / PostQuitMessage 后返回
	current.Store(webview2.WebView(nil))
	return nil
}

// terminateWindow 请求关闭窗口；可从任意 goroutine 调用。
func terminateWindow() {
	if w, ok := current.Load().(webview2.WebView); ok && w != nil {
		w.Terminate()
	}
}
