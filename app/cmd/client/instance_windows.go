//go:build windows

package main

// 单实例保护。
//
// 关窗收进托盘之后，关窗不再退出进程——于是"双击、关窗、过会儿又双击"就会
// 悄悄堆出多个后台实例。这在本程序里是硬故障而非小瑕疵：服务端只维护一个
// 会话槽位与一个 peer 地址，多个客户端同时握手会互相抢占，peer 被反复改写，
// 回包发给上一轮的端口，表现为"包在往返但进不去游戏"。
//
// 用命名互斥体判定：Windows 内核对象，进程崩溃时由系统自动释放，不像 pid
// 文件那样会留下需要清理的陈旧状态。

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// singleInstanceName 是互斥体名。放在 Local\ 命名空间（每个登录会话独立）：
// 隧道是按机器配置的，但远程桌面多用户各自跑一份属于合理场景，不该互相挡。
const singleInstanceName = `Local\PortForwardTunnelClient`

var (
	procCreateMutexW = kernel32.NewProc("CreateMutexW")
	procFindWindowW  = user32.NewProc("FindWindowW")
)

// instanceLock 持有互斥体句柄，进程存活期间不得释放。
var instanceLock windows.Handle

// openMutex 创建/打开命名互斥体，返回句柄与"之前是否已存在"。
func openMutex() (windows.Handle, bool, error) {
	name, err := windows.UTF16PtrFromString(singleInstanceName)
	if err != nil {
		return 0, false, err
	}
	h, _, lastErr := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return 0, false, lastErr
	}
	// CreateMutexW 在对象已存在时仍返回有效句柄，靠 GetLastError 区分。
	return windows.Handle(h), lastErr == windows.ERROR_ALREADY_EXISTS, nil
}

// instanceRunning 探测是否已有实例在跑，不占用所有权。
//
// 命名内核对象的生命周期由句柄计数决定，所以"创建后立刻关闭"不会影响真正的
// 持有者。放在提权之前探测，能让重复双击直接唤起已有窗口，而不是先弹一次
// 多余的 UAC 再发现自己该退出。
func instanceRunning() bool {
	h, existed, err := openMutex()
	if err != nil {
		diag("单实例探测失败：%v（跳过检查）", err)
		return false
	}
	windows.CloseHandle(h)
	return existed
}

// claimSingleInstance 取得唯一实例所有权，句柄保留到进程结束。
// 返回 false 表示在探测之后又有别的实例抢先了（提权重启的时间窗内可能发生）。
func claimSingleInstance() bool {
	h, existed, err := openMutex()
	if err != nil {
		diag("创建单实例互斥体失败：%v（跳过检查）", err)
		return true
	}
	if existed {
		windows.CloseHandle(h)
		return false
	}
	instanceLock = h
	return true
}

// activateExistingInstance 把已在运行的实例的窗口唤到前台。
//
// 找不到窗口是正常情况——已有实例可能正处于启动过程中，窗口还没建出来。
// 这时静默返回即可，用户再点一次托盘图标就行；弹一个"程序已在运行但找不到
// 窗口"的框只会让人困惑。
func activateExistingInstance() {
	title, err := windows.UTF16PtrFromString(windowTitle)
	if err != nil {
		return
	}
	hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(title)))
	if hwnd == 0 {
		return
	}
	procShowWindow.Call(hwnd, swShow)
	procSetForegroundWindow.Call(hwnd)
}
