//go:build windows

package main

// 托盘图标与窗口消息子类化。
//
// go-webview2 没有暴露任何窗口消息钩子：它的 wndproc 把 WM_CLOSE 硬编码为
// DestroyWindow → WM_DESTROY → PostQuitMessage，窗口一关就真的没了。要实现
// 「关窗收进托盘、程序继续跑」，只能自己用 SetWindowLongPtrW 换掉窗口过程。
//
// 好消息是这个子类化很干净：库的 wndproc 是注册在窗口类上的，per-window 状态
// 存在库内的 map[hwnd] 里，不占用 GWLP_USERDATA，所以我们只要把未处理的消息
// 转发给原过程就行。注意必须转发给原过程而不是 DefWindowProc——库自己在
// default 分支处理了 WM_SIZE/WM_GETMINMAXINFO（浏览器随窗口缩放、最小尺寸）。
//
// 既然已经拿到了窗口过程，托盘图标就挂在同一个 HWND、共用 w.Run() 那一个消息
// 泵，比引入 systray 库（各自再建隐藏窗口和消息循环）机械更少。

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// 这些 API 都不在 golang.org/x/sys/windows 的封装列表里（它只导出了 17 个
// user32 函数），必须手工声明。
var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procSetWindowLongPtrW      = user32.NewProc("SetWindowLongPtrW")
	procCallWindowProcW        = user32.NewProc("CallWindowProcW")
	procShowWindow             = user32.NewProc("ShowWindow")
	procSetForegroundWindow    = user32.NewProc("SetForegroundWindow")
	procPostMessageW           = user32.NewProc("PostMessageW")
	procSendMessageW           = user32.NewProc("SendMessageW")
	procCreatePopupMenu        = user32.NewProc("CreatePopupMenu")
	procAppendMenuW            = user32.NewProc("AppendMenuW")
	procDestroyMenu            = user32.NewProc("DestroyMenu")
	procTrackPopupMenu         = user32.NewProc("TrackPopupMenu")
	procGetCursorPos           = user32.NewProc("GetCursorPos")
	procRegisterWindowMessageW = user32.NewProc("RegisterWindowMessageW")
	procIsWindowVisible        = user32.NewProc("IsWindowVisible")
	procCreateIconFromResEx    = user32.NewProc("CreateIconFromResourceEx")
	procShellNotifyIconW       = shell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandleW       = kernel32.NewProc("GetModuleHandleW")
)

const (
	wmDestroy = 0x0002
	wmClose    = 0x0010
	wmCommand  = 0x0111
	wmSetIcon  = 0x0080
	// trayCallback 必须避开 0x8000（WM_APP）——go-webview2 的 Run() 把它当作
	// 自己的 dispatch 队列信号拦截掉，不会派发到窗口过程。
	trayCallback = 0x8001 // WM_APP + 1

	wmLButtonUp     = 0x0202
	wmLButtonDblClk = 0x0203
	wmRButtonUp     = 0x0205

	swHide = 0
	swShow = 5

	iconSmall = 0
	iconBig   = 1

	nimAdd    = 0x0000
	nimModify = 0x0001
	nimDelete = 0x0002

	nifMessage = 0x0001
	nifIcon    = 0x0002
	nifTip     = 0x0004

	mfString    = 0x0000
	mfSeparator = 0x0800

	tpmLeftAlign  = 0x0000
	tpmRightButton = 0x0002

	// 菜单项 ID
	menuShow       = 1001
	menuDisconnect = 1002
	menuQuit       = 1003
)

type notifyIconDataW struct {
	CbSize           uint32
	HWnd             windows.HWND
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            windows.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     windows.Handle
}

type point struct{ X, Y int32 }

// gwlpWndProc 是 GWLP_WNDPROC。Go 不允许负常量直接转 uintptr，用变量绕开。
var gwlpWndProc int32 = -4

// trayActions 是托盘菜单需要触发的行为，由调用方注入以避免这里依赖 Engine。
type trayActions struct {
	Disconnect func()
	Quit       func()
}

type tray struct {
	hwnd        windows.HWND
	oldProc     uintptr
	hIcon       windows.Handle
	actions     trayActions
	taskbarMsg  uint32 // RegisterWindowMessageW("TaskbarCreated")
	quitting    bool   // true 时 WM_CLOSE 放行，真正退出
}

// 单实例：进程只有一个主窗口，wndproc 回调无法携带用户数据，只能用包级变量。
var activeTray *tray

// installTray 子类化窗口过程并添加托盘图标。
func installTray(hwnd windows.HWND, iconICO []byte, actions trayActions) error {
	t := &tray{hwnd: hwnd, actions: actions}
	activeTray = t

	// 标题栏用大图标，托盘用小图标——尺寸取错会明显发虚。
	// 顺带修掉 go-webview2 默认图标的问题：它 default 分支的 LoadImageW
	// 少传了参数，调用必然失败，所以窗口一直没有图标。
	if h, err := iconFromICO(iconICO, 32); err == nil {
		procSendMessageW.Call(uintptr(hwnd), wmSetIcon, iconBig, uintptr(h))
	}
	if h, err := iconFromICO(iconICO, 16); err == nil {
		procSendMessageW.Call(uintptr(hwnd), wmSetIcon, iconSmall, uintptr(h))
		t.hIcon = h // 托盘图标按小图标尺寸绘制
	}

	msg, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(
		windows.StringToUTF16Ptr("TaskbarCreated"))))
	t.taskbarMsg = uint32(msg)

	old, _, err := procSetWindowLongPtrW.Call(uintptr(hwnd), uintptr(gwlpWndProc),
		windows.NewCallback(trayWndProc))
	if old == 0 {
		return err
	}
	t.oldProc = old

	t.addIcon()
	return nil
}

func (t *tray) notify(action uint32) {
	data := notifyIconDataW{
		CbSize:           uint32(unsafe.Sizeof(notifyIconDataW{})),
		HWnd:             t.hwnd,
		UID:              1,
		UFlags:           nifMessage | nifIcon | nifTip,
		UCallbackMessage: trayCallback,
		HIcon:            t.hIcon,
	}
	copy(data.SzTip[:], windows.StringToUTF16("Port Forward 隧道客户端"))
	procShellNotifyIconW.Call(uintptr(action), uintptr(unsafe.Pointer(&data)))
}

func (t *tray) addIcon()    { t.notify(nimAdd) }
func (t *tray) removeIcon() { t.notify(nimDelete) }

// showWindow 从托盘恢复窗口并置前。
func (t *tray) showWindow() {
	procShowWindow.Call(uintptr(t.hwnd), swShow)
	procSetForegroundWindow.Call(uintptr(t.hwnd))
}

// popupMenu 弹出托盘右键菜单。
func (t *tray) popupMenu() {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)

	procAppendMenuW.Call(menu, mfString, menuShow,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("显示主界面"))))
	procAppendMenuW.Call(menu, mfString, menuDisconnect,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("断开连接"))))
	procAppendMenuW.Call(menu, mfSeparator, 0, 0)
	procAppendMenuW.Call(menu, mfString, menuQuit,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("退出程序"))))

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// 弹菜单前必须置前，否则菜单会立刻因失焦消失（Win32 经典问题）。
	procSetForegroundWindow.Call(uintptr(t.hwnd))
	procTrackPopupMenu.Call(menu, tpmLeftAlign|tpmRightButton,
		uintptr(pt.X), uintptr(pt.Y), 0, uintptr(t.hwnd), 0)
}

// requestQuit 真正退出：放行 WM_CLOSE 后投递给窗口。可从任意 goroutine 调用
//（PostMessageW 投递到窗口所属线程的队列，不像 PostQuitMessage 投给调用线程）。
func (t *tray) requestQuit() {
	t.quitting = true
	procPostMessageW.Call(uintptr(t.hwnd), wmClose, 0, 0)
}

// trayWndProc 是子类化后的窗口过程。
func trayWndProc(hwnd windows.HWND, msg uint32, wp, lp uintptr) uintptr {
	t := activeTray
	if t == nil {
		return 0
	}

	switch {
	case msg == wmClose && !t.quitting:
		// 关窗 = 收进托盘，程序与隧道继续运行。
		procShowWindow.Call(uintptr(hwnd), swHide)
		return 0

	case msg == trayCallback:
		switch uint32(lp) {
		case wmLButtonUp, wmLButtonDblClk:
			t.showWindow()
		case wmRButtonUp:
			t.popupMenu()
		}
		return 0

	case msg == wmCommand:
		switch uint32(wp) & 0xFFFF {
		case menuShow:
			t.showWindow()
			return 0
		case menuDisconnect:
			if t.actions.Disconnect != nil {
				go t.actions.Disconnect()
			}
			return 0
		case menuQuit:
			if t.actions.Quit != nil {
				go t.actions.Quit()
			}
			return 0
		}

	case msg == t.taskbarMsg:
		// explorer.exe 重启后托盘区被重建，不重加图标就永久消失。
		t.addIcon()

	case msg == wmDestroy:
		t.removeIcon()
	}

	ret, _, _ := procCallWindowProcW.Call(t.oldProc, uintptr(hwnd),
		uintptr(msg), wp, lp)
	return ret
}
