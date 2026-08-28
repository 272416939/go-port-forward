//go:build windows

package main

// 从 .ico 字节流创建 HICON。
//
// CreateIconFromResourceEx 直接吃 ICO 里的图像数据，不需要落地临时文件——
// systray 类库普遍要写 %TEMP% 再 LoadImageW(LR_LOADFROMFILE)，是因为它们要
// 兼容任意来源；我们的图标是自己打包的，格式已知（48×48 32bpp 未压缩 DIB）。

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// iconFromICO 从 ICO 数据中取第一张图，缩放到 cx×cy 生成 HICON。
func iconFromICO(ico []byte, cx, cy int) (windows.Handle, error) {
	const dirHeader = 6  // ICONDIR: reserved(2) type(2) count(2)
	const dirEntry = 16  // ICONDIRENTRY
	if len(ico) < dirHeader+dirEntry {
		return 0, fmt.Errorf("icon: 数据过短")
	}
	if count := binary.LittleEndian.Uint16(ico[4:6]); count == 0 {
		return 0, fmt.Errorf("icon: 无图像")
	}
	size := binary.LittleEndian.Uint32(ico[dirHeader+8:])
	offset := binary.LittleEndian.Uint32(ico[dirHeader+12:])
	if uint64(offset)+uint64(size) > uint64(len(ico)) {
		return 0, fmt.Errorf("icon: 图像数据越界")
	}
	img := ico[offset : offset+size]

	// 0x00030000 = 图标资源版本号（ICO/CUR 资源固定值）。
	h, _, err := procCreateIconFromResEx.Call(
		uintptr(unsafe.Pointer(&img[0])), uintptr(size),
		1, // fIcon=TRUE（图标而非光标）
		0x00030000,
		uintptr(cx), uintptr(cy),
		0, // LR_DEFAULTCOLOR
	)
	if h == 0 {
		return 0, err
	}
	return windows.Handle(h), nil
}
