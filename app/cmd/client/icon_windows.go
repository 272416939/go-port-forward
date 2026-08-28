//go:build windows

package main

// 从 .ico 字节流创建 HICON。
//
// CreateIconFromResourceEx 直接吃 ICO 里的图像数据，不需要落地临时文件——
// systray 类库普遍要写 %TEMP% 再 LoadImageW(LR_LOADFROMFILE)，是因为它们要
// 兼容任意来源（含 PNG 压缩的条目）。我们的 icon.ico 是自己拼的，每个条目都是
// 未压缩 DIB，直接交给这个 API 即可。

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	icoDirHeader = 6  // ICONDIR: reserved(2) type(2) count(2)
	icoDirEntry  = 16 // ICONDIRENTRY
)

// iconFromICO 取 ICO 中最贴合 size 的那一张，生成 size×size 的 HICON。
//
// 选最接近的条目而不是固定取第一张：把 16×16 放大成 32×32 会明显发虚，而
// 我们的 icon.ico 本来就备了 16/24/32/48 四个尺寸。
func iconFromICO(ico []byte, size int) (windows.Handle, error) {
	if len(ico) < icoDirHeader+icoDirEntry {
		return 0, fmt.Errorf("icon: 数据过短")
	}
	count := int(binary.LittleEndian.Uint16(ico[4:6]))
	if count == 0 {
		return 0, fmt.Errorf("icon: 无图像")
	}
	if len(ico) < icoDirHeader+icoDirEntry*count {
		return 0, fmt.Errorf("icon: 目录区截断")
	}

	best, bestScore := -1, 1<<31
	for i := 0; i < count; i++ {
		e := ico[icoDirHeader+icoDirEntry*i:]
		w := int(e[0])
		if w == 0 {
			w = 256 // ICO 用 0 表示 256
		}
		// 优先不小于目标的尺寸（缩小比放大清晰），差距越小越好。
		score := w - size
		if score < 0 {
			score = -score * 4
		}
		if score < bestScore {
			best, bestScore = i, score
		}
	}

	e := ico[icoDirHeader+icoDirEntry*best:]
	imgSize := binary.LittleEndian.Uint32(e[8:])
	imgOff := binary.LittleEndian.Uint32(e[12:])
	if imgSize == 0 || uint64(imgOff)+uint64(imgSize) > uint64(len(ico)) {
		return 0, fmt.Errorf("icon: 图像数据越界")
	}
	img := ico[imgOff : imgOff+imgSize]

	// 0x00030000 = 图标资源版本号（ICO/CUR 资源固定值）。
	h, _, err := procCreateIconFromResEx.Call(
		uintptr(unsafe.Pointer(&img[0])), uintptr(imgSize),
		1, // fIcon=TRUE（图标而非光标）
		0x00030000,
		uintptr(size), uintptr(size),
		0, // LR_DEFAULTCOLOR
	)
	if h == 0 {
		return 0, err
	}
	return windows.Handle(h), nil
}
