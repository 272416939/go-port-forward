//go:build windows

package main

// 软内存上限（runtime/debug.SetMemoryLimit）。
//
// 背景（2026-09-03 用户实测）：客户端后台跑一晚，任务管理器里 23MB → 80MB。
// 排查结论：**不是泄漏**——每一块增长的内存都有固定上界：
//
//	Go 堆的梯级扩张      GOGC=100 的正常节奏（活内存翻倍才 GC），约为峰值活内存的 2 倍
//	wintun 读缓冲        ~6MB（128 槽 × 48KB），设备创建时一次性分配
//	FEC 接收状态         ~45KB/方向（32 槽环形复用，仅服务端开纠错时）
//	回程路由 pending 缓冲 全局 8MB 闸门
//	日志环               400 条字符串
//	routeManager 状态    ≤512 条目
//
// 80MB 是「有过流量高峰的隧道」的正常常驻水位。判定泄漏的金标准是斜率：
// 有上界的缓存一两天内进入平台期，泄漏是持续线性增长。
//
// SetMemoryLimit 不裁剪任何缓冲，只改变 GC 的激进程度：活内存逼近上限时 GC
// 变频繁，把堆压回限内。默认 96MB（80MB 常驻 + 裕量）；低配机器可用环境变量
// PF_CLIENT_MEMLIMIT_MB 下调——下限 48MB：读缓冲 6MB + pending 峰值 8MB 之外
// 还得留堆活量，再低只是让 GC 空转。
//
// 注意这是软上限：Go 宁可多 GC 也不 OOM，实在压不住时会超限（比崩溃好）。

import (
	"os"
	"runtime/debug"
	"strconv"
)

const (
	defaultMemoryLimitMB = 96
	minMemoryLimitMB     = 48
)

// applyMemoryLimit 设置软内存上限并返回生效值（诊断日志用）。
func applyMemoryLimit() int {
	mb := defaultMemoryLimitMB
	if v := os.Getenv("PF_CLIENT_MEMLIMIT_MB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= minMemoryLimitMB {
			mb = n
		}
	}
	debug.SetMemoryLimit(int64(mb) << 20)
	return mb
}
