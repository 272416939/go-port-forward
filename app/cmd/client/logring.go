//go:build windows

package main

// 环形日志缓冲：UI 轮询读取，容量固定，写入侧永不阻塞。

import (
	"fmt"
	"sync"
	"time"
)

type logRing struct {
	mu    sync.Mutex
	items []string
	cap   int
}

func newLogRing(capacity int) *logRing {
	return &logRing{items: make([]string, 0, capacity), cap: capacity}
}

func (r *logRing) add(msg string) {
	line := fmt.Sprintf("%s  %s", time.Now().Format("15:04:05"), msg)
	r.mu.Lock()
	if len(r.items) >= r.cap {
		r.items = append(r.items[:0], r.items[len(r.items)-r.cap+1:]...)
	}
	r.items = append(r.items, line)
	r.mu.Unlock()
}

func (r *logRing) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.items))
	copy(out, r.items)
	return out
}
