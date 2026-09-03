//go:build windows

package main

// 引擎生命周期（Start/Stop/自退）的语义锁。
//
// 2026-09-03 用户实测暴露的两个状态机缺陷都在这里回归：
//  1. run 自行退出（终态拒绝、创建网卡失败）后句柄残留，Start 永远报
//     「隧道已在运行」而界面上没有断开按钮可清 → 只能重启程序；
//  2. 断开进行中点退出，Stop 看到 cancel 已被取走就当无事发生直接返回，
//     进程退出把正在执行的 route.exe 删除拦腰截断 → 残留 /32 路由吸走
//     玩家全部回包，进不来服务器。

import (
	"os"
	"strings"
	"testing"
	"time"

	"go-port-forward/pkg/tunnel"
)

// withLifecycleStubs 把提权与设备指纹换成恒真替身，让 Start 能走进状态机。
// Start 会把凭据落盘到 exe 目录的 pf-client.conf，结束必须清掉——否则同包
// 后跑的用例（如 ui_test 的「拒绝缺凭据」）会读到这份配置，行为取决于文件
// 而不是用例自己的布置。
func withLifecycleStubs(t *testing.T) {
	t.Helper()
	oldElev, oldFP := isElevatedFn, deviceFingerprintFn
	isElevatedFn = func() bool { return true }
	deviceFingerprintFn = func() (string, error) {
		return strings.Repeat("ab", tunnel.FingerprintSize), nil
	}
	t.Cleanup(func() {
		isElevatedFn, deviceFingerprintFn = oldElev, oldFP
		_ = os.Remove(confPath())
	})
}

func testConf(addr string) clientConfig {
	return clientConfig{
		Addr:   addr,
		CodeID: "00112233445566778899aabbccddeeff",
		Secret: "c2VjcmV0",
	}
}

// waitForState 轮询直到引擎进入目标状态。
func waitForState(t *testing.T, e *Engine, want State, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if got := e.Snapshot().State; got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("引擎状态停在 %q，%v 内未进入 %q", e.Snapshot().State, d, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// run 自行退出（不经 Stop）后必须清掉 cancel/done：这是「断开后点连接永远
// 没反应」的根因。用超范围端口让 run 在第一步解析失败立即退出（不能用无法
// 解析的主机名：那会走 DNS 慢路径，测试时序不可控），不碰网络。
func TestStartWorksAfterRunSelfExit(t *testing.T) {
	withLifecycleStubs(t)
	e := NewEngine()
	if err := e.Start(testConf("1.2.3.4:99999")); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitForState(t, e, StateError, 3*time.Second)

	// fail 置错误态与包装 goroutine 清句柄之间有微小窗口，容忍重试；
	// 但旧实现的「已在运行」是永久性的，重试到超时也过不去。
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := e.Start(testConf("1.2.3.4:99999"))
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "已在运行") || time.Now().After(deadline) {
			t.Fatalf("run 自退后 Start 被拒绝：%v（退出时必须清掉 cancel/done）", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	waitForState(t, e, StateError, 3*time.Second)
}

// 断开进行中（run 尚未退出）Start 必须被拒：放行会让新连接与旧收尾并发，
// 收尾的 cleanupSystem 会删掉新连接刚装的防火墙规则——「显示已连接但玩家
// 进不来」。
func TestStartRejectedDuringTeardown(t *testing.T) {
	withLifecycleStubs(t)
	e := NewEngine()
	e.mu.Lock()
	e.cancel, e.done = nil, make(chan struct{}) // 模拟：断开已发起、清理未完成
	e.mu.Unlock()

	err := e.Start(testConf("127.0.0.1:7947"))
	if err == nil || !strings.Contains(err.Error(), "正在断开") {
		t.Fatalf("断开进行中 Start = %v，期望「正在断开」拒绝", err)
	}
}

// 断开进行中再调 Stop（退出按钮、托盘退出）必须等待清理完成而不是直接
// 返回——否则进程带着没删完的路由退出，留下残留 /32。
func TestStopWaitsForInFlightTeardown(t *testing.T) {
	e := NewEngine()
	e.mu.Lock()
	done := make(chan struct{})
	e.cancel, e.done = nil, done // 模拟：断开已发起、清理未完成
	e.mu.Unlock()
	e.setState(StateDisconnecting, "")

	finished := make(chan struct{})
	go func() { e.Stop(); close(finished) }()

	select {
	case <-finished:
		t.Fatal("Stop 在 run 退出前就返回了——退出程序会在这里截断路由清理")
	case <-time.After(150 * time.Millisecond):
	}
	close(done) // run 退出
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("run 退出后 Stop 仍未返回")
	}
	if st := e.Snapshot().State; st != StateIdle {
		t.Errorf("Stop 完成后状态 = %q，期望 %q", st, StateIdle)
	}
}
