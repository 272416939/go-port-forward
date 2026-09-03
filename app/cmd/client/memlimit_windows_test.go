//go:build windows

package main

import "testing"

// 下限与非法输入的防御：SetMemoryLimit 是全局的，测试只验证取值逻辑
// （不重复调用 Set 本身——applyMemoryLimit 会做，重复 Set 无害但无意义）。
func TestMemoryLimitPicksEnvValue(t *testing.T) {
	// 复用 applyMemoryLimit 的取值路径需要可注入；这里直接测下限判断的语义。
	t.Setenv("PF_CLIENT_MEMLIMIT_MB", "64")
	if got := applyMemoryLimit(); got != 64 {
		t.Fatalf("合法环境值 64 未生效：got %d", got)
	}
}

func TestMemoryLimitClampsTooSmall(t *testing.T) {
	t.Setenv("PF_CLIENT_MEMLIMIT_MB", "16") // 读缓冲 6MB + pending 8MB 之外还得留活量
	if got := applyMemoryLimit(); got != defaultMemoryLimitMB {
		t.Fatalf("低于下限应回落到默认：got %d", got)
	}
}

func TestMemoryLimitIgnoresGarbage(t *testing.T) {
	t.Setenv("PF_CLIENT_MEMLIMIT_MB", "not-a-number")
	if got := applyMemoryLimit(); got != defaultMemoryLimitMB {
		t.Fatalf("非法值应回落到默认：got %d", got)
	}
}
