//go:build windows

package syssetup

// route.exe 文案匹配器的用例。
//
// AddRoute 的幂等性是「升级后旧玩家连不上」事故的修复点：客户端升级时进程被
// 强杀，上一轮的 /32 路由留在系统里；新客户端 route add 报「对象已存在」，
// 安装器从此无限退避，旧玩家全部连不上而新玩家正常。匹配不到就是事故重放。
// route.exe 不给可区分的退出码，只能认文案——中英文各一套，逐条锁死。

import "testing"

func TestIsRouteAlreadyExists(t *testing.T) {
	cases := map[string]bool{
		"The route addition failed: The object already exists.":       true,
		"路由添加失败: 对象已存在。":                                             true,
		"对象已存在": true,
		// 差一个字都不行：匹配过宽会把真实失败吞成成功。
		"The route addition failed: The object cannot be found.": false,
		"路由添加失败: 找不到元素。":                                         false,
		"":                                                       false,
		"对象存":                                                     false, // 部分匹配不算
	}
	for out, want := range cases {
		if got := isRouteAlreadyExists(out); got != want {
			t.Errorf("isRouteAlreadyExists(%q) = %v, 期望 %v", out, got, want)
		}
	}
}

// ListRoutesViaGateway 的解析规则：只认「目标 掩码 /32 网关 接口 跃点数」五列
// 且网关恰为隧道网关的行。route print 的表头、分隔线、「在链路上」行天然不匹配。
// 解析真数据而不匹配文案——表头文案随系统语言变，数据列不变。
func TestListRoutesViaGatewayParsing(t *testing.T) {
	// run() 是私有函数且真要起 route.exe；解析逻辑抽不出去了就退一步：
	// 这里只测 isIPv4 边界，route print 全链路在真机冒烟覆盖。
	if !isIPv4("111.29.236.135") || !isIPv4("8.8.8.8") {
		t.Fatal("合法 IPv4 被拒")
	}
	for _, bad := range []string{"在链路上", "1.2.3", "1.2.3.4.5", "999.1.1.1", "1..2.3", ""} {
		if isIPv4(bad) {
			t.Errorf("isIPv4(%q) 应为 false", bad)
		}
	}
}
