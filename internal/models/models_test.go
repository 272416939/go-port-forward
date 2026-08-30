package models

// 规则名校验的回归测试：白名单字符集与长度上限是防火墙同步（iptables
// comment/netsh 规则名）能正确加、删的前提。

import (
	"strings"
	"testing"
)

func TestValidateRuleName(t *testing.T) {
	valid := []string{
		"我的服务器",             // 中文
		"mc-server 01",       // 字母数字空格
		"ubuntu:nginx:tcp/80", // WSL 导入自动生成的形态
		"备份(1)【测试】：UDP",      // 全角括号与冒号
		"a.b_c-d/e、f",
	}
	for _, name := range valid {
		if err := ValidateRuleName(name); err != nil {
			t.Errorf("%q 应通过校验, got %v", name, err)
		}
	}

	invalid := []string{
		"",              // 空
		`quote"inside`,  // 双引号
		"single'quote",  // 单引号（netsh 参数值）
		"back\\slash",   // 反斜杠
		"a;b",           // 分号
		"a$b",           // 美元符
		"a|b",           // 竖线
		"new\nline",     // 控制字符
		strings.Repeat("a", 65), // 超长（>64）
	}
	for _, name := range invalid {
		if err := ValidateRuleName(name); err == nil {
			t.Errorf("%q 应被拒绝", name)
		}
	}
}
