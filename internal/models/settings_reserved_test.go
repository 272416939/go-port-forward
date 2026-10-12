package models

import (
	"testing"
)

func TestParseReservedPorts(t *testing.T) {
	cases := []struct {
		input   string
		wantErr bool
		wantLen int
	}{
		{"", false, 0},
		{"   ", false, 0},
		{"80", false, 1},
		{"80, 443, 3306", false, 3},
		{"80;443 3306\n8080-8090", false, 4},
		{"19132-19139", false, 1},
		{"0", true, 0},             // 端口需在 1~65535
		{"65536", true, 0},         // 超出上限
		{"8090-8080", true, 0},     // 起始大于结束
		{"abc", true, 0},           // 非法字符
		{"80-abc", true, 0},        // 非法字符
	}

	for _, c := range cases {
		ranges, err := ParseReservedPorts(c.input)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseReservedPorts(%q) error = %v, wantErr %v", c.input, err, c.wantErr)
		}
		if err == nil && len(ranges) != c.wantLen {
			t.Errorf("ParseReservedPorts(%q) len = %d, want %d", c.input, len(ranges), c.wantLen)
		}
	}
}

func TestIsPortReserved(t *testing.T) {
	raw := "80, 443, 8080-8090, 19132-19139"

	// 命中单端口
	if !IsPortReserved(80, raw) || !IsPortReserved(443, raw) {
		t.Errorf("应命中单端口 80, 443")
	}

	// 命中区间边缘与中间
	if !IsPortReserved(8080, raw) || !IsPortReserved(8085, raw) || !IsPortReserved(8090, raw) {
		t.Errorf("应命中区间 8080-8090")
	}
	if !IsPortReserved(19132, raw) || !IsPortReserved(19139, raw) {
		t.Errorf("应命中区间 19132-19139")
	}

	// 未命中
	if IsPortReserved(8079, raw) || IsPortReserved(8091, raw) || IsPortReserved(20000, raw) {
		t.Errorf("不应命中未预留端口")
	}

	// 边界与空配置
	if IsPortReserved(0, raw) || IsPortReserved(80, "") {
		t.Errorf("空配置或端口 0 不应判定为预留")
	}
}
