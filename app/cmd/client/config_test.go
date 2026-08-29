//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-port-forward/pkg/accesscode"
)

// withTempExeDir 把配置文件路径重定向到临时目录。
// confPath 基于 os.Executable()，测试里那是 go test 的临时二进制，直接写会
// 污染构建目录，所以只测纯函数，文件读写用显式路径。
func writeConf(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pf-client.conf")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// loadFrom 是 loadConfig 的可测版本（同一套解析逻辑，路径可注入）。
func loadFrom(t *testing.T, path string) clientConfig {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return clientConfig{}
	}
	return parseConfigBytes(raw)
}

func TestParseConfigYAML(t *testing.T) {
	p := writeConf(t, "addr: 1.2.3.4:7947\nuser_id: 3f2b1c4d-5e6f-4071-8293-a4b5c6d7e8f9\nsecret: c2VjcmV0\n")
	got := loadFrom(t, p)
	if got.Addr != "1.2.3.4:7947" || got.UserID != "3f2b1c4d-5e6f-4071-8293-a4b5c6d7e8f9" || got.Secret != "c2VjcmV0" {
		t.Fatalf("解析结果 = %+v", got)
	}
	if !got.complete() {
		t.Fatal("三项齐备应判为 complete")
	}
}

// 旧版配置就是一行裸地址，而那也是合法的 YAML 标量——不能因为"解析成
// mapping 失败"就当作损坏丢弃，否则升级后用户的地址凭空消失。
func TestParseConfigMigratesLegacyPlainAddr(t *testing.T) {
	p := writeConf(t, "124.221.181.159:7947\n")
	got := loadFrom(t, p)
	if got.Addr != "124.221.181.159:7947" {
		t.Fatalf("旧格式地址未被识别：%+v", got)
	}
	if got.complete() {
		t.Fatal("旧格式没有凭据，不应判为 complete")
	}
}

// 旧格式且没写端口时要补上默认端口。
func TestParseConfigLegacyAddsDefaultPort(t *testing.T) {
	p := writeConf(t, "124.221.181.159")
	if got := loadFrom(t, p); got.Addr != "124.221.181.159:7947" {
		t.Fatalf("未补默认端口：%q", got.Addr)
	}
}

func TestParseConfigEmptyAndGarbage(t *testing.T) {
	if got := loadFrom(t, writeConf(t, "")); got.Addr != "" {
		t.Fatalf("空文件应返回零值：%+v", got)
	}
	if got := loadFrom(t, writeConf(t, "   \n\n")); got.Addr != "" {
		t.Fatalf("空白文件应返回零值：%+v", got)
	}
	// 多行但不是有效 mapping 也不是单行地址：返回零值而不是把整段当地址。
	if got := loadFrom(t, writeConf(t, "这不是配置\n也不是地址\n")); got.Addr != "" {
		t.Fatalf("无法识别的内容应返回零值：%+v", got)
	}
}

func TestParseConnectInputFromAccessCode(t *testing.T) {
	code, err := accesscode.Encode(accesscode.Code{
		Addr: "203.0.113.9:7947", UserID: "3f2b1c4d-5e6f-4071-8293-a4b5c6d7e8f9", Secret: "c2VjcmV0",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseConnectInput(code, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !got.complete() || got.Addr != "203.0.113.9:7947" {
		t.Fatalf("接入码解析结果 = %+v", got)
	}
}

// 手工填的地址要能覆盖接入码里的：服务端没配 tunnel.public_addr 时，
// 接入码里的地址可能是内网的或不可达的。
func TestParseConnectInputAddrOverridesCode(t *testing.T) {
	code, _ := accesscode.Encode(accesscode.Code{Addr: "10.0.0.5", UserID: "u", Secret: "k"})
	got, err := parseConnectInput(code, "203.0.113.9:7947", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr != "203.0.113.9:7947" {
		t.Fatalf("手工地址未覆盖接入码：%q", got.Addr)
	}
	if got.UserID != "u" || got.Secret != "k" {
		t.Fatalf("凭据被覆盖了：%+v", got)
	}
}

func TestParseConnectInputManual(t *testing.T) {
	got, err := parseConnectInput("", "1.2.3.4", "uid", "key")
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr != "1.2.3.4:7947" {
		t.Fatalf("未补默认端口：%q", got.Addr)
	}
}

// 缺凭据必须报错而不是带着空密钥去握手——那样服务端只会静默丢包，
// 用户看到的是「服务端无应答」，完全指不到真正的原因。
func TestParseConnectInputRejectsIncomplete(t *testing.T) {
	cases := []struct{ code, addr, uid, secret string }{
		{"", "", "", ""},
		{"", "1.2.3.4", "", ""},
		{"", "1.2.3.4", "uid", ""},
		{"", "1.2.3.4", "", "key"},
		{"", "", "uid", "key"},
		{"pf1.!!!broken", "", "", ""},
		{"not-an-access-code", "", "", ""},
	}
	for _, c := range cases {
		if _, err := parseConnectInput(c.code, c.addr, c.uid, c.secret); err == nil {
			t.Fatalf("%+v 应报错", c)
		}
	}
}

func TestWithDefaultPort(t *testing.T) {
	if got := withDefaultPort("1.2.3.4"); got != "1.2.3.4:7947" {
		t.Fatalf("got %q", got)
	}
	if got := withDefaultPort("1.2.3.4:9999"); got != "1.2.3.4:9999" {
		t.Fatalf("已有端口不应改动：%q", got)
	}
	if got := withDefaultPort(""); got != "" {
		t.Fatalf("空地址不应补端口：%q", got)
	}
}

// saveConfig 写出的内容必须能被 loadConfig 读回来（往返一致）。
func TestSaveLoadRoundTrip(t *testing.T) {
	in := clientConfig{Addr: "203.0.113.9:7947", UserID: "uid-1", Secret: "c2VjcmV0"}
	data, err := marshalConfig(in)
	if err != nil {
		t.Fatal(err)
	}
	out := parseConfigBytes(data)
	if out != in {
		t.Fatalf("往返不一致：%+v -> %+v", in, out)
	}
	// 配置里有隧道密钥，不能出现在一个人人可读的文件里。
	if strings.Contains(string(data), "\t") {
		t.Fatal("YAML 不应含制表符")
	}
}
