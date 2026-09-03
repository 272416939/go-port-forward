//go:build windows

package main

// 重连语义（2026-09-03 二次实测的真正根因）：界面在连接成功后会清掉接入码与
// 密钥两个输入框（防泄漏），重连请求的真实形态是 code 空、code_id 有值（回填）、
// secret 空。后端必须把「密钥留空」解释为沿用已保存凭据，否则断开后永远连不上——
// 而 400 的报错又被状态轮询抹掉，用户看到的就是「点连接没反应」。

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func postConnect(t *testing.T, base, token, body string) *http.Response {
	t.Helper()
	res, err := http.Post(base+"/api/connect?t="+token, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("connect %s: %v", body, err)
	}
	return res
}

func TestConnectSecretEmptyMeansSavedCredentials(t *testing.T) {
	withLifecycleStubs(t)
	// 模拟上一次成功连接留下的凭据。
	saveConfig(testConf("127.0.0.1:1"))

	eng := NewEngine()
	url, _, err := startUI(eng)
	if err != nil {
		t.Fatalf("startUI: %v", err)
	}
	base, token, ok := strings.Cut(url, "/?t=")
	if !ok {
		t.Fatalf("入口 URL 缺少 token：%s", url)
	}

	// 重连形态：code 空、code_id 回填、secret 空 → 必须接受并真的启动引擎。
	res := postConnect(t, base, token, `{"addr":"127.0.0.1:1","code_id":"`+testConf("").CodeID+`","secret":""}`)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("重连（secret 留空）= %d，期望 200——这是「断开后点连接没反应」的根因", res.StatusCode)
	}
	waitForState(t, eng, StateConnecting, 2*time.Second)
	eng.Stop() // 结束握手重试循环

	// 全空（老的无输入路径）仍然沿用已保存凭据。
	res = postConnect(t, base, token, `{}`)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("全空重连 = %d，期望 200", res.StatusCode)
	}
	eng.Stop()

	// 手工改了访问码 ID 但密钥留空：沿用旧密钥必然握手失败，必须明确拒绝
	// 并给出指引，不能让用户对着「服务端无应答」排查。
	res = postConnect(t, base, token, `{"code_id":"ffffffffffffffffffffffffffffffff","secret":""}`)
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("换了 code_id 但 secret 留空 = %d，期望 400", res.StatusCode)
	}

	// 没有任何已保存凭据时密钥留空 → 引导粘贴接入码。
	if err := os.Remove(confPath()); err != nil && !os.IsNotExist(err) {
		t.Fatalf("清理配置文件: %v", err)
	}
	res = postConnect(t, base, token, `{"code_id":"`+testConf("").CodeID+`","secret":""}`)
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("无已保存凭据且 secret 留空 = %d，期望 400", res.StatusCode)
	}
}

// 手工三项（访问码 ID + 密钥）路径不受影响：secret 非空时照常按手工输入走。
func TestConnectManualSecretPathIntact(t *testing.T) {
	withLifecycleStubs(t)
	if err := os.Remove(confPath()); err != nil && !os.IsNotExist(err) {
		t.Fatalf("清理配置文件: %v", err)
	}

	eng := NewEngine()
	url, _, err := startUI(eng)
	if err != nil {
		t.Fatalf("startUI: %v", err)
	}
	base, token, _ := strings.Cut(url, "/?t=")

	body := `{"addr":"127.0.0.1:1","code_id":"` + testConf("").CodeID + `","secret":"c2VjcmV0"}`
	res := postConnect(t, base, token, body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("手工三项连接 = %d，期望 200", res.StatusCode)
	}
	waitForState(t, eng, StateConnecting, 2*time.Second)
	eng.Stop()
}
