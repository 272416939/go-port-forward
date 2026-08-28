//go:build windows

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// startUI 必须能真正提供页面与接口，并且写操作要拒绝错误的 token——
// 这是这个本地控制面唯一的访问控制，不能回归。
func TestUIServerServesAndGuards(t *testing.T) {
	eng := NewEngine()
	url, _, err := startUI(eng)
	if err != nil {
		t.Fatalf("startUI: %v", err)
	}
	base, token, ok := strings.Cut(url, "/?t=")
	if !ok {
		t.Fatalf("入口 URL 缺少 token：%s", url)
	}

	t.Run("嵌入页面可访问", func(t *testing.T) {
		for _, path := range []string{"/", "/app.css", "/app.js"} {
			res, err := http.Get(base + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Errorf("GET %s = %d, 期望 200（embed 资源是否漏打包？）", path, res.StatusCode)
			}
		}
	})

	t.Run("带 token 可读状态", func(t *testing.T) {
		res, err := http.Get(base + "/api/status?t=" + token)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, 期望 200", res.StatusCode)
		}
		var snap Snapshot
		if err := json.NewDecoder(res.Body).Decode(&snap); err != nil {
			t.Fatalf("解析响应: %v", err)
		}
		if snap.State != StateIdle {
			t.Errorf("初始状态 = %q, 期望 %q", snap.State, StateIdle)
		}
		if snap.TunIP != tunClientIP {
			t.Errorf("tun_ip = %q, 期望 %q", snap.TunIP, tunClientIP)
		}
	})

	t.Run("错误 token 被拒绝", func(t *testing.T) {
		for _, path := range []string{"/api/status?t=wrong", "/api/status"} {
			res, err := http.Get(base + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			res.Body.Close()
			if res.StatusCode != http.StatusForbidden {
				t.Errorf("GET %s = %d, 期望 403", path, res.StatusCode)
			}
		}
	})

	t.Run("连接接口拒绝非法地址", func(t *testing.T) {
		res, err := http.Post(base+"/api/connect?t="+token, "application/json",
			strings.NewReader(`{"addr":""}`))
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("空地址 = %d, 期望 400", res.StatusCode)
		}
	})

	t.Run("GET 不能触发连接", func(t *testing.T) {
		res, err := http.Get(base + "/api/connect?t=" + token)
		if err != nil {
			t.Fatalf("connect via GET: %v", err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("GET /api/connect = %d, 期望 403（写操作必须是 POST）", res.StatusCode)
		}
	})
}

// eligible 是防止把隧道自身流量或本机流量导进 TUN 的唯一守卫。
func TestRouteEligibility(t *testing.T) {
	relay := "203.0.113.9"
	m := newRouteManager(relay, func(string, ...any) {})

	rejected := []string{
		relay,       // 中转机自己：会形成隧道环路
		tunServerIP, // 隧道网段
		tunClientIP,
		"127.0.0.1",
		"10.1.2.3",
		"192.168.1.1",
		"172.16.0.1",
		"224.0.0.1",
		"169.254.1.1",
		"0.0.0.0",
		"255.255.255.255",
		"2001:db8::1", // 仅支持 IPv4
		"",
		"不是地址",
	}
	for _, ip := range rejected {
		if m.eligible(ip) {
			t.Errorf("eligible(%q) = true, 期望被拒绝", ip)
		}
	}

	for _, ip := range []string{"111.29.236.135", "8.8.8.8", "203.0.113.10"} {
		if !m.eligible(ip) {
			t.Errorf("eligible(%q) = false, 期望允许（公网单播）", ip)
		}
	}
}
