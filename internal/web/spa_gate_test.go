package web

// SPA 入口网关的测试：未登录访客必须被 302 到登录页，而不是短暂渲染面板
// 骨架后靠 JS 跳转。

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go-port-forward/internal/auth"
)

func stubSPA(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("panel-shell"))
}

func TestSPAGateRedirectsAnonymous(t *testing.T) {
	gate := (&Server{}).spaGate(http.HandlerFunc(stubSPA))

	for _, path := range []string{"/", "/index.html"} {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("GET %s 无凭据 = %d, want 302", path, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/login.html" {
			t.Fatalf("重定向目标 = %q, want /login.html", loc)
		}
	}
}

// 带会话 cookie（哪怕已过期——有效性由 API 层校验）或 Basic Auth 头的请求
// 必须放行：后者是应急后门的用法。
func TestSPAGateAllowsCredentialed(t *testing.T) {
	gate := (&Server{}).spaGate(http.HandlerFunc(stubSPA))

	withCookie := httptest.NewRequest(http.MethodGet, "/", nil)
	withCookie.AddCookie(&http.Cookie{Name: auth.CookieName, Value: "whatever"})
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, withCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("带 cookie = %d, want 200", rec.Code)
	}

	withAuth := httptest.NewRequest(http.MethodGet, "/", nil)
	withAuth.SetBasicAuth("root", "x")
	rec = httptest.NewRecorder()
	gate.ServeHTTP(rec, withAuth)
	if rec.Code != http.StatusOK {
		t.Fatalf("带 Authorization = %d, want 200", rec.Code)
	}
}

// 其余静态资源保持公开（login.html 自身、css/js、图标），否则登录页加载不出来。
func TestSPAGateAllowsOtherAssets(t *testing.T) {
	gate := (&Server{}).spaGate(http.HandlerFunc(stubSPA))

	for _, path := range []string{"/login.html", "/css/app.css", "/js/app.js", "/images/logo.png"} {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200（静态资源保持公开）", path, rec.Code)
		}
	}

	// POST / 不拦（非 SPA 入口场景）。
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST / = %d, want 200", rec.Code)
	}
}
