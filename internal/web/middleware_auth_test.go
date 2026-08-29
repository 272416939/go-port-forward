package web

// 认证中间件的放行矩阵。
//
// 这一层决定「谁能进到 handler」，与 tenant_test.go 的「进来之后能看到什么」
// 互补。两者都不能少：中间件放错人，handler 里的作用域判定就成了唯一防线。

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/config"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
	"go-port-forward/internal/users"

	"go.uber.org/zap"
)

func newAuthServer(t *testing.T, cfg config.WebConfig) (*Server, *users.Service, *auth.Store, storage.Store) {
	t.Helper()
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	store, err := storage.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	sessions := auth.NewStore(false)
	svc, err := users.New(store, sessions, "10.66.0.1/24", "203.0.113.9:7947")
	if err != nil {
		t.Fatal(err)
	}
	return &Server{cfg: cfg, users: svc, sessions: sessions}, svc, sessions, store
}

func okHandler(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(me.Username))
}

func TestAuthedRejectsAnonymous(t *testing.T) {
	srv, _, _, _ := newAuthServer(t, config.WebConfig{})
	rec := httptest.NewRecorder()
	srv.authed(okHandler)(rec, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAuthedAcceptsSessionCookie(t *testing.T) {
	srv, svc, sessions, _ := newAuthServer(t, config.WebConfig{})
	u, err := svc.Create(&models.CreateUserRequest{Username: "alice", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := sessions.Issue(u.ID)

	req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rec := httptest.NewRecorder()
	srv.authed(okHandler)(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "alice" {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
}

// 用户被删除后，残留的会话不能继续放行。
func TestAuthedRejectsSessionOfDeletedUser(t *testing.T) {
	srv, svc, sessions, store := newAuthServer(t, config.WebConfig{})
	if _, err := svc.Create(&models.CreateUserRequest{Username: "admin", Password: "password123", Role: models.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	u, err := svc.Create(&models.CreateUserRequest{Username: "alice", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := sessions.Issue(u.ID)
	// 直接经 store 删除，绕过 Service.Delete（它会主动注销会话），
	// 模拟「会话表与用户表不一致」这个中间件必须自己兜住的状态。
	if err := store.DeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rec := httptest.NewRecorder()
	srv.authed(okHandler)(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	// 无效会话应被顺手清掉，避免每次请求都白查一次库。
	if _, ok := sessions.Lookup(token); ok {
		t.Fatal("失效会话未被清理")
	}
}

func TestAdminOnlyBlocksRegularUser(t *testing.T) {
	srv, svc, sessions, _ := newAuthServer(t, config.WebConfig{})
	if _, err := svc.Create(&models.CreateUserRequest{Username: "admin", Password: "password123", Role: models.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	alice, err := svc.Create(&models.CreateUserRequest{Username: "alice", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := sessions.Issue(alice.ID)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rec := httptest.NewRecorder()
	srv.adminOnly(okHandler)(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("普通用户访问管理端点 = %d, want 403", rec.Code)
	}
}

func TestAdminOnlyAllowsAdmin(t *testing.T) {
	srv, svc, sessions, _ := newAuthServer(t, config.WebConfig{})
	admin, err := svc.Create(&models.CreateUserRequest{Username: "admin", Password: "password123", Role: models.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := sessions.Issue(admin.ID)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rec := httptest.NewRecorder()
	srv.adminOnly(okHandler)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("管理员访问管理端点 = %d, want 200", rec.Code)
	}
}

// 应急后门只在回环访问时生效。它是一对明文存在配置文件里的凭据，一旦对公网
// 生效就是整个多租户体系上的一个洞。
func TestRescueAccountIsLoopbackOnly(t *testing.T) {
	srv, _, _, _ := newAuthServer(t, config.WebConfig{Username: "root", Password: "s3cret"})

	local := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	local.RemoteAddr = "127.0.0.1:5555"
	local.SetBasicAuth("root", "s3cret")
	rec := httptest.NewRecorder()
	srv.authed(okHandler)(rec, local)
	if rec.Code != http.StatusOK {
		t.Fatalf("回环 + 正确凭据 = %d, want 200", rec.Code)
	}

	remote := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	remote.RemoteAddr = "203.0.113.9:5555"
	remote.SetBasicAuth("root", "s3cret")
	rec = httptest.NewRecorder()
	srv.authed(okHandler)(rec, remote)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("远端 + 正确凭据 = %d, want 401（后门必须限本机）", rec.Code)
	}

	wrong := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	wrong.RemoteAddr = "127.0.0.1:5555"
	wrong.SetBasicAuth("root", "wrong")
	rec = httptest.NewRecorder()
	srv.authed(okHandler)(rec, wrong)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("回环 + 错误密码 = %d, want 401", rec.Code)
	}
}

// 未配置后门凭据时，任何 Basic Auth 都不该放行。
func TestRescueDisabledWhenUnconfigured(t *testing.T) {
	srv, _, _, _ := newAuthServer(t, config.WebConfig{})
	req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	req.SetBasicAuth("root", "")
	rec := httptest.NewRecorder()
	srv.authed(okHandler)(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// 跨站写请求必须被拒。SameSite=Strict 已经让浏览器不带 cookie，Origin 校验是
// 兜住浏览器差异的第二道。
func TestCheckOriginRejectsCrossSiteWrites(t *testing.T) {
	srv, svc, sessions, _ := newAuthServer(t, config.WebConfig{})
	u, err := svc.Create(&models.CreateUserRequest{Username: "alice", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := sessions.Issue(u.ID)

	req := httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(`{}`))
	req.Host = "panel.example.com"
	req.Header.Set("Origin", "https://evil.example.com")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rec := httptest.NewRecorder()
	srv.authed(okHandler)(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("跨站写请求 = %d, want 403", rec.Code)
	}
}

func TestCheckOriginAllowsSameSiteAndNoOrigin(t *testing.T) {
	cases := []struct {
		name   string
		method string
		host   string
		origin string
		want   bool
	}{
		{"GET 免校验", http.MethodGet, "panel.example.com", "https://evil.example.com", true},
		{"同源写", http.MethodPost, "panel.example.com", "https://panel.example.com", true},
		{"带端口同源", http.MethodPost, "panel.example.com:8989", "http://panel.example.com:8989", true},
		// 非浏览器客户端（curl、脚本）不带这些头，拒绝它们只会打断自动化用法。
		{"无 Origin 的写", http.MethodPost, "panel.example.com", "", true},
		{"跨站写", http.MethodPost, "panel.example.com", "https://evil.example.com", false},
		{"跨端口写", http.MethodPost, "panel.example.com:8989", "http://panel.example.com:9999", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "/api/rules", nil)
		req.Host = c.host
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		if got := checkOrigin(req); got != c.want {
			t.Errorf("%s: checkOrigin = %v, want %v", c.name, got, c.want)
		}
	}
}

// Referer 兜底：部分老浏览器在同站 POST 上只发 Referer 不发 Origin。
func TestCheckOriginFallsBackToReferer(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/rules", nil)
	req.Host = "panel.example.com"
	req.Header.Set("Referer", "https://panel.example.com/index.html")
	if !checkOrigin(req) {
		t.Fatal("同站 Referer 应放行")
	}
	req.Header.Set("Referer", "https://evil.example.com/x")
	if checkOrigin(req) {
		t.Fatal("跨站 Referer 应被拒")
	}
}

// 停用的用户即便持有有效会话也不能进（会话通常已被注销，这是第二道）。
func TestAuthedRejectsDisabledUser(t *testing.T) {
	srv, svc, sessions, store := newAuthServer(t, config.WebConfig{})
	if _, err := svc.Create(&models.CreateUserRequest{Username: "admin", Password: "password123", Role: models.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	u, err := svc.Create(&models.CreateUserRequest{Username: "alice", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := sessions.Issue(u.ID)
	u.Disabled = true
	if err := store.SaveUser(u); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rec := httptest.NewRecorder()
	srv.authed(okHandler)(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("停用用户 = %d, want 401", rec.Code)
	}
}
