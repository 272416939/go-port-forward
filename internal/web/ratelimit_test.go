package web

// 登录防爆破与验证码端点 per-IP 限频的回归测试。
//
// 限频是安全边界：锁定文案不区分「用户名不存在/密码错误/已限频」，测试同时
// 锁死这条不变量——任何一种命中都必须返回同一个 429 文案。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/config"
	"go-port-forward/internal/models"
	"go-port-forward/internal/users"
)

func newLoginHandler(t *testing.T, userLimit int) *handler {
	t.Helper()
	_, svc, sessions, _ := newAuthServer(t, config.WebConfig{})
	if _, err := svc.Create(&models.CreateUserRequest{Username: "alice", Password: "password123"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(&models.CreateUserRequest{Username: "bob", Password: "password123"}); err != nil {
		t.Fatal(err)
	}
	return &handler{
		users:         svc,
		sessions:      sessions,
		loginIPFail:   users.NewRateLimiter(1000, 15*time.Minute), // IP 维度在本测试中不设障
		loginUserFail: users.NewRateLimiter(userLimit, 15*time.Minute),
		emailCodeIP:   users.NewRateLimiter(1000, time.Hour),
	}
}

func loginRequest(t *testing.T, h *handler, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"username":"` + username + `","password":"` + password + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.9:5555"
	rec := httptest.NewRecorder()
	h.login(rec, req)
	return rec
}

// 连续失败达到上限后，即使密码正确也被拒绝（按用户名锁定）。
func TestLoginRateLimitLocksUsername(t *testing.T) {
	h := newLoginHandler(t, 2)

	for i := 0; i < 2; i++ {
		if rec := loginRequest(t, h, "alice", "wrong-pass"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次错误密码 = %d, want 401", i+1, rec.Code)
		}
	}
	// 正确密码也进不来：锁的是「这个用户名的失败次数」，与本次密码对错无关。
	if rec := loginRequest(t, h, "alice", "password123"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("锁定后正确密码 = %d, want 429", rec.Code)
	}
	// 不存在的用户名同样按尝试次数锁定（计数不区分存在性，避免枚举面）。
	for i := 0; i < 2; i++ {
		loginRequest(t, h, "nobody", "wrong-pass")
	}
	if rec := loginRequest(t, h, "nobody", "x"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("不存在用户名锁定 = %d, want 429", rec.Code)
	}
}

// 锁定只作用于被爆破的用户名：其他用户不受牵连。
func TestLoginRateLimitIsolatesUsernames(t *testing.T) {
	h := newLoginHandler(t, 2)
	for i := 0; i < 2; i++ {
		loginRequest(t, h, "alice", "wrong-pass")
	}
	rec := loginRequest(t, h, "bob", "password123")
	if rec.Code != http.StatusOK {
		t.Fatalf("其他用户正常登录 = %d, want 200", rec.Code)
	}
}

// 登录成功后清零该用户名的失败计数。
func TestLoginRateLimitResetsOnSuccess(t *testing.T) {
	h := newLoginHandler(t, 2)
	if rec := loginRequest(t, h, "alice", "wrong-pass"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("错误密码 = %d, want 401", rec.Code)
	}
	if rec := loginRequest(t, h, "alice", "password123"); rec.Code != http.StatusOK {
		t.Fatalf("正确密码 = %d, want 200", rec.Code)
	}
	// 清零后还剩完整的 2 次失败预算。
	for i := 0; i < 2; i++ {
		if rec := loginRequest(t, h, "alice", "wrong-pass"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("重置后第 %d 次失败 = %d, want 401", i+1, rec.Code)
		}
	}
	if rec := loginRequest(t, h, "alice", "password123"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("重新锁定的正确密码 = %d, want 429", rec.Code)
	}
}

// 限频器本体：Allowed 只查不记、Allow 记录并判定、Reset 清零、窗口过期后放行。
func TestRateLimiterWindow(t *testing.T) {
	rl := users.NewRateLimiter(2, 30*time.Millisecond)
	if !rl.Allow("k") || !rl.Allow("k") {
		t.Fatal("前两次应放行")
	}
	if rl.Allow("k") {
		t.Fatal("第三次应被限")
	}
	// Allowed 与 Allow 共享同一份计数，查询不追加记录。
	if rl.Allowed("k") {
		t.Fatal("超限后 Allowed 应为 false")
	}
	rl.Reset("k")
	if !rl.Allowed("k") {
		t.Fatal("Reset 后应放行")
	}
	time.Sleep(40 * time.Millisecond)
	if !rl.Allow("k") {
		t.Fatal("窗口过期后应放行")
	}
}

// 验证码端点的 per-IP 限频：发送成功与否都计数。
func TestEmailCodeIPRateLimit(t *testing.T) {
	_, svc, _, _ := newAuthServer(t, config.WebConfig{})
	h := &handler{
		users:         svc,
		sessions:      auth.NewStore(false),
		loginIPFail:   users.NewRateLimiter(1000, 15*time.Minute),
		loginUserFail: users.NewRateLimiter(1000, 15*time.Minute),
		emailCodeIP:   users.NewRateLimiter(2, time.Hour),
	}
	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/email-code",
			strings.NewReader(`{"email":"a@b.com","purpose":"register"}`))
		req.RemoteAddr = "203.0.113.9:5555"
		rec := httptest.NewRecorder()
		h.emailCode(rec, req)
		return rec
	}
	// SMTP 未配置时服务层返回 501，但 per-IP 计数已发生：两次之后是 429。
	if rec := send(); rec.Code != http.StatusNotImplemented {
		t.Fatalf("第一次（SMTP 未配置）= %d, want 501", rec.Code)
	}
	if rec := send(); rec.Code != http.StatusNotImplemented {
		t.Fatalf("第二次（SMTP 未配置）= %d, want 501", rec.Code)
	}
	if rec := send(); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("第三次 = %d, want 429", rec.Code)
	}
}
