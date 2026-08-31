package web

// 注册 / 找回密码 / SMTP 端点的行为测试。
//
// 公开端点的纪律：能不返回的字段绝不返回、语义相同的失败返回语义相同的
// 响应（防枚举）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-port-forward/internal/email"
	"go-port-forward/internal/models"
	"go-port-forward/pkg/emailtest"
)

// 打开注册 + 注入可控验证码服务。
func (f *tenantFixture) openRegistration(t *testing.T) {
	t.Helper()
	yes := true
	if _, err := f.svc.UpdateSettings(&models.UpdateSettingsRequest{EnableRegistration: &yes}); err != nil {
		t.Fatal(err)
	}
	// 测试验证码：任何签发的码都是固定值（emailtest 包的确定性实现）。
	f.svc.SetVerifier(emailtest.NewFixed())
}

// public-config 只暴露两个布尔：多一个字段都是给探测者递信息。
func TestPublicConfigMinimal(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	rec := httptest.NewRecorder()
	f.h.publicConfig(rec, httptest.NewRequest(http.MethodGet, "/api/auth/public-config", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 2 {
		t.Fatalf("public-config 只应有两个字段：%v", resp.Data)
	}
	if resp.Data["registration_open"] != false || resp.Data["email_ready"] != false {
		t.Fatalf("默认状态错误：%v", resp.Data)
	}
}

// 注册开关关闭时注册被 403 拒绝；打开后成功并落入默认组。
func TestRegisterGate(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	body := `{"username":"newbie","password":"password123"}`
	rec := httptest.NewRecorder()
	f.h.register(rec, postJSON("/api/auth/register", body, nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("开关关闭时 status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}

	f.openRegistration(t)
	rec = httptest.NewRecorder()
	f.h.register(rec, postJSON("/api/auth/register", body, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	// 新用户在默认组里（从用户列表核对）。
	rec = httptest.NewRecorder()
	f.h.listUsers(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/users", nil), f.admin))
	if !strings.Contains(rec.Body.String(), `"username":"newbie"`) {
		t.Fatalf("注册的用户未出现：%s", rec.Body.String())
	}
}

// SMTP 配置后注册必须带验证码；验证码正确则成功。
func TestRegisterRequiresCodeWhenSMTPReady(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	f.openRegistration(t)
	// 配置 SMTP（email_ready = true）。
	if _, err := f.svc.UpdateSMTP(&models.UpdateSMTPRequest{
		Host: strptr("smtp.x.com"), Port: intptr(587), From: strptr("n@x.com"),
	}); err != nil {
		t.Fatal(err)
	}

	body := `{"username":"webuser","password":"password123","email":"a@x.com"}`
	rec := httptest.NewRecorder()
	f.h.register(rec, postJSON("/api/auth/register", body, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺验证码应被拒，status = %d, body=%s", rec.Code, rec.Body.String())
	}

	// 发码（发往固定码实现）→ 注册成功。
	rec = httptest.NewRecorder()
	f.h.emailCode(rec, postJSON("/api/auth/email-code", `{"email":"a@x.com","purpose":"register"}`, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("发码失败：%s", rec.Body.String())
	}
	body = `{"username":"webuser","password":"password123","email":"a@x.com","code":"654321"}`
	rec = httptest.NewRecorder()
	f.h.register(rec, postJSON("/api/auth/register", body, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

// /api/smtp 的响应里绝不能有密码字段；更新时密码留空保留原值。
func TestSMTPPasswordNeverEchoed(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	// 配置带密码。
	req := postJSON("/api/smtp", `{"host":"smtp.x.com","port":587,"from":"n@x.com","password":"s3cret"}`, f.admin)
	rec := httptest.NewRecorder()
	f.h.updateSMTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "s3cret") {
		t.Fatalf("更新响应泄漏了密码：%s", rec.Body.String())
	}

	// 查询响应同样无密码。
	rec = httptest.NewRecorder()
	f.h.getSMTP(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/smtp", nil), f.admin))
	body := rec.Body.String()
	if strings.Contains(body, "s3cret") || strings.Contains(body, `"password"`) {
		t.Fatalf("查询响应泄漏了密码：%s", body)
	}
	if !strings.Contains(body, `"has_password":true`) {
		t.Fatalf("应返回 has_password 标记：%s", body)
	}

	// 更新时密码留空 = 保留原值（不覆盖为空）。
	rec = httptest.NewRecorder()
	f.h.updateSMTP(rec, postJSON("/api/smtp", `{"host":"smtp.y.com","port":587,"from":"n@x.com","password":""}`, f.admin))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	cfg, err := f.svc.SMTPConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "s3cret" || cfg.Host != "smtp.y.com" {
		t.Fatalf("密码保留语义失效：%+v", cfg)
	}
}

// SMTP 端点的 adminOnly 包装行为由 middleware_auth_test 的放行矩阵覆盖
// （直接调 handler 方法不经过路由上的包装，这里无法测 403/401）。

// /api/settings 必须带回 smtp_configured 字段：设置弹窗的「已配置」徽章由
// 它驱动（曾因前端读了不存在的 _smtp_configured 而永远显示未配置——字段名
// 前后端各写一份，这里把后端的名字钉住）。
func TestSettingsCarriesSMTPConfigured(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	rec := httptest.NewRecorder()
	f.h.getSettings(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/settings", nil), f.admin))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"smtp_configured":true`) {
		t.Fatalf("未配置 SMTP 时不应为 true：%s", rec.Body.String())
	}

	if _, err := f.svc.UpdateSMTP(&models.UpdateSMTPRequest{
		Host: strptr("smtp.x.com"), Port: intptr(587), From: strptr("n@x.com"),
	}); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	f.h.getSettings(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/settings", nil), f.admin))
	if !strings.Contains(rec.Body.String(), `"smtp_configured":true`) {
		t.Fatalf("配置后应返回 smtp_configured=true：%s", rec.Body.String())
	}
}

// 发信失败 / 验证码限频必须按语义映射（503/429），不能兜底成 500——
// 那会把「邮件服务暂时不可用」显示成「服务器内部错误」。
func TestWritePublicErrorEmailMapping(t *testing.T) {
	rec := httptest.NewRecorder()
	writePublicError(rec, fmt.Errorf("%w: dial tcp: refused", email.ErrSendFailed))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("发送失败应映射 503，got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	writePublicError(rec, fmt.Errorf("%w: 请 1 分钟后再试", email.ErrCodeRateLimited))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("验证码限频应映射 429，got %d", rec.Code)
	}
}

func strptr(s string) *string { return &s }
func intptr(i int) *int       { return &i }

// 绑定/更换邮箱：登录态 + 当前密码 + purpose=bind 验证码三重前置；
// 重复邮箱按防枚举纪律脱敏；bind 的码不得跨用途使用。
func TestBindEmailFlow(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	if _, err := f.svc.UpdateSMTP(&models.UpdateSMTPRequest{
		Host: strptr("smtp.x.com"), Port: intptr(587), From: strptr("n@x.com"),
	}); err != nil {
		t.Fatal(err)
	}
	f.svc.SetVerifier(emailtest.NewFixed())

	// 未登录 → 401。
	rec := httptest.NewRecorder()
	f.h.bindEmail(rec, postJSON("/api/account/email", `{"email":"a@x.com","code":"654321","password":"password123"}`, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未登录应 401，got %d", rec.Code)
	}
	// 发码端点同样要登录态。
	rec = httptest.NewRecorder()
	f.h.bindEmailCode(rec, postJSON("/api/account/email-code", `{"email":"a@x.com"}`, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("发码未登录应 401，got %d", rec.Code)
	}

	// 当前密码错误 → 401。
	rec = httptest.NewRecorder()
	f.h.bindEmail(rec, postJSON("/api/account/email", `{"email":"a@x.com","code":"654321","password":"wrong-pass"}`, f.alice))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("密码错误应 401，got %d body=%s", rec.Code, rec.Body.String())
	}

	// 登录态发码 → 固定码生效（SendBindEmailCode 会规范化邮箱）。
	rec = httptest.NewRecorder()
	f.h.bindEmailCode(rec, postJSON("/api/account/email-code", `{"email":"Alice@X.com"}`, f.alice))
	if rec.Code != http.StatusOK {
		t.Fatalf("发码应成功，got %d body=%s", rec.Code, rec.Body.String())
	}

	// 正确密码 + 固定验证码 → 绑定成功，me 回显 email。
	rec = httptest.NewRecorder()
	f.h.bindEmail(rec, postJSON("/api/account/email", `{"email":"Alice@X.com","code":"654321","password":"password123"}`, f.alice))
	if rec.Code != http.StatusOK {
		t.Fatalf("绑定应成功，got %d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	f.h.me(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/auth/me", nil), f.alice))
	if !strings.Contains(rec.Body.String(), `"email":"alice@x.com"`) {
		t.Fatalf("me 应带回规范化后的 email：%s", rec.Body.String())
	}

	// bob 重新发码后再绑同一邮箱：验证码通过，卡在唯一性 → 400 且文案脱敏
	// （不出现「已注册」语义）。
	rec = httptest.NewRecorder()
	f.h.bindEmailCode(rec, postJSON("/api/account/email-code", `{"email":"alice@x.com"}`, f.bob))
	if rec.Code != http.StatusOK {
		t.Fatalf("bob 发码应成功，got %d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	f.h.bindEmail(rec, postJSON("/api/account/email", `{"email":"alice@x.com","code":"654321","password":"password123"}`, f.bob))
	if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "already") {
		t.Fatalf("重复邮箱应 400 脱敏：got %d body=%s", rec.Code, rec.Body.String())
	}

	// purpose 隔离：bind 签发的码不能用于找回密码（reset 键下没有条目）。
	rec = httptest.NewRecorder()
	f.h.forgotPassword(rec, postJSON("/api/auth/forgot-password", `{"email":"alice@x.com","code":"654321","new_password":"newpass123"}`, nil))
	if rec.Code == http.StatusOK {
		t.Fatal("bind 验证码不得用于重置密码")
	}
}
