package users

// 注册 / 找回密码 / 验证码集成的测试。

import (
	"errors"
	"testing"

	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
)

// fakeMailer（service_test.go 已有一个 fakeEvictor；邮件这边独立一个）。
type fakeMailer struct {
	sent int
	err  error
}

func (f *fakeMailer) Send(to, subject, body string) error {
	if f.err != nil {
		return f.err
	}
	f.sent++
	return nil
}

func newRegService(t *testing.T) (*fixture, *fakeMailer) {
	t.Helper()
	f := newService(t)
	m := &fakeMailer{}
	f.svc.SetMailer(m)
	return f, m
}

func (f *fixture) enableRegistration(t *testing.T) {
	t.Helper()
	yes := true
	if _, err := f.svc.UpdateSettings(&models.UpdateSettingsRequest{EnableRegistration: &yes}); err != nil {
		t.Fatal(err)
	}
}

// 注册开关默认关闭：fail-closed。注册是把创建账号的权力交给公网，
// 「未配置即开放」等于把门拆了。
func TestRegisterClosedByDefault(t *testing.T) {
	f, _ := newRegService(t)
	_, err := f.svc.Register(RegisterInput{Username: "alice", Password: "password123", IP: "1.2.3.4"})
	if !errors.Is(err, ErrRegistrationClosed) {
		t.Fatalf("默认应拒绝注册，得到 %v", err)
	}
}

// 注册成功：落入默认组、角色 user、启用状态。
func TestRegisterSuccess(t *testing.T) {
	f, _ := newRegService(t)
	f.enableRegistration(t)

	u, err := f.svc.Register(RegisterInput{Username: "alice", Password: "password123", IP: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if u.GroupID != f.cfg.DefaultGroupID {
		t.Fatalf("注册用户应落入默认组：%q", u.GroupID)
	}
	if u.Role != models.RoleUser || u.Disabled {
		t.Fatalf("角色/状态不符：%+v", u)
	}
	if _, err := f.svc.Authenticate("alice", "password123"); err != nil {
		t.Fatalf("注册后应可登录：%v", err)
	}
}

// 重名注册被拒（与手动建用户同一套查重）。
func TestRegisterDuplicateRejected(t *testing.T) {
	f, _ := newRegService(t)
	f.enableRegistration(t)
	if _, err := f.svc.Register(RegisterInput{Username: "alice", Password: "password123", IP: "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Register(RegisterInput{Username: "alice", Password: "password123", IP: "5.6.7.8"}); !errors.Is(err, storage.ErrUserExists) {
		t.Fatalf("重名应被拒，得到 %v", err)
	}
}

// SMTP 未配置时注册可无邮箱；配置后必须邮箱 + 验证码。
func TestRegisterEmailRequiredWhenSMTPConfigured(t *testing.T) {
	f, m := newRegService(t)
	f.enableRegistration(t)

	// 未配置 SMTP：直接注册成功（不收集未验证的邮箱）。
	if _, err := f.svc.Register(RegisterInput{Username: "alice", Password: "password123", Email: "a@x.com", IP: "1.2.3.4"}); err != nil {
		t.Fatalf("未配置 SMTP 时应可无邮箱注册：%v", err)
	}

	// 配置 SMTP：缺验证码被拒。
	if _, err := f.svc.UpdateSMTP(&models.UpdateSMTPRequest{
		Host: ptr("smtp.x.com"), Port: ptrInt(587), From: ptr("noreply@x.com"), Password: ptr("pw"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Register(RegisterInput{Username: "bob", Password: "password123", IP: "1.2.3.4"}); err == nil {
		t.Fatal("配置 SMTP 后缺邮箱必须被拒")
	}
	if _, err := f.svc.Register(RegisterInput{Username: "bob", Password: "password123", Email: "b@x.com", IP: "1.2.3.4"}); err == nil {
		t.Fatal("配置 SMTP 后缺验证码必须被拒")
	}

	// 发码 + 注册成功。
	if err := f.svc.SendEmailCode("b@x.com", models.PurposeRegister); err != nil {
		t.Fatal(err)
	}
	if m.sent == 0 {
		t.Fatal("应已发送验证码邮件")
	}
}

// 验证码真实验证路径：从服务拿码（测试里从 verifier 的内部结构取不到，
// 通过 fake Mailer 记录的正文不行——这里用 Issue 后直接调 Verify 的组合）。
func TestRegisterWithCode(t *testing.T) {
	f, m := newRegService(t)
	f.enableRegistration(t)
	if _, err := f.svc.UpdateSMTP(&models.UpdateSMTPRequest{
		Host: ptr("smtp.x.com"), Port: ptrInt(587), From: ptr("noreply@x.com"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.SendEmailCode("b@x.com", models.PurposeRegister); err != nil {
		t.Fatal(err)
	}
	if m.sent != 1 {
		t.Fatalf("发码次数 = %d", m.sent)
	}
	fake := &fakeCodes{}
	f.svc.verifier = fake
	_ = f.svc.verifier.Issue("b@x.com", models.PurposeRegister)

	if _, err := f.svc.Register(RegisterInput{
		Username: "bob", Password: "password123", Email: "B@X.com ", Code: fakeCodesValue, IP: "1.2.3.4",
	}); err != nil {
		t.Fatalf("带正确验证码应注册成功：%v", err)
	}
	// 验证码已被消费，第二次注册不能再用。
	if _, err := f.svc.Register(RegisterInput{
		Username: "carol", Password: "password123", Email: "b@x.com", Code: fakeCodesValue, IP: "1.2.3.4",
	}); err == nil {
		t.Fatal("验证码不得重复使用")
	}
}

// 注册 IP 限频：SMTP 未配置时它是唯一防线。
func TestRegisterRateLimit(t *testing.T) {
	f, _ := newRegService(t)
	f.enableRegistration(t)

	for i := 0; i < RegistrationRateLimit; i++ {
		if _, err := f.svc.Register(RegisterInput{
			Username: "user" + itoa(i), Password: "password123", IP: "9.9.9.9",
		}); err != nil {
			t.Fatalf("第 %d 次注册不应被限频：%v", i+1, err)
		}
	}
	if _, err := f.svc.Register(RegisterInput{Username: "overflow", Password: "password123", IP: "9.9.9.9"}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("超出 IP 限频应被拒，得到 %v", err)
	}
	// 其它 IP 不受影响。
	if _, err := f.svc.Register(RegisterInput{Username: "elsewhere", Password: "password123", IP: "8.8.8.8"}); err != nil {
		t.Fatalf("限频应按 IP 隔离：%v", err)
	}
}

// 找回密码：验证码正确则重置并踢会话；错误则拒绝。
func TestResetPasswordWithCode(t *testing.T) {
	f, _ := newRegService(t)
	f.enableRegistration(t)
	if _, err := f.svc.UpdateSMTP(&models.UpdateSMTPRequest{
		Host: ptr("smtp.x.com"), Port: ptrInt(587), From: ptr("noreply@x.com"),
	}); err != nil {
		t.Fatal(err)
	}

	// 预置一个带邮箱的用户。
	u, err := f.svc.Create(&models.CreateUserRequest{Username: "alice", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	u.Email = "alice@x.com"
	if err := f.store.SaveUser(u); err != nil {
		t.Fatal(err)
	}
	sessions := f.sessions
	token, _ := sessions.Issue(u.ID)

	if err := f.svc.SendEmailCode("alice@x.com", models.PurposeReset); err != nil {
		t.Fatal(err)
	}
	fake := &fakeCodes{}
	f.svc.verifier = fake
	_ = f.svc.verifier.Issue("alice@x.com", models.PurposeReset)

	if err := f.svc.ResetPasswordWithCode("Alice@X.com", fakeCodesValue, "newpassword456"); err != nil {
		t.Fatalf("重置应成功：%v", err)
	}
	if _, ok := sessions.Lookup(token); ok {
		t.Fatal("重置后旧会话应失效")
	}
	if _, err := f.svc.Authenticate("alice", "newpassword456"); err != nil {
		t.Fatalf("新密码应可登录：%v", err)
	}
}

// SendEmailCode 对未注册邮箱静默成功（防枚举），ResetPasswordWithCode 拒绝。
func TestResetPasswordUnknownEmail(t *testing.T) {
	f, m := newRegService(t)
	f.enableRegistration(t)
	if _, err := f.svc.UpdateSMTP(&models.UpdateSMTPRequest{
		Host: ptr("smtp.x.com"), Port: ptrInt(587), From: ptr("noreply@x.com"),
	}); err != nil {
		t.Fatal(err)
	}

	// 发码：未注册邮箱不报错也不发信（防「邮箱是否注册」探测）。
	if err := f.svc.SendEmailCode("ghost@x.com", models.PurposeReset); err != nil {
		t.Fatalf("未注册邮箱的发码应静默成功：%v", err)
	}
	if m.sent != 0 {
		t.Fatal("未注册邮箱不应真的发信")
	}

	// 重置：验证码不存在，必须失败。
	if err := f.svc.ResetPasswordWithCode("ghost@x.com", "123456", "newpassword456"); err == nil {
		t.Fatal("未注册邮箱的重置应失败")
	}
}

// 配额用量：访问码数、规则数（隧道数依赖隧道服务，fakeEvictor 的在线表覆盖）。
func TestQuotaUsage(t *testing.T) {
	f, _ := newRegService(t)
	u := f.mustUser(t, "alice", models.RoleUser, "")
	c1 := f.mustCode(t, u, "a")
	f.mustCode(t, u, "b")
	f.evictor.online[c1.ID] = true

	f.svc.SetRulesCounter(func(userID string) int {
		if userID == u.ID {
			return 3
		}
		return 0
	})

	used, err := f.svc.QuotaUsage(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if used.AccessCodes != 2 || used.Tunnels != 1 || used.Rules != 3 {
		t.Fatalf("用量不符：%+v", used)
	}

	// FillQuotaUsage 把用量并进配额视图。
	q, err := f.svc.EffectiveQuota(u)
	if err != nil {
		t.Fatal(err)
	}
	filled, err := f.svc.FillQuotaUsage(u.ID, q)
	if err != nil {
		t.Fatal(err)
	}
	if filled.Used.AccessCodes != 2 {
		t.Fatalf("Filled 配额缺用量：%+v", filled)
	}
}

// 管理员建用户时邮箱也可绑定（可选），登录页自助注册与它共享查重。
func TestCreateUserWithEmail(t *testing.T) {
	f, _ := newRegService(t)
	u, err := f.svc.Create(&models.CreateUserRequest{Username: "alice", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	u.Email = "Alice@X.com"
	if err := f.store.SaveUser(u); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.GetByEmail("alice@x.com")
	if err != nil {
		t.Fatalf("按邮箱查用户（不分大小写）失败：%v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("id = %s", got.ID)
	}
}

// UpdateSMTP 的密码保留语义：留空 = 保留原值，这是「密码永不回显」后面板
// 能正常工作的前提。
func TestUpdateSMTPKeepsPassword(t *testing.T) {
	f, _ := newRegService(t)
	if _, err := f.svc.UpdateSMTP(&models.UpdateSMTPRequest{
		Host: ptr("smtp.x.com"), Port: ptrInt(587), From: ptr("n@x.com"), Password: ptr("secret"),
	}); err != nil {
		t.Fatal(err)
	}
	// 只改 host，密码留空：原密码必须还在。
	cfg, err := f.svc.UpdateSMTP(&models.UpdateSMTPRequest{Host: ptr("smtp.y.com")})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "secret" {
		t.Fatalf("密码被清掉了：%q", cfg.Password)
	}
	if cfg.Host != "smtp.y.com" {
		t.Fatalf("host 未更新：%q", cfg.Host)
	}
	// API 视图永不携带密码（SMTPView 上根本没有 Password 字段，编译期就锁住）。
	v := cfg.View()
	if !v.HasPassword {
		t.Fatalf("视图缺 has_password：%+v", v)
	}
	// host 清空 = 整体停用。
	cfg, err = f.svc.UpdateSMTP(&models.UpdateSMTPRequest{Host: ptr("")})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Configured() {
		t.Fatal("清空后应为未配置状态")
	}
}

// fakeCodes 是 CodeIssuer 的确定性替身：任何签发的验证码都是 fakeCodesValue。
// 真实现（email.VerificationService）的安全语义（限频/过期/防爆破）由
// internal/email 自己的测试覆盖，这里只关心 users 层的编排。
type fakeCodes struct{ used map[string]bool }

const fakeCodesValue = "654321"

func (f *fakeCodes) Issue(email, purpose string) error {
	if f.used == nil {
		f.used = map[string]bool{}
	}
	f.used[purpose+"|"+email] = false
	return nil
}

func (f *fakeCodes) Verify(email, purpose, code string) error {
	key := purpose + "|" + email
	if _, ok := f.used[key]; !ok || code != fakeCodesValue {
		return errors.New("invalid code")
	}
	if f.used[key] {
		return errors.New("already used")
	}
	f.used[key] = true
	return nil
}

func ptr(s string) *string { return &s }
func ptrInt(i int) *int    { return &i }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
