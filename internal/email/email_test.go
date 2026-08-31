package email

// 验证码服务与 SMTP 消息构造的测试。
//
// 发信本身（net/smtp 对接真实服务器）不在单测范围——那需要一台 SMTP 服务器；
// 单测锁的是验证码的安全语义与邮件消息的编码正确性。

import (
	"errors"
	"io"
	"mime/quotedprintable"
	"strings"
	"testing"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"

	"go.uber.org/zap"
)

func init() {
	// email 包在多处打日志，测试里替换成 no-op。
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()
}

// fakeMailer 记录发送的邮件，供断言。
type fakeMailer struct {
	sent []struct{ to, subject, body string }
	err  error
}

func (f *fakeMailer) Send(to, subject, body string) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, struct{ to, subject, body string }{to, subject, body})
	return nil
}

func (f *fakeMailer) last() (to, subject, body string) {
	last := f.sent[len(f.sent)-1]
	return last.to, last.subject, last.body
}

func newTestService() (*VerificationService, *fakeMailer) {
	m := &fakeMailer{}
	s := NewVerificationService(m)
	return s, m
}

// extractCode 从邮件正文提取验证码（正文里验证码后面还有说明文字，
// 必须取第一个空白分隔的 token 而不是整段尾巴）。
func extractCode(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, "验证码：")
	if i < 0 {
		t.Fatalf("正文缺少验证码：%q", body)
	}
	rest := strings.TrimSpace(body[i+len("验证码："):])
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		t.Fatalf("验证码为空：%q", body)
	}
	return fields[0]
}

func TestIssueAndVerify(t *testing.T) {
	s, m := newTestService()
	if err := s.Issue("Alice@Example.com ", models.PurposeRegister); err != nil {
		t.Fatal(err)
	}
	if len(m.sent) != 1 {
		t.Fatalf("发送了 %d 封, want 1", len(m.sent))
	}
	to, subject, body := m.last()
	if to != "alice@example.com" {
		t.Fatalf("邮箱未规范化：%q", to)
	}
	if !strings.Contains(subject, "注册") {
		t.Fatalf("注册验证码主题不对：%q", subject)
	}
	code := extractCode(t, body)

	if err := s.Verify("alice@example.com", models.PurposeRegister, code); err != nil {
		t.Fatalf("正确验证码应通过：%v", err)
	}
	// 验证通过即消费：一次性凭据不能二次使用。
	if err := s.Verify("alice@example.com", models.PurposeRegister, code); err == nil {
		t.Fatal("同一验证码不应能使用两次")
	}
}

// purpose 绑定：注册码不能用于重置密码。否则「注册一次的验证码」就成了
// 「改任意账号密码的万能钥匙」。
func TestPurposeIsolation(t *testing.T) {
	s, m := newTestService()
	if err := s.Issue("a@x.com", models.PurposeRegister); err != nil {
		t.Fatal(err)
	}
	_, _, body := m.last()
	code := extractCode(t, body)

	if err := s.Verify("a@x.com", models.PurposeReset, code); err == nil {
		t.Fatal("注册验证码不得用于重置密码")
	}
	if err := s.Verify("a@x.com", models.PurposeRegister, code); err != nil {
		t.Fatalf("正确用途应通过：%v", err)
	}
}

	// 60 秒重发间隔 + 每小时 5 封上限。不限频的话，发码接口就是一条现成的
	// 垃圾邮件中继。
func TestIssueRateLimit(t *testing.T) {
	s, _ := newTestService()
	if err := s.Issue("a@x.com", models.PurposeRegister); err != nil {
		t.Fatal(err)
	}
	// 60 秒内重发被拒，且必须带限频 sentinel（上层映射 429 用）。
	if err := s.Issue("a@x.com", models.PurposeRegister); err == nil {
		t.Fatal("60 秒内的重发应被拒绝")
	} else if !errors.Is(err, ErrCodeRateLimited) {
		t.Fatalf("重发间隔错误应包装 ErrCodeRateLimited：%v", err)
	}
	// 用测试时钟快进，把 5 封发满。
	base := s.Now()
	for i := 0; i < CodeHourlyLimit-1; i++ {
		s.Now = func() time.Time { return base.Add(time.Duration(i+1) * 61 * time.Second) }
		if err := s.Issue("a@x.com", models.PurposeRegister); err != nil {
			t.Fatalf("第 %d 封应放行：%v", i+2, err)
		}
	}
	// 第 6 封（1 小时窗口内）被拒。
	s.Now = func() time.Time { return base.Add(5 * 61 * time.Second) }
	if err := s.Issue("a@x.com", models.PurposeRegister); err == nil {
		t.Fatal("超出每小时上限应被拒绝")
	} else if !errors.Is(err, ErrCodeRateLimited) {
		t.Fatalf("每小时上限错误应包装 ErrCodeRateLimited：%v", err)
	}
	// 另一个邮箱不受影响。
	if err := s.Issue("b@x.com", models.PurposeRegister); err != nil {
		t.Fatalf("限频应按邮箱隔离：%v", err)
	}
}

// 发送失败必须包装 ErrSendFailed：上层靠它映射 503 与「稍后重试」文案，
// 裸错误会被兜底成「服务器内部错误」（LESSONS#70 同源）。
func TestIssueSendFailureWrapped(t *testing.T) {
	s, m := newTestService()
	m.err = errors.New("dial tcp: connection refused")
	err := s.Issue("a@x.com", models.PurposeRegister)
	if err == nil {
		t.Fatal("mailer 失败应上抛")
	}
	if !errors.Is(err, ErrSendFailed) {
		t.Fatalf("应包装 ErrSendFailed：%v", err)
	}
}

// 验证码过期。
func TestCodeExpiry(t *testing.T) {
	s, _ := newTestService()
	base := time.Now()
	s.Now = func() time.Time { return base }
	if err := s.Issue("a@x.com", models.PurposeRegister); err != nil {
		t.Fatal(err)
	}
	s.Now = func() time.Time { return base.Add(CodeTTL + time.Second) }
	if err := s.Verify("a@x.com", models.PurposeRegister, "000000"); err == nil {
		t.Fatal("过期验证码应被拒")
	}
}

// 错 5 次作废：6 位数字码 10 分钟内不限次尝试会被暴力枚举击穿。
func TestMaxAttempts(t *testing.T) {
	s, _ := newTestService()
	if err := s.Issue("a@x.com", models.PurposeRegister); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < CodeMaxAttempts; i++ {
		if err := s.Verify("a@x.com", models.PurposeRegister, "000000"); err == nil {
			t.Fatal("错误验证码应被拒")
		}
	}
	// 第 6 次：整条验证码已作废（连正确的也无效）。
	if err := s.Verify("a@x.com", models.PurposeRegister, "999999"); err == nil {
		t.Fatal("超过错误次数上限后验证码应整体作废")
	}
}

// 邮箱维度隔离：A 的验证码不能用于 B。
func TestEmailIsolation(t *testing.T) {
	s, _ := newTestService()
	if err := s.Issue("a@x.com", models.PurposeRegister); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify("b@x.com", models.PurposeRegister, "123456"); err == nil {
		t.Fatal("B 不应能使用 A 的验证码")
	}
}

// 日志脱敏：完整邮箱不能出现在日志里——发码接口是公开的，留全量等于贴用户名单。
func TestMaskEmail(t *testing.T) {
	if got := maskEmail("alice@example.com"); got != "a***@example.com" {
		t.Fatalf("maskEmail = %q", got)
	}
	if got := maskEmail("a@x.com"); got != "***@x.com" {
		t.Fatalf("maskEmail = %q", got)
	}
	if got := maskEmail("no-at-sign"); got != "***" {
		t.Fatalf("maskEmail = %q", got)
	}
}

// 邮件消息构造：中文主题/正文必须经过编码，否则部分客户端显示乱码。
func TestBuildMessageEncoding(t *testing.T) {
	body := "这是一封测试邮件。收到它说明 SMTP 配置正确，\n\n验证码：123456\n\n" +
		"注册验证码与找回密码邮件将经由同一通道发送。"
	msg := string(buildMessage("Port Forward 面板", "noreply@x.com", "to@y.com",
		"注册验证码", body))
	for _, want := range []string{
		"From: =?utf-8?", // 主题与显示名走 RFC 2047
		"To: to@y.com",
		"charset=utf-8",
		"quoted-printable",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("邮件消息缺少 %q：\n%s", want, msg)
		}
	}
	// 头部声明全对不等于正文能读——曾把多字节字符按 rune 截断成单字节
	// 发出，唯一的锁法是按 QP 解码回读并与原文逐字节比对。
	i := strings.Index(msg, "\r\n\r\n")
	if i < 0 {
		t.Fatalf("消息缺少头部与正文的空行分隔：\n%s", msg)
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(msg[i+len("\r\n\r\n"):])))
	if err != nil {
		t.Fatalf("正文 QP 解码失败：%v", err)
	}
	if got := strings.ReplaceAll(string(decoded), "\r\n", "\n"); got != body {
		t.Fatalf("正文解码回读与原文不符：\n got %q\nwant %q", got, body)
	}
}

func TestSMTPConfigured(t *testing.T) {
	var empty *models.SMTPConfig
	if empty.Configured() {
		t.Fatal("nil 配置不应视为已配置")
	}
	if (&models.SMTPConfig{Host: "smtp.x.com"}).Configured() {
		t.Fatal("缺端口/发件人不应视为已配置")
	}
	if !(&models.SMTPConfig{Host: "smtp.x.com", Port: 587, From: "n@x.com"}).Configured() {
		t.Fatal("三项齐全应视为已配置")
	}
}
