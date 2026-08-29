// Package email 提供发信（SMTP）与邮箱验证码服务。
//
// 发信走标准库 net/smtp：任何像样的邮件服务商都支持 STARTTLS（587）或隐式
// TLS（465），引入第三方 SDK 换来的只是更多的依赖与配置面。
//
// 验证码服务是内存态的：验证码的生命周期本来就不该跨进程——重启即失效与
// auth 会话是同一个哲学，落盘反而制造了「重启后旧验证码还能用」的类持久凭据。
package email

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
)

// SendTimeout 是一次 SMTP 会话的上限。SMTP 服务器挂起是真实场景，
// 不能让一个验证码请求拖住 HTTP 工作线程。
const SendTimeout = 5 * time.Second

// Mailer 是发信能力的抽象（测试用 fake 替换，不打真邮件）。
type Mailer interface {
	Send(to, subject, textBody string) error
}

// --- SMTP 实现 ---

// SMTPMailer 按 models.SMTPConfig 发信。配置可被面板热改，因此每次发送都取
// 最新配置，而不是构造时捕获一份。
type SMTPMailer struct {
	Config func() *models.SMTPConfig
}

// Send 发送一封纯文本邮件。
func (m *SMTPMailer) Send(to, subject, textBody string) error {
	cfg := m.Config()
	if !cfg.Configured() {
		return fmt.Errorf("邮件功能未配置 | email is not configured")
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	from := cfg.From
	msg := buildMessage(cfg.FromName, from, to, subject, textBody)

	ctx, cancel := context.WithTimeout(context.Background(), SendTimeout)
	defer cancel()

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	switch cfg.Encryption {
	case models.SMTPSSL:
		return sendImplicitTLS(ctx, addr, cfg.Host, auth, from, to, msg)
	default: // starttls 与 none 都先明文拨号
		return sendWithOptionalSTARTTLS(ctx, addr, cfg.Host, auth, from, to, msg,
			cfg.Encryption != models.SMTPNone)
	}
}

// sendWithOptionalSTARTTLS 明文连接后按需升级 TLS（587 端口的标准流程）。
func sendWithOptionalSTARTTLS(ctx context.Context, addr, host string, auth smtp.Auth,
	from, to string, msg []byte, requireTLS bool) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("连接 SMTP 服务器失败: %w", err)
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SMTP 握手失败: %w", err)
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return fmt.Errorf("STARTTLS 升级失败: %w", err)
		}
	} else if requireTLS {
		return fmt.Errorf("服务器不支持 STARTTLS，请改用 465 端口的 ssl 模式或明确选择 none")
	}

	if err := c.Auth(auth); err != nil && auth != nil {
		return fmt.Errorf("SMTP 认证失败: %w", err)
	}
	return sendBody(c, from, to, msg)
}

// sendImplicitTLS 连接即 TLS（465 端口）。net/smtp 没有 DialSSL，手写一遍
// 客户端循环——逻辑与 net/smtp.SendMail 相同，只是套在 tls.Conn 上。
func sendImplicitTLS(ctx context.Context, addr, host string, auth smtp.Auth,
	from, to string, msg []byte) error {
	var d tls.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("连接 SMTP 服务器失败: %w", err)
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SMTP 握手失败: %w", err)
	}
	defer c.Close()

	if err := c.Auth(auth); err != nil && auth != nil {
		return fmt.Errorf("SMTP 认证失败: %w", err)
	}
	return sendBody(c, from, to, msg)
}

func sendBody(c *smtp.Client, from, to string, msg []byte) error {
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM 失败: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO 失败: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA 失败: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// buildMessage 构造 RFC 5322 邮件。主题与显示名按 RFC 2047 编码，正文用
// quoted-printable——中文内容不过这两道编码，在部分客户端会显示乱码。
func buildMessage(fromName, from, to, subject, textBody string) []byte {
	display := from
	if fromName != "" {
		display = mime.QEncoding.Encode("utf-8", fromName) + " <" + from + ">"
	}
	var b strings.Builder
	b.WriteString("From: " + display + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	b.WriteString("\r\n")
	qp := &quotedPrinter{w: &b}
	_, _ = qp.Write([]byte(textBody))
	return []byte(b.String())
}

// quotedPrinter 是够用的 quoted-printable 编码器：行宽 76、末尾软换行、
// 特殊字符转 =XX。不做完整流式实现——验证码邮件是几行文本，简单正确优先。
type quotedPrinter struct {
	w    *strings.Builder
	line int
}

func (q *quotedPrinter) Write(p []byte) (int, error) {
	for _, r := range string(p) {
		s := encodeQPByte(byte(r), r)
		// 76 行宽：留出软换行两个字符的余量
		if q.line+len(s) > 74 {
			q.w.WriteString("=\r\n")
			q.line = 0
		}
		q.w.WriteString(s)
		q.line += len(s)
	}
	return len(p), nil
}

func encodeQPByte(b byte, r rune) string {
	switch {
	case r == '\n':
		return "\r\n"
	case r == '\r':
		return "" // \r\n 由 \n 分支输出
	case b == '=' || b == '?' || b == '_' || b < 0x20 || b > 0x7E:
		return fmt.Sprintf("=%02X", b)
	default:
		return string(r)
	}
}

// --- 验证码服务 ---

// 验证码策略常量。
const (
	CodeTTL          = 10 * time.Minute
	CodeResendGap    = 60 * time.Second  // 同邮箱两次发送的最小间隔
	CodeHourlyLimit  = 5                 // 同邮箱每小时最多发送次数
	CodeMaxAttempts  = 5                 // 错误次数上限，超过作废
	CodeLength       = 6
)

// CodeEntry 是一条待验证的验证码。
type CodeEntry struct {
	Code      string
	Purpose   string
	ExpiresAt time.Time
	SentAt    time.Time
	Attempts  int
}

// VerificationService 管理验证码的签发与校验。
type VerificationService struct {
	mu    sync.Mutex
	codes map[string]*CodeEntry // key: purpose|email
	sendTimes map[string][]time.Time // key: email → 历次发送时间（限频）

	// Now 便于测试注入时钟。
	Now func() time.Time
	// Mailer 用于实际发信。
	Mailer Mailer
}

// NewVerificationService 创建验证码服务。
func NewVerificationService(m Mailer) *VerificationService {
	return &VerificationService{
		codes:     make(map[string]*CodeEntry),
		sendTimes: make(map[string][]time.Time),
		Now:       time.Now,
		Mailer:    m,
	}
}

func codeKey(purpose, email string) string { return purpose + "|" + strings.ToLower(email) }

// Issue 生成并发送验证码。
//
// 限频在同邮箱维度：发送验证码的接口是公开的，不限频它就是一条现成的
// 垃圾邮件中继。错误返回 error 且不区分原因给调用方展示的文案——细节只在
// 日志里，防止攻击者借此探测限频状态。
func (s *VerificationService) Issue(email, purpose string) error {
	if s.Mailer == nil {
		return fmt.Errorf("邮件功能未配置 | email is not configured")
	}
	email = strings.ToLower(strings.TrimSpace(email))
	now := s.Now()

	s.mu.Lock()
	// 清理过期条目（顺手，避免长期运行 map 只增不减）。
	for k, e := range s.codes {
		if now.After(e.ExpiresAt) {
			delete(s.codes, k)
		}
	}

	// 每小时发送次数限制。
	times := s.sendTimes[email][:0]
	for _, t := range s.sendTimes[email] {
		if now.Sub(t) < time.Hour {
			times = append(times, t)
		}
	}
	s.sendTimes[email] = times
	if len(times) >= CodeHourlyLimit {
		s.mu.Unlock()
		logger.S.Warnw("验证码发送被限频", "email", maskEmail(email))
		return fmt.Errorf("发送过于频繁，请稍后再试 | too many requests")
	}
	if len(times) > 0 && now.Sub(times[len(times)-1]) < CodeResendGap {
		s.mu.Unlock()
		return fmt.Errorf("发送过于频繁，请 1 分钟后再试 | please wait a minute before resending")
	}

	code, err := randomCode()
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.codes[codeKey(purpose, email)] = &CodeEntry{
		Code: code, Purpose: purpose,
		ExpiresAt: now.Add(CodeTTL), SentAt: now,
	}
	s.sendTimes[email] = append(s.sendTimes[email], now)
	s.mu.Unlock()

	if err := s.Mailer.Send(email, verificationSubject(purpose), verificationBody(code, purpose)); err != nil {
		logger.S.Warnw("验证码邮件发送失败", "email", maskEmail(email), "err", err)
		return fmt.Errorf("验证码邮件发送失败，请稍后重试 | failed to send the code")
	}
	logger.S.Infow("验证码已发送", "email", maskEmail(email), "purpose", purpose)
	return nil
}

// Verify 校验并消费验证码。purpose 必须匹配。
//
// 错误尝试累计到上限后作废整条验证码：6 位数字码 10 分钟内不限次尝试，
// 会被 10^-6 量级的暴力枚举击穿。
func (s *VerificationService) Verify(email, purpose, code string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	now := s.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	key := codeKey(purpose, email)
	e, ok := s.codes[key]
	if !ok {
		return fmt.Errorf("验证码无效或已过期 | the code is invalid or expired")
	}
	if now.After(e.ExpiresAt) {
		delete(s.codes, key)
		return fmt.Errorf("验证码已过期，请重新获取 | the code has expired")
	}
	if e.Code != strings.TrimSpace(code) {
		e.Attempts++
		if e.Attempts >= CodeMaxAttempts {
			delete(s.codes, key)
		}
		return fmt.Errorf("验证码错误 | the code is incorrect")
	}
	// 验证通过即消费：一次性凭据不能留在内存里等二次使用。
	delete(s.codes, key)
	return nil
}

// randomCode 生成 6 位数字验证码（crypto/rand，可抗预测）。
func randomCode() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	n := (uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])) % 1000000
	return fmt.Sprintf("%06d", n), nil
}

// maskEmail 打日志用的脱敏：a***b@example.com。验证码邮件接口是公开的，
// 日志里留完整邮箱等于把用户名单贴出来。
func maskEmail(email string) string {
	at := strings.IndexByte(email, '@')
	if at <= 0 {
		return "***"
	}
	local := email[:at]
	if len(local) > 1 {
		local = local[:1] + "***"
	} else {
		local = "***"
	}
	return local + email[at:]
}

func verificationSubject(purpose string) string {
	if purpose == models.PurposeReset {
		return "Port Forward 密码重置验证码"
	}
	return "Port Forward 注册验证码"
}

func verificationBody(code, purpose string) string {
	if purpose == models.PurposeReset {
		return fmt.Sprintf("你正在重置 Port Forward 面板账号的密码。\n\n验证码：%s\n\n验证码 10 分钟内有效。" +
			"如果不是你本人操作，请忽略本邮件并检查账号安全。", code)
	}
	return fmt.Sprintf("你正在注册 Port Forward 面板账号。\n\n验证码：%s\n\n验证码 10 分钟内有效。" +
		"如果不是你本人操作，请忽略本邮件。", code)
}
