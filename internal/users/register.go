package users

// 自助注册与找回密码。
//
// 注册是把「创建账号」的权力交给公网，所以这里的每一步都是安全边界：
// 开关默认关、SMTP 配置了就必须验证码、限频、事务内查重。任何一步松了，
// 面板就多了一批来历不明的账号。

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
)

// RegistrationRateLimit 是同一 IP 的注册次数上限（每小时）。
//
// SMTP 配置了时限频主要靠验证码发送限频；SMTP 未配置时注册完全不经过邮箱，
// 没有这条 IP 限频就是敞开灌号。
const RegistrationRateLimit = 10

// RateLimiter 是极简的内存滑动窗口限频器（key → 历次时间戳）。
// 注册限频、登录防爆破（web 层）与验证码端点 per-IP 限频共用这一个实现。
type RateLimiter struct {
	mu     sync.Mutex
	events map[string][]time.Time
	limit  int
	window time.Duration
	now    func() time.Time
}

// maxLimiterKeys 是触发全表清扫的键数上限。登录限频按用户名计数，键来自
// 请求输入：不设上限的话，攻击者用随机用户名灌失败计数就是一场内存 DoS。
// 清扫只删「窗口内再无记录」的键，正常在窗口内的键不受影响。
const maxLimiterKeys = 8192

// NewRateLimiter 创建限频器：window 内最多 limit 次。
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		events: make(map[string][]time.Time),
		limit:  limit,
		window: window,
		now:    time.Now,
	}
}

// pruneLocked 清掉窗口内已无记录的键（仅在键数超限时做全表清扫）。
func (r *RateLimiter) pruneLocked(now time.Time) {
	if len(r.events) <= maxLimiterKeys {
		return
	}
	for k, times := range r.events {
		if len(times) == 0 || now.Sub(times[len(times)-1]) >= r.window {
			delete(r.events, k)
		}
	}
}

// trimLocked 摘掉单个键里已出窗的记录。
func (r *RateLimiter) trimLocked(key string, now time.Time) []time.Time {
	times := r.events[key][:0]
	for _, t := range r.events[key] {
		if now.Sub(t) < r.window {
			times = append(times, t)
		}
	}
	return times
}

// Allow 记录并判定一次请求。超限返回 false（该次不计入）。
func (r *RateLimiter) Allow(key string) bool {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
	times := r.trimLocked(key, now)
	if len(times) >= r.limit {
		r.events[key] = times
		return false
	}
	r.events[key] = append(times, now)
	return true
}

// Allowed 只查询不记录：超限返回 false。登录限频用它做「先看再验」——
// 锁定期间连 bcrypt 校验都不该做，限频本身也是资源保护。
func (r *RateLimiter) Allowed(key string) bool {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
	times := r.trimLocked(key, now)
	r.events[key] = times
	return len(times) < r.limit
}

// Reset 清零一个键（登录成功后清该用户名的失败计数）。
func (r *RateLimiter) Reset(key string) {
	r.mu.Lock()
	delete(r.events, key)
	r.mu.Unlock()
}

// RegisterRequest 是注册的输入（web 层解析后传入）。
type RegisterInput struct {
	Username string
	Password string
	Email    string
	Code     string
	IP       string
}

// Register 自助注册一个用户。
//
// SMTP 已配置时必须邮箱 + 验证码；未配置时忽略邮箱字段——收集了不验证的
// 邮箱是假数据，找回密码会因此误判「能找回」。
func (s *Service) Register(in RegisterInput) (*models.User, error) {
	cfg, err := s.store.Settings()
	if err != nil {
		return nil, err
	}
	if !cfg.EnableRegistration {
		return nil, fmt.Errorf("%w: 管理员未开放注册 | registration is disabled by the administrator", ErrRegistrationClosed)
	}
	if !s.registerLimiter.Allow(in.IP) {
		return nil, fmt.Errorf("%w: 注册过于频繁，请稍后再试 | too many attempts", ErrRateLimited)
	}

	smtpCfg, err := s.store.SMTPConfig()
	if err != nil {
		return nil, err
	}
	emailReady := smtpCfg.Configured()

	req := &models.CreateUserRequest{
		Username: in.Username,
		Password: in.Password,
		Role:     models.RoleUser,
		Comment:  "自助注册 | self-registered",
	}
	if err := models.ValidateCreateUserRequest(req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}

	var email string
	if emailReady {
		email, err = models.ValidateEmail(in.Email)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidUser, err)
		}
		if err := s.verifier.Verify(email, models.PurposeRegister, in.Code); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidUser, err)
		}
	}

	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		return nil, err
	}
	u := &models.User{
		ID:           uuid.NewString(),
		Username:     req.Username,
		Role:         models.RoleUser,
		GroupID:      cfg.DefaultGroupID,
		Email:        email,
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	}
	if err := s.store.CreateUser(u); err != nil {
		return nil, err
	}
	logger.S.Infow("新用户已注册 | user registered", "user", u.Username, "email", email != "", "ip", in.IP)
	return u, nil
}

// SendEmailCode 发送验证码。
//
// purpose=reset 且邮箱未注册时静默成功：响应与「已发送」完全一致，否则接口
// 成了「这个邮箱有没有注册」的探测器。SMTP 未配置时明确报 501 语义的错误。
func (s *Service) SendEmailCode(emailRaw, purpose string) error {
	smtpCfg, err := s.store.SMTPConfig()
	if err != nil {
		return err
	}
	if !smtpCfg.Configured() {
		return fmt.Errorf("%w: 邮件功能未配置 | email is not configured", ErrEmailNotConfigured)
	}
	email, err := models.ValidateEmail(emailRaw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}
	if purpose != models.PurposeRegister && purpose != models.PurposeReset {
		return fmt.Errorf("%w: 无效的验证码用途 | invalid purpose", ErrInvalidUser)
	}
	if purpose == models.PurposeReset {
		if _, uerr := s.store.GetUserByEmail(email); uerr != nil {
			// 防枚举：响应与成功一致，什么都不发。
			logger.S.Infow("找回密码请求的邮箱未注册（静默处理）", "email", email != "")
			return nil
		}
	}
	return s.verifier.Issue(email, purpose)
}

// SendBindEmailCode 向登录用户要绑定的新邮箱发验证码（purpose=bind）。
//
// 与公开发码端点隔离：bind 必须携带登录态，公开端点永远不受理 bind 用途，
// 否则它就成了「向任意邮箱投递可信邮件」的匿名通道。
func (s *Service) SendBindEmailCode(userID, emailRaw string) error {
	smtpCfg, err := s.store.SMTPConfig()
	if err != nil {
		return err
	}
	if !smtpCfg.Configured() {
		return fmt.Errorf("%w: 邮件功能未配置 | email is not configured", ErrEmailNotConfigured)
	}
	email, err := models.ValidateEmail(emailRaw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}
	return s.verifier.Issue(email, models.PurposeBind)
}

// BindOwnEmail 给账号绑定/更换邮箱。验证码证明新邮箱的控制权，当前密码
// 证明请求者不是偷来的会话——邮箱一旦绑上就开通了找回密码的通路，只凭
// cookie 就能绑等于给了会话劫持者一条改密旁路（改密本身要旧密码）。
// 唯一性由 storage.UpdateUserEmail 在写事务内把关。
func (s *Service) BindOwnEmail(userID, password, emailRaw, code string) error {
	smtpCfg, err := s.store.SMTPConfig()
	if err != nil {
		return err
	}
	if !smtpCfg.Configured() {
		return fmt.Errorf("%w: 邮件功能未配置 | email is not configured", ErrEmailNotConfigured)
	}
	u, err := s.store.GetUser(userID)
	if err != nil {
		return err
	}
	// 先验密码再验码：密码错了不该消费掉验证码（它是限频资源）。
	if !auth.CheckPassword(u.PasswordHash, password) {
		return ErrBadCredentials
	}
	email, err := models.ValidateEmail(emailRaw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}
	if err := s.verifier.Verify(email, models.PurposeBind, code); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}
	if err := s.store.UpdateUserEmail(userID, email); err != nil {
		return err
	}
	logger.S.Infow("账号已绑定邮箱 | email bound", "user", u.Username, "has_email", email != "")
	return nil
}

// ResetPasswordWithCode 凭邮箱验证码重置密码。
//
// 与 SendEmailCode 同源的防枚举考量在重置这一步不成立——验证码已验证通过，
// 此时按邮箱找不到用户只能是数据不一致，如实报错。
func (s *Service) ResetPasswordWithCode(emailRaw, code, newPassword string) error {
	smtpCfg, err := s.store.SMTPConfig()
	if err != nil {
		return err
	}
	if !smtpCfg.Configured() {
		return fmt.Errorf("%w: 邮件功能未配置 | email is not configured", ErrEmailNotConfigured)
	}
	email, err := models.ValidateEmail(emailRaw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}
	if err := s.verifier.Verify(email, models.PurposeReset, code); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}
	if err := models.ValidatePassword(newPassword); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}

	u, err := s.store.GetUserByEmail(email)
	if err != nil {
		return fmt.Errorf("%w: 该邮箱未绑定任何账号 | no account is bound to this email", ErrInvalidUser)
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	u.MustChangePassword = false
	if err := s.store.SaveUser(u); err != nil {
		return err
	}
	// 密码已换，旧会话必须全部失效——否则重置密码挡不住已经登录的人。
	if s.sessions != nil {
		s.sessions.RevokeUser(u.ID)
	}
	logger.S.Infow("密码已通过邮箱验证码重置 | password reset via email code", "user", u.Username)
	return nil
}

// PublicConfig 是公开端点返回的注册可用性信息。
//
// 只有这几个布尔：多返回一个字段都是给探测者递信息。
type PublicConfig struct {
	RegistrationOpen bool `json:"registration_open"`
	EmailReady       bool `json:"email_ready"`
}

// PublicConfig 计算注册入口的公开可见状态。
func (s *Service) PublicConfig() (PublicConfig, error) {
	cfg, err := s.store.Settings()
	if err != nil {
		return PublicConfig{}, err
	}
	smtpCfg, err := s.store.SMTPConfig()
	if err != nil {
		return PublicConfig{}, err
	}
	return PublicConfig{
		RegistrationOpen: cfg.EnableRegistration,
		EmailReady:       smtpCfg.Configured(),
	}, nil
}

// GetByEmail 按邮箱查用户（存储层的转发，供 handler 与测试用）。
func (s *Service) GetByEmail(email string) (*models.User, error) {
	return s.store.GetUserByEmail(strings.ToLower(strings.TrimSpace(email)))
}

// SetRulesCounter 注入「某用户名下规则数」的查询。
//
// 规则计数在 forward.Manager 里，users 依赖它会造成 users→forward 而
// forward 不依赖 users 的单向是好的，但 manager 由 main 装配且晚于用户服务
// ——和隧道 evictor 一样走二段注入。
func (s *Service) SetRulesCounter(fn func(userID string) int) {
	s.mu.Lock()
	s.rulesCounter = fn
	s.mu.Unlock()
}

func (s *Service) countRules(userID string) int {
	s.mu.RLock()
	fn := s.rulesCounter
	s.mu.RUnlock()
	if fn == nil {
		return 0
	}
	return fn(userID)
}

// QuotaUsage 统计某用户的当前用量（配额 0/5 展示的数据源）。
func (s *Service) QuotaUsage(userID string) (models.QuotaUsage, error) {
	codes, err := s.store.CountAccessCodesByUser(userID)
	if err != nil {
		return models.QuotaUsage{}, err
	}
	tunnels := 0
	tun := s.tunnel()
	if tun != nil {
		online := map[string]bool{}
		for _, id := range tun.OnlineCodeIDs() {
			online[id] = true
		}
		userCodes, err := s.store.ListAccessCodesByUser(userID)
		if err != nil {
			return models.QuotaUsage{}, err
		}
		for _, c := range userCodes {
			if online[c.ID] {
				tunnels++
			}
		}
	}
	return models.QuotaUsage{
		AccessCodes: codes,
		Tunnels:     tunnels,
		Rules:       s.countRules(userID),
	}, nil
}

// EnsureUsedInQuota 把用量填进配额视图（handler 组装 me 响应时调用）。
func (s *Service) FillQuotaUsage(userID string, q models.Quota) (models.Quota, error) {
	used, err := s.QuotaUsage(userID)
	if err != nil {
		return q, err
	}
	q.Used = used
	return q, nil
}

// 服务层错误（与 service.go 里的放在一起语义上更顺，但避免循环编辑，独立声明）。
var (
	// ErrRegistrationClosed 表示管理员未开放注册。
	ErrRegistrationClosed = errors.New("registration is closed")
	// ErrRateLimited 表示触发限频。
	ErrRateLimited = errors.New("too many requests")
	// ErrEmailNotConfigured 表示 SMTP 未配置（对应 HTTP 501）。
	ErrEmailNotConfigured = errors.New("email is not configured")
)
