// Package users 管理 Web 账号、用户组与访问码。
//
// 三层关系：Settings（全局天花板）→ UserGroup（配额载体）→ User（归属组）
// → AccessCode（隧道身份，绑定一台设备）。
//
// 这一层的职责边界：所有「谁能做什么」的判定都在这里或调用方 handler 里，
// storage 只负责存取，tunnelapp 只消费 Identity 查询。
package users

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/email"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
	"go-port-forward/pkg/accesscode"
)

// TunnelSecretBytes 是隧道密钥长度。32 字节既够 HMAC-SHA256 的安全裕度，
// 又让 base64 文本控制在 44 字符（接入码整串仍可一行复制）。
const TunnelSecretBytes = 32

// TunnelEvictor 让用户服务在停用/解绑/删除访问码时立刻踢掉在线隧道。
//
// 不踢的话「停用」只是界面上的一个状态：对方的隧道还在跑，流量照常。解绑更
// 明显——用户以为已经换到新机器，实际上旧机器还占着那个隧道地址。
type TunnelEvictor interface {
	EvictCode(codeID string) bool
	OnlineCodeIDs() []string
}

// Service 是用户服务。
type Service struct {
	store    storage.Store
	sessions *auth.Store

	mu         sync.RWMutex
	tunPool    netip.Prefix
	tunGateway netip.Addr
	publicAddr string        // 写进接入码的中转机地址（config 的 tunnel.public_addr 兜底）
	evictor    TunnelEvictor // 隧道服务端；未启用隧道时为 nil

	// detectAddr 是公网 IP 探测（publicip.go），publicAddr 与全局设置都未
	// 配置时的最后兜底；测试注入替身时直接替换这个字段。
	detectAddr func() string

	// rulesCounter 是「某用户名下规则数」的查询（forward.Manager 注入），
	// 配额用量 0/5 展示的数据源之一。
	rulesCounter func(userID string) int

	// registerLimiter 限制同一 IP 的注册频率（SMTP 未配置时的主要防线）。
	registerLimiter *RateLimiter
	// verifier 是邮箱验证码服务（接口由本包定义，email.VerificationService 实现）；
	// Mailer 由装配层注入（SMTP 配置在 bbolt 里，面板改完即生效）。
	verifier CodeIssuer
}

// CodeIssuer 是验证码的签发与校验能力。接口由消费者（users）定义，
// email.VerificationService 天然满足——与 TunnelEvictor 是同一个模式：
// 依赖最小的形状，而不是另一个包的具体类型。
type CodeIssuer interface {
	Issue(email, purpose string) error
	Verify(email, purpose, code string) error
}

// New 创建用户服务。tunAddr 是 config 的 tunnel.tun_addr（如 "10.66.0.1/16"）。
func New(store storage.Store, sessions *auth.Store, tunAddr, publicAddr string) (*Service, error) {
	pool, gw, err := storage.ParseTunnelPrefix(tunAddr)
	if err != nil {
		return nil, err
	}
	detector := &publicIPDetector{}
	return &Service{
		store:      store,
		sessions:   sessions,
		tunPool:    pool,
		tunGateway: gw,
		publicAddr: strings.TrimSpace(publicAddr),
		detectAddr: detector.Detect,
		registerLimiter: NewRateLimiter(RegistrationRateLimit, time.Hour),
		verifier:        email.NewVerificationService(nil), // Mailer 由装配层注入
	}, nil
}

// SetMailer 注入发信实现（SMTPMailer 由装配层创建，配置从 store 实时读取）。
// 同时喂给默认的验证码服务；测试注入自定义 CodeIssuer 时自行持有 Mailer。
func (s *Service) SetMailer(m email.Mailer) {
	if v, ok := s.verifier.(*email.VerificationService); ok {
		v.Mailer = m
	}
}

// SetVerifier 替换验证码服务（测试注入确定性实现用；生产代码不要调用）。
func (s *Service) SetVerifier(v CodeIssuer) {
	s.verifier = v
}

// SetEvictor 注入隧道服务端。隧道晚于用户服务启动（它需要 Identity 查询），
// 所以这里是二段装配而不是构造参数。
func (s *Service) SetEvictor(e TunnelEvictor) {
	s.mu.Lock()
	s.evictor = e
	s.mu.Unlock()
}

func (s *Service) tunnel() TunnelEvictor {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.evictor
}

// TunnelPrefix 返回隧道网段与网关。
func (s *Service) TunnelPrefix() (netip.Prefix, netip.Addr) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tunPool, s.tunGateway
}

// --- 用户 ---

// List 返回全部用户（附带组名与访问码数，供面板展示）。
func (s *Service) List() ([]*models.User, error) {
	all, err := s.store.ListUsers()
	if err != nil {
		return nil, err
	}
	groups, err := s.groupNames()
	if err != nil {
		return nil, err
	}
	codes, err := s.store.ListAccessCodes()
	if err != nil {
		return nil, err
	}
	online := s.onlineCodes()
	perUser := map[string]int{}
	onlinePerUser := map[string]int{}
	for _, c := range codes {
		perUser[c.UserID]++
		if online[c.ID] {
			onlinePerUser[c.UserID]++
		}
	}
	for _, u := range all {
		u.GroupName = groups[u.GroupID]
		u.AccessCodeCount = perUser[u.ID]
		u.TunnelOnline = onlinePerUser[u.ID]
	}
	return all, nil
}

// Get 按 ID 取用户。
func (s *Service) Get(id string) (*models.User, error) { return s.store.GetUser(id) }

// GetByName 按用户名取用户。
func (s *Service) GetByName(name string) (*models.User, error) { return s.store.GetUserByName(name) }

// Create 创建用户。未指定组时落到全局设置里的默认组。
func (s *Service) Create(req *models.CreateUserRequest) (*models.User, error) {
	if err := models.ValidateCreateUserRequest(req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}
	cfg, err := s.store.Settings()
	if err != nil {
		return nil, err
	}
	groupID := req.GroupID
	if groupID == "" && req.Role != models.RoleAdmin {
		groupID = cfg.DefaultGroupID
	}
	if groupID != "" {
		if _, gerr := s.store.GetGroup(groupID); gerr != nil {
			return nil, fmt.Errorf("%w: 指定的用户组不存在 | group not found: %s", ErrInvalidUser, groupID)
		}
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}
	u := &models.User{
		ID:        uuid.NewString(),
		Username:  req.Username,
		Role:      req.Role,
		GroupID:   groupID,
		Comment:   req.Comment,
		PasswordHash: hash,
		CreatedAt: time.Now(),
	}
	if err := s.store.CreateUser(u); err != nil {
		return nil, err
	}
	logger.S.Infow("用户已创建 | user created", "user", u.Username, "role", u.Role, "group", groupID)
	return u, nil
}

// Update 修改用户属性。改密码或停用都会立刻注销该用户的全部会话，停用还会
// 踢掉他名下所有在线隧道——否则「停用」只是界面上的状态。
func (s *Service) Update(id string, req *models.UpdateUserRequest) (*models.User, error) {
	u, err := s.store.GetUser(id)
	if err != nil {
		return nil, err
	}
	revoke := false
	// 记下改动前是否为「生效中的管理员」：只有让这样一个账号失效才需要检查
	// 是否还剩别的管理员。
	wasActiveAdmin := u.Role == models.RoleAdmin && !u.Disabled

	if req.Password != nil {
		if err := models.ValidatePassword(*req.Password); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidUser, err)
		}
		hash, herr := auth.HashPassword(*req.Password)
		if herr != nil {
			return nil, herr
		}
		u.PasswordHash = hash
		u.MustChangePassword = false
		revoke = true
	}
	if req.Role != nil {
		role, rerr := models.ValidateRole(*req.Role)
		if rerr != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidUser, rerr)
		}
		u.Role = role
	}
	if req.GroupID != nil {
		gid := strings.TrimSpace(*req.GroupID)
		if gid != "" {
			if _, gerr := s.store.GetGroup(gid); gerr != nil {
				return nil, fmt.Errorf("%w: 指定的用户组不存在 | group not found: %s", ErrInvalidUser, gid)
			}
		}
		u.GroupID = gid
	}
	if req.Comment != nil {
		u.Comment = strings.TrimSpace(*req.Comment)
	}
	disableNow := false
	if req.Disabled != nil {
		if *req.Disabled && !u.Disabled {
			revoke = true
			disableNow = true
		}
		u.Disabled = *req.Disabled
	}

	// 降级/停用最后一个生效管理员会把面板锁死，与删除最后一个管理员同源。
	if wasActiveAdmin && (u.Role != models.RoleAdmin || u.Disabled) {
		if err := s.ensureAnotherAdmin(u.ID); err != nil {
			return nil, err
		}
	}

	if err := s.store.SaveUser(u); err != nil {
		return nil, err
	}
	if revoke && s.sessions != nil {
		s.sessions.RevokeUser(u.ID)
	}
	if disableNow {
		s.evictUserTunnels(u.ID)
	}
	return u, nil
}

// ChangeOwnPassword 用户自助改密（需验证旧密码）。
func (s *Service) ChangeOwnPassword(id, oldPw, newPw string) error {
	u, err := s.store.GetUser(id)
	if err != nil {
		return err
	}
	if !auth.CheckPassword(u.PasswordHash, oldPw) {
		return ErrBadCredentials
	}
	if err := models.ValidatePassword(newPw); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}
	if oldPw == newPw {
		return fmt.Errorf("%w: 新密码不能与旧密码相同 | new password must differ", ErrInvalidUser)
	}
	hash, err := auth.HashPassword(newPw)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	u.MustChangePassword = false
	if err := s.store.SaveUser(u); err != nil {
		return err
	}
	// 改密后其它设备上的会话必须失效，否则改密码挡不住已经登录的人。
	if s.sessions != nil {
		s.sessions.RevokeUser(u.ID)
	}
	return nil
}

// Delete 删除用户：连带删掉他的访问码并踢掉在线隧道。
//
// 连带删除而不是拒绝：访问码没有独立存在的意义，留着会变成永远无人认领的
// 孤儿凭据，而它仍然能建立隧道。调用方（handler）负责先确认没有规则引用。
func (s *Service) Delete(id string) error {
	codes, err := s.store.ListAccessCodesByUser(id)
	if err != nil {
		return err
	}
	if err := s.store.DeleteUser(id); err != nil {
		return err
	}
	n, derr := s.store.DeleteAccessCodesByUser(id)
	if derr != nil {
		logger.S.Warnw("删除用户后清理访问码失败 | failed to clean up access codes", "user_id", id, "err", derr)
	}
	if tun := s.tunnel(); tun != nil {
		for _, c := range codes {
			tun.EvictCode(c.ID)
		}
	}
	if s.sessions != nil {
		s.sessions.RevokeUser(id)
	}
	if n > 0 {
		logger.S.Infow("用户已删除 | user deleted", "user_id", id, "access_codes_removed", n)
	}
	return nil
}

// Authenticate 校验用户名密码，返回用户。
func (s *Service) Authenticate(username, password string) (*models.User, error) {
	u, err := s.store.GetUserByName(username)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			// 不区分「用户不存在」与「密码错误」，避免用户名枚举。
			return nil, ErrBadCredentials
		}
		return nil, err
	}
	if !auth.CheckPassword(u.PasswordHash, password) {
		return nil, ErrBadCredentials
	}
	if u.Disabled {
		return nil, ErrUserDisabled
	}
	return u, nil
}

// ensureAnotherAdmin 确认除 excludeID 外还有启用状态的管理员。
func (s *Service) ensureAnotherAdmin(excludeID string) error {
	all, err := s.store.ListUsers()
	if err != nil {
		return err
	}
	for _, u := range all {
		if u.ID != excludeID && u.Role == models.RoleAdmin && !u.Disabled {
			return nil
		}
	}
	return storage.ErrLastAdmin
}

// evictUserTunnels 踢掉某用户名下全部在线隧道。
func (s *Service) evictUserTunnels(userID string) {
	tun := s.tunnel()
	if tun == nil {
		return
	}
	codes, err := s.store.ListAccessCodesByUser(userID)
	if err != nil {
		return
	}
	for _, c := range codes {
		tun.EvictCode(c.ID)
	}
}

// onlineCodes 返回当前在线的访问码集合。
func (s *Service) onlineCodes() map[string]bool {
	out := map[string]bool{}
	tun := s.tunnel()
	if tun == nil {
		return out
	}
	for _, id := range tun.OnlineCodeIDs() {
		out[id] = true
	}
	return out
}

func (s *Service) groupNames() (map[string]string, error) {
	groups, err := s.store.ListGroups()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(groups))
	for _, g := range groups {
		out[g.ID] = g.Name
	}
	return out, nil
}

// 服务层错误。
var (
	ErrInvalidUser    = errors.New("invalid user request")
	ErrBadCredentials = errors.New("用户名或密码错误 | invalid username or password")
	ErrUserDisabled   = errors.New("账号已停用 | account is disabled")
	ErrQuotaExceeded  = errors.New("quota exceeded")
)

// accessCodeAddr 返回写进接入码的中转机地址。
//
// 优先级：全局设置 relay_addr（存 bbolt，面板改完即时生效）→ config 的
// tunnel.public_addr（旧配置兼容兜底）→ 自动探测本机公网 IP → 报错。
// 刻意不做任何「按请求 Host 推导域名」：面板域名被 CDN/反代接管时，推导
// 出来的地址指向 CDN 而不是真实节点，客户端从此连不上隧道。
func (s *Service) accessCodeAddr() (string, error) {
	if st, serr := s.store.Settings(); serr == nil {
		if addr := strings.TrimSpace(st.RelayAddr); addr != "" {
			return addr, nil
		}
	}
	s.mu.RLock()
	addr := s.publicAddr
	s.mu.RUnlock()
	if addr == "" && s.detectAddr != nil {
		addr = s.detectAddr()
	}
	if addr == "" {
		return "", fmt.Errorf("%w: 无法确定中转机地址，请在面板「全局设置」填写，或在 config.yaml 配置 tunnel.public_addr | cannot determine relay address; set it in admin panel global settings or config.yaml", ErrInvalidUser)
	}
	return addr, nil
}

// encodeCode 生成某访问码的接入码文本。
func encodeCode(addr string, c *models.AccessCode) (string, error) {
	return accesscode.Encode(accesscode.Code{Addr: addr, CodeID: c.ID, Secret: c.Secret})
}
