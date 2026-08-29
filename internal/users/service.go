// Package users 管理 Web 账号与隧道身份（两者是同一个对象）。
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
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
	"go-port-forward/pkg/accesscode"
)

// TunnelSecretBytes 是隧道密钥长度。32 字节既够 HMAC-SHA256 的安全裕度，
// 又让 base64 文本控制在 44 字符（接入码整串仍可一行复制）。
const TunnelSecretBytes = 32

// Service 是用户服务。
type Service struct {
	store    storage.Store
	sessions *auth.Store

	mu         sync.RWMutex
	tunPool    netip.Prefix
	tunGateway netip.Addr
	publicAddr string // 写进接入码的中转机地址（config 的 tunnel.public_addr）
}

// New 创建用户服务。tunAddr 是 config 的 tunnel.tun_addr（如 "10.66.0.1/24"）。
func New(store storage.Store, sessions *auth.Store, tunAddr, publicAddr string) (*Service, error) {
	pool, gw, err := storage.ParseTunnelPrefix(tunAddr)
	if err != nil {
		return nil, err
	}
	return &Service{
		store:      store,
		sessions:   sessions,
		tunPool:    pool,
		tunGateway: gw,
		publicAddr: strings.TrimSpace(publicAddr),
	}, nil
}

// TunnelPrefix 返回隧道网段与网关（tunnelapp 校验用）。
func (s *Service) TunnelPrefix() (netip.Prefix, netip.Addr) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tunPool, s.tunGateway
}

// List 返回全部用户。
func (s *Service) List() ([]*models.User, error) { return s.store.ListUsers() }

// Get 按 ID 取用户。
func (s *Service) Get(id string) (*models.User, error) { return s.store.GetUser(id) }

// GetByName 按用户名取用户。
func (s *Service) GetByName(name string) (*models.User, error) { return s.store.GetUserByName(name) }

// Create 创建用户：生成密码哈希与隧道密钥，隧道地址由存储层在事务内分配。
func (s *Service) Create(req *models.CreateUserRequest) (*models.User, error) {
	if err := models.ValidateCreateUserRequest(req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}
	secret, err := auth.RandomSecret(TunnelSecretBytes)
	if err != nil {
		return nil, err
	}
	u := &models.User{
		ID:             uuid.NewString(),
		Username:       req.Username,
		Role:           req.Role,
		Comment:        req.Comment,
		PasswordHash:   hash,
		TunnelSecret:   secret,
		PortRangeStart: req.PortRangeStart,
		PortRangeEnd:   req.PortRangeEnd,
		MaxRules:       req.MaxRules,
		CreatedAt:      time.Now(),
	}
	pool, gw := s.TunnelPrefix()
	if err := s.store.CreateUser(u, pool, gw); err != nil {
		return nil, err
	}
	logger.S.Infow("用户已创建 | user created", "user", u.Username, "role", u.Role, "tun_ip", u.TunIP)
	return u, nil
}

// Update 修改用户属性。改密码或停用都会立刻注销该用户的全部会话——否则
// 「停用」只是界面上的状态，对方手里的 cookie 依然能用到自然过期。
func (s *Service) Update(id string, req *models.UpdateUserRequest) (*models.User, error) {
	u, err := s.store.GetUser(id)
	if err != nil {
		return nil, err
	}
	revoke := false
	// 记下改动前是否为「生效中的管理员」：只有让这样一个账号失效才需要
	// 检查是否还剩别的管理员。按 req 字段判断会把「停用一个普通用户」也
	// 卷进来，那是无关的。
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
	if req.Comment != nil {
		u.Comment = strings.TrimSpace(*req.Comment)
	}
	start, end := u.PortRangeStart, u.PortRangeEnd
	if req.PortRangeStart != nil {
		start = *req.PortRangeStart
	}
	if req.PortRangeEnd != nil {
		end = *req.PortRangeEnd
	}
	if err := models.ValidatePortRange(start, end); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}
	u.PortRangeStart, u.PortRangeEnd = start, end
	if req.MaxRules != nil {
		if *req.MaxRules < 0 {
			return nil, fmt.Errorf("%w: 规则数上限不能为负 | max_rules must not be negative", ErrInvalidUser)
		}
		u.MaxRules = *req.MaxRules
	}
	if req.Disabled != nil {
		if *req.Disabled && !u.Disabled {
			revoke = true
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

// Delete 删除用户并注销其会话。
func (s *Service) Delete(id string) error {
	if err := s.store.DeleteUser(id); err != nil {
		return err
	}
	if s.sessions != nil {
		s.sessions.RevokeUser(id)
	}
	return nil
}

// RegenerateSecret 重新生成隧道密钥（旧接入码立即失效）。
func (s *Service) RegenerateSecret(id string) (*models.User, error) {
	u, err := s.store.GetUser(id)
	if err != nil {
		return nil, err
	}
	secret, err := auth.RandomSecret(TunnelSecretBytes)
	if err != nil {
		return nil, err
	}
	u.TunnelSecret = secret
	if err := s.store.SaveUser(u); err != nil {
		return nil, err
	}
	logger.S.Infow("隧道密钥已重新生成 | tunnel secret regenerated", "user", u.Username)
	return u, nil
}

// AccessCode 生成该用户的接入码。fallbackAddr 用于 publicAddr 未配置时
// （通常取自 HTTP 请求的 Host，因为服务端无从知晓自己的公网地址）。
func (s *Service) AccessCode(id, fallbackAddr string) (models.UserAccessCode, error) {
	var out models.UserAccessCode
	u, err := s.store.GetUser(id)
	if err != nil {
		return out, err
	}
	s.mu.RLock()
	addr := s.publicAddr
	s.mu.RUnlock()
	if addr == "" {
		addr = strings.TrimSpace(fallbackAddr)
	}
	if addr == "" {
		return out, fmt.Errorf("%w: 无法确定中转机地址，请在 config.yaml 配置 tunnel.public_addr | cannot determine relay address", ErrInvalidUser)
	}
	code, err := accesscode.Encode(accesscode.Code{Addr: addr, UserID: u.ID, Secret: u.TunnelSecret})
	if err != nil {
		return out, err
	}
	return models.UserAccessCode{
		UserID:   u.ID,
		Username: u.Username,
		Addr:     addr,
		Secret:   u.TunnelSecret,
		Code:     code,
	}, nil
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

// 服务层错误。
var (
	ErrInvalidUser    = errors.New("invalid user request")
	ErrBadCredentials = errors.New("用户名或密码错误 | invalid username or password")
	ErrUserDisabled   = errors.New("账号已停用 | account is disabled")
)
