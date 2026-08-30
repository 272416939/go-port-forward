package users

// 全局设置与用户组。

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"go-port-forward/internal/email"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
)

// Settings 返回全局设置。
func (s *Service) Settings() (models.Settings, error) { return s.store.Settings() }

// UpdateSettings 更新全局设置。
//
// 改小全局区间/上限时会检查已有组是否越界，越界则拒绝并列出冲突的组名。
// 静默截断的话，那些组的用户下次建规则才会莫名被拒，而那时没人记得是这次
// 改动引起的。
func (s *Service) UpdateSettings(req *models.UpdateSettingsRequest) (models.Settings, error) {
	cur, err := s.store.Settings()
	if err != nil {
		return cur, err
	}
	next := cur
	if req.PortRangeStart != nil {
		next.PortRangeStart = *req.PortRangeStart
	}
	if req.PortRangeEnd != nil {
		next.PortRangeEnd = *req.PortRangeEnd
	}
	if req.MaxAccessCodesPerUser != nil {
		next.MaxAccessCodesPerUser = *req.MaxAccessCodesPerUser
	}
	if req.MaxTunnelsPerUser != nil {
		next.MaxTunnelsPerUser = *req.MaxTunnelsPerUser
	}
	if req.MaxRulesPerUser != nil {
		next.MaxRulesPerUser = *req.MaxRulesPerUser
	}
	if req.EnableRegistration != nil {
		next.EnableRegistration = *req.EnableRegistration
	}
	if req.DefaultGroupID != nil {
		gid := strings.TrimSpace(*req.DefaultGroupID)
		if gid != "" {
			if _, gerr := s.store.GetGroup(gid); gerr != nil {
				return cur, fmt.Errorf("%w: 指定的默认组不存在 | default group not found: %s", ErrInvalidUser, gid)
			}
		}
		next.DefaultGroupID = gid
	}
	if req.RelayAddr != nil {
		next.RelayAddr = strings.TrimSpace(*req.RelayAddr)
	}
	if err := models.ValidateSettings(&next); err != nil {
		return cur, fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}

	// 收紧全局值时，已有组不能越界。
	groups, err := s.store.ListGroups()
	if err != nil {
		return cur, err
	}
	var conflicts []string
	for _, g := range groups {
		if verr := models.ValidateGroupAgainstSettings(g, next); verr != nil {
			conflicts = append(conflicts, fmt.Sprintf("%s（%v）", g.Name, verr))
		}
	}
	if len(conflicts) > 0 {
		return cur, fmt.Errorf("%w: 以下用户组的配额会超出新的全局限制，请先调整它们：%s | these groups would exceed the new global limits",
			ErrInvalidUser, strings.Join(conflicts, "；"))
	}

	if err := s.store.SaveSettings(next); err != nil {
		return cur, err
	}
	logger.S.Infow("全局设置已更新 | global settings updated",
		"port_range", fmt.Sprintf("%d-%d", next.PortRangeStart, next.PortRangeEnd),
		"max_codes", next.MaxAccessCodesPerUser, "max_tunnels", next.MaxTunnelsPerUser,
		"max_rules", next.MaxRulesPerUser, "registration", next.EnableRegistration,
		"relay_addr", next.RelayAddr)
	return next, nil
}

// SMTPConfig 读取发信配置（可能为 nil = 未配置）。
func (s *Service) SMTPConfig() (*models.SMTPConfig, error) { return s.store.SMTPConfig() }

// testMailer 取当前发信实现（测试注入的 CodeIssuer 不持有 Mailer）。
func (s *Service) testMailer() email.Mailer {
	if v, ok := s.verifier.(*email.VerificationService); ok {
		return v.Mailer
	}
	return nil
}

// UpdateSMTP 更新发信配置。
func (s *Service) UpdateSMTP(req *models.UpdateSMTPRequest) (*models.SMTPConfig, error) {
	cfg, err := s.store.UpdateSMTP(req)
	if err != nil {
		return nil, err
	}
	logger.S.Infow("邮件设置已更新 | email settings updated",
		"host", cfg.Host, "port", cfg.Port, "configured", cfg.Configured())
	return cfg, nil
}

// SendTestEmail 发一封测试邮件。
func (s *Service) SendTestEmail(to string) error {
	cfg, err := s.store.SMTPConfig()
	if err != nil {
		return err
	}
	if !cfg.Configured() {
		return fmt.Errorf("%w: 邮件功能未配置，请先填写服务器与发件人 | email is not configured", ErrEmailNotConfigured)
	}
	m := s.testMailer()
	if m == nil {
		return fmt.Errorf("%w: 邮件功能未配置 | mailer is not available", ErrEmailNotConfigured)
	}
	body := "这是一封测试邮件。收到它说明 SMTP 配置正确，" +
		"注册验证码与找回密码邮件将经由同一通道发送。\n\n" +
		"If you received this, the SMTP settings work; " +
		"registration and password-reset emails use the same channel."
	return m.Send(to, "Port Forward 测试邮件 | test email", body)
}

// ListGroups 返回全部用户组（附带成员数）。
func (s *Service) ListGroups() ([]*models.UserGroup, error) {
	groups, err := s.store.ListGroups()
	if err != nil {
		return nil, err
	}
	counts, err := s.store.CountGroupMembers()
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		g.MemberCount = counts[g.ID]
	}
	return groups, nil
}

// GetGroup 按 ID 取组。
func (s *Service) GetGroup(id string) (*models.UserGroup, error) { return s.store.GetGroup(id) }

// CreateGroup 创建用户组。
func (s *Service) CreateGroup(req *models.CreateGroupRequest) (*models.UserGroup, error) {
	cfg, err := s.store.Settings()
	if err != nil {
		return nil, err
	}
	g := &models.UserGroup{
		ID:             uuid.NewString(),
		Name:           models.NormalizeGroupName(req.Name),
		Comment:        strings.TrimSpace(req.Comment),
		PortRangeStart: req.PortRangeStart,
		PortRangeEnd:   req.PortRangeEnd,
		MaxAccessCodes: req.MaxAccessCodes,
		MaxTunnels:     req.MaxTunnels,
		MaxRules:       req.MaxRules,
		IsDefault:      req.IsDefault,
	}
	if err := models.ValidateGroupName(g.Name); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}
	if err := models.ValidateGroupAgainstSettings(g, cfg); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}
	if err := s.store.SaveGroup(g); err != nil {
		return nil, err
	}
	if g.IsDefault {
		cfg.DefaultGroupID = g.ID
		if err := s.store.SaveSettings(cfg); err != nil {
			return nil, err
		}
	}
	logger.S.Infow("用户组已创建 | user group created", "group", g.Name,
		"port_range", fmt.Sprintf("%d-%d", g.PortRangeStart, g.PortRangeEnd))
	return g, nil
}

// UpdateGroup 更新用户组。
func (s *Service) UpdateGroup(id string, req *models.UpdateGroupRequest) (*models.UserGroup, error) {
	g, err := s.store.GetGroup(id)
	if err != nil {
		return nil, err
	}
	cfg, err := s.store.Settings()
	if err != nil {
		return nil, err
	}
	if req.Name != nil {
		g.Name = models.NormalizeGroupName(*req.Name)
		if verr := models.ValidateGroupName(g.Name); verr != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidUser, verr)
		}
	}
	if req.Comment != nil {
		g.Comment = strings.TrimSpace(*req.Comment)
	}
	if req.PortRangeStart != nil {
		g.PortRangeStart = *req.PortRangeStart
	}
	if req.PortRangeEnd != nil {
		g.PortRangeEnd = *req.PortRangeEnd
	}
	if req.MaxAccessCodes != nil {
		g.MaxAccessCodes = *req.MaxAccessCodes
	}
	if req.MaxTunnels != nil {
		g.MaxTunnels = *req.MaxTunnels
	}
	if req.MaxRules != nil {
		g.MaxRules = *req.MaxRules
	}
	// 不允许直接取消默认标记：那会让系统没有默认组，新建用户无处可去。
	// 要换默认组，去把另一个组设为默认（存储层会自动清掉旧标记）。
	if req.IsDefault != nil {
		if !*req.IsDefault && g.IsDefault {
			return nil, fmt.Errorf("%w: 请把另一个组设为默认，而不是取消当前默认组 | set another group as default instead", ErrInvalidUser)
		}
		g.IsDefault = *req.IsDefault
	}
	if err := models.ValidateGroupAgainstSettings(g, cfg); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}
	if err := s.store.SaveGroup(g); err != nil {
		return nil, err
	}
	if g.IsDefault && cfg.DefaultGroupID != g.ID {
		cfg.DefaultGroupID = g.ID
		if err := s.store.SaveSettings(cfg); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// DeleteGroup 删除用户组（存储层会拒绝删掉默认组或仍有成员的组）。
func (s *Service) DeleteGroup(id string) error { return s.store.DeleteGroup(id) }

// EffectiveQuota 解析某用户的有效配额。
//
// 管理员返回不受限的配额视图——他要能建指向任意后端的共享规则、用任意端口。
func (s *Service) EffectiveQuota(u *models.User) (models.Quota, error) {
	if u == nil {
		return models.Quota{}, fmt.Errorf("%w: 用户不能为空 | user is required", ErrInvalidUser)
	}
	if u.IsAdmin() {
		return models.AdminQuota(), nil
	}
	cfg, err := s.store.Settings()
	if err != nil {
		return models.Quota{}, err
	}
	var g *models.UserGroup
	if u.GroupID != "" {
		if got, gerr := s.store.GetGroup(u.GroupID); gerr == nil {
			g = got
		}
		// 组被删掉了（正常流程会拦住，但数据可能来自手工修改）：回落到全局
		// 默认而不是报错——报错会让这个用户完全无法使用面板。
	}
	return models.ResolveQuota(g, cfg), nil
}

// QuotaFor 是 EffectiveQuota 的按 ID 版本。
func (s *Service) QuotaFor(userID string) (models.Quota, error) {
	u, err := s.store.GetUser(userID)
	if err != nil {
		return models.Quota{}, err
	}
	return s.EffectiveQuota(u)
}

// Bootstrap 之外的首启需求：确保至少有一个默认组。
//
// 迁移逻辑（storage/migrate.go）会建它，这里只是二次兜底：手工删库重建
// settings 但保留 groups 的情况下，默认组可能不存在。
func (s *Service) ensureDefaultGroup() (string, error) {
	cfg, err := s.store.Settings()
	if err != nil {
		return "", err
	}
	if cfg.DefaultGroupID != "" {
		if _, gerr := s.store.GetGroup(cfg.DefaultGroupID); gerr == nil {
			return cfg.DefaultGroupID, nil
		}
	}
	groups, err := s.store.ListGroups()
	if err != nil {
		return "", err
	}
	for _, g := range groups {
		if g.IsDefault {
			cfg.DefaultGroupID = g.ID
			return g.ID, s.store.SaveSettings(cfg)
		}
	}
	g := &models.UserGroup{
		ID:        uuid.NewString(),
		Name:      "default",
		Comment:   "默认组：配额取全局设置 | default group, quotas follow global settings",
		IsDefault: true,
		CreatedAt: time.Now(),
	}
	if err := s.store.SaveGroup(g); err != nil {
		return "", err
	}
	cfg.DefaultGroupID = g.ID
	return g.ID, s.store.SaveSettings(cfg)
}
