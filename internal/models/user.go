package models

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// 用户角色。
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// User 同时是 Web 登录账号与隧道用户。
//
// 两种身份合并成一个对象是刻意的：如果 Web 账号与隧道凭据各自一套模型，
// 「谁的规则能指向谁的隧道」就会变成一个需要额外维护的关联表，而这正是
// 隔离最容易出错的地方。
//
// PasswordHash 与 TunnelSecret 都带 json:"-"：本结构体既用于 bbolt 持久化
// （pkg/serializer/json 会尊重 tag），也直接作为 API 响应体，标签一旦漏了
// 密钥就会从 REST 接口泄漏出去。持久化改用 userRecord（见 storage/user.go）。
type User struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	ID       string `json:"id"` // uuid，同时是隧道协议里的用户 ID
	Username string `json:"username"`
	Role     string `json:"role"`  // admin | user
	TunIP    string `json:"tun_ip"` // 分配到的隧道内地址（规则的目标地址指向它）
	Comment  string `json:"comment,omitempty"`

	PasswordHash string `json:"-"` // bcrypt
	TunnelSecret string `json:"-"` // 32 字节随机的 base64；必须可逆存储（服务端要用它验 MAC 并派生会话密钥）

	PortRangeStart int `json:"port_range_start"` // 该用户可用的监听端口区间（含）
	PortRangeEnd   int `json:"port_range_end"`
	MaxRules       int `json:"max_rules"` // 规则数上限；0 表示不限

	Disabled           bool `json:"disabled"`
	MustChangePassword bool `json:"must_change_password"`
}

// IsAdmin 报告是否为管理员。
func (u *User) IsAdmin() bool { return u != nil && u.Role == RoleAdmin }

// PortAllowed 报告某监听端口是否在该用户的配额区间内。
// 管理员不受区间限制；普通用户未配置区间等于没有可用端口（fail-closed）。
func (u *User) PortAllowed(port int) bool {
	if u == nil {
		return false
	}
	if u.IsAdmin() {
		return true
	}
	if u.PortRangeStart <= 0 || u.PortRangeEnd <= 0 {
		return false
	}
	return port >= u.PortRangeStart && port <= u.PortRangeEnd
}

// CreateUserRequest 是创建用户的 API 请求。
//
// TunIP 不在请求里：隧道地址由服务端在存储事务内分配，让调用方指定会引入
// 撞号与「指定了别人地址」两种问题。
type CreateUserRequest struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	Role           string `json:"role"`
	Comment        string `json:"comment"`
	PortRangeStart int    `json:"port_range_start"`
	PortRangeEnd   int    `json:"port_range_end"`
	MaxRules       int    `json:"max_rules"`
}

// UpdateUserRequest 是更新用户的 API 请求（指针字段表示"未提供即不改"）。
type UpdateUserRequest struct {
	Password       *string `json:"password"`
	Role           *string `json:"role"`
	Comment        *string `json:"comment"`
	PortRangeStart *int    `json:"port_range_start"`
	PortRangeEnd   *int    `json:"port_range_end"`
	MaxRules       *int    `json:"max_rules"`
	Disabled       *bool   `json:"disabled"`
}

// LoginRequest 是登录请求。
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ChangePasswordRequest 是修改自身密码的请求。
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// CurrentUser 是 /api/auth/me 的响应：当前身份与其边界。
type CurrentUser struct {
	ID                 string `json:"id"`
	Username           string `json:"username"`
	Role               string `json:"role"`
	TunIP              string `json:"tun_ip"`
	PortRangeStart     int    `json:"port_range_start"`
	PortRangeEnd       int    `json:"port_range_end"`
	MaxRules           int    `json:"max_rules"`
	MustChangePassword bool   `json:"must_change_password"`
}

// View 生成当前身份视图。
func (u *User) View() CurrentUser {
	if u == nil {
		return CurrentUser{}
	}
	return CurrentUser{
		ID:                 u.ID,
		Username:           u.Username,
		Role:               u.Role,
		TunIP:              u.TunIP,
		PortRangeStart:     u.PortRangeStart,
		PortRangeEnd:       u.PortRangeEnd,
		MaxRules:           u.MaxRules,
		MustChangePassword: u.MustChangePassword,
	}
}

// UserAccessCode 是「取接入码」接口的响应。
type UserAccessCode struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Addr     string `json:"addr"`
	Secret   string `json:"secret"`
	Code     string `json:"code"`
}

// MinPasswordLength 是密码最小长度。
const MinPasswordLength = 8

// ValidatePassword 校验密码强度（长度下限 + 非空白）。
func ValidatePassword(pw string) error {
	if len(pw) < MinPasswordLength {
		return fmt.Errorf("密码至少 %d 位 | password must be at least %d characters", MinPasswordLength, MinPasswordLength)
	}
	if strings.TrimSpace(pw) == "" {
		return fmt.Errorf("密码不能全为空白 | password must not be blank")
	}
	return nil
}

// NormalizeUsername 规范化用户名（小写、去空白）。
func NormalizeUsername(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// ValidateRole 规范化并校验角色。
func ValidateRole(role string) (string, error) {
	r := strings.ToLower(strings.TrimSpace(role))
	if r == "" {
		r = RoleUser
	}
	if r != RoleAdmin && r != RoleUser {
		return "", fmt.Errorf("角色必须为 admin 或 user | role must be admin or user")
	}
	return r, nil
}

// ValidatePortRange 校验端口区间（0/0 表示未配置，允许）。
func ValidatePortRange(start, end int) error {
	if start == 0 && end == 0 {
		return nil
	}
	if start <= 0 || start > 65535 || end <= 0 || end > 65535 {
		return fmt.Errorf("端口区间超出范围 (1-65535) | port range out of range (1-65535)")
	}
	if start > end {
		return fmt.Errorf("端口区间起点不能大于终点 | port range start must not exceed end")
	}
	return nil
}

// ValidateCreateUserRequest 规范化并校验创建请求。
func ValidateCreateUserRequest(req *CreateUserRequest) error {
	if req == nil {
		return fmt.Errorf("请求不能为空 | request is required")
	}
	req.Username = NormalizeUsername(req.Username)
	req.Comment = strings.TrimSpace(req.Comment)
	if err := ValidateUsername(req.Username); err != nil {
		return err
	}
	if err := ValidatePassword(req.Password); err != nil {
		return err
	}
	role, err := ValidateRole(req.Role)
	if err != nil {
		return err
	}
	req.Role = role
	if err := ValidatePortRange(req.PortRangeStart, req.PortRangeEnd); err != nil {
		return err
	}
	if req.MaxRules < 0 {
		return fmt.Errorf("规则数上限不能为负 | max_rules must not be negative")
	}
	return nil
}

// ValidateUsername 校验用户名字符集与长度。
func ValidateUsername(name string) error {
	if len(name) < 3 || len(name) > 32 {
		return fmt.Errorf("用户名长度需为 3-32 个字符 | username must be 3-32 characters")
	}
	for _, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.'
		if !ok {
			return fmt.Errorf("用户名只能包含小写字母、数字与 _ - . | username may only contain lowercase letters, digits and _ - .")
		}
	}
	return nil
}

// ParseTunIP 解析用户的隧道地址（空值返回无效地址而非错误，便于调用方区分）。
func ParseTunIP(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !addr.Is4() {
		return netip.Addr{}, false
	}
	return addr, true
}
