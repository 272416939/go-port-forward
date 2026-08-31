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

// User 是 Web 登录账号。
//
// 隧道身份不在这里：一个用户可以有多个访问码（AccessCode），每个访问码才是
// 一份独立的隧道凭据与地址。用户上只留「他是谁」与「他属于哪个组」，配额
// 一律由组解析（见 ResolveQuota）——配额挂在用户上时，改套餐要逐个用户去改。
//
// PasswordHash 带 json:"-"：本结构体既用于 bbolt 持久化（pkg/serializer/json
// 会尊重 tag），也直接作为 API 响应体，标签一旦漏了密码哈希就会从 REST 接口
// 泄漏出去。持久化改用 userRecord（见 storage/user.go）。
type User struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	ID       string `json:"id"` // uuid
	Username string `json:"username"`
	Role     string `json:"role"`  // admin | user
	GroupID  string `json:"group_id"` // 所属用户组；空值表示未分组（配额取全局默认）
	// Email 用于注册验证与找回密码。小写存储；可为空（SMTP 未配置时注册的
	// 账号没有邮箱——收集了不验证等于没有）。
	Email   string `json:"email,omitempty"`
	Comment string `json:"comment,omitempty"`

	PasswordHash string `json:"-"` // bcrypt

	Disabled           bool `json:"disabled"`
	MustChangePassword bool `json:"must_change_password"`

	// 运行时字段，不持久化
	GroupName       string `json:"group_name,omitempty"`
	AccessCodeCount int    `json:"access_code_count,omitempty"`
	TunnelOnline    int    `json:"tunnel_online,omitempty"`
}

// IsAdmin 报告是否为管理员。
func (u *User) IsAdmin() bool { return u != nil && u.Role == RoleAdmin }

// CreateUserRequest 是创建用户的 API 请求。
//
// 没有配额字段：配额由所属组决定。GroupID 留空时取全局设置里的默认组。
type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
	GroupID  string `json:"group_id"`
	Comment  string `json:"comment"`
}

// UpdateUserRequest 是更新用户的 API 请求（指针字段表示"未提供即不改"）。
type UpdateUserRequest struct {
	Password *string `json:"password"`
	Role     *string `json:"role"`
	GroupID  *string `json:"group_id"`
	Comment  *string `json:"comment"`
	Disabled *bool   `json:"disabled"`
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

// RegisterRequest 是自助注册的请求。
//
// Email 与 Code 只在 SMTP 已配置时必填；未配置时提交了也会被忽略——收集了
// 不验证的邮箱是假数据。
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Code     string `json:"code"`
}

// EmailCodeRequest 是请求发验证码的请求。
//
// Purpose 绑定用途：注册用的验证码不能拿去重置密码，否则「注册一次的验证码」
// 就成了「改任意账号密码的万能钥匙」。
type EmailCodeRequest struct {
	Email   string `json:"email"`
	Purpose string `json:"purpose"` // register | reset
}

// ForgotPasswordRequest 是凭邮箱验证码重置密码的请求。
type ForgotPasswordRequest struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

// 验证码用途。
const (
	PurposeRegister = "register"
	PurposeReset    = "reset"
	PurposeBind     = "bind" // 登录用户补绑/更换邮箱（另需当前密码）
)

// BindEmailCodeRequest 是登录用户请求向新邮箱发绑定验证码的请求。
type BindEmailCodeRequest struct {
	Email string `json:"email"`
}

// BindEmailRequest 是绑定/更换邮箱的请求。
//
// Password 必填：绑定邮箱等于给账号加了一条找回密码的通路，只凭会话就能
// 绑的话，偷到 cookie 的人可以先绑自己的邮箱再走找回——加一道当前密码，
// 与改密需旧密码对齐。
type BindEmailRequest struct {
	Email    string `json:"email"`
	Code     string `json:"code"`
	Password string `json:"password"`
}

// ValidateEmail 校验并规范化邮箱（小写、非空、含 @）。
//
// 只做形态校验，不验证可达性——验证码本身才是可达性验证，正则写得再严也
// 挡不住 typo 域名。
func ValidateEmail(s string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(s))
	if email == "" {
		return "", fmt.Errorf("邮箱不能为空 | email is required")
	}
	at := strings.IndexByte(email, '@')
	if at <= 0 || at == len(email)-1 || strings.ContainsAny(email, " \t") {
		return "", fmt.Errorf("邮箱格式无效 | invalid email format")
	}
	return email, nil
}

// CurrentUser 是 /api/auth/me 的响应：当前身份与其有效配额。
//
// 配额连来源一起返回：用户看到「上限 3」时要能知道这是组给的还是全局默认，
// 否则只能来问管理员。
type CurrentUser struct {
	ID                 string `json:"id"`
	Username           string `json:"username"`
	Role               string `json:"role"`
	Email              string `json:"email,omitempty"`
	GroupID            string `json:"group_id,omitempty"`
	GroupName          string `json:"group_name,omitempty"`
	Quota              Quota  `json:"quota"`
	MustChangePassword bool   `json:"must_change_password"`
}

// View 生成当前身份视图。quota 由调用方解析后传入（models 层不访问存储）。
func (u *User) View(quota Quota) CurrentUser {
	if u == nil {
		return CurrentUser{}
	}
	return CurrentUser{
		ID:                 u.ID,
		Username:           u.Username,
		Role:               u.Role,
		Email:              u.Email,
		GroupID:            u.GroupID,
		GroupName:          quota.GroupName,
		Quota:              quota,
		MustChangePassword: u.MustChangePassword,
	}
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
	req.GroupID = strings.TrimSpace(req.GroupID)
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
