package models

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// SchemaVersion 是当前的数据模型版本。
//
// 迁移靠它判定是否已执行过（见 internal/storage/migrate.go）。加一次不可逆的
// 数据结构变更就加一，不要复用旧号。
const SchemaVersion = 2

// Settings 是全局设置（单例）。
//
// 它是配额的天花板：用户组只能在这个范围内切分，不能突破。分成两层是因为
// 「管理员想统一收紧全站」与「给某个组特殊放宽」是两件不同的事，混在一层会
// 让前者必须逐组去改。
type Settings struct {
	// PortRangeStart/End 是全站可分配的监听端口天花板。用户组的区间必须
	// 落在其内；0/0 表示不限制（管理员未配置）。
	PortRangeStart int `json:"port_range_start"`
	PortRangeEnd   int `json:"port_range_end"`

	// 下面三项是组未单独配置（值为 0）时的兜底上限。0 表示不限。
	MaxAccessCodesPerUser int `json:"max_access_codes_per_user"`
	MaxTunnelsPerUser     int `json:"max_tunnels_per_user"`
	MaxRulesPerUser       int `json:"max_rules_per_user"`

	// DefaultGroupID 是新建用户的默认组。
	DefaultGroupID string `json:"default_group_id"`

	// EnableRegistration 控制自助注册入口。默认 false（fail-closed）：注册
	// 是把「创建账号」的权力交给公网，不开就是不开，绝不该有「未配置即开放」。
	EnableRegistration bool `json:"enable_registration"`

	// RelayAddr 是写进接入码的中转机地址（host 或 host:port，如 1.2.3.4 或
	// relay.example.com:7947）。留空 = 自动探测本机公网 IP。它必须在这里或
	// config.yaml 显式给出：面板域名可能被 CDN/反代接管，按请求 Host 推导
	// 会把接入码指向 CDN 而不是真实节点，客户端从此连不上隧道。
	RelayAddr string `json:"relay_addr"`

	// SchemaVersion 记录数据已迁移到哪个版本，迁移逻辑据此保持幂等。
	SchemaVersion int `json:"schema_version"`
}

// DefaultSettings 返回首次初始化时写入的全局设置。
//
// 端口区间给一个明确的默认值而不是留空：留空意味着「不限制」，而普通用户
// 拿到不限制的端口范围就能占用 22、443 这类端口，与多租户的初衷相悖。
func DefaultSettings() Settings {
	return Settings{
		PortRangeStart:        20000,
		PortRangeEnd:          29999,
		MaxAccessCodesPerUser: 3,
		MaxTunnelsPerUser:     3,
		MaxRulesPerUser:       10,
		SchemaVersion:         SchemaVersion,
	}
}

// UpdateSettingsRequest 是更新全局设置的请求（指针 = 未提供即不改）。
type UpdateSettingsRequest struct {
	PortRangeStart        *int    `json:"port_range_start"`
	PortRangeEnd          *int    `json:"port_range_end"`
	MaxAccessCodesPerUser *int    `json:"max_access_codes_per_user"`
	MaxTunnelsPerUser     *int    `json:"max_tunnels_per_user"`
	MaxRulesPerUser       *int    `json:"max_rules_per_user"`
	DefaultGroupID        *string `json:"default_group_id"`
	EnableRegistration    *bool   `json:"enable_registration"`
	RelayAddr             *string `json:"relay_addr"`
}

// ValidateSettings 校验全局设置自身的合法性。
func ValidateSettings(s *Settings) error {
	if err := ValidatePortRange(s.PortRangeStart, s.PortRangeEnd); err != nil {
		return err
	}
	for name, v := range map[string]int{
		"访问码上限 | max_access_codes_per_user": s.MaxAccessCodesPerUser,
		"隧道上限 | max_tunnels_per_user":      s.MaxTunnelsPerUser,
		"规则上限 | max_rules_per_user":        s.MaxRulesPerUser,
	} {
		if v < 0 {
			return fmt.Errorf("%s 不能为负 | must not be negative", name)
		}
	}
	if err := ValidateRelayAddr(s.RelayAddr); err != nil {
		return err
	}
	return nil
}

// ValidateRelayAddr 校验中转机地址：允许留空（= 自动探测公网 IP），否则必须
// 是 host 或 host:port。裸 IPv6（多冒号）要求写成 [::1]:7947 形式——接入码
// 里的地址面向客户端补默认端口，歧义格式宁可拒绝。
func ValidateRelayAddr(s string) error {
	addr := strings.TrimSpace(s)
	if addr == "" {
		return nil
	}
	if strings.ContainsAny(addr, " \t\r\n/@\\") || strings.Contains(addr, "://") {
		return fmt.Errorf("中转机地址只能是 host 或 host:port，如 1.2.3.4 或 relay.example.com:7947 | relay address must be host or host:port")
	}
	if host, port, err := net.SplitHostPort(addr); err == nil {
		if host == "" {
			return fmt.Errorf("中转机地址缺少主机部分 | relay address is missing the host part")
		}
		if p, perr := strconv.Atoi(port); perr != nil || p < 1 || p > 65535 {
			return fmt.Errorf("中转机地址端口无效 | invalid port in relay address")
		}
		return nil
	}
	if strings.Contains(addr, ":") {
		return fmt.Errorf("IPv6 地址请写成 [地址]:端口 形式 | use [addr]:port form for IPv6")
	}
	return nil
}

// QuotaSource 标明某项配额的来源，供界面解释「为什么是这个值」。
//
// 少了这个，用户看到「上限 3」却无从知道该找谁改，只能来问。
type QuotaSource string

const (
	QuotaFromGroup   QuotaSource = "group"   // 来自所属用户组
	QuotaFromGlobal  QuotaSource = "global"  // 组未配置，取全局默认
	QuotaUnlimited   QuotaSource = "none"    // 两级都未配置：不限
	QuotaFromAdmin   QuotaSource = "admin"   // 管理员身份，不受配额约束
)

// Quota 是某个用户的有效配额与各项来源。
type Quota struct {
	PortRangeStart int `json:"port_range_start"`
	PortRangeEnd   int `json:"port_range_end"`
	MaxAccessCodes int `json:"max_access_codes"`
	MaxTunnels     int `json:"max_tunnels"`
	MaxRules       int `json:"max_rules"`

	GroupID   string `json:"group_id,omitempty"`
	GroupName string `json:"group_name,omitempty"`

	PortSource       QuotaSource `json:"port_source"`
	AccessCodeSource QuotaSource `json:"access_code_source"`
	TunnelSource     QuotaSource `json:"tunnel_source"`
	RuleSource       QuotaSource `json:"rule_source"`

	// Used 是当前已用的量，供界面显示 0/5 形态的进度。上限与来源是"规则"，
	// 用量是"现状"，两者一起才算完整的配额视图——用户看到"上限 3"还要知道
	// "已用 2"，才知道自己还能建几个。
	Used QuotaUsage `json:"used"`
}

// QuotaUsage 是各项配额的当前用量。
type QuotaUsage struct {
	AccessCodes int `json:"access_codes"`
	Tunnels     int `json:"tunnels"` // 当前在线的隧道数
	Rules       int `json:"rules"`
}

// PortAllowed 报告某监听端口是否在配额区间内。
// 区间未配置（0/0）时 fail-closed：没配就是没有可用端口，而不是随便用。
func (q Quota) PortAllowed(port int) bool {
	if q.PortSource == QuotaFromAdmin {
		return true
	}
	if q.PortRangeStart <= 0 || q.PortRangeEnd <= 0 {
		return false
	}
	return port >= q.PortRangeStart && port <= q.PortRangeEnd
}

// AdminQuota 是管理员的配额视图：全部不受限。
func AdminQuota() Quota {
	return Quota{
		PortSource:       QuotaFromAdmin,
		AccessCodeSource: QuotaFromAdmin,
		TunnelSource:     QuotaFromAdmin,
		RuleSource:       QuotaFromAdmin,
	}
}

// ResolveQuota 按「组优先、全局兜底」算出有效配额。
//
// 组值为 0 表示该项未单独配置，回落到全局值；全局值也为 0 则不限。
// 端口区间不做这种回落——区间是成对的，混用组的起点与全局的终点会得到一个
// 谁都没配过的范围。
func ResolveQuota(g *UserGroup, s Settings) Quota {
	q := Quota{
		PortRangeStart: s.PortRangeStart,
		PortRangeEnd:   s.PortRangeEnd,
		PortSource:     QuotaFromGlobal,
	}
	if g != nil {
		q.GroupID, q.GroupName = g.ID, g.Name
		if g.PortRangeStart > 0 && g.PortRangeEnd > 0 {
			q.PortRangeStart, q.PortRangeEnd = g.PortRangeStart, g.PortRangeEnd
			q.PortSource = QuotaFromGroup
		}
	}
	if q.PortRangeStart <= 0 || q.PortRangeEnd <= 0 {
		q.PortSource = QuotaUnlimited
	}

	pick := func(groupVal, globalVal int) (int, QuotaSource) {
		if groupVal > 0 {
			return groupVal, QuotaFromGroup
		}
		if globalVal > 0 {
			return globalVal, QuotaFromGlobal
		}
		return 0, QuotaUnlimited
	}
	var gc, gt, gr int
	if g != nil {
		gc, gt, gr = g.MaxAccessCodes, g.MaxTunnels, g.MaxRules
	}
	q.MaxAccessCodes, q.AccessCodeSource = pick(gc, s.MaxAccessCodesPerUser)
	q.MaxTunnels, q.TunnelSource = pick(gt, s.MaxTunnelsPerUser)
	q.MaxRules, q.RuleSource = pick(gr, s.MaxRulesPerUser)
	return q
}

// NormalizeGroupName 规范化组名。
func NormalizeGroupName(s string) string { return strings.TrimSpace(s) }

// SMTP 加密方式。
const (
	SMTPStartTLS = "starttls" // 587：明文连接后升级 TLS
	SMTPSSL      = "ssl"      // 465：连接即 TLS
	SMTPNone     = "none"     // 25：明文（仅内网中继）
)

// SMTPConfig 是发信服务器的配置（存 bbolt，管理员在面板里改）。
//
// Password 带 json:"-"：本结构体会原样进出 /api/smtp 接口，标签是「密码永不
// 出 API」的唯一实现。更新时请求里密码留空 = 保留原值（见 storage.UpdateSMTP）。
// 与 SQLite 一样 bbolt 无内置加密，0600 文件 + API 不回显是实际的边界，
// 不做伪装加密制造虚假安全感。
type SMTPConfig struct {
	Host       string `json:"host"`
	Port       int    `json:"port"` // 465 / 587 / 25
	Username   string `json:"username"`
	Password   string `json:"-"`
	From       string `json:"from"`      // 发件人地址，如 no-reply@example.com
	FromName   string `json:"from_name"` // 发件人显示名
	Encryption string `json:"encryption"`
}

// Configured 报告 SMTP 是否已配置到可发信的程度。
func (c *SMTPConfig) Configured() bool {
	return c != nil && c.Host != "" && c.Port > 0 && c.From != ""
}

// UpdateSMTPRequest 是更新 SMTP 配置的请求。
//
// Password 为 nil 或空串表示保留原值——面板回显时没有密码可显示，提交时也
// 不该强迫管理员重输。
type UpdateSMTPRequest struct {
	Host       *string `json:"host"`
	Port       *int    `json:"port"`
	Username   *string `json:"username"`
	Password   *string `json:"password"`
	From       *string `json:"from"`
	FromName   *string `json:"from_name"`
	Encryption *string `json:"encryption"`
}

// ValidateSMTPConfig 校验 SMTP 配置自身合法性。
func ValidateSMTPConfig(c *SMTPConfig) error {
	if c.Host == "" && c.Port == 0 && c.From == "" {
		return nil // 整体清空 = 停用邮件功能，合法
	}
	if c.Host == "" || c.Port <= 0 || c.Port > 65535 || c.From == "" {
		return fmt.Errorf("SMTP 配置不完整：服务器、端口与发件人都必填 | smtp host, port and from are required")
	}
	switch c.Encryption {
	case "", SMTPStartTLS, SMTPSSL, SMTPNone:
	default:
		return fmt.Errorf("加密方式必须是 starttls、ssl 或 none | encryption must be starttls, ssl or none")
	}
	if c.Encryption == "" {
		c.Encryption = SMTPStartTLS
	}
	return nil
}

// SMTPView 是 /api/smtp 的响应：配置可见，密码只体现为布尔。
type SMTPView struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	From        string `json:"from"`
	FromName    string `json:"from_name"`
	Encryption  string `json:"encryption"`
	HasPassword bool   `json:"has_password"`
	Configured  bool   `json:"configured"`
}

// View 生成脱敏视图。
func (c *SMTPConfig) View() SMTPView {
	if c == nil {
		return SMTPView{}
	}
	return SMTPView{
		Host: c.Host, Port: c.Port, Username: c.Username,
		From: c.From, FromName: c.FromName, Encryption: c.Encryption,
		HasPassword: c.Password != "",
		Configured:  c.Configured(),
	}
}
