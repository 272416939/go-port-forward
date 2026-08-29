package models

import (
	"fmt"
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
