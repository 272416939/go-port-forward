package models

import (
	"fmt"
	"time"
)

// UserGroup 是配额的载体。
//
// 配额挂在组上而不是用户上：管理员按「套餐」维护少量组，用户只需归属到某个
// 组。挂在用户上时每个新用户都要重填一遍配额，而改套餐要逐个用户去改。
//
// 三个上限为 0 表示「该项未单独配置」，回落到全局设置（见 ResolveQuota）。
// 端口区间 0/0 同理。
type UserGroup struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	ID      string `json:"id"`
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`

	PortRangeStart int `json:"port_range_start"`
	PortRangeEnd   int `json:"port_range_end"`
	MaxAccessCodes int `json:"max_access_codes"`
	MaxTunnels     int `json:"max_tunnels"`
	MaxRules       int `json:"max_rules"`

	// IsDefault 标记新建用户的默认归属组。同一时刻只有一个组带此标记
	//（存储层保证），删除默认组会被拒绝。
	IsDefault bool `json:"is_default"`

	// 运行时字段，不持久化
	MemberCount int `json:"member_count,omitempty"`
}

// CreateGroupRequest 是创建用户组的请求。
type CreateGroupRequest struct {
	Name           string `json:"name"`
	Comment        string `json:"comment"`
	PortRangeStart int    `json:"port_range_start"`
	PortRangeEnd   int    `json:"port_range_end"`
	MaxAccessCodes int    `json:"max_access_codes"`
	MaxTunnels     int    `json:"max_tunnels"`
	MaxRules       int    `json:"max_rules"`
	IsDefault      bool   `json:"is_default"`
}

// UpdateGroupRequest 是更新用户组的请求（指针 = 未提供即不改）。
type UpdateGroupRequest struct {
	Name           *string `json:"name"`
	Comment        *string `json:"comment"`
	PortRangeStart *int    `json:"port_range_start"`
	PortRangeEnd   *int    `json:"port_range_end"`
	MaxAccessCodes *int    `json:"max_access_codes"`
	MaxTunnels     *int    `json:"max_tunnels"`
	MaxRules       *int    `json:"max_rules"`
	IsDefault      *bool   `json:"is_default"`
}

// ValidateGroupName 校验组名。
func ValidateGroupName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("组名不能为空 | group name is required")
	}
	if len(name) > 64 {
		return fmt.Errorf("组名不能超过 64 个字符 | group name must not exceed 64 characters")
	}
	return nil
}

// ValidateGroupAgainstSettings 校验组配额没有突破全局天花板。
//
// 这是 fail-closed 的关键一环：组是管理员日常操作的对象，若允许它越过全局
// 上限，全局设置就退化成一个没有约束力的建议值。
func ValidateGroupAgainstSettings(g *UserGroup, s Settings) error {
	if err := ValidatePortRange(g.PortRangeStart, g.PortRangeEnd); err != nil {
		return err
	}
	if g.PortRangeStart > 0 && g.PortRangeEnd > 0 && s.PortRangeStart > 0 && s.PortRangeEnd > 0 {
		if g.PortRangeStart < s.PortRangeStart || g.PortRangeEnd > s.PortRangeEnd {
			return fmt.Errorf("组端口区间 %d-%d 超出全局允许范围 %d-%d | group port range exceeds the global range",
				g.PortRangeStart, g.PortRangeEnd, s.PortRangeStart, s.PortRangeEnd)
		}
	}
	checks := []struct {
		name        string
		group, glob int
	}{
		{"访问码上限 | max access codes", g.MaxAccessCodes, s.MaxAccessCodesPerUser},
		{"隧道上限 | max tunnels", g.MaxTunnels, s.MaxTunnelsPerUser},
		{"规则上限 | max rules", g.MaxRules, s.MaxRulesPerUser},
	}
	for _, c := range checks {
		if c.group < 0 {
			return fmt.Errorf("%s 不能为负 | must not be negative", c.name)
		}
		// 全局为 0（不限）时组可以任意设值；全局有限时组不得超过它。
		if c.glob > 0 && c.group > c.glob {
			return fmt.Errorf("%s 不能超过全局上限 %d | must not exceed the global limit of %d",
				c.name, c.glob, c.glob)
		}
	}
	return nil
}
