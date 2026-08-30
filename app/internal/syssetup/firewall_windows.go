//go:build windows

package syssetup

import (
	"fmt"
	"strings"
)

// 防火墙规则显示名（清理时按名移除）。
const firewallRuleName = "Port Forward Tunnel (pf-client)"

// AllowInboundOnInterface 为指定网卡添加 Windows 防火墙入站放行规则。
// wintun 新适配器默认归类为公用网络且入站默认阻止——没有这条规则，
// 玩家经隧道到达的包会被防火墙静默丢弃（表现为回程路由正确但无回包）。
func AllowInboundOnInterface(ifaceName string) error {
	cmd := fmt.Sprintf(
		`New-NetFirewallRule -DisplayName %s -Direction Inbound -Action Allow -InterfaceAlias %s | Out-Null`,
		psQuote(firewallRuleName), psQuote(ifaceName))
	out, err := execPowerShell(cmd)
	if err != nil {
		// 已存在同名规则视为成功
		if strings.Contains(out, "already exists") {
			return nil
		}
		return fmt.Errorf("firewall: %w — %s", err, strings.TrimSpace(out))
	}
	return nil
}

// RemoveInboundRule 移除启动时添加的防火墙放行规则（不存在不报错）。
func RemoveInboundRule() {
	_, _ = execPowerShell(fmt.Sprintf(
		`Remove-NetFirewallRule -DisplayName %s -ErrorAction SilentlyContinue`,
		psQuote(firewallRuleName)))
}
