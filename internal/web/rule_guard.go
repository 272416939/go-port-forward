package web

// 规则的多租户边界校验。
//
// 分成独立文件是因为这些判定是安全边界，而不是普通的表单校验：漏掉任何一条
// 都会让普通用户越过自己的隧道去操作别人的资源或整台中转机。校验点必须在
// handler 里（拿得到当前身份与配额），manager 只负责执行。

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"go-port-forward/internal/models"
)

// guardCreate 校验一次建规则请求是否在当前身份的权限内，并回填归属。
//
// 管理员：可指定任意归属（含空归属=共享规则），不受端口区间与目标地址限制。
// 普通用户：归属强制为自己，端口必须落在配额区间内，规则数不得超过上限；
// 目标地址按代理模式分流——透明规则必须是启用中访问码的隧道地址（数据面
// 按「target_addr=隧道地址」分流，这是硬要求），通用规则允许任意公网地址
// 但拒绝内网/回环/本机地址。
func (h *handler) guardCreate(me *models.User, req *models.CreateRuleRequest) error {
	if me == nil {
		return fmt.Errorf("未登录 | not authenticated")
	}
	if me.IsAdmin() {
		if req.UserID != "" {
			if _, err := h.users.Get(req.UserID); err != nil {
				return fmt.Errorf("指定的归属用户不存在 | owner user not found: %s", req.UserID)
			}
		}
		return nil
	}

	// 普通用户不得代他人建规则。静默改写而不是报错：前端会锁定这个字段，
	// 能走到这里的多是脚本调用，直接纠正比让它猜错在哪更省事。
	req.UserID = me.ID

	quota, err := h.users.EffectiveQuota(me)
	if err != nil {
		return err
	}
	if err := checkPortQuota(quota, req.ListenPort); err != nil {
		return err
	}
	if err := h.checkTargetRule(me, req.Transparent, req.TargetAddr); err != nil {
		return err
	}
	return h.checkRuleQuota(me, quota)
}

// guardUpdate 校验一次改规则请求。ownerID 是规则当前的归属。
func (h *handler) guardUpdate(me *models.User, ownerID string, req *models.UpdateRuleRequest, next *models.ForwardRule) error {
	if me == nil {
		return fmt.Errorf("未登录 | not authenticated")
	}
	if me.IsAdmin() {
		if req.UserID != nil && *req.UserID != "" {
			if _, err := h.users.Get(*req.UserID); err != nil {
				return fmt.Errorf("指定的归属用户不存在 | owner user not found: %s", *req.UserID)
			}
		}
		return nil
	}
	if ownerID != me.ID {
		return errForbidden
	}
	// 普通用户不得把规则转给别人（也不得转成共享规则）。
	if req.UserID != nil && *req.UserID != me.ID {
		return fmt.Errorf("不能变更规则归属 | changing rule owner is not permitted")
	}
	quota, err := h.users.EffectiveQuota(me)
	if err != nil {
		return err
	}
	if err := checkPortQuota(quota, next.ListenPort); err != nil {
		return err
	}
	return h.checkTargetRule(me, next.Transparent, next.TargetAddr)
}

// checkPortQuota 校验监听端口是否在有效配额区间内。
func checkPortQuota(quota models.Quota, port int) error {
	if quota.PortAllowed(port) {
		return nil
	}
	if quota.PortRangeStart <= 0 || quota.PortRangeEnd <= 0 {
		return fmt.Errorf("尚未为你所在的用户组分配端口区间，请联系管理员 | no port range assigned to your group")
	}
	return fmt.Errorf("监听端口 %d 超出分配区间 %d-%d | listen port out of assigned range",
		port, quota.PortRangeStart, quota.PortRangeEnd)
}

// checkTargetRule 按代理模式分流目标地址校验：透明规则锁定为启用中访问码的
// 隧道地址；通用规则放行任意公网地址（checkPublicTarget）。
func (h *handler) checkTargetRule(me *models.User, transparent bool, targetAddr string) error {
	if transparent {
		return h.checkTargetScope(me, targetAddr)
	}
	return h.checkPublicTarget(me, targetAddr)
}

// checkTargetScope 限制透明规则的目标只能是自己某个启用中访问码的隧道地址。
//
// 透明模式的数据面按「target_addr=隧道地址」把流量送进 TUN 分流到对应客户端，
// target 不是隧道地址的透明规则根本无处可发；规则的归属用户还决定回程路由
// 推送给谁的客户端，所以这条也不是形式主义。
func (h *handler) checkTargetScope(me *models.User, targetAddr string) error {
	allowed, err := h.users.TunIPsOf(me.ID)
	if err != nil {
		return err
	}
	if len(allowed) == 0 {
		return fmt.Errorf("你还没有启用中的访问码，请先在「我的访问码」里创建一个 | create an access code first")
	}
	target := strings.TrimSpace(targetAddr)
	if _, ok := allowed[target]; !ok {
		return fmt.Errorf("目标地址必须是你某个访问码的隧道地址（当前可用：%s）| target must be one of your access code tunnel addresses",
			strings.Join(sortedKeys(allowed), ", "))
	}
	return nil
}

// checkPublicTarget 校验通用模式规则的目标地址：任意公网地址放行，内网/
// 回环/本机地址拒绝。
//
// 通用模式与隧道彻底无关（目标必须是公网地址，不需要客户端）。隧道网段内
// 的地址一律拒绝——包括自己的隧道地址：指向它的通用规则是「TCP 经隧道」的
// 旧通路，已随网关例外一起移除（透明模式仅 UDP，TCP 无法经隧道转发）。
//
// 主机名不做解析校验：创建时解析存在 TOCTOU，且公网域名是合法用例；解析成
// 隧道网段地址的包由数据面丢弃（tunnelapp 的用户隔离检查）——API 层不是
// 这条边界的执行点，只是把最常见的误用在提交时就拦下并指路。
func (h *handler) checkPublicTarget(me *models.User, targetAddr string) error {
	target := strings.TrimSpace(targetAddr)
	ip := net.ParseIP(target)
	if ip == nil {
		if strings.EqualFold(target, "localhost") {
			return errPublicTarget
		}
		return nil // 主机名放行
	}
	// 隧道网段内：大概率是想走隧道填错了模式，给出引导（自己的地址也在内，
	// 通用模式已经不承接任何隧道流量）。
	if v4 := ip.To4(); v4 != nil {
		pool, _ := h.users.TunnelPrefix()
		if pool.IsValid() && pool.Contains(netip.AddrFrom4([4]byte(v4))) {
			return errTunnelTarget
		}
	}
	if isForbiddenTargetIP(ip) || isLocalIP(ip) {
		return errPublicTarget
	}
	return nil
}

var errPublicTarget = fmt.Errorf("目标地址不能是内网、回环或本机地址 | target must not be a private, loopback or host-local address")

// errTunnelTarget 引导用户走透明模式：通用模式的目标填隧道地址是常见误用——
// 用户以为「填自己后端的隧道地址」就叫通用模式，实际那是透明模式的语义。
// 文案必须指出路怎么走，而不是只说不行。
var errTunnelTarget = fmt.Errorf(
	"该地址属于隧道网段：经隧道转发的流量请使用透明代理模式（转发目标选访问码的隧道地址，仅 UDP），通用模式只转发到公网地址 | this address is inside the tunnel subnet; use transparent mode for tunnel traffic (UDP only), general mode forwards to public addresses only")

// isForbiddenTargetIP 报告一个 IP 是否属于禁止作为转发目标的地址段。
func isForbiddenTargetIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// CGNAT 100.64.0.0/10：IsPrivate 不覆盖，但它同样不是公网可达地址。
		if v4[0] == 100 && v4[1] >= 64 && v4[1] < 128 {
			return true
		}
	}
	return false
}

// isLocalIP 报告 IP 是否为本机网卡地址（含中转机自己的公网 IP——指向它的
// 规则等于绕过防火墙直连本机服务）。网卡集合进程生命周期内不变，只查一次。
var (
	localIPOnce sync.Once
	localIPs    []net.IP
)

func isLocalIP(ip net.IP) bool {
	localIPOnce.Do(func() {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				localIPs = append(localIPs, ipnet.IP)
			}
		}
	})
	for _, l := range localIPs {
		if l.Equal(ip) {
			return true
		}
	}
	return false
}

// checkRuleQuota 校验规则数上限（0 表示不限）。
func (h *handler) checkRuleQuota(me *models.User, quota models.Quota) error {
	if quota.MaxRules <= 0 {
		return nil
	}
	if n := h.mgr.CountRulesByUser(me.ID); n >= quota.MaxRules {
		return fmt.Errorf("规则数已达上限 %d 条 | rule quota reached (%d)", quota.MaxRules, quota.MaxRules)
	}
	return nil
}

// scopeOf 返回当前身份的数据作用域：管理员是空字符串（全部），普通用户是自身 ID。
func scopeOf(me *models.User) string {
	if me == nil || me.IsAdmin() {
		return ""
	}
	return me.ID
}

// sortedKeys 返回 map 的键（升序），用于把可选值稳定地写进错误信息。
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
