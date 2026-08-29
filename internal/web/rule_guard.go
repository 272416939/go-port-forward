package web

// 规则的多租户边界校验。
//
// 分成独立文件是因为这些判定是安全边界，而不是普通的表单校验：漏掉任何一条
// 都会让普通用户越过自己的隧道去操作别人的资源或整台中转机。校验点必须在
// handler 里（拿得到当前身份与配额），manager 只负责执行。

import (
	"fmt"
	"strings"

	"go-port-forward/internal/models"
)

// guardCreate 校验一次建规则请求是否在当前身份的权限内，并回填归属。
//
// 管理员：可指定任意归属（含空归属=共享规则），不受端口区间与目标地址限制。
// 普通用户：归属强制为自己，端口必须落在配额区间内，目标地址只能是自己某个
// 启用中访问码的隧道地址，规则数不得超过上限。
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
	if err := h.checkTargetScope(me, req.TargetAddr); err != nil {
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
	return h.checkTargetScope(me, next.TargetAddr)
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

// checkTargetScope 限制普通用户的转发目标只能是自己某个启用中访问码的隧道地址。
//
// 这条不是形式主义：不限制的话普通用户可以建一条指向 127.0.0.1:22 或内网
// 任意主机的转发，把中转机变成一个对外开放的跳板。
//
// 「target_addr 落在自己的访问码地址集合里」同时也是「这条规则喂给哪条隧道」
// 的唯一真相——数据面本来就只按目的 IP 分流，再给规则加一个访问码字段等于
// 制造一个能与 target_addr 互相矛盾的第二真相。
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
