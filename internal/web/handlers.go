package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/firewall"
	"go-port-forward/internal/forward"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
	"go-port-forward/internal/users"
	"go-port-forward/pkg/os/wsl"
	"go-port-forward/pkg/serializer/json"
)

const maxJSONBodyBytes int64 = 1 << 20

type handler struct {
	mgr      *forward.Manager
	fw       firewall.Manager
	users    *users.Service
	sessions *auth.Store
	tunnel   TunnelStatus
}

type dashboardResponse struct {
	Stats *models.Stats         `json:"stats"`
	Rules []*models.ForwardRule `json:"rules"`
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func ok(w http.ResponseWriter, data interface{}) {
	writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: data})
}

func okWithMessage(w http.ResponseWriter, data interface{}, msg string) {
	writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: data, Message: msg})
}

func createdWithMessage(w http.ResponseWriter, data interface{}, msg string) {
	writeJSON(w, http.StatusCreated, models.APIResponse{Success: true, Data: data, Message: msg})
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, models.APIResponse{Success: false, Message: msg})
}

func decodeBody[T any](w http.ResponseWriter, r *http.Request, dst *T) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	defer r.Body.Close()

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return decodeBodyError(err)
	}

	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("请求体只能包含单个 JSON 对象 | request body must contain a single JSON object")
	}
	return nil
}

func decodeBodyError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, io.EOF):
		return fmt.Errorf("请求体不能为空 | request body is required")
	default:
		return fmt.Errorf("无效的请求体 | invalid JSON body: %v", err)
	}
}

func writeAPIError(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		return
	case errors.Is(err, storage.ErrRuleNotFound):
		fail(w, http.StatusNotFound, err.Error())
	case errors.Is(err, forward.ErrInvalidRule):
		fail(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, forward.ErrPortConflict):
		fail(w, http.StatusConflict, err.Error())
	case errors.Is(err, wsl.ErrNotSupported):
		fail(w, http.StatusNotImplemented, err.Error())
	default:
		fail(w, http.StatusInternalServerError, err.Error())
	}
}

func (h *handler) firewallRule(rule *models.ForwardRule) firewall.Rule {
	return firewall.Rule{Name: rule.Name, Port: rule.ListenPort, Protocol: rule.Protocol}
}

func (h *handler) syncFirewallOnCreate(rule *models.ForwardRule) string {
	if h.fw == nil || rule == nil || !rule.AddFirewall || !rule.Enabled {
		return ""
	}
	if err := h.fw.AddRule(h.firewallRule(rule)); err != nil {
		logger.S.Warnw("Firewall sync failed after rule create", "rule_id", rule.ID, "rule", rule.Name, "err", err)
		return "规则已创建，但防火墙规则同步失败 | rule created, but firewall sync failed: " + err.Error()
	}
	return ""
}

func (h *handler) syncFirewallOnDelete(rule *models.ForwardRule) string {
	if h.fw == nil || rule == nil || !rule.AddFirewall {
		return ""
	}
	if err := h.fw.DeleteRule(h.firewallRule(rule)); err != nil {
		logger.S.Warnw("Firewall sync failed after rule delete", "rule_id", rule.ID, "rule", rule.Name, "err", err)
		return "规则已删除，但防火墙规则清理失败 | rule deleted, but firewall cleanup failed: " + err.Error()
	}
	return ""
}

func (h *handler) syncFirewallOnUpdate(before, after *models.ForwardRule) string {
	if h.fw == nil || before == nil || after == nil {
		return ""
	}

	oldRule := h.firewallRule(before)
	newRule := h.firewallRule(after)
	oldManaged := before.AddFirewall && before.Enabled
	newManaged := after.AddFirewall && after.Enabled

	switch {
	case after.AddFirewall && !after.Enabled:
		if before.AddFirewall {
			if err := h.fw.DeleteRule(oldRule); err != nil {
				logger.S.Warnw("Firewall cleanup failed while disabling rule", "rule_id", after.ID, "rule", after.Name, "err", err)
				return "规则已更新，但防火墙规则清理失败 | rule updated, but firewall cleanup failed: " + err.Error()
			}
		}
		return ""
	case !after.AddFirewall:
		if before.AddFirewall {
			if err := h.fw.DeleteRule(oldRule); err != nil {
				logger.S.Warnw("Firewall cleanup failed after disabling firewall option", "rule_id", after.ID, "rule", after.Name, "err", err)
				return "规则已更新，但防火墙规则清理失败 | rule updated, but firewall cleanup failed: " + err.Error()
			}
		}
		return ""
	case !oldManaged && newManaged:
		if err := h.fw.AddRule(newRule); err != nil {
			logger.S.Warnw("Firewall sync failed after enabling firewall option", "rule_id", after.ID, "rule", after.Name, "err", err)
			return "规则已更新，但防火墙规则同步失败 | rule updated, but firewall sync failed: " + err.Error()
		}
		return ""
	case oldManaged && newManaged && firewallRuleEqual(oldRule, newRule):
		return ""
	case oldManaged && newManaged:
		if err := h.fw.DeleteRule(oldRule); err != nil {
			logger.S.Warnw("Firewall cleanup failed before re-adding updated rule", "rule_id", after.ID, "rule", after.Name, "err", err)
			return "规则已更新，但旧防火墙规则清理失败 | rule updated, but old firewall rule cleanup failed: " + err.Error()
		}
		if err := h.fw.AddRule(newRule); err != nil {
			logger.S.Warnw("Firewall sync failed after rule endpoint change", "rule_id", after.ID, "rule", after.Name, "err", err)
			return "规则已更新，但新防火墙规则同步失败 | rule updated, but new firewall rule sync failed: " + err.Error()
		}
	}
	return ""
}

func firewallRuleEqual(a, b firewall.Rule) bool {
	return a.Name == b.Name && a.Port == b.Port && models.NormalizeProtocol(a.Protocol) == models.NormalizeProtocol(b.Protocol)
}

// --- Rules CRUD ---
//
// 每个 handler 都从上下文取当前身份，再据此决定「看到哪些规则」与「能改哪些
// 规则」。作用域判定不能下放给 manager：manager 没有身份概念，一旦有一个
// handler 忘了传就是静默的越权。

func (h *handler) listRules(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	rules, err := h.mgr.ListRulesForUser(scopeOf(me))
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ok(w, h.withOwnerNames(rules))
}

func (h *handler) createRule(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	var req models.CreateRuleRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := models.ValidateCreateRuleRequest(&req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.guardCreate(me, &req); err != nil {
		writeGuardError(w, err)
		return
	}

	rule, err := h.mgr.AddRule(&req)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	createdWithMessage(w, rule, h.syncFirewallOnCreate(rule))
}

func (h *handler) getRule(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	id := r.PathValue("id")
	rule, err := h.mgr.GetRule(id)
	if err != nil {
		fail(w, http.StatusNotFound, err.Error())
		return
	}
	if !canTouchRule(me, rule.UserID) {
		// 用「不存在」而不是「无权限」回答：确认某个 ID 存在本身就是信息泄漏。
		fail(w, http.StatusNotFound, "规则不存在 | rule not found")
		return
	}
	ok(w, rule)
}

func (h *handler) updateRule(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	id := r.PathValue("id")
	var req models.UpdateRuleRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	before, err := h.mgr.GetRule(id)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if !canTouchRule(me, before.UserID) {
		fail(w, http.StatusNotFound, "规则不存在 | rule not found")
		return
	}
	// 校验的是「改完之后」的状态：普通用户可能只提交了 target_addr，但配额
	// 判定必须基于合并后的完整规则。
	next := *before
	applyUpdateForGuard(&next, &req)
	if err := h.guardUpdate(me, before.UserID, &req, &next); err != nil {
		writeGuardError(w, err)
		return
	}
	rule, err := h.mgr.UpdateRule(id, &req)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	okWithMessage(w, rule, h.syncFirewallOnUpdate(before, rule))
}

func (h *handler) deleteRule(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	id := r.PathValue("id")
	// Fetch before delete so we can remove the firewall rule.
	existing, err := h.mgr.GetRule(id)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if !canTouchRule(me, existing.UserID) {
		fail(w, http.StatusNotFound, "规则不存在 | rule not found")
		return
	}
	if err := h.mgr.DeleteRule(id); err != nil {
		writeAPIError(w, err)
		return
	}
	okWithMessage(w, nil, h.syncFirewallOnDelete(existing))
}

func (h *handler) toggleRule(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	id := r.PathValue("id")
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Enabled == nil {
		fail(w, http.StatusBadRequest, "enabled 字段不能为空 | enabled field is required")
		return
	}
	before, err := h.mgr.GetRule(id)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if !canTouchRule(me, before.UserID) {
		fail(w, http.StatusNotFound, "规则不存在 | rule not found")
		return
	}
	rule, err := h.mgr.ToggleRule(id, *body.Enabled)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	okWithMessage(w, rule, h.syncFirewallOnUpdate(before, rule))
}

func (h *handler) globalStats(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	_, stats, err := h.mgr.SnapshotForUser(scopeOf(me))
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ok(w, stats)
}

func (h *handler) dashboard(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	rules, stats, err := h.mgr.SnapshotForUser(scopeOf(me))
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ok(w, dashboardResponse{Rules: h.withOwnerNames(rules), Stats: stats})
}

// canTouchRule 判断当前身份能否读写归属为 ownerID 的规则。
// 管理员可操作全部（含无归属的共享规则）；普通用户只能操作自己的。
func canTouchRule(me *models.User, ownerID string) bool {
	if me == nil {
		return false
	}
	if me.IsAdmin() {
		return true
	}
	return ownerID != "" && ownerID == me.ID
}

// withOwnerNames 给规则列表回填归属用户名（纯展示字段，不持久化）。
func (h *handler) withOwnerNames(rules []*models.ForwardRule) []*models.ForwardRule {
	if h.users == nil {
		return rules
	}
	names := map[string]string{}
	for _, r := range rules {
		if r.UserID == "" {
			continue
		}
		if _, seen := names[r.UserID]; seen {
			continue
		}
		if u, err := h.users.Get(r.UserID); err == nil {
			names[r.UserID] = u.Username
		} else {
			names[r.UserID] = r.UserID
		}
	}
	for _, r := range rules {
		r.UserName = names[r.UserID]
	}
	return rules
}

// applyUpdateForGuard 把部分更新合并进一份副本，供边界校验使用。
// 与 forward.applyUpdate 是同一套语义，但那个函数不导出，且这里只需要
// 参与校验的几个字段。
func applyUpdateForGuard(r *models.ForwardRule, req *models.UpdateRuleRequest) {
	if req.ListenAddr != nil {
		r.ListenAddr = *req.ListenAddr
	}
	if req.ListenPort != nil {
		r.ListenPort = *req.ListenPort
	}
	if req.TargetAddr != nil {
		r.TargetAddr = *req.TargetAddr
	}
	if req.TargetPort != nil {
		r.TargetPort = *req.TargetPort
	}
	if req.Protocol != nil {
		r.Protocol = *req.Protocol
	}
	if req.UserID != nil {
		r.UserID = *req.UserID
	}
}

// writeGuardError 把边界校验错误映射成 HTTP 状态码。
func writeGuardError(w http.ResponseWriter, err error) {
	if errors.Is(err, errForbidden) {
		fail(w, http.StatusForbidden, err.Error())
		return
	}
	fail(w, http.StatusBadRequest, err.Error())
}
