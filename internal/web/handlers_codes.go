package web

// 访问码接口。
//
// 这些端点是「登录即可」而不是 adminOnly：用户要能自助管理自己的访问码。
// 作用域靠 codeScope 收敛——管理员可带 ?user_id= 管理他人，普通用户的这个
// 参数一律忽略。

import (
	"fmt"
	"net/http"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/models"
)

// codeOwnerScope 解析列表接口的作用域：管理员可查任意用户（或全部），
// 普通用户只能查自己。
func codeOwnerScope(r *http.Request) (string, bool) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		return "", false
	}
	if !me.IsAdmin() {
		return me.ID, true
	}
	return r.URL.Query().Get("user_id"), true
}

func (h *handler) listAccessCodes(w http.ResponseWriter, r *http.Request) {
	scope, authed := codeOwnerScope(r)
	if !authed {
		unauthorized(w)
		return
	}
	codes, lerr := h.users.ListAccessCodes(scope)
	if lerr != nil {
		writeUserError(w, lerr)
		return
	}
	if codes == nil {
		codes = []*models.AccessCode{}
	}
	ok(w, codes)
}

func (h *handler) createAccessCode(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		unauthorized(w)
		return
	}
	var req models.CreateAccessCodeRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	owner := me
	if me.IsAdmin() && req.UserID != "" && req.UserID != me.ID {
		got, gerr := h.users.Get(req.UserID)
		if gerr != nil {
			writeUserError(w, gerr)
			return
		}
		owner = got
	}
	// 管理员自己也可以有访问码（他也可能跑一台后端机），但不受配额限制。
	c, err := h.users.CreateAccessCode(owner, &req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	createdWithMessage(w, c, "访问码已创建 | access code created")
}

func (h *handler) updateAccessCode(w http.ResponseWriter, r *http.Request) {
	c, allowed := h.ownedCode(w, r)
	if !allowed {
		return
	}
	var req models.UpdateAccessCodeRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	next, err := h.users.UpdateAccessCode(c.ID, &req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	okWithMessage(w, next, "访问码已更新 | access code updated")
}

func (h *handler) deleteAccessCode(w http.ResponseWriter, r *http.Request) {
	c, allowed := h.ownedCode(w, r)
	if !allowed {
		return
	}
	// 仍被规则引用的访问码不能删：规则的 target_addr 指着它的隧道地址，删掉
	// 之后那条规则会把流量发进一个不再属于任何人的地址，而界面上看不出异常。
	if n := h.mgr.CountRulesByTarget(c.TunIP); n > 0 {
		fail(w, http.StatusConflict, fmt.Sprintf(
			"该访问码的隧道地址 %s 还被 %d 条转发规则使用，请先删除或改掉那些规则 | still referenced by %d rules",
			c.TunIP, n, n))
		return
	}
	if err := h.users.DeleteAccessCode(c.ID); err != nil {
		writeUserError(w, err)
		return
	}
	okWithMessage(w, nil, "访问码已删除 | access code deleted")
}

func (h *handler) accessCodeText(w http.ResponseWriter, r *http.Request) {
	c, allowed := h.ownedCode(w, r)
	if !allowed {
		return
	}
	view, err := h.users.AccessCodeText(c.ID, relayHostFrom(r))
	if err != nil {
		writeUserError(w, err)
		return
	}
	ok(w, view)
}

func (h *handler) regenerateAccessCode(w http.ResponseWriter, r *http.Request) {
	c, allowed := h.ownedCode(w, r)
	if !allowed {
		return
	}
	if _, err := h.users.RegenerateSecret(c.ID); err != nil {
		writeUserError(w, err)
		return
	}
	view, err := h.users.AccessCodeText(c.ID, relayHostFrom(r))
	if err != nil {
		writeUserError(w, err)
		return
	}
	okWithMessage(w, view, "隧道密钥已重新生成，旧接入码立即失效 | tunnel secret regenerated, the old access code no longer works")
}

func (h *handler) unbindAccessCode(w http.ResponseWriter, r *http.Request) {
	c, allowed := h.ownedCode(w, r)
	if !allowed {
		return
	}
	next, err := h.users.UnbindDevice(c.ID)
	if err != nil {
		writeUserError(w, err)
		return
	}
	okWithMessage(w, next, "设备绑定已解除，下次连接会绑定到新设备 | device unbound, the next connection will bind a new device")
}

// ownedCode 取出路径里的访问码并校验当前身份有权操作它。
//
// 越权时返回 404 而不是 403：确认某个访问码 ID 存在本身就是信息泄漏。
func (h *handler) ownedCode(w http.ResponseWriter, r *http.Request) (*models.AccessCode, bool) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		unauthorized(w)
		return nil, false
	}
	c, err := h.users.GetAccessCode(r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusNotFound, "访问码不存在 | access code not found")
		return nil, false
	}
	if !me.IsAdmin() && c.UserID != me.ID {
		fail(w, http.StatusNotFound, "访问码不存在 | access code not found")
		return nil, false
	}
	return c, true
}
