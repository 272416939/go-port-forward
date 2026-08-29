package web

// 认证接口：登录、登出、当前身份、自助改密。

import (
	"net/http"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
)

func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	if !checkOrigin(r) {
		fail(w, http.StatusForbidden, "跨站请求被拒绝 | cross-site request rejected")
		return
	}
	var req models.LoginRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if h.users == nil || h.sessions == nil {
		fail(w, http.StatusServiceUnavailable, "用户服务未就绪 | user service unavailable")
		return
	}
	u, err := h.users.Authenticate(req.Username, req.Password)
	if err != nil {
		// 登录失败一律记 warn：这是唯一能看出爆破尝试的地方。
		logger.S.Warnw("登录失败 | login failed", "username", req.Username, "remote", r.RemoteAddr)
		writeUserError(w, err)
		return
	}
	token, err := h.sessions.Issue(u.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.sessions.SetCookie(w, token)
	logger.S.Infow("用户已登录 | user logged in", "username", u.Username, "role", u.Role, "remote", r.RemoteAddr)
	ok(w, u.View())
}

func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	if h.sessions != nil {
		h.sessions.Revoke(auth.TokenFromRequest(r))
		h.sessions.ClearCookie(w)
	}
	ok(w, nil)
}

func (h *handler) me(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		unauthorized(w)
		return
	}
	ok(w, me.View())
}

func (h *handler) changePassword(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		unauthorized(w)
		return
	}
	var req models.ChangePasswordRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	// 应急后门账号的凭据在配置文件里，没有可改的哈希。
	if me.ID == "rescue" {
		fail(w, http.StatusBadRequest, "应急账号的密码请在 config.yaml 中修改 | change the rescue account password in config.yaml")
		return
	}
	if err := h.users.ChangeOwnPassword(me.ID, req.OldPassword, req.NewPassword); err != nil {
		writeUserError(w, err)
		return
	}
	// 改密会注销全部会话（含本次请求用的那个），前端需要重新登录。
	h.sessions.ClearCookie(w)
	okWithMessage(w, nil, "密码已修改，请重新登录 | password changed, please sign in again")
}
