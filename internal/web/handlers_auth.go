package web

// 认证接口：登录、登出、当前身份、自助改密。

import (
	"errors"
	"net/http"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
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
	ip := clientIP(r)
	// 防爆破：先查不记录——锁定期间连 bcrypt 校验都不做（限频也是资源保护）；
	// 只对失败记录计数，成功登录清该用户名的失败计数（IP 计数靠窗口自然过期，
	// 共享出口 IP 的办公环境不会被单人拖垮）。文案不区分 IP/用户名两种命中，
	// 也不区分用户名是否存在，避免限频本身变成新的枚举面。
	if !h.loginIPFail.Allowed(ip) || !h.loginUserFail.Allowed(req.Username) {
		logger.S.Warnw("登录被限频 | login rate limited", "username", req.Username, "remote", r.RemoteAddr)
		fail(w, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试 | too many attempts, please try again later")
		return
	}
	u, err := h.users.Authenticate(req.Username, req.Password)
	if err != nil {
		h.loginIPFail.Allow(ip)
		h.loginUserFail.Allow(req.Username)
		// 登录失败一律记 warn：这是唯一能看出爆破尝试的地方。
		logger.S.Warnw("登录失败 | login failed", "username", req.Username, "remote", r.RemoteAddr)
		writeUserError(w, err)
		return
	}
	h.loginUserFail.Reset(req.Username)
	token, err := h.sessions.Issue(u.ID)
	if err != nil {
		internalError(w, err)
		return
	}
	h.sessions.SetCookie(w, token)
	logger.S.Infow("用户已登录 | user logged in", "username", u.Username, "role", u.Role, "remote", r.RemoteAddr)
	h.writeIdentity(w, u)
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
	// 会话里的身份是登录时的快照；邮箱这类自助资料要反映库里的最新值。
	// 应急后门没有存储记录，保持快照。停用等状态由中间件与会话撤销兜底。
	if me.ID != "rescue" {
		if fresh, err := h.users.Get(me.ID); err == nil {
			me = fresh
		}
	}
	h.writeIdentity(w, me)
}

// writeIdentity 输出当前身份与其有效配额（含用量）。
//
// 配额连来源一起给前端：用户看到「访问码上限 3」时要能知道这是组给的还是全局
// 默认，否则只能来问管理员。用量（Used）一并返回，界面才有 0/5 形态的展示。
func (h *handler) writeIdentity(w http.ResponseWriter, u *models.User) {
	quota, err := h.users.EffectiveQuota(u)
	if err != nil {
		// 配额解析失败不该让人登不进来（组被手工删掉之类），退化成不限。
		logger.S.Warnw("解析用户配额失败 | failed to resolve quota", "user", u.Username, "err", err)
		quota = models.Quota{}
	}
	// 管理员不受配额约束，用量对它是噪音；普通用户才需要看到自己用了多少。
	if !u.IsAdmin() {
		if filled, ferr := h.users.FillQuotaUsage(u.ID, quota); ferr == nil {
			ok(w, u.View(filled))
			return
		}
	}
	ok(w, u.View(quota))
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

// bindEmailCode handles POST /api/account/email-code —— 向要绑定的新邮箱发码。
//
// 与公开发码端点（/api/auth/email-code）隔离：bind 用途必须带登录态，
// 公开端点不受理。应急后门账号没有存储记录，无可绑定。
func (h *handler) bindEmailCode(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		unauthorized(w)
		return
	}
	if me.ID == "rescue" {
		fail(w, http.StatusBadRequest, "应急账号不支持绑定邮箱 | the rescue account cannot bind an email")
		return
	}
	var req models.BindEmailCodeRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if !h.bindCodeIP.Allow(clientIP(r)) {
		logger.S.Warnw("绑定邮箱发码被限频 | bind email code rate limited", "remote", r.RemoteAddr)
		fail(w, http.StatusTooManyRequests, "请求过于频繁，请稍后再试 | too many requests, please try again later")
		return
	}
	if err := h.users.SendBindEmailCode(me.ID, req.Email); err != nil {
		writePublicError(w, err)
		return
	}
	okWithMessage(w, nil, "验证码已发送，请查收邮箱（10 分钟内有效） | the code has been sent")
}

// bindEmail handles POST /api/account/email —— 绑定/更换自己的邮箱。
func (h *handler) bindEmail(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		unauthorized(w)
		return
	}
	if me.ID == "rescue" {
		fail(w, http.StatusBadRequest, "应急账号不支持绑定邮箱 | the rescue account cannot bind an email")
		return
	}
	var req models.BindEmailRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.users.BindOwnEmail(me.ID, req.Password, req.Email, req.Code); err != nil {
		if errors.Is(err, storage.ErrEmailExists) {
			// 与注册同一纪律：不回显「这个邮箱有没有被注册」，避免登录用户
			// 拿绑定接口绘制本站用户名单。
			fail(w, http.StatusBadRequest, "绑定失败：该邮箱不可用 | failed to bind: this email is unavailable")
			return
		}
		writePublicError(w, err)
		return
	}
	okWithMessage(w, nil, "邮箱已绑定 | email bound")
}
