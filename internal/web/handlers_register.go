package web

// 注册 / 邮箱验证码 / 找回密码 / 公开配置 —— 全部是无需登录的公开端点。
//
// 公开端点的纪律：能不返回的字段绝不返回（public-config 只有两个布尔）、
// 语义相同的失败要返回语义相同的响应（防枚举）、限频在服务层做。

import (
	"errors"
	"net"
	"net/http"

	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
	"go-port-forward/internal/users"
)

// publicConfig handles GET /api/auth/public-config
func (h *handler) publicConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.users.PublicConfig()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ok(w, cfg)
}

// register handles POST /api/auth/register
func (h *handler) register(w http.ResponseWriter, r *http.Request) {
	if !checkOrigin(r) {
		fail(w, http.StatusForbidden, "跨站请求被拒绝 | cross-site request rejected")
		return
	}
	var req models.RegisterRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	u, uerr := h.users.Register(users.RegisterInput{
		Username: req.Username,
		Password: req.Password,
		Email:    req.Email,
		Code:     req.Code,
		IP:       ip,
	})
	if uerr != nil {
		// 注册失败记 warn：这是除登录外唯一能观察灌号尝试的地方。
		logger.S.Warnw("注册被拒绝 | registration rejected", "username", req.Username, "remote", r.RemoteAddr, "err", uerr)
		writePublicError(w, uerr)
		return
	}
	okWithMessage(w, u.View(models.AdminQuota()), "注册成功，请登录 | registered, please sign in")
}

// emailCode handles POST /api/auth/email-code
func (h *handler) emailCode(w http.ResponseWriter, r *http.Request) {
	if !checkOrigin(r) {
		fail(w, http.StatusForbidden, "跨站请求被拒绝 | cross-site request rejected")
		return
	}
	var req models.EmailCodeRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.users.SendEmailCode(req.Email, req.Purpose); err != nil {
		writePublicError(w, err)
		return
	}
	// 无论邮箱是否存在都返回同一句话（找回密码路径的防枚举在服务层已处理）。
	okWithMessage(w, nil, "验证码已发送，请查收邮箱（10 分钟内有效） | the code has been sent")
}

// forgotPassword handles POST /api/auth/forgot-password
func (h *handler) forgotPassword(w http.ResponseWriter, r *http.Request) {
	if !checkOrigin(r) {
		fail(w, http.StatusForbidden, "跨站请求被拒绝 | cross-site request rejected")
		return
	}
	var req models.ForgotPasswordRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.users.ResetPasswordWithCode(req.Email, req.Code, req.NewPassword); err != nil {
		writePublicError(w, err)
		return
	}
	okWithMessage(w, nil, "密码已重置，请用新密码登录 | password has been reset")
}

// writeUserError 的注册相关补充映射（email 包与 users 包的新错误）。
func writePublicError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, users.ErrEmailNotConfigured):
		fail(w, http.StatusNotImplemented, err.Error())
	case errors.Is(err, users.ErrRateLimited):
		fail(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, users.ErrRegistrationClosed):
		fail(w, http.StatusForbidden, err.Error())
	case errors.Is(err, storage.ErrEmailExists):
		fail(w, http.StatusConflict, err.Error())
	default:
		writeUserError(w, err)
	}
}
