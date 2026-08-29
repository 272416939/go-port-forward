package web

// 用户组与全局设置接口（仅管理员）。

import (
	"net/http"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/models"
)

func (h *handler) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := h.users.ListGroups()
	if err != nil {
		writeUserError(w, err)
		return
	}
	if groups == nil {
		groups = []*models.UserGroup{}
	}
	ok(w, groups)
}

func (h *handler) createGroup(w http.ResponseWriter, r *http.Request) {
	var req models.CreateGroupRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	g, err := h.users.CreateGroup(&req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	createdWithMessage(w, g, "用户组已创建 | user group created")
}

func (h *handler) updateGroup(w http.ResponseWriter, r *http.Request) {
	var req models.UpdateGroupRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	g, err := h.users.UpdateGroup(r.PathValue("id"), &req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	okWithMessage(w, g, "用户组已更新 | user group updated")
}

func (h *handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	if err := h.users.DeleteGroup(r.PathValue("id")); err != nil {
		writeUserError(w, err)
		return
	}
	okWithMessage(w, nil, "用户组已删除 | user group deleted")
}

func (h *handler) getSettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.users.Settings()
	if err != nil {
		writeUserError(w, err)
		return
	}
	// 附带邮件功能的可用状态：注册开关旁要提示「未配置邮件时注册无邮箱验证」，
	// 这个信息只有设置端点能带出去（SMTP 详情与密码在独立的 /api/smtp）。
	smtpCfg, serr := h.users.SMTPConfig()
	resp := struct {
		models.Settings
		SMTPConfigured bool `json:"smtp_configured"`
	}{cfg, serr == nil && smtpCfg != nil && smtpCfg.Configured()}
	ok(w, resp)
}

func (h *handler) updateSettings(w http.ResponseWriter, r *http.Request) {
	var req models.UpdateSettingsRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg, err := h.users.UpdateSettings(&req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	okWithMessage(w, cfg, "全局设置已更新 | global settings updated")
}

// --- SMTP（仅管理员；密码永不回显） ---

// getSMTP handles GET /api/smtp
func (h *handler) getSMTP(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.users.SMTPConfig()
	if err != nil {
		writeUserError(w, err)
		return
	}
	ok(w, cfg.View())
}

// updateSMTP handles PUT /api/smtp
//
// 请求里密码留空 = 保留原值（storage 层实现）。响应是脱敏视图——密码一旦从
// 接口出去，就会出现在浏览器缓存、代理日志与截屏里。
func (h *handler) updateSMTP(w http.ResponseWriter, r *http.Request) {
	var req models.UpdateSMTPRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg, err := h.users.UpdateSMTP(&req)
	if err != nil {
		writePublicError(w, err)
		return
	}
	okWithMessage(w, cfg.View(), "邮件设置已更新 | email settings updated")
}

// testSMTP handles POST /api/smtp/test —— 发一封测试邮件到管理员自己的邮箱。
func (h *handler) testSMTP(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		unauthorized(w)
		return
	}
	var req struct {
		To string `json:"to"`
	}
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	to, err := models.ValidateEmail(req.To)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.users.SendTestEmail(to); err != nil {
		// 失败原因要原样给管理员：SMTP 报错（认证失败、端口不通）只有看原文
		// 才能定位，这里不是防枚举的场景。
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	okWithMessage(w, nil, "测试邮件已发送 | test email sent")
}
