package web

// 用户组与全局设置接口（仅管理员）。

import (
	"net/http"

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
	ok(w, cfg)
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
