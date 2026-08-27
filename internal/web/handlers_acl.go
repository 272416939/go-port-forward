package web

// 访问控制 / 玩家封禁 / 连接日志 / 在线玩家 的 HTTP 处理器。
// HTTP handlers for IP access control, player bans, connection logs and the
// live online-player view. All mutations reload the compiled snapshots live.

import (
	"errors"
	"net/http"
	"strconv"

	"go-port-forward/internal/forward"
	"go-port-forward/internal/models"
)

// listACL handles GET /api/acl
func (h *handler) listACL(w http.ResponseWriter, r *http.Request) {
	entries, err := h.mgr.ListACLEntries()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	ok(w, entries)
}

// createACL handles POST /api/acl
func (h *handler) createACL(w http.ResponseWriter, r *http.Request) {
	var req models.CreateACLRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	entry, err := h.mgr.AddACLEntry(&req)
	if err != nil {
		writeACLError(w, err)
		return
	}
	createdWithMessage(w, entry, "访问控制条目已生效 | access control entry is now active")
}

// deleteACL handles DELETE /api/acl/{id}
func (h *handler) deleteACL(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.mgr.DeleteACLEntry(id); err != nil {
		writeACLError(w, err)
		return
	}
	okWithMessage(w, nil, "访问控制条目已删除 | access control entry deleted")
}

// listPlayerBans handles GET /api/bans
func (h *handler) listPlayerBans(w http.ResponseWriter, r *http.Request) {
	bans, err := h.mgr.ListPlayerBans()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	ok(w, bans)
}

// createPlayerBan handles POST /api/bans
func (h *handler) createPlayerBan(w http.ResponseWriter, r *http.Request) {
	var req models.CreatePlayerBanRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	ban, err := h.mgr.AddPlayerBan(&req)
	if err != nil {
		writeBanError(w, err)
		return
	}
	createdWithMessage(w, ban, "玩家封禁已生效，命中会话将被立即断开 | player ban is now active, matching sessions will be cut")
}

// deletePlayerBan handles DELETE /api/bans/{id}
func (h *handler) deletePlayerBan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.mgr.DeletePlayerBan(id); err != nil {
		writeBanError(w, err)
		return
	}
	okWithMessage(w, nil, "玩家封禁已解除 | player ban removed")
}

// listConnLogs handles GET /api/logs?limit=200
func (h *handler) listConnLogs(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}
	logs, err := h.mgr.ConnLogs(limit)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	ok(w, logs)
}

// listOnlinePlayers handles GET /api/players
func (h *handler) listOnlinePlayers(w http.ResponseWriter, r *http.Request) {
	players := h.mgr.OnlinePlayers()
	if players == nil {
		players = []models.OnlinePlayer{}
	}
	ok(w, models.OnlinePlayersResponse{Players: players})
}

// writeACLError keeps ACL validation failures as 400s.
func writeACLError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, forward.ErrInvalidRule):
		fail(w, http.StatusBadRequest, err.Error())
	default:
		fail(w, http.StatusInternalServerError, err.Error())
	}
}

// writeBanError keeps player-ban validation failures as 400s.
func writeBanError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, forward.ErrInvalidRule):
		fail(w, http.StatusBadRequest, err.Error())
	default:
		fail(w, http.StatusInternalServerError, err.Error())
	}
}
