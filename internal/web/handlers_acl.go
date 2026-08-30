package web

// 访问控制 / 连接日志 / 活跃会话 的 HTTP 处理器。
// HTTP handlers for IP access control, connection logs and the live session
// view. All mutations reload the compiled snapshots live.

import (
	"errors"
	"net/http"
	"strconv"

	"go-port-forward/internal/auth"
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

// listConnLogs handles GET /api/logs?limit=200
func (h *handler) listConnLogs(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}
	logs, err := h.mgr.ConnLogsForUser(scopeOf(auth.UserFrom(r.Context())), limit)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	ok(w, logs)
}

// listSessions handles GET /api/sessions
func (h *handler) listSessions(w http.ResponseWriter, r *http.Request) {
	sessions := h.mgr.SessionsForUser(scopeOf(auth.UserFrom(r.Context())))
	if sessions == nil {
		sessions = []models.SessionEntry{}
	}
	ok(w, models.SessionsResponse{Sessions: sessions})
}

// writeACLError keeps ACL validation failures as 400s.
func writeACLError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, forward.ErrInvalidRule):
		fail(w, http.StatusBadRequest, err.Error())
	default:
		internalError(w, err)
	}
}
