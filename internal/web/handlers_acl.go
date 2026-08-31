package web

// 访问控制 / 连接日志 / 活跃会话 的 HTTP 处理器。
// HTTP handlers for IP access control, connection logs and the live session
// view. All mutations reload the compiled snapshots live.

import (
	"errors"
	"fmt"
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

// listConnLogs handles GET /api/logs?page=1&per_page=50
//
// per_page 只允许固定档位（20/50/100/200），不给任意 page size 打库的机会；
// 响应里的 retention 是管理员配置的每用户保留上限，前端据此显示「最多保留 N 条」。
func (h *handler) listConnLogs(w http.ResponseWriter, r *http.Request) {
	page := 1
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	perPage := 50
	if v := r.URL.Query().Get("per_page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && connLogPerPageAllowed(n) {
			perPage = n
		}
	}
	logs, total, err := h.mgr.ConnLogsForUser(scopeOf(auth.UserFrom(r.Context())), page, perPage)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if logs == nil {
		logs = []*models.ConnLogEntry{}
	}
	retention := models.ConnLogMaxDefault
	if s, serr := h.users.Settings(); serr == nil && s.ConnLogMaxPerUser > 0 {
		retention = s.ConnLogMaxPerUser
	}
	ok(w, models.ConnLogsResponse{
		Logs:      logs,
		Total:     total,
		Page:      page,
		PerPage:   perPage,
		Retention: retention,
	})
}

// connLogPerPageAllowed 限定每页条数的可选档位。
func connLogPerPageAllowed(n int) bool {
	switch n {
	case 20, 50, 100, 200:
		return true
	}
	return false
}

// deleteConnLogs handles POST /api/logs/delete（body: {"ids": [...]}）。
// 作用域与列表一致：普通用户只能删自己名下的日志，admin 全量。
func (h *handler) deleteConnLogs(w http.ResponseWriter, r *http.Request) {
	var req models.ConnLogDeleteRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.IDs) == 0 {
		fail(w, http.StatusBadRequest, "缺少要删除的日志 ID | ids is required")
		return
	}
	if len(req.IDs) > 2000 {
		fail(w, http.StatusBadRequest, "单次最多删除 2000 条 | at most 2000 ids per request")
		return
	}
	n, err := h.mgr.DeleteConnLogs(scopeOf(auth.UserFrom(r.Context())), req.IDs)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	okWithMessage(w, map[string]int{"deleted": n},
		fmt.Sprintf("已删除 %d 条日志 | %d log entries deleted", n, n))
}

// clearConnLogs handles POST /api/logs/clear：清空作用域内的全部连接日志。
func (h *handler) clearConnLogs(w http.ResponseWriter, r *http.Request) {
	n, err := h.mgr.ClearConnLogs(scopeOf(auth.UserFrom(r.Context())))
	if err != nil {
		writeAPIError(w, err)
		return
	}
	okWithMessage(w, map[string]int{"deleted": n},
		fmt.Sprintf("已清空 %d 条日志 | %d log entries cleared", n, n))
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
