package web

// 用户管理接口（仅管理员）。

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/models"
)

func (h *handler) listUsers(w http.ResponseWriter, r *http.Request) {
	all, err := h.users.List()
	if err != nil {
		writeUserError(w, err)
		return
	}
	if all == nil {
		all = []*models.User{}
	}
	ok(w, all)
}

func (h *handler) createUser(w http.ResponseWriter, r *http.Request) {
	var req models.CreateUserRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := h.users.Create(&req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	createdWithMessage(w, u, "用户已创建 | user created")
}

func (h *handler) updateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req models.UpdateUserRequest
	if err := decodeBody(w, r, &req); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	// 管理员不得把自己降级或停用：那会让面板当场失去唯一的管理入口，而且
	// 「最后一个管理员」的检查挡不住"还有另一个管理员但那个也是我自己"这类
	// 情形之外的误操作。
	if me := auth.UserFrom(r.Context()); me != nil && me.ID == id {
		if req.Role != nil && *req.Role != models.RoleAdmin {
			fail(w, http.StatusBadRequest, "不能降级自己的角色 | cannot demote yourself")
			return
		}
		if req.Disabled != nil && *req.Disabled {
			fail(w, http.StatusBadRequest, "不能停用自己的账号 | cannot disable your own account")
			return
		}
	}
	u, err := h.users.Update(id, &req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	okWithMessage(w, u, "用户已更新 | user updated")
}

func (h *handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if me := auth.UserFrom(r.Context()); me != nil && me.ID == id {
		fail(w, http.StatusBadRequest, "不能删除自己的账号 | cannot delete your own account")
		return
	}
	// 仍被规则引用的用户不能删：留下孤儿规则会让「这条转发属于谁」永久
	// 无法回答，而它的目标地址还指着一个即将被回收的隧道地址。
	if n := h.mgr.CountRulesByUser(id); n > 0 {
		fail(w, http.StatusConflict, fmt.Sprintf("该用户名下还有 %d 条转发规则，请先删除或转移 | user still owns %d forwarding rules", n, n))
		return
	}
	if err := h.users.Delete(id); err != nil {
		writeUserError(w, err)
		return
	}
	okWithMessage(w, nil, "用户及其访问码已删除 | user and access codes deleted")
}

// relayHostFrom 从请求推断中转机地址，作为 tunnel.public_addr 未配置时的兜底。
//
// 面板与隧道跑在同一台机器上，管理员访问面板用的主机名/IP 通常就是客户端要
// 连的地址。端口不同（面板 8989、隧道 7947），所以只取主机部分，让接入码
// 落在客户端侧补默认端口。
func relayHostFrom(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSpace(host)
	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
		// 本机地址对客户端毫无意义，宁可报错让管理员去配 public_addr。
		return ""
	}
	return host
}
