package web

// 认证与授权中间件。
//
// 两层包装：authed 要求已登录，adminOnly 额外要求管理员。判定结果（当前用户）
// 放进请求上下文，handler 用 auth.UserFrom(r.Context()) 取出来决定数据作用域。
//
// CSRF：会话 cookie 是 SameSite=Strict，跨站请求根本不会带上它；再对所有
// 非 GET 请求做一次 Origin/Referer 同源校验兜住浏览器差异。不引入令牌双提交
// ——那需要前端每个 fetch 都改，收益重复。

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
	"go-port-forward/internal/users"
)

// errForbidden 是越权访问的哨兵错误。
var errForbidden = errors.New("无权访问该资源 | you are not allowed to access this resource")

// isErr 是 errors.Is 的短名（本文件里要写很多次）。
func isErr(err, target error) bool { return errors.Is(err, target) }

// authed 包装一个需要登录的 handler。
func (s *Server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkOrigin(r) {
			fail(w, http.StatusForbidden, "跨站请求被拒绝 | cross-site request rejected")
			return
		}
		me := s.resolveUser(r)
		if me == nil {
			unauthorized(w)
			return
		}
		if me.Disabled {
			// 会话在停用时会被注销，走到这里通常是应急后门账号被停用之类的
			// 边缘情况，仍然要挡住。
			unauthorized(w)
			return
		}
		next(w, r.WithContext(auth.WithUser(r.Context(), me)))
	}
}

// adminOnly 包装一个仅管理员可访问的 handler。
func (s *Server) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return s.authed(func(w http.ResponseWriter, r *http.Request) {
		me := auth.UserFrom(r.Context())
		if !me.IsAdmin() {
			fail(w, http.StatusForbidden, "需要管理员权限 | administrator privileges required")
			return
		}
		next(w, r)
	})
}

// resolveUser 解析当前身份：先看会话 cookie，再看应急后门。
func (s *Server) resolveUser(r *http.Request) *models.User {
	if s.sessions != nil && s.users != nil {
		if uid, ok := s.sessions.Lookup(auth.TokenFromRequest(r)); ok {
			if u, err := s.users.Get(uid); err == nil {
				return u
			}
			// 用户已被删除但会话还在：注销它，避免每次请求都查一次库。
			s.sessions.Revoke(auth.TokenFromRequest(r))
		}
	}
	return s.rescueUser(r)
}

// rescueUser 是应急后门：config.yaml 的 web.username/password，且仅在从回环
// 地址访问时生效。
//
// 限定回环是这个后门可以存在的前提：它是一对明文存在配置文件里的凭据，
// 一旦对公网生效就成了整个多租户体系上的一个洞。管理员忘记密码时可以
// SSH 到中转机上从本机访问面板重置。
func (s *Server) rescueUser(r *http.Request) *models.User {
	if s.cfg.Username == "" || s.cfg.Password == "" {
		return nil
	}
	if !isLoopbackRequest(r) {
		return nil
	}
	u, p, ok := r.BasicAuth()
	if !ok {
		return nil
	}
	if !auth.ConstantTimeEqual(u, s.cfg.Username) || !auth.ConstantTimeEqual(p, s.cfg.Password) {
		return nil
	}
	return &models.User{
		ID:       "rescue",
		Username: s.cfg.Username + " (本机应急)",
		Role:     models.RoleAdmin,
	}
}

// isLoopbackRequest 判断请求是否来自本机。
func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkOrigin 对写操作做同源校验。
//
// 只在请求带了 Origin/Referer 时才校验：非浏览器客户端（curl、脚本）不带这些
// 头，拒绝它们只会打断正常的自动化用法，而 CSRF 的前提本来就是浏览器。
func checkOrigin(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		if ref := r.Header.Get("Referer"); ref != "" {
			origin = ref
		}
	}
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func unauthorized(w http.ResponseWriter) {
	fail(w, http.StatusUnauthorized, "请先登录 | authentication required")
}

// writeUserError 把用户服务的错误映射成 HTTP 状态码。
func writeUserError(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		return
	case isErr(err, users.ErrBadCredentials), isErr(err, users.ErrUserDisabled):
		fail(w, http.StatusUnauthorized, err.Error())
	case isErr(err, errForbidden):
		fail(w, http.StatusForbidden, err.Error())
	case isErr(err, storage.ErrUserNotFound):
		fail(w, http.StatusNotFound, err.Error())
	case isErr(err, storage.ErrUserExists):
		fail(w, http.StatusConflict, err.Error())
	case isErr(err, storage.ErrLastAdmin), isErr(err, storage.ErrTunPoolFull), isErr(err, users.ErrInvalidUser):
		fail(w, http.StatusBadRequest, err.Error())
	default:
		internalError(w, err)
	}
}
