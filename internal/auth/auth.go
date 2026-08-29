// Package auth 提供 Web 面板的身份认证：密码哈希、内存会话表与请求上下文。
//
// 会话只存在内存里，进程重启即全部失效。这是有意的取舍：把会话落盘会让
// 「重启进程」不再是一个干净的兜底手段（比如密钥泄漏后），而多租户面板的
// 使用频率远低于强制重新登录带来的代价。
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go-port-forward/internal/models"

	"golang.org/x/crypto/bcrypt"
)

// CookieName 是会话 cookie 名。
const CookieName = "pf_session"

// SessionTTL 是会话的滑动过期时间：每次成功鉴权都会顺延。
const SessionTTL = 12 * time.Hour

// bcryptCost 采用库默认值（10）。调高会让登录明显变慢却挡不住已泄漏的哈希，
// 面板的实际威胁是弱密码而不是离线爆破速度。
const bcryptCost = bcrypt.DefaultCost

// HashPassword 生成 bcrypt 哈希。
func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// CheckPassword 校验密码。哈希为空时恒失败（避免"未设置密码"变成免密登录）。
func CheckPassword(hash, pw string) bool {
	if hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// RandomSecret 生成 n 字节随机数据的 base64 文本（隧道密钥、初始密码用）。
func RandomSecret(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// RandomPassword 生成便于人工转录的随机初始密码（无易混淆字符）。
func RandomPassword(n int) (string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out), nil
}

type session struct {
	userID    string
	expiresAt time.Time
}

// Store 是内存会话表。
type Store struct {
	mu       sync.Mutex
	sessions map[string]*session
	secure   bool // cookie 是否带 Secure 标记（置于 TLS 之后时应开启）
}

// NewStore 创建会话表。secure 对应 config 的 web.secure_cookie。
func NewStore(secure bool) *Store {
	return &Store{sessions: make(map[string]*session), secure: secure}
}

// Issue 为用户签发一个会话令牌。
func (s *Store) Issue(userID string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	s.mu.Lock()
	s.sessions[token] = &session{userID: userID, expiresAt: time.Now().Add(SessionTTL)}
	s.mu.Unlock()
	return token, nil
}

// Lookup 校验令牌并顺延过期时间，返回用户 ID。
func (s *Store) Lookup(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return "", false
	}
	if now.After(sess.expiresAt) {
		delete(s.sessions, token)
		return "", false
	}
	sess.expiresAt = now.Add(SessionTTL)
	return sess.userID, true
}

// Revoke 注销一个令牌。
func (s *Store) Revoke(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// RevokeUser 注销某用户的全部会话（改密码、停用、删除时调用）。
//
// 漏掉这一步会让「停用用户」变成纸面操作：对方手上的 cookie 仍然有效，
// 直到 12 小时后自然过期。
func (s *Store) RevokeUser(userID string) {
	s.mu.Lock()
	for token, sess := range s.sessions {
		if sess.userID == userID {
			delete(s.sessions, token)
		}
	}
	s.mu.Unlock()
}

// Sweep 清理已过期会话（周期调用，避免长期运行下 map 只增不减）。
func (s *Store) Sweep() {
	now := time.Now()
	s.mu.Lock()
	for token, sess := range s.sessions {
		if now.After(sess.expiresAt) {
			delete(s.sessions, token)
		}
	}
	s.mu.Unlock()
}

// Count 返回当前会话数（诊断用）。
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// SetCookie 下发会话 cookie。
//
// HttpOnly 挡住 XSS 读取；SameSite=Strict 让跨站请求不带上 cookie，这也是
// 本项目 CSRF 防护的主力（配合 Origin 校验，不引入令牌双提交）。
func (s *Store) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(SessionTTL / time.Second),
	})
}

// ClearCookie 清除会话 cookie。
func (s *Store) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// TokenFromRequest 取出请求携带的会话令牌。
func TokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// --- 请求上下文 ---

type ctxKey struct{}

// WithUser 把当前用户放进请求上下文。
func WithUser(ctx context.Context, u *models.User) context.Context {
	return context.WithValue(ctx, ctxKey{}, u)
}

// UserFrom 取出当前用户；未登录返回 nil。
func UserFrom(ctx context.Context) *models.User {
	u, _ := ctx.Value(ctxKey{}).(*models.User)
	return u
}

// ConstantTimeEqual 常量时间比较（应急后门账号用）。
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ErrUnauthorized 是未认证错误。
var ErrUnauthorized = fmt.Errorf("unauthorized")
