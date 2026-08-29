package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go-port-forward/internal/models"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(hash, "correct horse battery") {
		t.Fatal("正确密码应通过")
	}
	if CheckPassword(hash, "wrong") {
		t.Fatal("错误密码必须被拒")
	}
}

// 空哈希必须恒失败。若返回 true，「未设置密码的用户」就等于免密登录。
func TestEmptyHashNeverPasses(t *testing.T) {
	if CheckPassword("", "") || CheckPassword("", "anything") {
		t.Fatal("空哈希不得通过任何密码")
	}
}

func TestSessionIssueAndLookup(t *testing.T) {
	s := NewStore(false)
	token, err := s.Issue("u1")
	if err != nil {
		t.Fatal(err)
	}
	if uid, ok := s.Lookup(token); !ok || uid != "u1" {
		t.Fatalf("Lookup = %q, %v", uid, ok)
	}
	if _, ok := s.Lookup("bogus"); ok {
		t.Fatal("未知令牌不得通过")
	}
	if _, ok := s.Lookup(""); ok {
		t.Fatal("空令牌不得通过")
	}
}

func TestSessionExpiry(t *testing.T) {
	s := NewStore(false)
	token, _ := s.Issue("u1")
	// 手工把过期时间推回过去。
	s.mu.Lock()
	s.sessions[token].expiresAt = time.Now().Add(-time.Second)
	s.mu.Unlock()
	if _, ok := s.Lookup(token); ok {
		t.Fatal("过期会话不得通过")
	}
	if s.Count() != 0 {
		t.Fatal("过期会话应在查询时被清理")
	}
}

// 滑动过期：每次成功鉴权都顺延，否则用户会在使用中被强制登出。
func TestSessionSlidingExpiry(t *testing.T) {
	s := NewStore(false)
	token, _ := s.Issue("u1")
	s.mu.Lock()
	original := s.sessions[token].expiresAt
	s.sessions[token].expiresAt = time.Now().Add(time.Minute)
	s.mu.Unlock()
	if _, ok := s.Lookup(token); !ok {
		t.Fatal("未过期会话应通过")
	}
	s.mu.Lock()
	renewed := s.sessions[token].expiresAt
	s.mu.Unlock()
	if !renewed.After(original.Add(-time.Hour)) || renewed.Before(time.Now().Add(SessionTTL-time.Minute)) {
		t.Fatalf("过期时间未顺延：%v", renewed)
	}
}

// 停用/改密时必须能一次注销某用户的全部会话。少了这一步，「停用用户」只是
// 界面上的状态，对方手上的 cookie 仍然有效直到自然过期。
func TestRevokeUserDropsAllSessions(t *testing.T) {
	s := NewStore(false)
	t1, _ := s.Issue("u1")
	t2, _ := s.Issue("u1")
	other, _ := s.Issue("u2")

	s.RevokeUser("u1")
	if _, ok := s.Lookup(t1); ok {
		t.Fatal("u1 的会话 1 未被注销")
	}
	if _, ok := s.Lookup(t2); ok {
		t.Fatal("u1 的会话 2 未被注销")
	}
	if _, ok := s.Lookup(other); !ok {
		t.Fatal("其它用户的会话被误注销")
	}
}

func TestRevokeSingleToken(t *testing.T) {
	s := NewStore(false)
	t1, _ := s.Issue("u1")
	t2, _ := s.Issue("u1")
	s.Revoke(t1)
	if _, ok := s.Lookup(t1); ok {
		t.Fatal("被注销的令牌仍可用")
	}
	if _, ok := s.Lookup(t2); !ok {
		t.Fatal("同用户的另一个令牌被误注销")
	}
}

func TestSweepRemovesExpired(t *testing.T) {
	s := NewStore(false)
	expired, _ := s.Issue("u1")
	alive, _ := s.Issue("u2")
	s.mu.Lock()
	s.sessions[expired].expiresAt = time.Now().Add(-time.Hour)
	s.mu.Unlock()
	s.Sweep()
	if s.Count() != 1 {
		t.Fatalf("清理后会话数 = %d, want 1", s.Count())
	}
	if _, ok := s.Lookup(alive); !ok {
		t.Fatal("未过期会话被误清")
	}
}

func TestTokensAreUnique(t *testing.T) {
	s := NewStore(false)
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		tok, err := s.Issue("u1")
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok] {
			t.Fatal("令牌重复")
		}
		seen[tok] = true
	}
}

// cookie 属性直接决定 CSRF 防护是否成立：SameSite=Strict 是主力，
// HttpOnly 挡 XSS 读取。
func TestCookieAttributes(t *testing.T) {
	s := NewStore(true)
	rec := httptest.NewRecorder()
	s.SetCookie(rec, "tok")
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookie 数 = %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != CookieName || c.Value != "tok" {
		t.Fatalf("cookie = %+v", c)
	}
	if !c.HttpOnly {
		t.Fatal("必须 HttpOnly")
	}
	if !c.Secure {
		t.Fatal("secure_cookie=true 时必须带 Secure")
	}
	if c.SameSite != 3 { // http.SameSiteStrictMode
		t.Fatalf("SameSite = %v, want Strict", c.SameSite)
	}
	if c.Path != "/" {
		t.Fatalf("Path = %q", c.Path)
	}
}

func TestClearCookie(t *testing.T) {
	s := NewStore(false)
	rec := httptest.NewRecorder()
	s.ClearCookie(rec)
	c := rec.Result().Cookies()[0]
	if c.MaxAge >= 0 || c.Value != "" {
		t.Fatalf("清除 cookie 应置空并设负 MaxAge：%+v", c)
	}
}

func TestTokenFromRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if got := TokenFromRequest(r); got != "" {
		t.Fatalf("无 cookie 应返回空，得到 %q", got)
	}
	r.AddCookie(&http.Cookie{Name: CookieName, Value: "abc"})
	if got := TokenFromRequest(r); got != "abc" {
		t.Fatalf("token = %q", got)
	}
}

func TestUserContextRoundTrip(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if UserFrom(r.Context()) != nil {
		t.Fatal("空上下文应返回 nil")
	}
	u := &models.User{ID: "u1", Role: models.RoleAdmin}
	r = r.WithContext(WithUser(r.Context(), u))
	got := UserFrom(r.Context())
	if got == nil || got.ID != "u1" || !got.IsAdmin() {
		t.Fatalf("UserFrom = %+v", got)
	}
}

func TestRandomHelpers(t *testing.T) {
	a, err := RandomSecret(32)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := RandomSecret(32)
	if a == b || a == "" {
		t.Fatal("随机密钥应各不相同且非空")
	}
	pw, err := RandomPassword(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 16 {
		t.Fatalf("密码长度 = %d", len(pw))
	}
	// 初始密码要人工转录，不能含易混淆字符。
	for _, r := range pw {
		switch r {
		case 'l', 'I', '1', 'O', '0', 'o':
			t.Fatalf("初始密码含易混淆字符：%q", pw)
		}
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual("abc", "abc") {
		t.Fatal("相同字符串应相等")
	}
	if ConstantTimeEqual("abc", "abd") || ConstantTimeEqual("abc", "ab") {
		t.Fatal("不同字符串必须不等")
	}
}
