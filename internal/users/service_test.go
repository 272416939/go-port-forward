package users

import (
	"errors"
	"path/filepath"
	"testing"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
	"go-port-forward/pkg/accesscode"

	"go.uber.org/zap"
)

func newService(t *testing.T) (*Service, *auth.Store) {
	t.Helper()
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	store, err := storage.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	sessions := auth.NewStore(false)
	svc, err := New(store, sessions, "10.66.0.1/24", "203.0.113.9:7947")
	if err != nil {
		t.Fatal(err)
	}
	return svc, sessions
}

func mustCreate(t *testing.T, s *Service, name, role string) *models.User {
	t.Helper()
	u, err := s.Create(&models.CreateUserRequest{
		Username: name, Password: "password123", Role: role,
		PortRangeStart: 20000, PortRangeEnd: 20099, MaxRules: 3,
	})
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return u
}

func TestCreateAssignsSecretAndTunIP(t *testing.T) {
	s, _ := newService(t)
	u := mustCreate(t, s, "alice", models.RoleUser)
	if u.TunnelSecret == "" {
		t.Fatal("未生成隧道密钥")
	}
	if u.TunIP == "" {
		t.Fatal("未分配隧道地址")
	}
	if u.PasswordHash == "" || u.PasswordHash == "password123" {
		t.Fatalf("密码未哈希：%q", u.PasswordHash)
	}
	// 两个用户的密钥必须不同，否则一个用户的接入码能开另一个的隧道。
	b := mustCreate(t, s, "bob", models.RoleUser)
	if b.TunnelSecret == u.TunnelSecret {
		t.Fatal("两个用户拿到了相同的隧道密钥")
	}
	if b.TunIP == u.TunIP {
		t.Fatal("两个用户拿到了相同的隧道地址")
	}
}

func TestAuthenticate(t *testing.T) {
	s, _ := newService(t)
	mustCreate(t, s, "alice", models.RoleUser)

	if _, err := s.Authenticate("alice", "password123"); err != nil {
		t.Fatalf("正确凭据应通过：%v", err)
	}
	if _, err := s.Authenticate("ALICE", "password123"); err != nil {
		t.Fatalf("用户名应不分大小写：%v", err)
	}
	if _, err := s.Authenticate("alice", "wrong"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("错误密码应返回 ErrBadCredentials，得到 %v", err)
	}
	// 用户不存在与密码错误必须返回同一个错误，否则接口成了用户名枚举器。
	if _, err := s.Authenticate("nobody", "whatever"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("未知用户应返回 ErrBadCredentials，得到 %v", err)
	}
}

func TestAuthenticateRejectsDisabled(t *testing.T) {
	s, _ := newService(t)
	u := mustCreate(t, s, "alice", models.RoleUser)
	yes := true
	if _, err := s.Update(u.ID, &models.UpdateUserRequest{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate("alice", "password123"); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("停用账号应被拒，得到 %v", err)
	}
}

// 停用用户必须立即注销其会话。否则「停用」只是界面状态，对方手里的 cookie
// 仍然有效到自然过期。
func TestDisableRevokesSessions(t *testing.T) {
	s, sessions := newService(t)
	u := mustCreate(t, s, "alice", models.RoleUser)
	token, _ := sessions.Issue(u.ID)

	yes := true
	if _, err := s.Update(u.ID, &models.UpdateUserRequest{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	if _, ok := sessions.Lookup(token); ok {
		t.Fatal("停用后会话未被注销")
	}
}

// 改密同样要注销全部会话，否则改密码挡不住已经登录的人。
func TestPasswordChangeRevokesSessions(t *testing.T) {
	s, sessions := newService(t)
	u := mustCreate(t, s, "alice", models.RoleUser)
	token, _ := sessions.Issue(u.ID)

	if err := s.ChangeOwnPassword(u.ID, "password123", "newpassword456"); err != nil {
		t.Fatal(err)
	}
	if _, ok := sessions.Lookup(token); ok {
		t.Fatal("改密后会话未被注销")
	}
	if _, err := s.Authenticate("alice", "newpassword456"); err != nil {
		t.Fatalf("新密码应可登录：%v", err)
	}
	if _, err := s.Authenticate("alice", "password123"); err == nil {
		t.Fatal("旧密码不应再可用")
	}
}

func TestChangeOwnPasswordChecksOld(t *testing.T) {
	s, _ := newService(t)
	u := mustCreate(t, s, "alice", models.RoleUser)
	if err := s.ChangeOwnPassword(u.ID, "wrong", "newpassword456"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("旧密码错误应被拒，得到 %v", err)
	}
	if err := s.ChangeOwnPassword(u.ID, "password123", "short"); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("弱新密码应被拒，得到 %v", err)
	}
	if err := s.ChangeOwnPassword(u.ID, "password123", "password123"); !errors.Is(err, ErrInvalidUser) {
		t.Fatal("新旧密码相同应被拒")
	}
}

// 重新生成密钥后旧接入码必须失效——这是密钥泄漏时唯一的补救手段。
func TestRegenerateSecretInvalidatesOldCode(t *testing.T) {
	s, _ := newService(t)
	u := mustCreate(t, s, "alice", models.RoleUser)
	before, err := s.AccessCode(u.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegenerateSecret(u.ID); err != nil {
		t.Fatal(err)
	}
	after, err := s.AccessCode(u.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if before.Secret == after.Secret || before.Code == after.Code {
		t.Fatal("重新生成后密钥/接入码未变化")
	}
}

func TestAccessCodeRoundTrip(t *testing.T) {
	s, _ := newService(t)
	u := mustCreate(t, s, "alice", models.RoleUser)
	got, err := s.AccessCode(u.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := accesscode.Decode(got.Code)
	if err != nil {
		t.Fatalf("接入码应可解析：%v", err)
	}
	if decoded.UserID != u.ID || decoded.Secret != u.TunnelSecret {
		t.Fatalf("接入码内容不符：%+v", decoded)
	}
	if decoded.Addr != "203.0.113.9:7947" {
		t.Fatalf("接入码地址 = %q，应取 public_addr", decoded.Addr)
	}
}

// public_addr 未配置时用调用方给的兜底地址；都没有则明确报错，而不是
// 生成一个指向 127.0.0.1 的、对客户端毫无意义的接入码。
func TestAccessCodeFallbackAddr(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()
	s, err := New(store, auth.NewStore(false), "10.66.0.1/24", "")
	if err != nil {
		t.Fatal(err)
	}
	u := mustCreate(t, s, "alice", models.RoleUser)

	got, err := s.AccessCode(u.ID, "198.51.100.4")
	if err != nil {
		t.Fatal(err)
	}
	if decoded, _ := accesscode.Decode(got.Code); decoded.Addr != "198.51.100.4" {
		t.Fatalf("未使用兜底地址：%+v", decoded)
	}
	if _, err := s.AccessCode(u.ID, ""); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("无地址可用时应报错，得到 %v", err)
	}
}

func TestUpdateValidatesPortRange(t *testing.T) {
	s, _ := newService(t)
	u := mustCreate(t, s, "alice", models.RoleUser)
	start, end := 30000, 20000
	if _, err := s.Update(u.ID, &models.UpdateUserRequest{PortRangeStart: &start, PortRangeEnd: &end}); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("起点大于终点应被拒，得到 %v", err)
	}
	// 只改一端时必须与另一端的现值一起校验，否则能改出非法区间。
	bad := 30000
	if _, err := s.Update(u.ID, &models.UpdateUserRequest{PortRangeStart: &bad}); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("单改起点越过现有终点应被拒，得到 %v", err)
	}
}

// 降级最后一个管理员和删除它是同一类问题：面板会失去管理入口。
func TestCannotDemoteLastAdmin(t *testing.T) {
	s, _ := newService(t)
	admin := mustCreate(t, s, "admin", models.RoleAdmin)
	mustCreate(t, s, "alice", models.RoleUser)

	role := models.RoleUser
	if _, err := s.Update(admin.ID, &models.UpdateUserRequest{Role: &role}); !errors.Is(err, storage.ErrLastAdmin) {
		t.Fatalf("降级最后一个管理员应被拒，得到 %v", err)
	}
	yes := true
	if _, err := s.Update(admin.ID, &models.UpdateUserRequest{Disabled: &yes}); !errors.Is(err, storage.ErrLastAdmin) {
		t.Fatalf("停用最后一个管理员应被拒，得到 %v", err)
	}
}

func TestBootstrapCreatesAdminOnce(t *testing.T) {
	s, _ := newService(t)
	created, name, pw, err := s.Bootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if !created || name != BootstrapAdminName || pw == "" {
		t.Fatalf("首启引导结果异常：%v %q %q", created, name, pw)
	}
	u, err := s.GetByName(BootstrapAdminName)
	if err != nil {
		t.Fatal(err)
	}
	if !u.IsAdmin() {
		t.Fatal("引导账号应为管理员")
	}
	// 初始密码在磁盘上留过痕，必须强制首登改密。
	if !u.MustChangePassword {
		t.Fatal("引导账号应要求首次登录改密")
	}
	if _, err := s.Authenticate(BootstrapAdminName, pw); err != nil {
		t.Fatalf("引导密码应可登录：%v", err)
	}

	// 第二次启动不得再建账号（否则每次重启都多一个 admin）。
	again, _, _, err := s.Bootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if again {
		t.Fatal("已有用户时不应再次引导")
	}
}

func TestCreateRejectsDuplicateAndWeakInput(t *testing.T) {
	s, _ := newService(t)
	mustCreate(t, s, "alice", models.RoleUser)

	if _, err := s.Create(&models.CreateUserRequest{Username: "alice", Password: "password123"}); !errors.Is(err, storage.ErrUserExists) {
		t.Fatalf("重名应被拒，得到 %v", err)
	}
	if _, err := s.Create(&models.CreateUserRequest{Username: "bob", Password: "short"}); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("弱密码应被拒，得到 %v", err)
	}
	if _, err := s.Create(&models.CreateUserRequest{Username: "Bob Smith", Password: "password123"}); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("非法用户名应被拒，得到 %v", err)
	}
	if _, err := s.Create(&models.CreateUserRequest{Username: "bob", Password: "password123", Role: "root"}); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("非法角色应被拒，得到 %v", err)
	}
}

func TestDeleteRevokesSessions(t *testing.T) {
	s, sessions := newService(t)
	mustCreate(t, s, "admin", models.RoleAdmin)
	u := mustCreate(t, s, "alice", models.RoleUser)
	token, _ := sessions.Issue(u.ID)

	if err := s.Delete(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := sessions.Lookup(token); ok {
		t.Fatal("删除用户后会话未被注销")
	}
}
