package storage

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

	"go-port-forward/internal/models"
)

func newUserStore(t *testing.T) Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

var (
	testPool = netip.MustParsePrefix("10.66.0.0/24")
	testGW    = netip.MustParseAddr("10.66.0.1")
)

func makeUser(id, name, role string) *models.User {
	return &models.User{ID: id, Username: name, Role: role, PasswordHash: "h", TunnelSecret: "s"}
}

// 密钥字段必须真的落盘。models.User 上的 PasswordHash/TunnelSecret 带
// json:"-"（它同时是 API 响应体），若持久化直接复用那个结构体，重启后所有
// 用户都会变成「密码为空、隧道密钥为空」——登录与握手同时失效。
func TestUserSecretsPersist(t *testing.T) {
	s := newUserStore(t)
	u := makeUser("u1", "alice", models.RoleUser)
	u.PasswordHash = "$2a$10$hash"
	u.TunnelSecret = "c2VjcmV0"
	if err := s.CreateUser(u, testPool, testGW); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUser("u1")
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordHash != "$2a$10$hash" {
		t.Fatalf("password hash lost: %q", got.PasswordHash)
	}
	if got.TunnelSecret != "c2VjcmV0" {
		t.Fatalf("tunnel secret lost: %q", got.TunnelSecret)
	}
}

// 隧道地址顺序分配，跳过网关，且不重复。重复的隧道地址会让出向包路由到
// 错误的会话——这是静默的串号故障。
func TestTunIPAllocationIsUniqueAndSkipsGateway(t *testing.T) {
	s := newUserStore(t)
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		u := makeUser("u"+string(rune('a'+i)), "user"+string(rune('a'+i)), models.RoleUser)
		if err := s.CreateUser(u, testPool, testGW); err != nil {
			t.Fatal(err)
		}
		if u.TunIP == testGW.String() {
			t.Fatal("分配到了网关地址")
		}
		if seen[u.TunIP] {
			t.Fatalf("隧道地址重复分配：%s", u.TunIP)
		}
		seen[u.TunIP] = true
	}
	// 第一个用户应拿到网关之后的第一个地址（网络号与网关都跳过）。
	first, err := s.GetUser("ua")
	if err != nil {
		t.Fatal(err)
	}
	if first.TunIP != "10.66.0.2" {
		t.Fatalf("首个分配地址 = %s, want 10.66.0.2", first.TunIP)
	}
}

// 删除用户后其地址应可被复用（否则长期增删会耗尽 /24 的 253 个位置）。
func TestTunIPReusedAfterDelete(t *testing.T) {
	s := newUserStore(t)
	a := makeUser("u1", "alice", models.RoleUser)
	if err := s.CreateUser(a, testPool, testGW); err != nil {
		t.Fatal(err)
	}
	freed := a.TunIP
	if err := s.DeleteUser("u1"); err != nil {
		t.Fatal(err)
	}
	b := makeUser("u2", "bob", models.RoleUser)
	if err := s.CreateUser(b, testPool, testGW); err != nil {
		t.Fatal(err)
	}
	if b.TunIP != freed {
		t.Fatalf("释放的地址未被复用：%s（期望 %s）", b.TunIP, freed)
	}
}

func TestTunIPPoolExhausted(t *testing.T) {
	s := newUserStore(t)
	// /30 只有 .1(网关) .2 两个可用主机位，去掉网关后只剩一个。
	small := netip.MustParsePrefix("10.99.0.0/30")
	gw := netip.MustParseAddr("10.99.0.1")
	if err := s.CreateUser(makeUser("u1", "alice", models.RoleUser), small, gw); err != nil {
		t.Fatal(err)
	}
	err := s.CreateUser(makeUser("u2", "bob", models.RoleUser), small, gw)
	if !errors.Is(err, ErrTunPoolFull) {
		t.Fatalf("地址池耗尽应返回 ErrTunPoolFull，得到 %v", err)
	}
}

func TestDuplicateUsernameRejected(t *testing.T) {
	s := newUserStore(t)
	if err := s.CreateUser(makeUser("u1", "alice", models.RoleUser), testPool, testGW); err != nil {
		t.Fatal(err)
	}
	// 用户名比较不分大小写：否则 Alice 与 alice 会成为两个账号，登录时
	// GetUserByName 只会命中其中一个，另一个永远登不上去。
	err := s.CreateUser(makeUser("u2", "ALICE", models.RoleUser), testPool, testGW)
	if !errors.Is(err, ErrUserExists) {
		t.Fatalf("重名应返回 ErrUserExists，得到 %v", err)
	}
}

func TestGetUserByNameIsCaseInsensitive(t *testing.T) {
	s := newUserStore(t)
	if err := s.CreateUser(makeUser("u1", "alice", models.RoleUser), testPool, testGW); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUserByName("ALICE")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "u1" {
		t.Fatalf("id = %s", got.ID)
	}
	if _, err := s.GetUserByName("nobody"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("未知用户应返回 ErrUserNotFound，得到 %v", err)
	}
}

// 删掉最后一个管理员会让面板永久失去管理入口。
func TestDeleteLastAdminRejected(t *testing.T) {
	s := newUserStore(t)
	if err := s.CreateUser(makeUser("admin", "admin", models.RoleAdmin), testPool, testGW); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(makeUser("u1", "alice", models.RoleUser), testPool, testGW); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser("admin"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("删除最后一个管理员应被拒，得到 %v", err)
	}
	// 有第二个管理员时可以删。
	if err := s.CreateUser(makeUser("admin2", "admin2", models.RoleAdmin), testPool, testGW); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser("admin"); err != nil {
		t.Fatalf("存在其它管理员时应可删除：%v", err)
	}
}

// 停用的管理员不计入「还剩几个管理员」。
func TestDisabledAdminDoesNotCount(t *testing.T) {
	s := newUserStore(t)
	if err := s.CreateUser(makeUser("a1", "admin1", models.RoleAdmin), testPool, testGW); err != nil {
		t.Fatal(err)
	}
	a2 := makeUser("a2", "admin2", models.RoleAdmin)
	a2.Disabled = true
	if err := s.CreateUser(a2, testPool, testGW); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser("a1"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("唯一启用的管理员应不可删，得到 %v", err)
	}
}

func TestCountUsersAndSaveUser(t *testing.T) {
	s := newUserStore(t)
	if n, err := s.CountUsers(); err != nil || n != 0 {
		t.Fatalf("初始用户数 = %d, %v", n, err)
	}
	u := makeUser("u1", "alice", models.RoleUser)
	if err := s.CreateUser(u, testPool, testGW); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountUsers(); n != 1 {
		t.Fatalf("用户数 = %d, want 1", n)
	}
	u.Comment = "改过了"
	if err := s.SaveUser(u); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetUser("u1")
	if got.Comment != "改过了" {
		t.Fatalf("comment = %q", got.Comment)
	}
	// SaveUser 不得创建新记录：它是"覆盖已存在"的语义，静默插入会掩盖
	// 调用方传错 ID 的 bug。
	if err := s.SaveUser(makeUser("ghost", "ghost", models.RoleUser)); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("SaveUser 对不存在的用户应报错，得到 %v", err)
	}
}

func TestParseTunnelPrefix(t *testing.T) {
	pool, gw, err := ParseTunnelPrefix("10.66.0.1/24")
	if err != nil {
		t.Fatal(err)
	}
	if pool.String() != "10.66.0.0/24" || gw.String() != "10.66.0.1" {
		t.Fatalf("pool=%v gw=%v", pool, gw)
	}
	if _, _, err := ParseTunnelPrefix("10.66.0.1"); err == nil {
		t.Fatal("缺前缀长度应报错")
	}
	if _, _, err := ParseTunnelPrefix("fd00::1/64"); err == nil {
		t.Fatal("IPv6 应被拒")
	}
}

func TestLastAddr(t *testing.T) {
	if got := lastAddr(netip.MustParsePrefix("10.66.0.0/24")); got.String() != "10.66.0.255" {
		t.Fatalf("/24 广播地址 = %v", got)
	}
	if got := lastAddr(netip.MustParsePrefix("10.66.0.0/30")); got.String() != "10.66.0.3" {
		t.Fatalf("/30 广播地址 = %v", got)
	}
}
