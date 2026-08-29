package storage

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

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
	testGW   = netip.MustParseAddr("10.66.0.1")
)

func makeUser(id, name, role string) *models.User {
	return &models.User{ID: id, Username: name, Role: role, PasswordHash: "h"}
}

func makeCode(id, userID, name string) *models.AccessCode {
	return &models.AccessCode{ID: id, UserID: userID, Name: name, Secret: "c2VjcmV0"}
}

// 密码哈希必须真的落盘。models.User 上的 PasswordHash 带 json:"-"（它同时是
// API 响应体），若持久化直接复用那个结构体，重启后所有用户都会变成「密码为空」
// ——登录当场失效。
func TestUserSecretsPersist(t *testing.T) {
	s := newUserStore(t)
	u := makeUser("u1", "alice", models.RoleUser)
	u.PasswordHash = "$2a$10$hash"
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUser("u1")
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordHash != "$2a$10$hash" {
		t.Fatalf("password hash lost: %q", got.PasswordHash)
	}
}

// 访问码的密钥与设备指纹同理：codeRecord 是它们唯一的落盘通道。
func TestAccessCodeSecretsPersist(t *testing.T) {
	s := newUserStore(t)
	if err := s.CreateUser(makeUser("u1", "alice", models.RoleUser)); err != nil {
		t.Fatal(err)
	}
	c := makeCode("c1", "u1", "家里的服务器")
	c.Secret = "c2VjcmV0LWtleQ=="
	if err := s.CreateAccessCode(c, testPool, testGW, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.BindAccessCodeDevice("c1", "abcd1234", "abcd…1234", time.Now(), "203.0.113.9:1000"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAccessCode("c1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Secret != "c2VjcmV0LWtleQ==" {
		t.Fatalf("tunnel secret lost: %q", got.Secret)
	}
	if got.DeviceFingerprint != "abcd1234" {
		t.Fatalf("device fingerprint lost: %q", got.DeviceFingerprint)
	}
	if got.LastSeenAddr != "203.0.113.9:1000" || got.BoundAt.IsZero() {
		t.Fatalf("绑定元数据未落盘：%+v", got)
	}
}

// 隧道地址顺序分配，跳过网关，且跨访问码不重复。重复的隧道地址会让出向包
// 路由到错误的会话——静默的串号故障。
func TestTunIPAllocationIsUniqueAcrossCodes(t *testing.T) {
	s := newUserStore(t)
	if err := s.CreateUser(makeUser("u1", "alice", models.RoleUser)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(makeUser("u2", "bob", models.RoleUser)); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		owner := "u1"
		if i%2 == 1 {
			owner = "u2"
		}
		c := makeCode("c"+string(rune('a'+i)), owner, "code")
		if err := s.CreateAccessCode(c, testPool, testGW, 0); err != nil {
			t.Fatal(err)
		}
		if c.TunIP == testGW.String() {
			t.Fatal("分配到了网关地址")
		}
		if seen[c.TunIP] {
			t.Fatalf("隧道地址重复分配：%s", c.TunIP)
		}
		seen[c.TunIP] = true
	}
	first, err := s.GetAccessCode("ca")
	if err != nil {
		t.Fatal(err)
	}
	if first.TunIP != "10.66.0.2" {
		t.Fatalf("首个分配地址 = %s, want 10.66.0.2", first.TunIP)
	}
}

// 删除访问码后其地址应可被复用（否则长期增删会耗尽网段）。
func TestTunIPReusedAfterCodeDelete(t *testing.T) {
	s := newUserStore(t)
	if err := s.CreateUser(makeUser("u1", "alice", models.RoleUser)); err != nil {
		t.Fatal(err)
	}
	a := makeCode("c1", "u1", "a")
	if err := s.CreateAccessCode(a, testPool, testGW, 0); err != nil {
		t.Fatal(err)
	}
	freed := a.TunIP
	if err := s.DeleteAccessCode("c1"); err != nil {
		t.Fatal(err)
	}
	b := makeCode("c2", "u1", "b")
	if err := s.CreateAccessCode(b, testPool, testGW, 0); err != nil {
		t.Fatal(err)
	}
	if b.TunIP != freed {
		t.Fatalf("释放的地址未被复用：%s（期望 %s）", b.TunIP, freed)
	}
}

// 配额检查在分配事务内：超上限必须拒绝，且错误可被上层识别。
func TestAccessCodeQuotaEnforced(t *testing.T) {
	s := newUserStore(t)
	if err := s.CreateUser(makeUser("u1", "alice", models.RoleUser)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		c := makeCode("c"+string(rune('a'+i)), "u1", "code")
		if err := s.CreateAccessCode(c, testPool, testGW, 2); err != nil {
			t.Fatal(err)
		}
	}
	err := s.CreateAccessCode(makeCode("cz", "u1", "third"), testPool, testGW, 2)
	if !errors.Is(err, ErrCodeQuota) {
		t.Fatalf("超配额应返回 ErrCodeQuota，得到 %v", err)
	}
	// 上限 0 = 不限。
	if err := s.CreateAccessCode(makeCode("cz", "u1", "third"), testPool, testGW, 0); err != nil {
		t.Fatalf("上限 0 应表示不限：%v", err)
	}
	// 别人的访问码不占我的配额。
	if err := s.CreateUser(makeUser("u2", "bob", models.RoleUser)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAccessCode(makeCode("cb1", "u2", "bob-code"), testPool, testGW, 2); err != nil {
		t.Fatalf("另一个用户的配额不应被占用：%v", err)
	}
}

func TestTunIPPoolExhausted(t *testing.T) {
	s := newUserStore(t)
	if err := s.CreateUser(makeUser("u1", "alice", models.RoleUser)); err != nil {
		t.Fatal(err)
	}
	// /30 只有 .1(网关) .2 两个可用主机位，去掉网关后只剩一个。
	small := netip.MustParsePrefix("10.99.0.0/30")
	gw := netip.MustParseAddr("10.99.0.1")
	if err := s.CreateAccessCode(makeCode("c1", "u1", "a"), small, gw, 0); err != nil {
		t.Fatal(err)
	}
	err := s.CreateAccessCode(makeCode("c2", "u1", "b"), small, gw, 0)
	if !errors.Is(err, ErrTunPoolFull) {
		t.Fatalf("地址池耗尽应返回 ErrTunPoolFull，得到 %v", err)
	}
	// 错误信息要给出可操作的建议，否则运维只知道"满了"。
	if !contains(err.Error(), "tunnel.tun_addr") {
		t.Fatalf("错误信息应提示扩大网段：%v", err)
	}
}

// 设备绑定的判定必须在事务内：两台设备同时首连时只有一台能绑上。
func TestDeviceBindIsExclusive(t *testing.T) {
	s := newUserStore(t)
	if err := s.CreateUser(makeUser("u1", "alice", models.RoleUser)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAccessCode(makeCode("c1", "u1", "a"), testPool, testGW, 0); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.BindAccessCodeDevice("c1", "aaaa", "aaaa", now, "1.1.1.1:1"); err != nil {
		t.Fatal(err)
	}
	// 同一设备重连：只刷新活跃信息，不报错。
	if err := s.BindAccessCodeDevice("c1", "aaaa", "aaaa", now.Add(time.Minute), "1.1.1.1:2"); err != nil {
		t.Fatalf("同设备重连应通过：%v", err)
	}
	// 另一台设备：拒绝。
	if err := s.BindAccessCodeDevice("c1", "bbbb", "bbbb", now, "2.2.2.2:1"); !errors.Is(err, ErrDeviceMismatch) {
		t.Fatalf("异设备应返回 ErrDeviceMismatch，得到 %v", err)
	}
	got, _ := s.GetAccessCode("c1")
	if got.DeviceFingerprint != "aaaa" {
		t.Fatalf("绑定被覆盖了：%q", got.DeviceFingerprint)
	}
	if got.LastSeenAddr != "1.1.1.1:2" {
		t.Fatalf("同设备重连应刷新来源地址：%q", got.LastSeenAddr)
	}
}

// 解绑后另一台设备才能绑上。
func TestDeviceUnbindAllowsRebind(t *testing.T) {
	s := newUserStore(t)
	if err := s.CreateUser(makeUser("u1", "alice", models.RoleUser)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAccessCode(makeCode("c1", "u1", "a"), testPool, testGW, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.BindAccessCodeDevice("c1", "aaaa", "aa…aa", time.Now(), "1.1.1.1:1"); err != nil {
		t.Fatal(err)
	}
	prev, err := s.UnbindAccessCodeDevice("c1")
	if err != nil {
		t.Fatal(err)
	}
	if prev != "aa…aa" {
		t.Fatalf("解绑应返回原绑定摘要（供审计），得到 %q", prev)
	}
	if err := s.BindAccessCodeDevice("c1", "bbbb", "bbbb", time.Now(), "2.2.2.2:1"); err != nil {
		t.Fatalf("解绑后应可绑新设备：%v", err)
	}
}

// 删除用户要连带删掉其访问码：留着会变成永远无人认领的孤儿凭据，而它仍然
// 能建立隧道。
func TestDeleteAccessCodesByUser(t *testing.T) {
	s := newUserStore(t)
	for _, id := range []string{"u1", "u2"} {
		if err := s.CreateUser(makeUser(id, "user-"+id, models.RoleUser)); err != nil {
			t.Fatal(err)
		}
	}
	for i, owner := range []string{"u1", "u1", "u2"} {
		if err := s.CreateAccessCode(makeCode("c"+string(rune('a'+i)), owner, "c"), testPool, testGW, 0); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.DeleteAccessCodesByUser("u1")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("删除数 = %d, want 2", n)
	}
	if left, _ := s.CountAccessCodesByUser("u1"); left != 0 {
		t.Fatalf("u1 仍有 %d 个访问码", left)
	}
	if left, _ := s.CountAccessCodesByUser("u2"); left != 1 {
		t.Fatalf("u2 的访问码被误删：%d", left)
	}
}

func TestDuplicateUsernameRejected(t *testing.T) {
	s := newUserStore(t)
	if err := s.CreateUser(makeUser("u1", "alice", models.RoleUser)); err != nil {
		t.Fatal(err)
	}
	// 用户名比较不分大小写：否则 Alice 与 alice 会成为两个账号，登录时
	// GetUserByName 只会命中其中一个，另一个永远登不上去。
	err := s.CreateUser(makeUser("u2", "ALICE", models.RoleUser))
	if !errors.Is(err, ErrUserExists) {
		t.Fatalf("重名应返回 ErrUserExists，得到 %v", err)
	}
}

func TestGetUserByNameIsCaseInsensitive(t *testing.T) {
	s := newUserStore(t)
	if err := s.CreateUser(makeUser("u1", "alice", models.RoleUser)); err != nil {
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
	if err := s.CreateUser(makeUser("admin", "admin", models.RoleAdmin)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(makeUser("u1", "alice", models.RoleUser)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser("admin"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("删除最后一个管理员应被拒，得到 %v", err)
	}
	if err := s.CreateUser(makeUser("admin2", "admin2", models.RoleAdmin)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser("admin"); err != nil {
		t.Fatalf("存在其它管理员时应可删除：%v", err)
	}
}

// 停用的管理员不计入「还剩几个管理员」。
func TestDisabledAdminDoesNotCount(t *testing.T) {
	s := newUserStore(t)
	if err := s.CreateUser(makeUser("a1", "admin1", models.RoleAdmin)); err != nil {
		t.Fatal(err)
	}
	a2 := makeUser("a2", "admin2", models.RoleAdmin)
	a2.Disabled = true
	if err := s.CreateUser(a2); err != nil {
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
	if err := s.CreateUser(u); err != nil {
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
	pool, gw, err := ParseTunnelPrefix("10.66.0.1/16")
	if err != nil {
		t.Fatal(err)
	}
	if pool.String() != "10.66.0.0/16" || gw.String() != "10.66.0.1" {
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
	if got := lastAddr(netip.MustParsePrefix("10.66.0.0/16")); got.String() != "10.66.255.255" {
		t.Fatalf("/16 广播地址 = %v", got)
	}
	if got := lastAddr(netip.MustParsePrefix("10.66.0.0/30")); got.String() != "10.66.0.3" {
		t.Fatalf("/30 广播地址 = %v", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
