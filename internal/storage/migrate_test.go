package storage

// 迁移与组/设置层的测试。

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"go-port-forward/internal/models"
	"go-port-forward/pkg/serializer/json"

	bolt "go.etcd.io/bbolt"
)

// writeLegacyDB 构造一个 v1（多用户版）的库：用户上直接挂着隧道身份与配额，
// 没有 settings/groups/codes。
func writeLegacyDB(t *testing.T, recs []userRecord) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.db")
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		b, cerr := tx.CreateBucketIfNotExists(usersBucket)
		if cerr != nil {
			return cerr
		}
		for _, r := range recs {
			data, merr := json.Marshal(&r)
			if merr != nil {
				return merr
			}
			if perr := b.Put([]byte(r.ID), data); perr != nil {
				return perr
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func legacyUser(id, name, role string, start, end, rules int) userRecord {
	return userRecord{
		CreatedAt: time.Now().Add(-time.Hour), ID: id, Username: name, Role: role,
		PasswordHash:         "$2a$10$hash-" + id,
		LegacyTunIP:          "",
		LegacyPortRangeStart: start, LegacyPortRangeEnd: end, LegacyMaxRules: rules,
	}
}

// 迁移的核心承诺：旧用户的隧道身份变成访问码，**访问码 ID 沿用原用户 ID**，
// 密钥与隧道地址原样继承。这样已经发出去的接入码在升级后依然有效，用户不必
// 重新配置客户端。
func TestMigrateV1KeepsAccessCodesUsable(t *testing.T) {
	alice := legacyUser("u-alice", "alice", models.RoleUser, 20000, 20099, 5)
	alice.LegacyTunIP = "10.66.0.5"
	alice.LegacyTunnelSecret = "alice-secret"

	path := writeLegacyDB(t, []userRecord{
		legacyUser("u-admin", "admin", models.RoleAdmin, 0, 0, 0),
		alice,
	})

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c, err := s.GetAccessCode("u-alice")
	if err != nil {
		t.Fatalf("旧用户的隧道身份应迁成同 ID 的访问码：%v", err)
	}
	if c.Secret != "alice-secret" {
		t.Fatalf("密钥未继承：%q", c.Secret)
	}
	if c.TunIP != "10.66.0.5" {
		t.Fatalf("隧道地址未继承：%q", c.TunIP)
	}
	if c.UserID != "u-alice" {
		t.Fatalf("归属错误：%q", c.UserID)
	}

	// 用户上的配额与隧道字段已清空（记录被重写）。
	u, err := s.GetUser("u-alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.PasswordHash != "$2a$10$hash-u-alice" {
		t.Fatalf("密码哈希在迁移中丢了：%q", u.PasswordHash)
	}
	if u.GroupID == "" {
		t.Fatal("普通用户应被挂到某个组上")
	}
}

// 按配额组合建组，而不是把所有人丢进默认组：后者会静默改掉现有用户的端口
// 区间，他们下次建规则才会莫名被拒。
func TestMigrateV1PreservesQuotasAsGroups(t *testing.T) {
	a := legacyUser("u-a", "alice", models.RoleUser, 20000, 20099, 5)
	b := legacyUser("u-b", "bob", models.RoleUser, 20000, 20099, 5) // 与 a 同配额
	c := legacyUser("u-c", "carol", models.RoleUser, 30000, 30099, 2)

	s, err := Open(writeLegacyDB(t, []userRecord{a, b, c}))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ua, _ := s.GetUser("u-a")
	ub, _ := s.GetUser("u-b")
	uc, _ := s.GetUser("u-c")
	if ua.GroupID != ub.GroupID {
		t.Fatal("同配额的用户应落到同一个组（去重）")
	}
	if ua.GroupID == uc.GroupID {
		t.Fatal("不同配额的用户不能共用一个组")
	}

	ga, err := s.GetGroup(ua.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	if ga.PortRangeStart != 20000 || ga.PortRangeEnd != 20099 || ga.MaxRules != 5 {
		t.Fatalf("组配额与原用户配额不符：%+v", ga)
	}
	gc, _ := s.GetGroup(uc.GroupID)
	if gc.PortRangeStart != 30000 || gc.PortRangeEnd != 30099 {
		t.Fatalf("组配额与原用户配额不符：%+v", gc)
	}

	// 全局区间必须覆盖所有迁移过来的组，否则那些组立刻处于越界状态。
	cfg, err := s.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PortRangeStart > 20000 || cfg.PortRangeEnd < 30099 {
		t.Fatalf("全局区间未覆盖迁移的组：%d-%d", cfg.PortRangeStart, cfg.PortRangeEnd)
	}
	for _, g := range []*models.UserGroup{ga, gc} {
		if verr := models.ValidateGroupAgainstSettings(g, cfg); verr != nil {
			t.Fatalf("迁移后的组越界：%v", verr)
		}
	}
}

// 迁移必须幂等：每次 Open 都会跑一遍，重复执行不能重复建组或重建访问码。
func TestMigrateIsIdempotent(t *testing.T) {
	a := legacyUser("u-a", "alice", models.RoleUser, 20000, 20099, 5)
	a.LegacyTunIP = "10.66.0.5"
	a.LegacyTunnelSecret = "s"
	path := writeLegacyDB(t, []userRecord{a})

	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	groups1, _ := s1.ListGroups()
	codes1, _ := s1.ListAccessCodes()
	_ = s1.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	groups2, _ := s2.ListGroups()
	codes2, _ := s2.ListAccessCodes()

	if len(groups1) != len(groups2) {
		t.Fatalf("第二次 Open 又建了组：%d → %d", len(groups1), len(groups2))
	}
	if len(codes1) != len(codes2) {
		t.Fatalf("第二次 Open 又建了访问码：%d → %d", len(codes1), len(codes2))
	}
}

// 全新库：写入默认设置 + 一个默认组，SchemaVersion 到位。
func TestFreshDatabaseBootstrapsSettings(t *testing.T) {
	s := newUserStore(t)
	cfg, err := s.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SchemaVersion != models.SchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", cfg.SchemaVersion, models.SchemaVersion)
	}
	if cfg.DefaultGroupID == "" {
		t.Fatal("应有默认组")
	}
	g, err := s.GetGroup(cfg.DefaultGroupID)
	if err != nil {
		t.Fatal(err)
	}
	if !g.IsDefault {
		t.Fatal("默认组应带 IsDefault 标记")
	}
	// 默认端口区间不能是"不限"：普通用户拿到不限的端口范围就能占用 22、443。
	if cfg.PortRangeStart <= 0 || cfg.PortRangeEnd <= 0 {
		t.Fatalf("默认全局端口区间不该为空：%d-%d", cfg.PortRangeStart, cfg.PortRangeEnd)
	}
}

// 默认组唯一：把第二个组设为默认时，第一个的标记要被清掉。否则新建用户会
// 随机落到其中一个。
func TestOnlyOneDefaultGroup(t *testing.T) {
	s := newUserStore(t)
	cfg, _ := s.Settings()
	first := cfg.DefaultGroupID

	g := &models.UserGroup{ID: "g2", Name: "vip", IsDefault: true}
	if err := s.SaveGroup(g); err != nil {
		t.Fatal(err)
	}
	old, err := s.GetGroup(first)
	if err != nil {
		t.Fatal(err)
	}
	if old.IsDefault {
		t.Fatal("旧默认组的标记未被清掉")
	}
	groups, _ := s.ListGroups()
	defaults := 0
	for _, x := range groups {
		if x.IsDefault {
			defaults++
		}
	}
	if defaults != 1 {
		t.Fatalf("默认组数量 = %d, want 1", defaults)
	}
}

func TestGroupNameUnique(t *testing.T) {
	s := newUserStore(t)
	if err := s.SaveGroup(&models.UserGroup{ID: "g1", Name: "vip"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveGroup(&models.UserGroup{ID: "g2", Name: "vip"}); !errors.Is(err, ErrGroupExists) {
		t.Fatalf("重名组应被拒，得到 %v", err)
	}
	// 改自己的名字不算重名。
	if err := s.SaveGroup(&models.UserGroup{ID: "g1", Name: "vip"}); err != nil {
		t.Fatalf("覆盖自身不应判为重名：%v", err)
	}
}

// 删除仍有成员的组要拒绝，而不是把成员挪到默认组——静默改一批用户的配额，
// 他们下次建规则才会发现端口区间变了。
func TestDeleteGroupWithMembersRejected(t *testing.T) {
	s := newUserStore(t)
	if err := s.SaveGroup(&models.UserGroup{ID: "g1", Name: "vip"}); err != nil {
		t.Fatal(err)
	}
	u := makeUser("u1", "alice", models.RoleUser)
	u.GroupID = "g1"
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup("g1"); !errors.Is(err, ErrGroupInUse) {
		t.Fatalf("有成员的组应被拒，得到 %v", err)
	}
	// 成员移走后可以删。
	u.GroupID = ""
	if err := s.SaveUser(u); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup("g1"); err != nil {
		t.Fatalf("无成员的组应可删：%v", err)
	}
}

// 删除默认组要拒绝：否则新建用户无处可去。
func TestDeleteDefaultGroupRejected(t *testing.T) {
	s := newUserStore(t)
	cfg, _ := s.Settings()
	if err := s.DeleteGroup(cfg.DefaultGroupID); !errors.Is(err, ErrGroupIsDefault) {
		t.Fatalf("删除默认组应被拒，得到 %v", err)
	}
}

func TestCountGroupMembers(t *testing.T) {
	s := newUserStore(t)
	if err := s.SaveGroup(&models.UserGroup{ID: "g1", Name: "vip"}); err != nil {
		t.Fatal(err)
	}
	for i, gid := range []string{"g1", "g1", ""} {
		u := makeUser("u"+string(rune('a'+i)), "user"+string(rune('a'+i)), models.RoleUser)
		u.GroupID = gid
		if err := s.CreateUser(u); err != nil {
			t.Fatal(err)
		}
	}
	counts, err := s.CountGroupMembers()
	if err != nil {
		t.Fatal(err)
	}
	if counts["g1"] != 2 {
		t.Fatalf("g1 成员数 = %d, want 2", counts["g1"])
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	s := newUserStore(t)
	cfg, _ := s.Settings()
	cfg.MaxAccessCodesPerUser = 7
	if err := s.SaveSettings(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := s.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxAccessCodesPerUser != 7 {
		t.Fatalf("max_access_codes = %d", got.MaxAccessCodesPerUser)
	}
}
