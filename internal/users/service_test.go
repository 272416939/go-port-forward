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

// fakeEvictor 记录被踢掉的访问码，供断言「停用/解绑会踢在线隧道」。
type fakeEvictor struct {
	evicted  []string
	online   map[string]bool
	peersN   int
}

func (f *fakeEvictor) EvictCode(id string) bool {
	f.evicted = append(f.evicted, id)
	return f.online[id]
}

func (f *fakeEvictor) OnlineCodeIDs() []string {
	out := make([]string, 0, len(f.online))
	for id, on := range f.online {
		if on {
			out = append(out, id)
		}
	}
	return out
}

type fixture struct {
	svc      *Service
	store    storage.Store
	sessions *auth.Store
	evictor  *fakeEvictor
	cfg      models.Settings
}

func newService(t *testing.T) *fixture {
	t.Helper()
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	store, err := storage.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ev := &fakeEvictor{online: map[string]bool{}}
	sessions := auth.NewStore(false)
	svc, err := New(store, sessions, "10.66.0.1/24", "203.0.113.9:7947")
	if err != nil {
		t.Fatal(err)
	}
	svc.SetEvictor(ev)
	cfg, err := svc.Settings()
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: svc, store: store, sessions: sessions, evictor: ev, cfg: cfg}
}

func (f *fixture) mustUser(t *testing.T, name, role, groupID string) *models.User {
	t.Helper()
	u, err := f.svc.Create(&models.CreateUserRequest{
		Username: name, Password: "password123", Role: role, GroupID: groupID,
	})
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return u
}

func (f *fixture) mustGroup(t *testing.T, name string, maxCodes int) *models.UserGroup {
	t.Helper()
	g, err := f.svc.CreateGroup(&models.CreateGroupRequest{
		Name: name, MaxAccessCodes: maxCodes,
	})
	if err != nil {
		t.Fatalf("create group %s: %v", name, err)
	}
	return g
}

func (f *fixture) mustCode(t *testing.T, owner *models.User, name string) *models.AccessCode {
	t.Helper()
	c, err := f.svc.CreateAccessCode(owner, &models.CreateAccessCodeRequest{Name: name})
	if err != nil {
		t.Fatalf("create code %s: %v", name, err)
	}
	return c
}

func TestCreateAssignsGroupAndHash(t *testing.T) {
	f := newService(t)
	g := f.mustGroup(t, "vip", 2)
	u := f.mustUser(t, "alice", models.RoleUser, g.ID)

	if u.GroupID != g.ID {
		t.Fatalf("group = %q, want %q", u.GroupID, g.ID)
	}
	if u.PasswordHash == "" || u.PasswordHash == "password123" {
		t.Fatalf("密码未哈希：%q", u.PasswordHash)
	}

	// 未指定组的普通用户落到默认组。
	free := f.mustUser(t, "bob", models.RoleUser, "")
	if free.GroupID != f.cfg.DefaultGroupID {
		t.Fatalf("未指定组的用户应落到默认组：%q", free.GroupID)
	}
	// 管理员不挂组（他不受配额约束）。
	admin := f.mustUser(t, "root", models.RoleAdmin, "")
	if admin.GroupID != "" {
		t.Fatalf("管理员不应挂组：%q", admin.GroupID)
	}
}

// 配额严格以组为准：组值为 0 时回落到全局值。
func TestEffectiveQuotaResolution(t *testing.T) {
	f := newService(t)
	// 组只配访问码上限（= 全局值 3，合法且走组来源），其余取全局。
	g := f.mustGroup(t, "partial", 3)
	u := f.mustUser(t, "alice", models.RoleUser, g.ID)

	q, err := f.svc.EffectiveQuota(u)
	if err != nil {
		t.Fatal(err)
	}
	if q.MaxAccessCodes != 3 || q.AccessCodeSource != models.QuotaFromGroup {
		t.Fatalf("组级访问码上限未生效：%+v", q)
	}
	if q.MaxTunnels != f.cfg.MaxTunnelsPerUser || q.TunnelSource != models.QuotaFromGlobal {
		t.Fatalf("隧道上限应回落到全局：%+v", q)
	}
	if q.PortRangeStart != f.cfg.PortRangeStart || q.PortSource != models.QuotaFromGlobal {
		t.Fatalf("端口区间应回落到全局：%+v", q)
	}

	// 未分组的用户全部取全局。
	free := f.mustUser(t, "bob", models.RoleUser, "")
	qf, err := f.svc.EffectiveQuota(free)
	if err != nil {
		t.Fatal(err)
	}
	if qf.MaxAccessCodes != f.cfg.MaxAccessCodesPerUser || qf.AccessCodeSource != models.QuotaFromGlobal {
		t.Fatalf("未分组用户应取全局值：%+v", qf)
	}

	// 管理员不受配额约束。
	admin := f.mustUser(t, "root", models.RoleAdmin, "")
	qa, err := f.svc.EffectiveQuota(admin)
	if err != nil {
		t.Fatal(err)
	}
	if qa.PortSource != models.QuotaFromAdmin || qa.MaxRules != 0 {
		t.Fatalf("管理员配额应不受限：%+v", qa)
	}
}

// 组的配额不能突破全局天花板，否则全局设置退化成一个没有约束力的建议值。
func TestGroupCannotExceedGlobal(t *testing.T) {
	f := newService(t)
	tooMany := 99
	_, err := f.svc.CreateGroup(&models.CreateGroupRequest{
		Name: "greedy", MaxAccessCodes: tooMany,
	})
	if !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("组上限超过全局应被拒，得到 %v", err)
	}
	// 全局为 0（不限）时组可以任意设值。
	cfg, _ := f.svc.Settings()
	cfg.MaxAccessCodesPerUser = 0
	if err := f.store.SaveSettings(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateGroup(&models.CreateGroupRequest{Name: "free", MaxAccessCodes: 99}); err != nil {
		t.Fatalf("全局不限时组可自由设值：%v", err)
	}
}

// 收紧全局值时已有组不能越界——静默截断会让那些组的用户下次建规则莫名失败。
func TestTighteningGlobalChecksExistingGroups(t *testing.T) {
	f := newService(t)
	f.mustGroup(t, "big", 3) // 与全局相同，合法

	newLimit := 2
	_, err := f.svc.UpdateSettings(&models.UpdateSettingsRequest{MaxAccessCodesPerUser: &newLimit})
	if !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("收紧全局值撞上已有组应被拒，得到 %v", err)
	}
	if !contains(err.Error(), "big") {
		t.Fatalf("错误信息应列出冲突的组名：%v", err)
	}
}

// 创建访问码要受组配额约束，且超限错误可读。
func TestAccessCodeQuotaFromGroup(t *testing.T) {
	f := newService(t)
	g := f.mustGroup(t, "small", 2)
	u := f.mustUser(t, "alice", models.RoleUser, g.ID)

	f.mustCode(t, u, "one")
	f.mustCode(t, u, "two")
	_, cerr := f.svc.CreateAccessCode(u, &models.CreateAccessCodeRequest{Name: "three"})
	if !errors.Is(cerr, ErrQuotaExceeded) {
		t.Fatalf("超配额应返回 ErrQuotaExceeded，得到 %v", cerr)
	}
	if !contains(cerr.Error(), "2") {
		t.Fatalf("错误信息应包含上限值：%v", cerr)
	}
}

// 全局配额兜底：组未配置时用全局值。
func TestAccessCodeQuotaFromGlobal(t *testing.T) {
	f := newService(t)
	u := f.mustUser(t, "alice", models.RoleUser, "")
	for i := 0; i < f.cfg.MaxAccessCodesPerUser; i++ {
		f.mustCode(t, u, "code")
	}
	if _, cerr := f.svc.CreateAccessCode(u, &models.CreateAccessCodeRequest{Name: "one-more"}); !errors.Is(cerr, ErrQuotaExceeded) {
		t.Fatalf("超出全局配额应被拒：%v", cerr)
	}
}

// 管理员的访问码不受配额限制。
func TestAdminAccessCodeUnlimited(t *testing.T) {
	f := newService(t)
	admin := f.mustUser(t, "root", models.RoleAdmin, "")
	for i := 0; i < f.cfg.MaxAccessCodesPerUser+2; i++ {
		f.mustCode(t, admin, "code")
	}
}

func TestAuthenticate(t *testing.T) {
	f := newService(t)
	f.mustUser(t, "alice", models.RoleUser, "")

	if _, err := f.svc.Authenticate("alice", "password123"); err != nil {
		t.Fatalf("正确凭据应通过：%v", err)
	}
	if _, err := f.svc.Authenticate("ALICE", "password123"); err != nil {
		t.Fatalf("用户名应不分大小写：%v", err)
	}
	if _, err := f.svc.Authenticate("alice", "wrong"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("错误密码应返回 ErrBadCredentials，得到 %v", err)
	}
	// 用户不存在与密码错误必须返回同一个错误，否则接口成了用户名枚举器。
	if _, err := f.svc.Authenticate("nobody", "whatever"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("未知用户应返回 ErrBadCredentials，得到 %v", err)
	}
}

// 停用用户必须：注销会话 + 踢掉名下全部在线隧道。否则「停用」只是界面状态。
func TestDisableRevokesAndEvicts(t *testing.T) {
	f := newService(t)
	u := f.mustUser(t, "alice", models.RoleUser, "")
	c := f.mustCode(t, u, "home")
	f.evictor.online[c.ID] = true

	yes := true
	if _, err := f.svc.Update(u.ID, &models.UpdateUserRequest{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	if !containsID(f.evictor.evicted, c.ID) {
		t.Fatalf("停用用户应踢掉其在线隧道，实际踢了 %v", f.evictor.evicted)
	}
}

// 改密同样要注销全部会话，否则改密码挡不住已经登录的人。
func TestPasswordChangeRevokesSessions(t *testing.T) {
	f := newService(t)
	u := f.mustUser(t, "alice", models.RoleUser, "")
	token, _ := f.sessions.Issue(u.ID)

	if err := f.svc.ChangeOwnPassword(u.ID, "password123", "newpassword456"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.sessions.Lookup(token); ok {
		t.Fatal("改密后会话未被注销")
	}
	if _, err := f.svc.Authenticate("alice", "newpassword456"); err != nil {
		t.Fatalf("新密码应可登录：%v", err)
	}
	if _, err := f.svc.Authenticate("alice", "password123"); err == nil {
		t.Fatal("旧密码不应再可用")
	}
}

func TestChangeOwnPasswordChecksOld(t *testing.T) {
	f := newService(t)
	u := f.mustUser(t, "alice", models.RoleUser, "")
	if err := f.svc.ChangeOwnPassword(u.ID, "wrong", "newpassword456"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("旧密码错误应被拒，得到 %v", err)
	}
	if err := f.svc.ChangeOwnPassword(u.ID, "password123", "short"); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("弱新密码应被拒，得到 %v", err)
	}
	if err := f.svc.ChangeOwnPassword(u.ID, "password123", "password123"); !errors.Is(err, ErrInvalidUser) {
		t.Fatal("新旧密码相同应被拒")
	}
}

// 删除用户要连带删访问码并踢掉在线隧道。
func TestDeleteUserCleansUpCodes(t *testing.T) {
	f := newService(t)
	admin := f.mustUser(t, "admin", models.RoleAdmin, "")
	_ = admin
	u := f.mustUser(t, "alice", models.RoleUser, "")
	c := f.mustCode(t, u, "home")
	f.evictor.online[c.ID] = true

	if err := f.svc.Delete(u.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.store.CountAccessCodesByUser(u.ID); n != 0 {
		t.Fatalf("删除用户后仍剩 %d 个访问码", n)
	}
	if !containsID(f.evictor.evicted, c.ID) {
		t.Fatalf("删除用户应踢掉其在线隧道，实际踢了 %v", f.evictor.evicted)
	}
	if _, err := f.svc.Get(u.ID); !errors.Is(err, storage.ErrUserNotFound) {
		t.Fatalf("用户应已被删除：%v", err)
	}
}

// 重新生成密钥后旧接入码必须失效——这是密钥泄漏时唯一的补救手段。
func TestRegenerateSecretInvalidatesOldCode(t *testing.T) {
	f := newService(t)
	u := f.mustUser(t, "alice", models.RoleUser, "")
	c := f.mustCode(t, u, "home")

	before, err := f.svc.AccessCodeText(c.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	f.evictor.online[c.ID] = true
	if _, err := f.svc.RegenerateSecret(c.ID); err != nil {
		t.Fatal(err)
	}
	after, err := f.svc.AccessCodeText(c.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if before.Secret == after.Secret || before.Code == after.Code {
		t.Fatal("重新生成后密钥/接入码未变化")
	}
	if !containsID(f.evictor.evicted, c.ID) {
		t.Fatal("重新生成密钥应踢掉旧密钥建立的在线隧道")
	}
}

func TestAccessCodeTextRoundTrip(t *testing.T) {
	f := newService(t)
	u := f.mustUser(t, "alice", models.RoleUser, "")
	c := f.mustCode(t, u, "home")

	got, err := f.svc.AccessCodeText(c.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := accesscode.Decode(got.Code)
	if err != nil {
		t.Fatalf("接入码应可解析：%v", err)
	}
	if decoded.CodeID != c.ID || decoded.Secret != c.Secret {
		t.Fatalf("接入码内容不符：%+v", decoded)
	}
	if decoded.Addr != "203.0.113.9:7947" {
		t.Fatalf("接入码地址 = %q，应取 public_addr", decoded.Addr)
	}
}

func TestIdentity(t *testing.T) {
	f := newService(t)
	g := f.mustGroup(t, "g", 0)
	// 组级隧道上限 0 → 全局值。
	u := f.mustUser(t, "alice", models.RoleUser, g.ID)
	c := f.mustCode(t, u, "home")

	ci, found := f.svc.Identity(c.ID)
	if !found {
		t.Fatal("访问码应可查到")
	}
	if ci.CodeID != c.ID || ci.UserID != u.ID || ci.Secret != c.Secret {
		t.Fatalf("Identity 内容不符：%+v", ci)
	}
	if ci.TunIP != c.TunIP {
		t.Fatalf("隧道地址不符：%q vs %q", ci.TunIP, c.TunIP)
	}
	if ci.MaxTunnels != f.cfg.MaxTunnelsPerUser {
		t.Fatalf("隧道上限应取全局值：%d", ci.MaxTunnels)
	}
	if _, found := f.svc.Identity("no-such-code"); found {
		t.Fatal("未知访问码不应查到")
	}
}

// 停用的访问码/用户仍可查到 Identity（服务端要先验 MAC 再给拒绝原因），
// 但停用标志要如实传递。
func TestIdentityKeepsDisabledFlags(t *testing.T) {
	f := newService(t)
	u := f.mustUser(t, "alice", models.RoleUser, "")
	c := f.mustCode(t, u, "home")

	yes := true
	if _, err := f.svc.UpdateAccessCode(c.ID, &models.UpdateAccessCodeRequest{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	ci, found := f.svc.Identity(c.ID)
	if !found {
		t.Fatal("停用的访问码仍应可查到（服务端要先认证再拒绝）")
	}
	if !ci.CodeDisabled || ci.UserDisabled {
		t.Fatalf("停用标志不符：%+v", ci)
	}
	if !containsID(f.evictor.evicted, c.ID) {
		t.Fatal("停用访问码应踢掉其在线隧道")
	}
}

// 解绑设备：清空指纹、踢在线隧道、返回原绑定摘要。
func TestUnbindDevice(t *testing.T) {
	f := newService(t)
	u := f.mustUser(t, "alice", models.RoleUser, "")
	c := f.mustCode(t, u, "home")

	if err := f.svc.BindDevice(c.ID, "aabbccdd", "aa…bb", "1.2.3.4:1000"); err != nil {
		t.Fatal(err)
	}
	f.evictor.online[c.ID] = true
	got, err := f.svc.UnbindDevice(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeviceFingerprint != "" {
		t.Fatalf("解绑后指纹应为空：%q", got.DeviceFingerprint)
	}
	if !containsID(f.evictor.evicted, c.ID) {
		t.Fatal("解绑后应踢掉在线隧道")
	}
}

// TunIPsOf 只含启用中的访问码：指向停用码的规则会被拒绝。
func TestTunIPsOfExcludesDisabled(t *testing.T) {
	f := newService(t)
	u := f.mustUser(t, "alice", models.RoleUser, "")
	c1 := f.mustCode(t, u, "a")
	c2 := f.mustCode(t, u, "b")
	yes := true
	if _, err := f.svc.UpdateAccessCode(c2.ID, &models.UpdateAccessCodeRequest{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	ips, err := f.svc.TunIPsOf(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ips[c1.TunIP]; !ok {
		t.Fatalf("启用中的访问码地址缺失：%v", ips)
	}
	if _, ok := ips[c2.TunIP]; ok {
		t.Fatalf("停用的访问码地址不应在集合里：%v", ips)
	}
}

// 删除仍有访问码引用的隧道地址计数：删访问码前 handler 用它拦规则。
func TestAllTunIPs(t *testing.T) {
	f := newService(t)
	u := f.mustUser(t, "alice", models.RoleUser, "")
	c := f.mustCode(t, u, "a")
	ips, err := f.svc.AllTunIPs()
	if err != nil {
		t.Fatal(err)
	}
	if ips[c.TunIP] != c.ID {
		t.Fatalf("映射不符：%v", ips)
	}
}

func TestBootstrapCreatesAdminOnce(t *testing.T) {
	f := newService(t)
	created, name, pw, err := f.svc.Bootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if !created || name != BootstrapAdminName || pw == "" {
		t.Fatalf("首启引导结果异常：%v %q %q", created, name, pw)
	}
	u, err := f.svc.GetByName(BootstrapAdminName)
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
	if _, err := f.svc.Authenticate(BootstrapAdminName, pw); err != nil {
		t.Fatalf("引导密码应可登录：%v", err)
	}

	// 第二次启动不得再建账号（否则每次重启都多一个 admin）。
	again, _, _, err := f.svc.Bootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if again {
		t.Fatal("已有用户时不应再次引导")
	}
}

func TestCreateRejectsDuplicateAndWeakInput(t *testing.T) {
	f := newService(t)
	f.mustUser(t, "alice", models.RoleUser, "")

	if _, err := f.svc.Create(&models.CreateUserRequest{Username: "alice", Password: "password123"}); !errors.Is(err, storage.ErrUserExists) {
		t.Fatalf("重名应被拒，得到 %v", err)
	}
	if _, err := f.svc.Create(&models.CreateUserRequest{Username: "bob", Password: "short"}); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("弱密码应被拒，得到 %v", err)
	}
	if _, err := f.svc.Create(&models.CreateUserRequest{Username: "Bob Smith", Password: "password123"}); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("非法用户名应被拒，得到 %v", err)
	}
	if _, err := f.svc.Create(&models.CreateUserRequest{Username: "bob", Password: "password123", Role: "root"}); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("非法角色应被拒，得到 %v", err)
	}
	if _, err := f.svc.Create(&models.CreateUserRequest{Username: "bob", Password: "password123", GroupID: "no-such"}); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("不存在的组应被拒，得到 %v", err)
	}
}

// 服务层错误消息的中英文文案拼接，抽个小工具给断言用。
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

func containsID(list []string, id string) bool {
	for _, x := range list {
		if x == id {
			return true
		}
	}
	return false
}
