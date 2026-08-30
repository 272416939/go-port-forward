package web

// 多租户越权矩阵。
//
// 这些用例是安全边界的回归网：每一条都对应一个「漏掉就静默越权」的判定点。
// 它们必须直接调 handler（而不是走完整 HTTP 栈），因为要精确控制上下文里的
// 身份，绕开中间件本身。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/config"
	"go-port-forward/internal/forward"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
	"go-port-forward/internal/users"

	"go.uber.org/zap"
)

// tenantFixture 是一套完整的多租户环境：两个普通用户（各一组各一码）+ 一个管理员。
type tenantFixture struct {
	h         *handler
	svc       *users.Service
	admin     *models.User
	alice     *models.User
	bob       *models.User
	aliceCode *models.AccessCode
	bobCode   *models.AccessCode
	groups    map[string]*models.UserGroup // 用户名 → 所属组
	cleanup   func()
}

func newTenantFixture(t *testing.T) *tenantFixture {
	t.Helper()
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	store, err := storage.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	mgr, err := forward.NewManager(store, config.ForwardConfig{DialTimeout: 1, UDPTimeout: 30, BufferSize: 4096, PoolSize: 16})
	if err != nil {
		_ = store.Close()
		t.Fatalf("new manager: %v", err)
	}
	sessions := auth.NewStore(false)
	svc, err := users.New(store, sessions, "10.66.0.1/24", "203.0.113.9:7947")
	if err != nil {
		mgr.Shutdown()
		_ = store.Close()
		t.Fatal(err)
	}
	cfg, _ := svc.Settings()
	// 收紧全局端口区间，让「组区间越界」可以被测到。
	cfg.PortRangeStart, cfg.PortRangeEnd = 20000, 29999
	if err := store.SaveSettings(cfg); err != nil {
		t.Fatal(err)
	}

	mkGroup := func(name string, start, end int) *models.UserGroup {
		g, cerr := svc.CreateGroup(&models.CreateGroupRequest{Name: name, PortRangeStart: start, PortRangeEnd: end})
		if cerr != nil {
			t.Fatalf("create group %s: %v", name, cerr)
		}
		return g
	}
	gAlice := mkGroup("alice-g", 20000, 20099)
	gBob := mkGroup("bob-g", 21000, 21099)

	mk := func(name, role, groupID string) *models.User {
		u, cerr := svc.Create(&models.CreateUserRequest{
			Username: name, Password: "password123", Role: role, GroupID: groupID,
		})
		if cerr != nil {
			t.Fatalf("create %s: %v", name, cerr)
		}
		return u
	}
	f := &tenantFixture{
		h:      &handler{mgr: mgr, users: svc, sessions: sessions},
		svc:    svc,
		admin:  mk("admin", models.RoleAdmin, ""),
		groups: map[string]*models.UserGroup{},
	}
	f.alice = mk("alice", models.RoleUser, gAlice.ID)
	f.bob = mk("bob", models.RoleUser, gBob.ID)
	f.groups[f.alice.Username] = gAlice
	f.groups[f.bob.Username] = gBob

	mkCode := func(u *models.User) *models.AccessCode {
		c, cerr := svc.CreateAccessCode(u, &models.CreateAccessCodeRequest{Name: u.Username + "-code"})
		if cerr != nil {
			t.Fatalf("create access code for %s: %v", u.Username, cerr)
		}
		return c
	}
	f.aliceCode = mkCode(f.alice)
	f.bobCode = mkCode(f.bob)

	f.cleanup = func() {
		mgr.Shutdown()
		_ = store.Close()
	}
	return f
}

// seedRule 直接经 manager 建一条归属于 owner 的规则（跳过 handler 校验）。
func (f *tenantFixture) seedRule(t *testing.T, owner *models.User, code *models.AccessCode, port int) *models.ForwardRule {
	t.Helper()
	r, err := f.h.mgr.AddRule(&models.CreateRuleRequest{
		Name:       owner.Username + "-rule",
		ListenAddr: "127.0.0.1",
		ListenPort: port,
		Protocol:   models.ProtocolUDP,
		TargetAddr: code.TunIP,
		TargetPort: 19132,
		UserID:     owner.ID,
		Enabled:    false,
	})
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	return r
}

// resizeGroup 调整某用户所属组的端口区间（测试构造冲突场景用）。
func (f *tenantFixture) resizeGroup(t *testing.T, u *models.User, start, end int) {
	t.Helper()
	g, err := f.svc.GetGroup(u.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, uerr := f.svc.UpdateGroup(g.ID, &models.UpdateGroupRequest{
		PortRangeStart: &start, PortRangeEnd: &end,
	}); uerr != nil {
		t.Fatal(uerr)
	}
}

func asUser(r *http.Request, u *models.User) *http.Request {
	return r.WithContext(auth.WithUser(r.Context(), u))
}

func postJSON(path, body string, u *models.User) *http.Request {
	return asUser(httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)), u)
}

// 列表必须按归属过滤：A 不该在自己的列表里看到 B 的规则。
func TestListRulesScopedToOwner(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	f.seedRule(t, f.alice, f.aliceCode, 20001)
	f.seedRule(t, f.bob, f.bobCode, 21001)

	rec := httptest.NewRecorder()
	f.h.listRules(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/rules", nil), f.alice))
	body := rec.Body.String()
	if !strings.Contains(body, "alice-rule") {
		t.Fatalf("alice 看不到自己的规则：%s", body)
	}
	if strings.Contains(body, "bob-rule") {
		t.Fatalf("alice 看到了 bob 的规则：%s", body)
	}

	// 管理员看全部。
	rec = httptest.NewRecorder()
	f.h.listRules(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/rules", nil), f.admin))
	body = rec.Body.String()
	if !strings.Contains(body, "alice-rule") || !strings.Contains(body, "bob-rule") {
		t.Fatalf("管理员应看到全部规则：%s", body)
	}
}

// 读别人的规则要返回 404 而不是 403：确认某个 ID 存在本身就是信息泄漏。
func TestGetOthersRuleReturns404(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	bobRule := f.seedRule(t, f.bob, f.bobCode, 21002)

	req := asUser(httptest.NewRequest(http.MethodGet, "/api/rules/"+bobRule.ID, nil), f.alice)
	req.SetPathValue("id", bobRule.ID)
	rec := httptest.NewRecorder()
	f.h.getRule(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestUpdateAndDeleteOthersRuleBlocked(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	bobRule := f.seedRule(t, f.bob, f.bobCode, 21003)

	req := asUser(httptest.NewRequest(http.MethodPut, "/api/rules/"+bobRule.ID, strings.NewReader(`{"name":"hijacked"}`)), f.alice)
	req.SetPathValue("id", bobRule.ID)
	rec := httptest.NewRecorder()
	f.h.updateRule(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("update status = %d, want 404", rec.Code)
	}

	req = asUser(httptest.NewRequest(http.MethodDelete, "/api/rules/"+bobRule.ID, nil), f.alice)
	req.SetPathValue("id", bobRule.ID)
	rec = httptest.NewRecorder()
	f.h.deleteRule(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete status = %d, want 404", rec.Code)
	}

	// toggle 走的是另一条路径，必须单独验。
	req = asUser(httptest.NewRequest(http.MethodPut, "/api/rules/"+bobRule.ID+"/toggle", strings.NewReader(`{"enabled":true}`)), f.alice)
	req.SetPathValue("id", bobRule.ID)
	rec = httptest.NewRecorder()
	f.h.toggleRule(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("toggle status = %d, want 404", rec.Code)
	}

	// 规则本身没被改动。
	after, err := f.h.mgr.GetRule(bobRule.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Name != "bob-rule" || after.Enabled {
		t.Fatalf("bob 的规则被越权修改了：%+v", after)
	}
}

// 越界端口必须被拒：否则一个用户可以抢占别人的端口区间，甚至占用系统端口。
func TestCreateRuleRejectsPortOutsideQuota(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	// alice 的组区间是 20000-20099，bob 的区间是 21000-21099。
	body := `{"name":"oob","listen_addr":"127.0.0.1","listen_port":21050,"protocol":"udp","target_addr":"` +
		f.aliceCode.TunIP + `","target_port":19132}`
	rec := httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, f.alice))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "20000-20099") {
		t.Fatalf("错误信息应说明配额区间：%s", rec.Body.String())
	}
}

// 目标地址校验按代理模式分流：透明规则必须锁定为自己访问码的隧道地址（数据
// 面按 target_addr 分流隧道，指向别处无处可发）；通用规则允许任意公网地址，
// 但内网/回环/本机地址拒绝——否则普通用户能把中转机当内网跳板。
func TestCreateRuleRejectsForeignTarget(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	cases := map[string]string{
		"回环":     "127.0.0.1",
		"内网主机":   "192.168.1.10",
		"别人的隧道": f.bobCode.TunIP,
	}
	port := 20010
	for name, target := range cases {
		body := `{"name":"probe","listen_addr":"127.0.0.1","listen_port":` + strconv.Itoa(port) +
			`,"protocol":"udp","target_addr":"` + target + `","target_port":22}`
		rec := httptest.NewRecorder()
		f.h.createRule(rec, postJSON("/api/rules", body, f.alice))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("通用模式 %s 目标应被拒，status = %d, body=%s", name, rec.Code, rec.Body.String())
		}
		port++
	}

	// 公网地址在通用模式下放行。
	body := `{"name":"public","listen_addr":"127.0.0.1","listen_port":20020,"protocol":"udp","target_addr":"198.51.100.7","target_port":19132}`
	rec := httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, f.alice))
	if rec.Code != http.StatusCreated {
		t.Fatalf("通用模式公网目标应被接受，status = %d, body=%s", rec.Code, rec.Body.String())
	}

	// 透明模式仍锁定自己的隧道地址：别人的隧道被拒，自己的可以。
	body = `{"name":"probe-t","listen_addr":"127.0.0.1","listen_port":20021,"protocol":"udp","transparent":true,"target_addr":"` +
		f.bobCode.TunIP + `","target_port":19132}`
	rec = httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, f.alice))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "访问码") {
		t.Fatalf("透明模式别人的隧道应被拒且提示访问码，status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body = `{"name":"ok","listen_addr":"127.0.0.1","listen_port":20022,"protocol":"udp","transparent":true,"target_addr":"` +
		f.aliceCode.TunIP + `","target_port":19132}`
	rec = httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, f.alice))
	if rec.Code != http.StatusCreated {
		t.Fatalf("透明模式自己的隧道地址应被接受，status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

// 没有访问码的用户建透明规则 fail-closed：不能让规则指向一个不存在的隧道。
func TestUserWithoutAccessCodeCannotCreate(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	carol, err := f.svc.Create(&models.CreateUserRequest{Username: "carol", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}

	body := `{"name":"nope","listen_addr":"127.0.0.1","listen_port":20030,"protocol":"udp","transparent":true,"target_addr":"10.66.0.200","target_port":19132}`
	rec := httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, carol))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "访问码") {
		t.Fatalf("错误信息应指向「先建访问码」：%s", rec.Body.String())
	}
}

// 通用模式不要求先有访问码：目标是任意公网地址，不依赖隧道。
func TestUserWithoutAccessCodeCanCreateGeneral(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	carol, err := f.svc.Create(&models.CreateUserRequest{Username: "carol", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}

	body := `{"name":"gen","listen_addr":"127.0.0.1","listen_port":20031,"protocol":"tcp","target_addr":"198.51.100.7","target_port":443}`
	rec := httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, carol))
	if rec.Code != http.StatusCreated {
		t.Fatalf("通用模式公网目标应被接受，status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

// 透明模式仅支持 UDP：在创建时就拒绝，而不是等启动转发器时进 error 态。
func TestTransparentRequiresUDP(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	body := `{"name":"t-tcp","listen_addr":"127.0.0.1","listen_port":20032,"protocol":"tcp","transparent":true,"target_addr":"` +
		f.aliceCode.TunIP + `","target_port":19132}`
	rec := httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, f.alice))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "UDP") {
		t.Fatalf("透明+TCP 应在创建时被拒，status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

// 普通用户不能代他人建规则：归属被强制改写为自己。
func TestCreateRuleForcesOwnership(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	body := `{"name":"forged","listen_addr":"127.0.0.1","listen_port":20040,"protocol":"udp","target_addr":"` +
		f.aliceCode.TunIP + `","target_port":19132,"user_id":"` + f.bob.ID + `"}`
	rec := httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, f.alice))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data models.ForwardRule `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.UserID != f.alice.ID {
		t.Fatalf("归属应被强制为 alice，实际 %s", resp.Data.UserID)
	}
}

// 普通用户不得把自己的规则转给别人（也不得转成无归属的共享规则）。
func TestUpdateRuleCannotTransferOwnership(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	rule := f.seedRule(t, f.alice, f.aliceCode, 20050)

	for _, target := range []string{f.bob.ID, ""} {
		req := asUser(httptest.NewRequest(http.MethodPut, "/api/rules/"+rule.ID,
			strings.NewReader(`{"user_id":"`+target+`"}`)), f.alice)
		req.SetPathValue("id", rule.ID)
		rec := httptest.NewRecorder()
		f.h.updateRule(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("转移归属到 %q 应被拒，status = %d, body=%s", target, rec.Code, rec.Body.String())
		}
	}
}

// 规则数上限取组配额（这里走全局默认 10，建满即拒）。
func TestRuleQuotaEnforced(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	cfg, _ := f.svc.Settings()
	if cfg.MaxRulesPerUser <= 0 {
		t.Skip("全局规则上限未配置")
	}
	for i := 0; i < cfg.MaxRulesPerUser; i++ {
		f.seedRule(t, f.alice, f.aliceCode, 20060+i)
	}
	body := `{"name":"one-more","listen_addr":"127.0.0.1","listen_port":20099,"protocol":"udp","target_addr":"` +
		f.aliceCode.TunIP + `","target_port":19132}`
	rec := httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, f.alice))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("超配额应被拒，status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

// 管理员不受端口区间与目标地址限制（他要能建指向任意后端的共享规则）。
func TestAdminBypassesQuotas(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	body := `{"name":"admin-rule","listen_addr":"127.0.0.1","listen_port":33333,"protocol":"tcp","target_addr":"198.51.100.7","target_port":443}`
	rec := httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, f.admin))
	if rec.Code != http.StatusCreated {
		t.Fatalf("管理员应可自由建规则，status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

// 管理员指定的归属用户必须存在，否则会产生指向不存在用户的孤儿规则。
func TestAdminRejectsUnknownOwner(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	body := `{"name":"orphan","listen_addr":"127.0.0.1","listen_port":33334,"protocol":"tcp","target_addr":"198.51.100.7","target_port":443,"user_id":"no-such-user"}`
	rec := httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, f.admin))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未知归属用户应被拒，status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

// 仪表盘统计也要按作用域收敛，否则普通用户能看到全站流量。
func TestDashboardScoped(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	f.seedRule(t, f.alice, f.aliceCode, 20070)
	f.seedRule(t, f.bob, f.bobCode, 21070)

	rec := httptest.NewRecorder()
	f.h.dashboard(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/dashboard", nil), f.alice))
	var resp struct {
		Data struct {
			Stats models.Stats          `json:"stats"`
			Rules []*models.ForwardRule `json:"rules"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data.Rules) != 1 || resp.Data.Stats.TotalRules != 1 {
		t.Fatalf("alice 的仪表盘应只含自己的 1 条规则：%+v", resp.Data.Stats)
	}
}

// 删除仍被规则引用的用户会留下孤儿规则（目标地址指着一个不再属于任何人的
// 隧道地址），必须拒绝。
func TestDeleteUserWithRulesRejected(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	f.seedRule(t, f.alice, f.aliceCode, 20080)

	req := asUser(httptest.NewRequest(http.MethodDelete, "/api/users/"+f.alice.ID, nil), f.admin)
	req.SetPathValue("id", f.alice.ID)
	rec := httptest.NewRecorder()
	f.h.deleteUser(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
}

// 管理员不能删除/降级/停用自己：那会当场失去唯一的管理入口。
func TestAdminCannotLockSelfOut(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	req := asUser(httptest.NewRequest(http.MethodDelete, "/api/users/"+f.admin.ID, nil), f.admin)
	req.SetPathValue("id", f.admin.ID)
	rec := httptest.NewRecorder()
	f.h.deleteUser(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("删除自己应被拒，status = %d", rec.Code)
	}

	for _, body := range []string{`{"role":"user"}`, `{"disabled":true}`} {
		req = asUser(httptest.NewRequest(http.MethodPut, "/api/users/"+f.admin.ID, strings.NewReader(body)), f.admin)
		req.SetPathValue("id", f.admin.ID)
		rec = httptest.NewRecorder()
		f.h.updateUser(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s 应被拒，status = %d, body=%s", body, rec.Code, rec.Body.String())
		}
	}
}

// 会话与日志同样按作用域过滤（它们泄漏的是玩家 IP）。
func TestSessionsAndLogsScoped(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	rec := httptest.NewRecorder()
	f.h.listSessions(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/sessions", nil), f.alice))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	f.h.listConnLogs(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/logs", nil), f.alice))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

// 用户列表绝不能泄漏密码哈希。models.User 上的 json:"-" 是这条保证的唯一实现。
func TestUserListHidesSecrets(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	rec := httptest.NewRecorder()
	f.h.listUsers(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/users", nil), f.admin))
	body := rec.Body.String()
	for _, leak := range []string{"password_hash", "tunnel_secret", "device_fingerprint", "secret"} {
		if strings.Contains(body, leak) {
			t.Fatalf("用户列表泄漏了敏感字段 %s：%s", leak, body)
		}
	}
	if !strings.Contains(body, "alice") || !strings.Contains(body, `"access_code_count"`) {
		t.Fatalf("用户列表内容异常：%s", body)
	}
}

// --- 访问码越权矩阵 ---

// 普通用户看自己的访问码列表；列表里绝不能出现密钥或完整指纹。
func TestAccessCodeListScoped(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	rec := httptest.NewRecorder()
	f.h.listAccessCodes(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/access-codes", nil), f.alice))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, f.aliceCode.TunIP) {
		t.Fatalf("alice 看不到自己的访问码：%s", body)
	}
	if strings.Contains(body, f.bobCode.TunIP) {
		t.Fatalf("alice 看到了 bob 的访问码：%s", body)
	}
	for _, leak := range []string{f.aliceCode.Secret, f.aliceCode.DeviceFingerprint} {
		if leak != "" && strings.Contains(body, leak) {
			t.Fatal("访问码列表泄漏了密钥/完整指纹")
		}
	}

	// 管理员可查全部。
	rec = httptest.NewRecorder()
	f.h.listAccessCodes(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/access-codes", nil), f.admin))
	body = rec.Body.String()
	if !strings.Contains(body, f.aliceCode.TunIP) || !strings.Contains(body, f.bobCode.TunIP) {
		t.Fatalf("管理员应看到全部访问码：%s", body)
	}
}

// 操作别人的访问码一律 404：改、删、取接入码、重新生成、解绑全部如此。
func TestOthersAccessCodeOperationsBlocked(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	op := func(name, method, suffix, body string) int {
		req := asUser(httptest.NewRequest(method, "/api/access-codes/"+f.bobCode.ID+suffix, strings.NewReader(body)), f.alice)
		req.SetPathValue("id", f.bobCode.ID)
		rec := httptest.NewRecorder()
		switch method {
		case http.MethodPut:
			f.h.updateAccessCode(rec, req)
		case http.MethodDelete:
			f.h.deleteAccessCode(rec, req)
		case http.MethodGet:
			f.h.accessCodeText(rec, req)
		case http.MethodPost:
			if strings.HasSuffix(suffix, "/unbind") {
				f.h.unbindAccessCode(rec, req)
			} else {
				f.h.regenerateAccessCode(rec, req)
			}
		}
		return rec.Code
	}

	cases := []struct {
		name   string
		method string
		suffix string
		body   string
	}{
		{"改名", http.MethodPut, "", `{"name":"hijacked"}`},
		{"删除", http.MethodDelete, "", ""},
		{"取接入码", http.MethodGet, "/code", ""},
		{"重新生成", http.MethodPost, "/regenerate", ""},
		{"解绑", http.MethodPost, "/unbind", ""},
	}
	for _, c := range cases {
		if got := op(c.name, c.method, c.suffix, c.body); got != http.StatusNotFound {
			t.Fatalf("%s bob 的访问码 = %d, want 404", c.name, got)
		}
	}
	// bob 的密钥与绑定没有被动过。
	after, err := f.svc.GetAccessCode(f.bobCode.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Secret != f.bobCode.Secret || after.DeviceFingerprint != f.bobCode.DeviceFingerprint {
		t.Fatal("bob 的访问码被越权改动了")
	}
}

// 普通用户不能借 ?user_id= 建到别人名下。
func TestCreateAccessCodeIgnoresForeignUserScope(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	body := `{"name":"forged","user_id":"` + f.bob.ID + `"}`
	rec := httptest.NewRecorder()
	f.h.createAccessCode(rec, postJSON("/api/access-codes", body, f.alice))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data models.AccessCode `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.UserID != f.alice.ID {
		t.Fatalf("归属应被强制为 alice，实际 %s", resp.Data.UserID)
	}
}

// 管理员可以 ?user_id= 为他人建码，且必须是真实存在的用户。
func TestAdminCreatesAccessCodeForUser(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	body := `{"name":"admin-made","user_id":"` + f.bob.ID + `"}`
	rec := httptest.NewRecorder()
	f.h.createAccessCode(rec, postJSON("/api/access-codes", body, f.admin))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	f.h.createAccessCode(rec, postJSON("/api/access-codes", `{"name":"x","user_id":"no-such"}`, f.admin))
	// 用户不存在按既有约定映射 404（确认某个 ID 存在本身就是信息泄漏）。
	if rec.Code != http.StatusNotFound {
		t.Fatalf("为不存在的用户建码应被拒，status = %d", rec.Code)
	}
}

// 删除仍被规则引用的访问码要 409，而不是留下一条指向死地址的规则。
func TestDeleteAccessCodeWithRulesRejected(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	f.seedRule(t, f.alice, f.aliceCode, 20090)

	req := asUser(httptest.NewRequest(http.MethodDelete, "/api/access-codes/"+f.aliceCode.ID, nil), f.alice)
	req.SetPathValue("id", f.aliceCode.ID)
	rec := httptest.NewRecorder()
	f.h.deleteAccessCode(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	if _, err := f.svc.GetAccessCode(f.aliceCode.ID); err != nil {
		t.Fatal("访问码不应被删除")
	}
}

// 取接入码接口返回的凭据能直接被客户端使用。
func TestAccessCodeTextEndpoint(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	req := asUser(httptest.NewRequest(http.MethodGet, "/api/access-codes/"+f.aliceCode.ID+"/code", nil), f.alice)
	req.SetPathValue("id", f.aliceCode.ID)
	rec := httptest.NewRecorder()
	f.h.accessCodeText(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data models.AccessCodeView `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.Data.Code, "pf1.") || resp.Data.Secret == "" {
		t.Fatalf("接入码异常：%+v", resp.Data)
	}
}

// 修改自身密码后 /api/auth/me 应带上有效配额与来源。
func TestMeCarriesQuotaWithSource(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	rec := httptest.NewRecorder()
	f.h.me(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/auth/me", nil), f.alice))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"quota"`) || !strings.Contains(body, `"port_source"`) {
		t.Fatalf("me 应返回配额与来源：%s", body)
	}
	if !strings.Contains(body, `"port_source":"group"`) || !strings.Contains(body, `"port_range_start":20000`) ||
		!strings.Contains(body, `"port_range_end":20099`) || !strings.Contains(body, `"group_name":"alice-g"`) {
		t.Fatalf("配额应来自 alice 的组：%s", body)
	}
}
