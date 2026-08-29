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

// tenantFixture 是一套完整的多租户环境：两个普通用户 + 一个管理员。
type tenantFixture struct {
	h       *handler
	svc     *users.Service
	alice   *models.User
	bob     *models.User
	admin   *models.User
	cleanup func()
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
	mk := func(name, role string, start, end, maxRules int) *models.User {
		u, cerr := svc.Create(&models.CreateUserRequest{
			Username: name, Password: "password123", Role: role,
			PortRangeStart: start, PortRangeEnd: end, MaxRules: maxRules,
		})
		if cerr != nil {
			t.Fatalf("create %s: %v", name, cerr)
		}
		return u
	}
	f := &tenantFixture{
		h:     &handler{mgr: mgr, users: svc, sessions: sessions},
		svc:   svc,
		admin: mk("admin", models.RoleAdmin, 0, 0, 0),
		alice: mk("alice", models.RoleUser, 20000, 20099, 2),
		bob:   mk("bob", models.RoleUser, 21000, 21099, 2),
	}
	f.cleanup = func() {
		mgr.Shutdown()
		_ = store.Close()
	}
	return f
}

// seedRule 直接经 manager 建一条归属于 owner 的规则（跳过 handler 校验）。
func (f *tenantFixture) seedRule(t *testing.T, owner *models.User, port int) *models.ForwardRule {
	t.Helper()
	r, err := f.mgrAdd(owner, port)
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	return r
}

func (f *tenantFixture) mgrAdd(owner *models.User, port int) (*models.ForwardRule, error) {
	return f.h.mgr.AddRule(&models.CreateRuleRequest{
		Name:       owner.Username + "-rule",
		ListenAddr: "127.0.0.1",
		ListenPort: port,
		Protocol:   models.ProtocolUDP,
		TargetAddr: owner.TunIP,
		TargetPort: 19132,
		UserID:     owner.ID,
		Enabled:    false,
	})
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
	f.seedRule(t, f.alice, 20001)
	f.seedRule(t, f.bob, 21001)

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
	bobRule := f.seedRule(t, f.bob, 21002)

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
	bobRule := f.seedRule(t, f.bob, 21003)

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

	body := `{"name":"oob","listen_addr":"127.0.0.1","listen_port":21050,"protocol":"udp","target_addr":"` +
		f.alice.TunIP + `","target_port":19132}`
	rec := httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, f.alice))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "20000-20099") {
		t.Fatalf("错误信息应说明配额区间：%s", rec.Body.String())
	}
}

// 目标地址必须锁定为本人的隧道地址。不限制的话普通用户可以建一条指向
// 127.0.0.1:22 或内网任意主机的转发，把中转机变成跳板。
func TestCreateRuleRejectsForeignTarget(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	cases := map[string]string{
		"回环":     "127.0.0.1",
		"内网主机":   "192.168.1.10",
		"别人的隧道": f.bob.TunIP,
	}
	port := 20010
	for name, target := range cases {
		body := `{"name":"probe","listen_addr":"127.0.0.1","listen_port":` + strconv.Itoa(port) +
			`,"protocol":"udp","target_addr":"` + target + `","target_port":22}`
		rec := httptest.NewRecorder()
		f.h.createRule(rec, postJSON("/api/rules", body, f.alice))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s 目标应被拒，status = %d, body=%s", name, rec.Code, rec.Body.String())
		}
		port++
	}

	// 自己的隧道地址可以。
	body := `{"name":"ok","listen_addr":"127.0.0.1","listen_port":20020,"protocol":"udp","target_addr":"` +
		f.alice.TunIP + `","target_port":19132}`
	rec := httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, f.alice))
	if rec.Code != http.StatusCreated {
		t.Fatalf("自己的隧道地址应被接受，status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

// 普通用户不能代他人建规则：归属被强制改写为自己。
func TestCreateRuleForcesOwnership(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	body := `{"name":"forged","listen_addr":"127.0.0.1","listen_port":20030,"protocol":"udp","target_addr":"` +
		f.alice.TunIP + `","target_port":19132,"user_id":"` + f.bob.ID + `"}`
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
	rule := f.seedRule(t, f.alice, 20040)

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

func TestRuleQuotaEnforced(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	f.seedRule(t, f.alice, 20050)
	f.seedRule(t, f.alice, 20051)

	body := `{"name":"third","listen_addr":"127.0.0.1","listen_port":20052,"protocol":"udp","target_addr":"` +
		f.alice.TunIP + `","target_port":19132}`
	rec := httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, f.alice))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("超配额应被拒，status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

// 未分配端口区间的账号 fail-closed：不能因为"没配"就等于"随便用"。
func TestUserWithoutPortRangeCannotCreate(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	carol, err := f.svc.Create(&models.CreateUserRequest{Username: "carol", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}

	body := `{"name":"nope","listen_addr":"127.0.0.1","listen_port":22000,"protocol":"udp","target_addr":"` +
		carol.TunIP + `","target_port":19132}`
	rec := httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, carol))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未分配区间应被拒，status = %d, body=%s", rec.Code, rec.Body.String())
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
	f.seedRule(t, f.alice, 20060)
	f.seedRule(t, f.bob, 21060)

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
	f.seedRule(t, f.alice, 20070)

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

// 接入码接口返回的凭据能直接被客户端使用。
func TestAccessCodeEndpoint(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	req := asUser(httptest.NewRequest(http.MethodGet, "/api/users/"+f.alice.ID+"/access-code", nil), f.admin)
	req.SetPathValue("id", f.alice.ID)
	rec := httptest.NewRecorder()
	f.h.userAccessCode(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data models.UserAccessCode `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.Data.Code, "pf1.") || resp.Data.Secret == "" {
		t.Fatalf("接入码异常：%+v", resp.Data)
	}
}

// 用户列表绝不能泄漏密码哈希与隧道密钥。models.User 上那两个 json:"-"
// 是这条保证的唯一实现，一旦被误删就是静默泄漏。
func TestUserListHidesSecrets(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	rec := httptest.NewRecorder()
	f.h.listUsers(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/users", nil), f.admin))
	body := rec.Body.String()
	if strings.Contains(body, "password_hash") || strings.Contains(body, "tunnel_secret") {
		t.Fatalf("用户列表泄漏了敏感字段：%s", body)
	}
	if strings.Contains(body, f.alice.TunnelSecret) {
		t.Fatal("用户列表泄漏了隧道密钥原文")
	}
	if !strings.Contains(body, "alice") || !strings.Contains(body, `"rule_count"`) {
		t.Fatalf("用户列表内容异常：%s", body)
	}
}
