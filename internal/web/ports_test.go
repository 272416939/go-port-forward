package web

// 注册提示脱敏、端口冲突脱敏、端口检测/随机端点的测试。

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-port-forward/internal/forward"
	"go-port-forward/internal/models"
)

// 注册重名的响应必须脱敏：回显用户名原文等于提供「这个用户名有没有被注册」
// 的探测器（登录接口早已防枚举，注册必须对齐）。
func TestRegisterDuplicateMasked(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	f.openRegistration(t)

	body := `{"username":"alice","password":"password123"}`
	rec := httptest.NewRecorder()
	f.h.register(rec, postJSON("/api/auth/register", body, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "alice") || strings.Contains(rec.Body.String(), "already exists") {
		t.Fatalf("注册重名响应泄漏了用户名原文：%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "不可用") && !strings.Contains(rec.Body.String(), "unavailable") {
		t.Fatalf("应返回通用提示：%s", rec.Body.String())
	}
}

// 管理员手动建用户的重名提示不脱敏（管理员本来就能看用户列表，409 详情
// 对他有用）。
func TestAdminCreateUserKeepsConflictDetail(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	rec := httptest.NewRecorder()
	f.h.createUser(rec, postJSON("/api/users", `{"username":"alice","password":"password123","role":"user","group_id":""}`, f.admin))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "alice") {
		t.Fatalf("管理员建用户应保留冲突详情：%s", rec.Body.String())
	}
}

// 普通用户撞上别人的端口时，错误里不能出现占用者的规则名；管理员看得到。
func TestPortConflictMaskedForUser(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	// bob 先占住 21001（他的区间内）。
	f.seedRule(t, f.bob, f.bobCode, 21001)

	// 管理员建一条 0.0.0.0:21001 的规则，制造与 bob 规则的冲突源。
	adminRule, err := f.h.mgr.AddRule(&models.CreateRuleRequest{
		Name: "secret-rule-name", ListenAddr: "0.0.0.0", ListenPort: 21001,
		Protocol: models.ProtocolUDP, TargetAddr: "198.51.100.7", TargetPort: 80,
		UserID: f.admin.ID, Enabled: false,
	})
	if err != nil {
		t.Fatalf("seed admin rule: %v", err)
	}
	_ = adminRule

	// 普通用户（alice）试图在 21001 建规则（她的区间是 20000-20099，先放宽：
	// 直接把她的组区间改成含 21001）。
	f.resizeGroup(t, f.alice, 20000, 21099)

	body := `{"name":"probe","listen_addr":"0.0.0.0","listen_port":21001,"protocol":"udp","target_addr":"` +
		f.aliceCode.TunIP + `","target_port":19132}`
	rec := httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", body, f.alice))
	if rec.Code != http.StatusConflict {
		t.Fatalf("冲突应返回 409，status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret-rule-name") {
		t.Fatalf("端口冲突响应泄漏了他人规则名：%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "21001") {
		t.Fatalf("响应应含自己请求的端口（可回显）：%s", rec.Body.String())
	}

	// 管理员建同端口规则：保留完整信息。
	rec = httptest.NewRecorder()
	adminBody := `{"name":"probe2","listen_addr":"0.0.0.0","listen_port":21001,"protocol":"udp","target_addr":"198.51.100.7","target_port":80}`
	f.h.createRule(rec, postJSON("/api/rules", adminBody, f.admin))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "secret-rule-name") {
		t.Fatalf("管理员应看到占用规则名：%s", rec.Body.String())
	}
}

// 端口检测：配额区间内可用；区间外被拒（防探测服务面）。
func TestPortCheckScoped(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	// 区间内（alice 组 20000-20099）。
	rec := httptest.NewRecorder()
	f.h.checkPort(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/ports/check?port=20001", nil), f.alice))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Port      int  `json:"port"`
			Available bool `json:"available"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.Port != 20001 || !resp.Data.Available {
		t.Fatalf("空闲端口应可用：%+v", resp.Data)
	}

	// 区间外被拒。
	rec = httptest.NewRecorder()
	f.h.checkPort(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/ports/check?port=22001", nil), f.alice))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("区间外检测应被拒，status = %d, body=%s", rec.Code, rec.Body.String())
	}

	// 非法端口。
	rec = httptest.NewRecorder()
	f.h.checkPort(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/ports/check?port=0", nil), f.alice))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法端口应被拒，status = %d", rec.Code)
	}
}

// 随机端口：必须落在配额区间内且真实可用。
func TestRandomPortInRange(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	rec := httptest.NewRecorder()
	f.h.randomPort(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/ports/random", nil), f.alice))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Port int `json:"port"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.Port < 20000 || resp.Data.Port > 20099 {
		t.Fatalf("随机端口越界：%d", resp.Data.Port)
	}
}

// 全局与组都没有端口区间时：随机与检测都 fail-closed（否则端口端点成了
// 全端口扫描器）。
func TestRandomPortWithoutRange(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()
	start, end := 0, 0
	if _, err := f.svc.UpdateSettings(&models.UpdateSettingsRequest{PortRangeStart: &start, PortRangeEnd: &end}); err != nil {
		t.Fatal(err)
	}
	carol, err := f.svc.Create(&models.CreateUserRequest{Username: "carol", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	f.h.randomPort(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/ports/random", nil), carol))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("无区间应被拒，status = %d, body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	f.h.checkPort(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/ports/check?port=20001", nil), carol))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("无区间的检测应被拒，status = %d", rec.Code)
	}
}

// maskPortConflict 的管理员透传与用户脱敏（单元级，覆盖 toggle/update 路径
// 共用的 helper）。
func TestMaskPortConflictHelper(t *testing.T) {
	conflict := fmt.Errorf("%w: 0.0.0.0:21001 已被规则 | already used by rule %q 占用 (协议 | protocol %s)",
		forward.ErrPortConflict, "secret-name", "udp")

	masked := maskPortConflict(&models.User{Role: models.RoleUser}, conflict, 21001)
	if strings.Contains(masked.Error(), "secret-name") {
		t.Fatalf("普通用户视角泄漏规则名：%v", masked)
	}
	if !strings.Contains(masked.Error(), "21001") {
		t.Fatalf("脱敏文案应含端口：%v", masked)
	}
	admin := maskPortConflict(&models.User{Role: models.RoleAdmin}, conflict, 21001)
	if !errors.Is(admin, forward.ErrPortConflict) || !strings.Contains(admin.Error(), "secret-name") {
		t.Fatalf("管理员应保留原文：%v", admin)
	}
	// 非冲突错误原样透传。
	other := errors.New("some other error")
	if maskPortConflict(nil, other, 1) != other {
		t.Fatal("非冲突错误应原样返回")
	}
}
