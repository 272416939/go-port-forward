package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-port-forward/internal/models"
)

func TestSettingsTimezoneAPIAndHotReload(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	// 1. 默认 GET /api/settings 携带 Asia/Shanghai
	rec := httptest.NewRecorder()
	f.h.getSettings(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/settings", nil), f.admin))
	if rec.Code != http.StatusOK {
		t.Fatalf("getSettings status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"timezone":"Asia/Shanghai"`) {
		t.Fatalf("默认时区应为 Asia/Shanghai: %s", rec.Body.String())
	}

	// 2. GET /api/auth/me 携带 timezone
	recMe := httptest.NewRecorder()
	f.h.me(recMe, asUser(httptest.NewRequest(http.MethodGet, "/api/auth/me", nil), f.admin))
	if recMe.Code != http.StatusOK {
		t.Fatalf("me status = %d, body=%s", recMe.Code, recMe.Body.String())
	}
	if !strings.Contains(recMe.Body.String(), `"timezone":"Asia/Shanghai"`) {
		t.Fatalf("me 响应应包含当前系统时区 Asia/Shanghai: %s", recMe.Body.String())
	}

	// 3. 管理员 PUT /api/settings 更新为 UTC
	tz := "UTC"
	body, _ := json.Marshal(models.UpdateSettingsRequest{
		Timezone: &tz,
	})
	reqPut := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
	reqPut.Header.Set("Content-Type", "application/json")
	recPut := httptest.NewRecorder()
	f.h.updateSettings(recPut, asUser(reqPut, f.admin))
	if recPut.Code != http.StatusOK {
		t.Fatalf("updateSettings status = %d, body=%s", recPut.Code, recPut.Body.String())
	}
	if !strings.Contains(recPut.Body.String(), `"timezone":"UTC"`) {
		t.Fatalf("更新后应返回 timezone=UTC: %s", recPut.Body.String())
	}

	// 4. 验证全局 models.SystemTimezoneName() 已经即时热切换为 UTC
	if models.SystemTimezoneName() != "UTC" {
		t.Fatalf("models.SystemTimezoneName() 期望 UTC，实际为 %q", models.SystemTimezoneName())
	}

	// 5. 再次 GET /api/auth/me，返回的时区同步变为 UTC
	recMe2 := httptest.NewRecorder()
	f.h.me(recMe2, asUser(httptest.NewRequest(http.MethodGet, "/api/auth/me", nil), f.admin))
	if !strings.Contains(recMe2.Body.String(), `"timezone":"UTC"`) {
		t.Fatalf("me 响应应同步变为 UTC: %s", recMe2.Body.String())
	}

	// 6. 非法时区应被拦截
	badTz := "Invalid/FakeZone"
	bodyBad, _ := json.Marshal(models.UpdateSettingsRequest{
		Timezone: &badTz,
	})
	reqBad := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(bodyBad))
	reqBad.Header.Set("Content-Type", "application/json")
	recBad := httptest.NewRecorder()
	f.h.updateSettings(recBad, asUser(reqBad, f.admin))
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("非法时区应返回 400，got %d: %s", recBad.Code, recBad.Body.String())
	}

	// 恢复默认时区
	_ = models.ApplyTimezone(models.DefaultTimezone)
}
