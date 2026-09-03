package web

// 隧道链路质量端点的用例。
//
// 两条线都要锁：① 端点是 admin-only 的（普通用户 403，匿名 401）——它暴露全部
// 用户的在线隧道与链路数据，属运维信息；② 隧道未开启时返回明确的
// enabled=false，面板据此显示「隧道未开启」而不是一张空表格（运维不会把它
// 误读成「所有玩家都断了」）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/config"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
	"go-port-forward/internal/users"

	"go.uber.org/zap"
)

// fakeTunnelLink 是 TunnelStatus 的替身。
type fakeTunnelLink struct {
	report *TunnelLinkReport
}

func (f *fakeTunnelLink) PeerCount() int { return len(f.report.Peers) }

func (f *fakeTunnelLink) TunnelLink() *TunnelLinkReport { return f.report }

func sampleReport() *TunnelLinkReport {
	return &TunnelLinkReport{
		Peers: []TunnelLinkPeer{{
			UserName: "alice", CodeName: "c1", TunIP: "10.66.0.2", Addr: "203.0.113.5:1000",
			Since: time.Unix(1700000000, 0), IdleSec: 3, MTU: 1400,
			LossPPM: 12000, ReorderPPM: 500, JitterMS: 3.2, RTTMS: 41.5,
			FECRecovered: 7,
		}},
		KernelDrops: 128, IOMode: "batch", MTU: 1400,
	}
}

// 走完整鉴权栈（真实会话 cookie）：这一层锁的是「路由确实包在 adminOnly 里」，
// 而不只是 handler 本身的行为——路由忘了包装的话，普通用户就是 200。
func TestTunnelStatusRouteIsAdminOnly(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()
	store, err := storage.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	sessions := auth.NewStore(false)
	svc, err := users.New(store, sessions, "10.66.0.1/24", "203.0.113.9:7947")
	if err != nil {
		t.Fatal(err)
	}
	srv := New(config.WebConfig{}, nil, nil, svc, sessions, &fakeTunnelLink{report: sampleReport()})
	h := &handler{tunnel: srv.tunnel}

	admin, err := svc.Create(&models.CreateUserRequest{Username: "admin", Password: "password123", Role: models.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	alice, err := svc.Create(&models.CreateUserRequest{Username: "alice", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}

	get := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/tunnel/status", nil)
		if token != "" {
			req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		}
		rec := httptest.NewRecorder()
		srv.adminOnly(h.tunnelStatus)(rec, req)
		return rec
	}

	// 匿名 → 401。
	if rec := get(""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("匿名请求 = %d, want 401", rec.Code)
	}
	// 普通用户 → 403：链路数据覆盖全部用户的在线隧道，不是个人数据。
	aliceToken, _ := sessions.Issue(alice.ID)
	if rec := get(aliceToken); rec.Code != http.StatusForbidden {
		t.Fatalf("普通用户请求 = %d, want 403", rec.Code)
	}
	// 管理员 → 200，且报告内容完整。
	adminToken, _ := sessions.Issue(admin.ID)
	rec := get(adminToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("管理员请求 = %d, want 200", rec.Code)
	}
	var envelope struct {
		Success bool `json:"success"`
		Data    struct {
			Enabled bool `json:"enabled"`
			Report  struct {
				Peers []struct {
					UserName string  `json:"user_name"`
					LossPPM  int64   `json:"loss_ppm"`
					RTTMS    float64 `json:"rtt_ms"`
				} `json:"peers"`
				KernelDrops uint64 `json:"kernel_drops"`
				IOMode      string `json:"io_mode"`
			} `json:"report"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if !envelope.Success {
		t.Fatalf("响应应走统一 success 封装: %s", rec.Body.String())
	}
	body := envelope.Data
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if !body.Enabled || len(body.Report.Peers) != 1 || body.Report.Peers[0].LossPPM != 12000 {
		t.Fatalf("报告内容不符: %+v", body)
	}
	if body.Report.KernelDrops != 128 || body.Report.IOMode != "batch" {
		t.Fatalf("全局字段不符: %+v", body.Report)
	}
}

// 隧道未开启（TunnelStatus 为 nil，main.go 里隧道关着时就是 nil）必须返回明确的
// enabled=false，而不是 404/500/空表格。
func TestTunnelStatusDisabledWhenTunnelOff(t *testing.T) {
	h := &handler{}
	rec := httptest.NewRecorder()
	h.tunnelStatus(rec, httptest.NewRequest(http.MethodGet, "/api/tunnel/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("未开启隧道应 200 而不是 404/500，得到 %d", rec.Code)
	}
	var envelope struct {
		Success bool `json:"success"`
		Data    struct {
			Enabled bool `json:"enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if !envelope.Success || envelope.Data.Enabled {
		t.Fatalf("隧道未开启应返回 success + enabled=false: %s", rec.Body.String())
	}

	// TunnelLink 返回 nil 同样视为未开启（防御：接口实现半截时不至于 panic）。
	h2 := &handler{tunnel: &fakeTunnelLink{}}
	rec2 := httptest.NewRecorder()
	h2.tunnelStatus(rec2, httptest.NewRequest(http.MethodGet, "/api/tunnel/status", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("TunnelLink 为 nil 应 200，得到 %d", rec2.Code)
	}
}
