package forward

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"go-port-forward/internal/config"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
	"go.uber.org/zap"
)

func newManagerFixture(t *testing.T) *Manager {
	t.Helper()
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()
	store, err := storage.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	mgr, err := NewManager(store, config.ForwardConfig{DialTimeout: 1, UDPTimeout: 30, BufferSize: 4096, PoolSize: 8})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	t.Cleanup(mgr.Shutdown)
	return mgr
}

func transparentRuleReq(name string, listenPort, targetPort int) *models.CreateRuleRequest {
	return &models.CreateRuleRequest{
		Name:        name,
		ListenAddr:  "",
		ListenPort:  listenPort,
		Protocol:    models.ProtocolUDP,
		TargetAddr:  "10.66.0.4",
		TargetPort:  targetPort,
		Transparent: true,
		Enabled:     false, // 本组用例只验证控制面，不启动转发器
	}
}

// TestTransparentDuplicateTargetRejected 锁「同隧道透明规则目标端口不可重复」：
// 两条规则指向同一后端 IP:端口时发往后端的四元组完全相同，后端无法区分入口，
// 属无意义配置——创建/更新即拒（2026-09 共享绑定立项时的用户决定）。
func TestTransparentDuplicateTargetRejected(t *testing.T) {
	mgr := newManagerFixture(t)

	r1, err := mgr.AddRule(transparentRuleReq("a", 21101, 58618))
	if err != nil {
		t.Fatalf("add rule a: %v", err)
	}
	// 不同目标端口：放行（这是同隧道多规则共存的主场景）
	r2, err := mgr.AddRule(transparentRuleReq("b", 21102, 58619))
	if err != nil {
		t.Fatalf("不同目标端口的第二条规则不应被拒: %v", err)
	}
	// 同目标端口：拒绝
	_, err = mgr.AddRule(transparentRuleReq("c", 21103, 58618))
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("同目标端口的第二条透明规则必须被拒（ErrInvalidRule），得到 %v", err)
	}

	// 更新造成碰撞：拒绝
	tp := 58618
	if _, err := mgr.UpdateRule(r2.ID, &models.UpdateRuleRequest{TargetPort: &tp}); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("更新碰撞必须被拒（ErrInvalidRule），得到 %v", err)
	}
	// 自身同值更新（排除自身）：放行
	if _, err := mgr.UpdateRule(r1.ID, &models.UpdateRuleRequest{TargetPort: &tp}); err != nil {
		t.Fatalf("自身同值更新不应被拒: %v", err)
	}
	// 非透明规则同目标不受限（connected socket 无独占绑定语义）
	if _, err := mgr.AddRule(&models.CreateRuleRequest{
		Name:       "general",
		ListenPort: 21104,
		Protocol:   models.ProtocolTCP,
		TargetAddr: "127.0.0.1",
		TargetPort: 58618,
		Enabled:    false,
	}); err != nil {
		t.Fatalf("非透明规则同目标不应被拒: %v", err)
	}
}

// TestTransparentDuplicateLegacyRulesLoadWithoutError：校验只拦新配置——
// 升级前已存在的重复规则照常加载启动（运行时由共享注册表按源广播兜底，
// 用户编辑任一条时被校验拦下自愈）。
func TestTransparentDuplicateLegacyRulesLoadWithoutError(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	store, err := storage.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	now := time.Now()
	dup1 := &models.ForwardRule{
		ID: "dup1", Name: "legacy-1", ListenPort: 21201, Protocol: models.ProtocolUDP,
		TargetAddr: "10.66.0.4", TargetPort: 58618, Transparent: true,
		Enabled: false, CreatedAt: now, UpdatedAt: now,
	}
	dup2 := &models.ForwardRule{
		ID: "dup2", Name: "legacy-2", ListenPort: 21202, Protocol: models.ProtocolUDP,
		TargetAddr: "10.66.0.4", TargetPort: 58618, Transparent: true,
		Enabled: false, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.SaveRule(dup1); err != nil {
		t.Fatalf("seed dup1: %v", err)
	}
	if err := store.SaveRule(dup2); err != nil {
		t.Fatalf("seed dup2: %v", err)
	}

	mgr, err := NewManager(store, config.ForwardConfig{DialTimeout: 1, UDPTimeout: 30, BufferSize: 4096, PoolSize: 8})
	if err != nil {
		t.Fatalf("存量重复规则不得阻碍启动: %v", err)
	}
	defer mgr.Shutdown()

	rules, err := mgr.ListRules()
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("应加载 2 条存量规则，得到 %d", len(rules))
	}
}

// TestNetherNetPortConflictWithGeneralRules 验证 NetherNet 与通用规则/透明规则的端口双向冲突拦截：
// 1. 已有 NetherNet 规则（监听 39042，默认复用占用 TCP 39042 信令端口与 UDP 39042 数据端口，或显式配置自定义数据端口 39043）：
//    - 新建通用 TCP 规则（端口 39042）必须被拦截（ErrPortConflict）；
//    - 新建通用 UDP 规则（端口 39042）必须被拦截；
//    - 新建普通透明 UDP 规则（端口 39042）必须被拦截；
// 2. 反向：已有通用 TCP 规则（端口 39042），新建 NetherNet 规则（监听 39042）必须被拦截；
// 3. 显式配置自定义数据端口（如 39043）时，39043 的 UDP 冲突也必须被拦截；
// 4. UpdateRule 更新撞上 NetherNet 端口也必须被拦截。
func TestNetherNetPortConflictWithGeneralRules(t *testing.T) {
	mgr := newManagerFixture(t)

	// 先建一条 NetherNet 规则（监听 0.0.0.0:39042，默认数据端口同为 39042）
	nnReq := &models.CreateRuleRequest{
		Name:        "bds26.51-1",
		ListenAddr:  "0.0.0.0",
		ListenPort:  39042,
		Protocol:    models.ProtocolUDP,
		TargetAddr:  "10.66.0.3",
		TargetPort:  39042,
		Transparent: true,
		NetherNet:   true,
		Enabled:     false,
	}
	nnRule, err := mgr.AddRule(nnReq)
	if err != nil {
		t.Fatalf("add nethernet rule: %v", err)
	}

	// 1.1 新建通用 TCP 规则（端口 39042）：信令端口占用 TCP，必须报 ErrPortConflict
	_, err = mgr.AddRule(&models.CreateRuleRequest{
		Name:        "general-tcp-39042",
		ListenAddr:  "0.0.0.0",
		ListenPort:  39042,
		Protocol:    models.ProtocolTCP,
		TargetAddr:  "198.51.100.1",
		TargetPort:  80,
		Transparent: false,
		Enabled:     false,
	})
	if !errors.Is(err, ErrPortConflict) {
		t.Fatalf("NetherNet 信令端口 (TCP 39042) 冲突必须返回 ErrPortConflict，得到 %v", err)
	}

	// 1.2 新建通用 UDP 规则（端口 39042）：数据端口占用 UDP，必须报 ErrPortConflict
	_, err = mgr.AddRule(&models.CreateRuleRequest{
		Name:        "general-udp-39042",
		ListenAddr:  "0.0.0.0",
		ListenPort:  39042,
		Protocol:    models.ProtocolUDP,
		TargetAddr:  "198.51.100.1",
		TargetPort:  80,
		Transparent: false,
		Enabled:     false,
	})
	if !errors.Is(err, ErrPortConflict) {
		t.Fatalf("NetherNet 数据端口 (UDP 39042) 冲突必须返回 ErrPortConflict，得到 %v", err)
	}

	// 1.3 新建普通透明代理 UDP 规则（端口 39042）：数据端口冲突
	_, err = mgr.AddRule(&models.CreateRuleRequest{
		Name:        "tp-udp-39042",
		ListenAddr:  "0.0.0.0",
		ListenPort:  39042,
		Protocol:    models.ProtocolUDP,
		TargetAddr:  "10.66.0.3",
		TargetPort:  19132,
		Transparent: true,
		Enabled:     false,
	})
	if !errors.Is(err, ErrPortConflict) {
		t.Fatalf("透明 UDP 规则撞上 NetherNet 端口 (39042) 必须被拦截，得到 %v", err)
	}

	// 1.4 39043 端口未被占用（因为默认数据端口不再 +1），新建通用 UDP 规则（端口 39043）应当放行
	udp39043, err := mgr.AddRule(&models.CreateRuleRequest{
		Name:        "general-udp-39043",
		ListenAddr:  "0.0.0.0",
		ListenPort:  39043,
		Protocol:    models.ProtocolUDP,
		TargetAddr:  "198.51.100.1",
		TargetPort:  80,
		Transparent: false,
		Enabled:     false,
	})
	if err != nil {
		t.Fatalf("39043 未被占用时应允许创建，得到 %v", err)
	}
	_ = mgr.DeleteRule(udp39043.ID)

	// 2. 反向验证：新建一个不同端口的通用 TCP 规则，然后更新为 39042
	tcpRule, err := mgr.AddRule(&models.CreateRuleRequest{
		Name:        "temp-tcp",
		ListenAddr:  "0.0.0.0",
		ListenPort:  39050,
		Protocol:    models.ProtocolTCP,
		TargetAddr:  "198.51.100.1",
		TargetPort:  80,
		Transparent: false,
		Enabled:     false,
	})
	if err != nil {
		t.Fatalf("add temp-tcp: %v", err)
	}
	newPort := 39042
	_, err = mgr.UpdateRule(tcpRule.ID, &models.UpdateRuleRequest{ListenPort: &newPort})
	if !errors.Is(err, ErrPortConflict) {
		t.Fatalf("更新通用 TCP 端口为 39042 必须被拦截 (ErrPortConflict)，得到 %v", err)
	}

	// 3. 验证 IsPortUsed
	if !mgr.IsPortUsed(39042) {
		t.Fatal("IsPortUsed(39042) should be true (NetherNet signal and data port)")
	}
	if mgr.IsPortUsed(39043) {
		t.Fatal("IsPortUsed(39043) should be false when data_port defaults to listen_port")
	}
	if mgr.IsPortUsed(39099) {
		t.Fatal("IsPortUsed(39099) should be false")
	}

	// 4. 自身更新排除自身：改名字不改端口放行
	newName := "bds-renamed"
	if _, err := mgr.UpdateRule(nnRule.ID, &models.UpdateRuleRequest{Name: &newName}); err != nil {
		t.Fatalf("自身更新同端口不应报错: %v", err)
	}
}

