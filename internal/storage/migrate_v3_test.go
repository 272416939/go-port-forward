package storage

import (
	"path/filepath"
	"testing"
	"time"

	"go-port-forward/internal/models"
	"go-port-forward/pkg/serializer/json"

	bolt "go.etcd.io/bbolt"
)

// TestMigrateV2ToV3UpgradesZeroQuotasToNegativeOne 测试将 v2 库（旧组配额全为 0，实际表示跟随全局）
// 升级到 v3 时，自动将 0 转换为 -1，保证老系统升级后仍继承全局值。
func TestMigrateV2ToV3UpgradesZeroQuotasToNegativeOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.db")
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	// 写入 v2 的 settings 与 groups
	if err := db.Update(func(tx *bolt.Tx) error {
		sb, err := tx.CreateBucketIfNotExists(settingsBucket)
		if err != nil {
			return err
		}
		gb, err := tx.CreateBucketIfNotExists(groupsBucket)
		if err != nil {
			return err
		}
		_, _ = tx.CreateBucketIfNotExists(usersBucket)
		_, _ = tx.CreateBucketIfNotExists(codesBucket)

		cfg := models.DefaultSettings()
		cfg.SchemaVersion = 2 // 伪造 v2
		data, _ := json.Marshal(cfg)
		_ = sb.Put(settingsKey, data)

		g := models.UserGroup{
			ID:             "g-v2",
			Name:           "default",
			MaxAccessCodes: 0, // 在 v2 中 0 代表跟随全局
			MaxTunnels:     0,
			MaxRules:       0,
			IsDefault:      true,
		}
		gData, _ := json.Marshal(&g)
		return gb.Put([]byte(g.ID), gData)
	}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// 用当前的 Open 打开数据库，自动触发迁移
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	cfg, err := s.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SchemaVersion != 3 {
		t.Fatalf("SchemaVersion = %d, want 3", cfg.SchemaVersion)
	}

	g, err := s.GetGroup("g-v2")
	if err != nil {
		t.Fatal(err)
	}
	if g.MaxAccessCodes != -1 || g.MaxTunnels != -1 || g.MaxRules != -1 {
		t.Fatalf("v2 存量组配额升级后应为 -1（跟随全局），得到 codes=%d tunnels=%d rules=%d",
			g.MaxAccessCodes, g.MaxTunnels, g.MaxRules)
	}
}
