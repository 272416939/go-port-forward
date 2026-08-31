package storage

// 按用户分桶的连接日志：分页 / 删除 / 清空 / 限额裁剪 / 旧版数据清理。

import (
	"testing"
	"time"

	"go-port-forward/internal/models"

	bolt "go.etcd.io/bbolt"
)

func connEntry(userID string) *models.ConnLogEntry {
	return &models.ConnLogEntry{
		UserID:   userID,
		Protocol: models.ProtocolUDP,
		RuleID:   "r1",
		RuleName: "rule",
		SrcIP:    "1.2.3.4",
		SrcPort:  1000,
		Event:    models.ConnEventJoin,
	}
}

func TestConnLogsEmptyUserIDRejected(t *testing.T) {
	s := newUserStore(t)
	if err := s.AppendConnLog(&models.ConnLogEntry{Protocol: models.ProtocolUDP, Event: models.ConnEventJoin}); err == nil {
		t.Fatal("缺 UserID 的日志应拒绝写入（归属必须在产生点确定）")
	}
}

func TestConnLogsPerPageScoped(t *testing.T) {
	s := newUserStore(t)
	for i := 0; i < 7; i++ {
		if err := s.AppendConnLog(connEntry("alice")); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := s.AppendConnLog(connEntry("bob")); err != nil {
			t.Fatal(err)
		}
	}

	logs, total, err := s.ListConnLogs("alice", 0, 3)
	if err != nil || total != 7 || len(logs) != 3 {
		t.Fatalf("第一页应为 3/7：logs=%d total=%d err=%v", len(logs), total, err)
	}
	if logs[0].UserID != "alice" {
		t.Fatalf("日志应带归属：%+v", logs[0])
	}

	// 三页合起来恰好覆盖全部 7 条，不重不漏。
	seen := map[string]bool{}
	for offset := 0; offset < 7; offset += 3 {
		page, tot, err := s.ListConnLogs("alice", offset, 3)
		if err != nil || tot != 7 {
			t.Fatalf("offset=%d: total=%d err=%v", offset, tot, err)
		}
		for _, l := range page {
			if seen[l.ID] {
				t.Fatalf("分页出现重复条目 %s", l.ID)
			}
			seen[l.ID] = true
		}
	}
	if len(seen) != 7 {
		t.Fatalf("翻页应覆盖全部 7 条：got %d", len(seen))
	}

	// bob 的桶独立计数。
	_, totalB, err := s.ListConnLogs("bob", 0, 10)
	if err != nil || totalB != 3 {
		t.Fatalf("bob 应为 3 条：total=%d err=%v", totalB, err)
	}

	// admin（userID=""）跨桶归并。
	all, totalAll, err := s.ListConnLogs("", 0, 100)
	if err != nil || totalAll != 10 || len(all) != 10 {
		t.Fatalf("全量视图应为 10 条：logs=%d total=%d err=%v", len(all), totalAll, err)
	}
	// 全量视图按时间倒序：时间相同的两条由 uuid 尾部定序，严格先后不保证。
	for i := 1; i < len(all); i++ {
		if all[i-1].Time.Before(all[i].Time) {
			t.Fatalf("全量视图应按时间倒序：第 %d 条早于第 %d 条", i, i-1)
		}
	}
}

func TestConnLogsDeleteAndClearScoped(t *testing.T) {
	s := newUserStore(t)
	for i := 0; i < 3; i++ {
		_ = s.AppendConnLog(connEntry("alice"))
	}
	for i := 0; i < 2; i++ {
		_ = s.AppendConnLog(connEntry("bob"))
	}
	bobLogs, _, err := s.ListConnLogs("bob", 0, 10)
	if err != nil || len(bobLogs) != 2 {
		t.Fatalf("bob 日志准备失败：err=%v", err)
	}
	bobIDs := []string{bobLogs[0].ID, bobLogs[1].ID}

	// alice 作用域拿 bob 的 ID 删除：应全部落空且不影响 bob。
	removed, err := s.DeleteConnLogs("alice", bobIDs)
	if err != nil || removed != 0 {
		t.Fatalf("跨用户删除应落空：removed=%d err=%v", removed, err)
	}
	if _, totalB, _ := s.ListConnLogs("bob", 0, 10); totalB != 2 {
		t.Fatalf("bob 的日志不应被别人的作用域删掉：total=%d", totalB)
	}

	// 删自己的。
	aliceLogs, _, _ := s.ListConnLogs("alice", 0, 10)
	removed, err = s.DeleteConnLogs("alice", []string{aliceLogs[0].ID})
	if err != nil || removed != 1 {
		t.Fatalf("按 ID 删除应命中 1 条：removed=%d err=%v", removed, err)
	}

	// 清空只清作用域：alice 清空后 bob 仍是 2 条。
	if n, err := s.ClearConnLogs("alice"); err != nil || n != 2 {
		t.Fatalf("清空应移除 2 条：n=%d err=%v", n, err)
	}
	if _, totalA, _ := s.ListConnLogs("alice", 0, 10); totalA != 0 {
		t.Fatalf("alice 清空后应为 0：total=%d", totalA)
	}
	if _, totalB, _ := s.ListConnLogs("bob", 0, 10); totalB != 2 {
		t.Fatalf("alice 清空不应影响 bob：total=%d", totalB)
	}
}

func TestConnLogsTrimPerUser(t *testing.T) {
	s := newUserStore(t)
	for i := 0; i < 12; i++ {
		_ = s.AppendConnLog(connEntry("alice"))
	}
	_ = s.AppendConnLog(connEntry("bob"))

	newest, _, err := s.ListConnLogs("alice", 0, 1)
	if err != nil || len(newest) != 1 {
		t.Fatalf("取最新一条失败：err=%v", err)
	}

	if n, err := s.TrimConnLogs(10); err != nil || n != 2 {
		t.Fatalf("裁剪应移除 2 条：n=%d err=%v", n, err)
	}
	logs, total, err := s.ListConnLogs("alice", 0, 100)
	if err != nil || total != 10 || len(logs) != 10 {
		t.Fatalf("裁剪后应为 10 条：logs=%d total=%d err=%v", len(logs), total, err)
	}
	// 留下的必须是最新的（环形写入的语义）。
	stillThere := false
	for _, l := range logs {
		if l.ID == newest[0].ID {
			stillThere = true
		}
	}
	if !stillThere {
		t.Fatal("裁剪后最新的那条不应被删")
	}
	if _, totalB, _ := s.ListConnLogs("bob", 0, 10); totalB != 1 {
		t.Fatalf("裁剪不应波及其他用户：bob total=%d", totalB)
	}
}

// dropLegacyConnLogs 只清父桶直存的旧版条目，用户子桶必须原样保留。
func TestDropLegacyConnLogsKeepsUserBuckets(t *testing.T) {
	db, err := bolt.Open(t.TempDir()+"/legacy.db", 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		parent, berr := tx.CreateBucketIfNotExists([]byte("connlogs"))
		if berr != nil {
			return berr
		}
		if err := parent.Put([]byte("legacy-key"), []byte(`{"id":"legacy"}`)); err != nil {
			return err
		}
		sub, berr := parent.CreateBucketIfNotExists([]byte("alice"))
		if berr != nil {
			return berr
		}
		return sub.Put([]byte("k"), []byte(`{}`))
	}); err != nil {
		t.Fatal(err)
	}

	if n, err := dropLegacyConnLogs(db); err != nil || n != 1 {
		t.Fatalf("应清理 1 条旧版条目：n=%d err=%v", n, err)
	}
	// 幂等：再跑一遍是空转。
	if n, err := dropLegacyConnLogs(db); err != nil || n != 0 {
		t.Fatalf("重复清理应为 0：n=%d err=%v", n, err)
	}

	_ = db.View(func(tx *bolt.Tx) error {
		parent := tx.Bucket([]byte("connlogs"))
		direct := 0
		_ = parent.ForEach(func(_, v []byte) error {
			if v != nil {
				direct++
			}
			return nil
		})
		if direct != 0 {
			t.Fatalf("旧版直存条目应清空：got %d", direct)
		}
		if parent.Bucket([]byte("alice")) == nil {
			t.Fatal("用户子桶不应被清理")
		}
		return nil
	})
	_ = db.Close()
}
