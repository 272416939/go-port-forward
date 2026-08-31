package storage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"go-port-forward/internal/models"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
	"go-port-forward/pkg/serializer/json"
)

var (
	aclBucket      = []byte("acl")
	connLogsBucket = []byte("connlogs")
)

// ListACLEntries returns every IP access-control entry.
func (s *boltStore) ListACLEntries() ([]*models.ACLEntry, error) {
	var entries []*models.ACLEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(aclBucket).ForEach(func(_, v []byte) error {
			var e models.ACLEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			entries = append(entries, &e)
			return nil
		})
	})
	return entries, err
}

// SaveACLEntry inserts or updates an entry keyed by ID.
func (s *boltStore) SaveACLEntry(entry *models.ACLEntry) error {
	if entry.ID == "" {
		return fmt.Errorf("storage: acl entry id is required")
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(aclBucket).Put([]byte(entry.ID), data)
	})
}

// DeleteACLEntry removes an entry; deleting a missing entry is not an error.
func (s *boltStore) DeleteACLEntry(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(aclBucket).Delete([]byte(id))
	})
}

// --- 连接日志：connlogs 父桶下按用户挂嵌套桶 ---
//
// 每用户一个子桶才能自然地做「按用户分页 / 删除 / 清空 / 限额」，桶内 key
// 仍是 8 字节 BigEndian UnixNano + uuid：时间前缀让跨桶的 key 可直接按字节
// 比较大小（admin 全量视图做 k 路归并就是靠这一点）。

// userLogsBucketTx 取某用户的日志子桶；create=true 时不存在则建。
func userLogsBucketTx(tx *bolt.Tx, userID string, create bool) (*bolt.Bucket, error) {
	parent := tx.Bucket(connLogsBucket)
	if parent == nil {
		return nil, fmt.Errorf("storage: bucket %s missing", connLogsBucket)
	}
	b := parent.Bucket([]byte(userID))
	if b == nil && create {
		var err error
		b, err = parent.CreateBucketIfNotExists([]byte(userID))
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

// connLogKey 生成时间有序 key：8 字节大端纳秒时间戳 + uuid 字符串。
func connLogKey(now time.Time, id string) []byte {
	key := make([]byte, 8, 8+len(id))
	binary.BigEndian.PutUint64(key[:8], uint64(now.UnixNano()))
	return append(key, id...)
}

// AppendConnLog stores one event under the owning user's bucket. Keys embed
// the nanosecond timestamp in big-endian order so listing reads newest first
// and trimming drops oldest. entry.UserID 为空时拒绝写入——日志的归属维度
// 在产生点（转发器手里的 rule）是已知的，落到存储层再补就晚了。
func (s *boltStore) AppendConnLog(entry *models.ConnLogEntry) error {
	if entry == nil || entry.UserID == "" {
		return fmt.Errorf("storage: conn log entry requires user id")
	}
	now := time.Now()
	id := uuid.NewString()
	entry.ID = id
	entry.Time = now
	key := connLogKey(now, id)

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := userLogsBucketTx(tx, entry.UserID, true)
		if err != nil {
			return err
		}
		return b.Put(key, data)
	})
}

// ListConnLogs returns up to limit most recent events starting at offset
// (newest first), plus the total count. userID 为空表示全量（admin）：跨所有
// 用户子桶按 key 归并——key 自带时间前缀，字节序即时间序。
func (s *boltStore) ListConnLogs(userID string, offset, limit int) ([]*models.ConnLogEntry, int, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	var (
		logs  []*models.ConnLogEntry
		total int
	)
	err := s.db.View(func(tx *bolt.Tx) error {
		parent := tx.Bucket(connLogsBucket)
		if parent == nil {
			return nil
		}
		var buckets []*bolt.Bucket
		if userID != "" {
			if b := parent.Bucket([]byte(userID)); b != nil {
				buckets = append(buckets, b)
			}
		} else {
			_ = parent.ForEach(func(k []byte, v []byte) error {
				if v == nil {
					if b := parent.Bucket(k); b != nil {
						buckets = append(buckets, b)
					}
				}
				return nil
			})
		}

		type bc struct {
			c    *bolt.Cursor
			k, v []byte
		}
		heads := make([]*bc, 0, len(buckets))
		for _, b := range buckets {
			total += b.Stats().KeyN
			c := b.Cursor()
			k, v := c.Last()
			if k != nil {
				heads = append(heads, &bc{c: c, k: k, v: v})
			}
		}

		advance := func(h *bc) {
			h.k, h.v = h.c.Prev()
		}
		for len(logs) < limit {
			// 找当前最大的 key（= 最新的一条）。
			var top *bc
			for _, h := range heads {
				if h.k == nil {
					continue
				}
				if top == nil || bytes.Compare(h.k, top.k) > 0 {
					top = h
				}
			}
			if top == nil {
				return nil
			}
			v := top.v
			advance(top)
			if offset > 0 {
				offset--
				continue
			}
			var e models.ConnLogEntry
			if err := json.Unmarshal(v, &e); err != nil {
				continue // 跳过损坏行而非整体失败 | skip corrupt rows instead of failing
			}
			logs = append(logs, &e)
		}
		return nil
	})
	return logs, total, err
}

// DeleteConnLogs removes entries whose uuid tail matches ids and reports how
// many were deleted. 只扫 key 不解 JSON：uuid 就拼在 key 尾部。userID 为空
// 时跨全部用户桶（admin）。
func (s *boltStore) DeleteConnLogs(userID string, ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	want := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id != "" {
			want[id] = struct{}{}
		}
	}
	if len(want) == 0 {
		return 0, nil
	}
	removed := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		parent := tx.Bucket(connLogsBucket)
		if parent == nil {
			return nil
		}
		var targets []*bolt.Bucket
		if userID != "" {
			if b := parent.Bucket([]byte(userID)); b != nil {
				targets = append(targets, b)
			}
		} else {
			_ = parent.ForEach(func(k []byte, v []byte) error {
				if v == nil {
					if b := parent.Bucket(k); b != nil {
						targets = append(targets, b)
					}
				}
				return nil
			})
		}
		for _, b := range targets {
			var doomed [][]byte
			c := b.Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				if len(k) <= 8 {
					continue
				}
				if _, ok := want[string(k[8:])]; ok {
					doomed = append(doomed, append([]byte(nil), k...))
				}
			}
			for _, k := range doomed {
				if err := b.Delete(k); err != nil {
					return err
				}
				removed++
			}
		}
		return nil
	})
	return removed, err
}

// ClearConnLogs drops every entry of one user (or all users when userID is
// empty) and reports how many were removed. 删桶再重建：比逐 key 删快得多。
func (s *boltStore) ClearConnLogs(userID string) (int, error) {
	removed := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		parent := tx.Bucket(connLogsBucket)
		if parent == nil {
			return nil
		}
		var names [][]byte
		if userID != "" {
			if parent.Bucket([]byte(userID)) != nil {
				names = append(names, []byte(userID))
			}
		} else {
			_ = parent.ForEach(func(k []byte, v []byte) error {
				if v == nil {
					names = append(names, append([]byte(nil), k...))
				}
				return nil
			})
		}
		for _, name := range names {
			b := parent.Bucket(name)
			if b == nil {
				continue
			}
			removed += b.Stats().KeyN
			if err := parent.DeleteBucket(name); err != nil {
				return err
			}
			if _, err := parent.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
	return removed, err
}

// TrimConnLogs keeps at most maxEntries newest rows per user and reports how
// many were removed in total.
func (s *boltStore) TrimConnLogs(maxEntries int) (int, error) {
	if maxEntries <= 0 {
		maxEntries = 2000
	}
	removed := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		parent := tx.Bucket(connLogsBucket)
		if parent == nil {
			return nil
		}
		return parent.ForEach(func(name, v []byte) error {
			if v != nil {
				return nil // 旧版直存数据由迁移清理 | legacy rows handled by migration
			}
			b := parent.Bucket(name)
			if b == nil {
				return nil
			}
			total := b.Stats().KeyN
			if total <= maxEntries {
				return nil
			}
			drop := total - maxEntries
			c := b.Cursor()
			for k, _ := c.First(); k != nil && drop > 0; k, _ = c.First() {
				if err := b.Delete(k); err != nil {
					return err
				}
				drop--
				removed++
			}
			return nil
		})
	})
	return removed, err
}

// dropLegacyConnLogs 删除旧版「全局单桶」时期直接写在 connlogs 父桶里的
// 条目：它们没有用户归属，分桶模型下不可见也不该再占地方。幂等：清理后
// 再跑是空转。旧上限默认只有 2000 条，丢弃是可接受的。
func dropLegacyConnLogs(db *bolt.DB) (int, error) {
	removed := 0
	err := db.Update(func(tx *bolt.Tx) error {
		parent := tx.Bucket(connLogsBucket)
		if parent == nil {
			return nil
		}
		var doomed [][]byte
		_ = parent.ForEach(func(k []byte, v []byte) error {
			if v != nil {
				doomed = append(doomed, append([]byte(nil), k...))
			}
			return nil
		})
		for _, k := range doomed {
			if err := parent.Delete(k); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	return removed, err
}
