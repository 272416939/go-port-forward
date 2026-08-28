package storage

import (
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

// AppendConnLog stores one event. Keys embed the nanosecond timestamp in
// big-endian order so listing reads newest first and trimming drops oldest.
func (s *boltStore) AppendConnLog(entry *models.ConnLogEntry) error {
	now := time.Now()
	id := uuid.NewString()
	entry.ID = id
	entry.Time = now

	key := make([]byte, 8, 8+len(id))
	binary.BigEndian.PutUint64(key[:8], uint64(now.UnixNano()))
	key = append(key, id...)

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(connLogsBucket).Put(key, data)
	})
}

// ListConnLogs returns up to limit most recent events, newest first.
func (s *boltStore) ListConnLogs(limit int) ([]*models.ConnLogEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	var logs []*models.ConnLogEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(connLogsBucket).Cursor()
		for k, v := c.Last(); k != nil && len(logs) < limit; k, v = c.Prev() {
			var e models.ConnLogEntry
			if err := json.Unmarshal(v, &e); err != nil {
				continue // 跳过损坏行而非整体失败 | skip corrupt rows instead of failing the whole query
			}
			logs = append(logs, &e)
		}
		return nil
	})
	return logs, err
}

// TrimConnLogs keeps at most maxEntries newest rows and reports how many were removed.
func (s *boltStore) TrimConnLogs(maxEntries int) (int, error) {
	if maxEntries <= 0 {
		maxEntries = 2000
	}
	removed := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(connLogsBucket)
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
	return removed, err
}
