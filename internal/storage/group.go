package storage

import (
	"errors"
	"fmt"
	"time"

	"go-port-forward/internal/models"
	"go-port-forward/pkg/serializer/json"

	bolt "go.etcd.io/bbolt"
)

var (
	settingsBucket = []byte("settings")
	groupsBucket   = []byte("groups")
)

// settingsKey 是 settings bucket 里的唯一键（全局设置是单例）。
var settingsKey = []byte("global")

// 组与设置相关错误。
var (
	ErrGroupNotFound  = errors.New("user group not found")
	ErrGroupExists    = errors.New("user group name already exists")
	ErrGroupInUse     = errors.New("user group still has members")
	ErrGroupIsDefault = errors.New("cannot delete the default user group")
)

// --- 全局设置 ---

// Settings 读取全局设置；未初始化时返回默认值。
func (s *boltStore) Settings() (models.Settings, error) {
	var out models.Settings
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(settingsBucket).Get(settingsKey)
		if v == nil {
			out = models.DefaultSettings()
			return nil
		}
		return json.Unmarshal(v, &out)
	})
	return out, err
}

// SaveSettings 覆盖写入全局设置。
func (s *boltStore) SaveSettings(cfg models.Settings) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(settingsBucket).Put(settingsKey, data)
	})
}

// --- 用户组 ---

// ListGroups 返回全部用户组。
func (s *boltStore) ListGroups() ([]*models.UserGroup, error) {
	var out []*models.UserGroup
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(groupsBucket).ForEach(func(_, v []byte) error {
			var g models.UserGroup
			if err := json.Unmarshal(v, &g); err != nil {
				return err
			}
			out = append(out, &g)
			return nil
		})
	})
	return out, err
}

// GetGroup 按 ID 取组。
func (s *boltStore) GetGroup(id string) (*models.UserGroup, error) {
	var out *models.UserGroup
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(groupsBucket).Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrGroupNotFound, id)
		}
		var g models.UserGroup
		if err := json.Unmarshal(v, &g); err != nil {
			return err
		}
		out = &g
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SaveGroup 创建或覆盖用户组。
//
// 组名查重与「默认组唯一」两件事都在同一个写事务里完成：默认标记是全局互斥的
// 状态，读与写分处两个事务会让并发的两次设置各自看到「没有别的默认组」，
// 最后留下两个默认组，而新建用户会随机落到其中一个。
func (s *boltStore) SaveGroup(g *models.UserGroup) error {
	if g.ID == "" {
		return fmt.Errorf("storage: group id is required")
	}
	wantName := models.NormalizeGroupName(g.Name)
	now := time.Now()
	if g.CreatedAt.IsZero() {
		g.CreatedAt = now
	}
	g.UpdatedAt = now

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(groupsBucket)
		type entry struct {
			key []byte
			g   models.UserGroup
		}
		var others []entry
		dup := false
		if err := b.ForEach(func(k, v []byte) error {
			if string(k) == g.ID {
				return nil
			}
			var cur models.UserGroup
			if err := json.Unmarshal(v, &cur); err != nil {
				return err
			}
			if models.NormalizeGroupName(cur.Name) == wantName {
				dup = true
			}
			others = append(others, entry{key: append([]byte(nil), k...), g: cur})
			return nil
		}); err != nil {
			return err
		}
		if dup {
			return fmt.Errorf("%w: %s", ErrGroupExists, g.Name)
		}

		// 本组成为默认组时，清掉其它组的标记。
		if g.IsDefault {
			for _, e := range others {
				if !e.g.IsDefault {
					continue
				}
				e.g.IsDefault = false
				e.g.UpdatedAt = now
				data, err := json.Marshal(&e.g)
				if err != nil {
					return err
				}
				if err := b.Put(e.key, data); err != nil {
					return err
				}
			}
		}

		data, err := json.Marshal(g)
		if err != nil {
			return err
		}
		return b.Put([]byte(g.ID), data)
	})
}

// DeleteGroup 删除用户组。仍有成员或是默认组时拒绝。
//
// 拒绝而不是把成员挪到默认组：静默改变一批用户的配额，他们下次建规则才会
// 发现端口区间变了，而那时已经没人记得是这次删除引起的。
func (s *boltStore) DeleteGroup(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(groupsBucket)
		v := b.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrGroupNotFound, id)
		}
		var g models.UserGroup
		if err := json.Unmarshal(v, &g); err != nil {
			return err
		}
		if g.IsDefault {
			return ErrGroupIsDefault
		}
		members := 0
		if err := tx.Bucket(usersBucket).ForEach(func(_, uv []byte) error {
			var r userRecord
			if err := json.Unmarshal(uv, &r); err != nil {
				return err
			}
			if r.GroupID == id {
				members++
			}
			return nil
		}); err != nil {
			return err
		}
		if members > 0 {
			return fmt.Errorf("%w: %d", ErrGroupInUse, members)
		}
		return b.Delete([]byte(id))
	})
}

// CountGroupMembers 返回「组 ID → 成员数」。
func (s *boltStore) CountGroupMembers() (map[string]int, error) {
	out := map[string]int{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(usersBucket).ForEach(func(_, v []byte) error {
			var r userRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if r.GroupID != "" {
				out[r.GroupID]++
			}
			return nil
		})
	})
	return out, err
}
