package storage

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"go-port-forward/internal/models"
	"go-port-forward/pkg/serializer/json"

	bolt "go.etcd.io/bbolt"
)

var codesBucket = []byte("codes")

// 访问码相关错误。
var (
	ErrCodeNotFound = errors.New("access code not found")
	ErrCodeQuota    = errors.New("access code quota reached")
)

// codeRecord 是访问码的持久化形态。
//
// models.AccessCode 的 Secret/DeviceFingerprint 带 json:"-"（它同时是 API
// 响应结构体），直接复用它落盘会把密钥与指纹写成空串——重启后所有访问码
// 既无法握手也失去设备绑定。与 userRecord 是同一个理由：一套标签服务两个
// 相反的需求必然出错，把用途拆开。
type codeRecord struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	ID     string `json:"id"`
	UserID string `json:"user_id"`
	Name   string `json:"name"`
	TunIP  string `json:"tun_ip"`
	Secret string `json:"secret"`

	Disabled bool `json:"disabled"`

	DeviceFingerprint string    `json:"device_fingerprint,omitempty"`
	DeviceLabel       string    `json:"device_label,omitempty"`
	BoundAt           time.Time `json:"bound_at,omitempty"`
	LastSeenAt        time.Time `json:"last_seen_at,omitempty"`
	LastSeenAddr      string    `json:"last_seen_addr,omitempty"`
}

func toCodeRecord(c *models.AccessCode) *codeRecord {
	return &codeRecord{
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
		ID: c.ID, UserID: c.UserID, Name: c.Name, TunIP: c.TunIP, Secret: c.Secret,
		Disabled:          c.Disabled,
		DeviceFingerprint: c.DeviceFingerprint, DeviceLabel: c.DeviceLabel,
		BoundAt: c.BoundAt, LastSeenAt: c.LastSeenAt, LastSeenAddr: c.LastSeenAddr,
	}
}

func (r *codeRecord) toModel() *models.AccessCode {
	return &models.AccessCode{
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		ID: r.ID, UserID: r.UserID, Name: r.Name, TunIP: r.TunIP, Secret: r.Secret,
		Disabled:          r.Disabled,
		DeviceFingerprint: r.DeviceFingerprint, DeviceLabel: r.DeviceLabel,
		BoundAt: r.BoundAt, LastSeenAt: r.LastSeenAt, LastSeenAddr: r.LastSeenAddr,
	}
}

// ListAccessCodes 返回全部访问码。
func (s *boltStore) ListAccessCodes() ([]*models.AccessCode, error) {
	var out []*models.AccessCode
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(codesBucket).ForEach(func(_, v []byte) error {
			var r codeRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			out = append(out, r.toModel())
			return nil
		})
	})
	return out, err
}

// ListAccessCodesByUser 返回某用户的访问码。
func (s *boltStore) ListAccessCodesByUser(userID string) ([]*models.AccessCode, error) {
	var out []*models.AccessCode
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(codesBucket).ForEach(func(_, v []byte) error {
			var r codeRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if r.UserID == userID {
				out = append(out, r.toModel())
			}
			return nil
		})
	})
	return out, err
}

// GetAccessCode 按 ID 取访问码（含密钥与指纹）。
func (s *boltStore) GetAccessCode(id string) (*models.AccessCode, error) {
	var out *models.AccessCode
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(codesBucket).Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrCodeNotFound, id)
		}
		var r codeRecord
		if err := json.Unmarshal(v, &r); err != nil {
			return err
		}
		out = r.toModel()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CreateAccessCode 在单个写事务内完成「配额检查 + 隧道地址分配 + 落盘」。
//
// 三步必须同事务，理由与 CreateUser 相同：地址分配依赖"当前已占用哪些地址"
// 这个读结果，读与写分处两个事务时两个并发请求会分到同一地址——而重复的隧道
// 地址会让出向包路由到错误的会话，是静默的串号故障。配额检查同理，否则并发
// 创建能突破上限。
//
// maxCodes <= 0 表示不限。
func (s *boltStore) CreateAccessCode(c *models.AccessCode, pool netip.Prefix, gateway netip.Addr, maxCodes int) error {
	if c.ID == "" || c.UserID == "" {
		return fmt.Errorf("storage: access code id and user id are required")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(codesBucket)
		used := map[netip.Addr]struct{}{}
		owned := 0
		if err := b.ForEach(func(_, v []byte) error {
			var r codeRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if addr, ok := models.ParseTunIP(r.TunIP); ok {
				used[addr] = struct{}{}
			}
			if r.UserID == c.UserID {
				owned++
			}
			return nil
		}); err != nil {
			return err
		}
		if maxCodes > 0 && owned >= maxCodes {
			return fmt.Errorf("%w: %d", ErrCodeQuota, maxCodes)
		}
		// 服务端的隧道地址也不能被分出去。
		if gateway.IsValid() {
			used[gateway] = struct{}{}
		}

		if c.TunIP == "" {
			addr, err := allocTunIP(pool, gateway, used)
			if err != nil {
				return err
			}
			c.TunIP = addr.String()
		}
		now := time.Now()
		if c.CreatedAt.IsZero() {
			c.CreatedAt = now
		}
		c.UpdatedAt = now

		data, err := json.Marshal(toCodeRecord(c))
		if err != nil {
			return err
		}
		return b.Put([]byte(c.ID), data)
	})
}

// SaveAccessCode 覆盖写入已存在的访问码（不做地址分配）。
func (s *boltStore) SaveAccessCode(c *models.AccessCode) error {
	if c.ID == "" {
		return fmt.Errorf("storage: access code id is required")
	}
	c.UpdatedAt = time.Now()
	data, err := json.Marshal(toCodeRecord(c))
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(codesBucket)
		if b.Get([]byte(c.ID)) == nil {
			return fmt.Errorf("%w: %s", ErrCodeNotFound, c.ID)
		}
		return b.Put([]byte(c.ID), data)
	})
}

// DeleteAccessCode 删除访问码。
func (s *boltStore) DeleteAccessCode(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(codesBucket)
		if b.Get([]byte(id)) == nil {
			return fmt.Errorf("%w: %s", ErrCodeNotFound, id)
		}
		return b.Delete([]byte(id))
	})
}

// DeleteAccessCodesByUser 删除某用户的全部访问码，返回删除数量（删用户时调用）。
func (s *boltStore) DeleteAccessCodesByUser(userID string) (int, error) {
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(codesBucket)
		var keys [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var r codeRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if r.UserID == userID {
				keys = append(keys, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// BindAccessCodeDevice 登记设备指纹（首次握手成功时调用）。
//
// 「已绑定则拒绝」的判定在事务内完成：两台设备同时首连时，只有一台能绑上，
// 另一台会拿到 ErrDeviceMismatch。在事务外先读后写会让两台都通过检查。
func (s *boltStore) BindAccessCodeDevice(id, fingerprint, label string, at time.Time, addr string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(codesBucket)
		v := b.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrCodeNotFound, id)
		}
		var r codeRecord
		if err := json.Unmarshal(v, &r); err != nil {
			return err
		}
		if r.DeviceFingerprint != "" {
			if r.DeviceFingerprint != fingerprint {
				return ErrDeviceMismatch
			}
			// 同一设备重连：只刷新活跃信息。
			r.LastSeenAt, r.LastSeenAddr = at, addr
		} else {
			r.DeviceFingerprint = fingerprint
			r.DeviceLabel = label
			r.BoundAt = at
			r.LastSeenAt, r.LastSeenAddr = at, addr
		}
		r.UpdatedAt = at
		data, err := json.Marshal(&r)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), data)
	})
}

// UnbindAccessCodeDevice 清除设备绑定，返回原绑定摘要（供审计日志）。
func (s *boltStore) UnbindAccessCodeDevice(id string) (string, error) {
	var prev string
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(codesBucket)
		v := b.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrCodeNotFound, id)
		}
		var r codeRecord
		if err := json.Unmarshal(v, &r); err != nil {
			return err
		}
		prev = r.DeviceLabel
		r.DeviceFingerprint = ""
		r.DeviceLabel = ""
		r.BoundAt = time.Time{}
		r.UpdatedAt = time.Now()
		data, err := json.Marshal(&r)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), data)
	})
	return prev, err
}

// MigrateAccessCodeDevice 把设备绑定从 fromFP CAS 迁移到 toFP（设备指纹 v2
// 升级：同一台设备换更强的指纹，不是换设备，**不踢隧道、不改 BoundAt**）。
// 「比对旧指纹 + 写入新指纹」在同一个写事务内完成（铁律 4b）：fromFP 已不匹配
// （被并发改写）返回 false，调用方下轮握手自然重估。
func (s *boltStore) MigrateAccessCodeDevice(id, fromFP, toFP, label string, at time.Time, addr string) (bool, error) {
	migrated := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(codesBucket)
		v := b.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrCodeNotFound, id)
		}
		var r codeRecord
		if err := json.Unmarshal(v, &r); err != nil {
			return err
		}
		if r.DeviceFingerprint != fromFP {
			return nil
		}
		r.DeviceFingerprint = toFP
		r.DeviceLabel = label
		r.LastSeenAt, r.LastSeenAddr = at, addr
		r.UpdatedAt = at
		migrated = true
		data, err := json.Marshal(&r)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), data)
	})
	return migrated, err
}

// TouchAccessCode 刷新最近活跃时间与来源地址。
//
// 调用方必须限频：这是数据面上的写操作，每个包都写一次会把 bbolt 的 fsync
// 拖进转发热路径。
func (s *boltStore) TouchAccessCode(id string, at time.Time, addr string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(codesBucket)
		v := b.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrCodeNotFound, id)
		}
		var r codeRecord
		if err := json.Unmarshal(v, &r); err != nil {
			return err
		}
		r.LastSeenAt, r.LastSeenAddr = at, addr
		data, err := json.Marshal(&r)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), data)
	})
}

// CountAccessCodesByUser 返回某用户的访问码数量。
func (s *boltStore) CountAccessCodesByUser(userID string) (int, error) {
	n := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(codesBucket).ForEach(func(_, v []byte) error {
			var r codeRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if r.UserID == userID {
				n++
			}
			return nil
		})
	})
	return n, err
}

// ErrDeviceMismatch 表示访问码已绑定到另一台设备。
var ErrDeviceMismatch = errors.New("access code is bound to another device")
