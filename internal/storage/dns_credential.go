package storage

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"go-port-forward/internal/models"
	"go-port-forward/pkg/serializer/json"

	bolt "go.etcd.io/bbolt"
)

// ErrDNSCredentialNotFound 表示请求的 DNS 凭证不存在。
var ErrDNSCredentialNotFound = errors.New("dns credential not found")

// dnsCredentialRecord 是 DNS 凭证的持久化形态。
//
// 按照铁律 6 规范：models.DNSCredential 的 Credentials 带有 json:"-"（用于 API 脱敏防泄露），
// 持久化必须使用独立的结构体显式保留 Token / Secret。
type dnsCredentialRecord struct {
	ID          string            `json:"id"`
	UserID      string            `json:"user_id"`
	Name        string            `json:"name"`
	Provider    string            `json:"provider"`
	Credentials map[string]string `json:"credentials"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

func toDNSCredentialRecord(c *models.DNSCredential) *dnsCredentialRecord {
	creds := make(map[string]string)
	for k, v := range c.Credentials {
		creds[k] = strings.TrimSpace(v)
	}
	return &dnsCredentialRecord{
		ID:          c.ID,
		UserID:      c.UserID,
		Name:        c.Name,
		Provider:    c.Provider,
		Credentials: creds,
		CreatedAt:   c.CreatedAt,
		UpdatedAt:   c.UpdatedAt,
	}
}

func (r *dnsCredentialRecord) toModel() *models.DNSCredential {
	creds := make(map[string]string)
	for k, v := range r.Credentials {
		creds[k] = v
	}
	return &models.DNSCredential{
		ID:          r.ID,
		UserID:      r.UserID,
		Name:        r.Name,
		Provider:    r.Provider,
		Credentials: creds,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

// ListDNSCredentials 获取全量 DNS 凭证（管理员视角）。
func (s *boltStore) ListDNSCredentials() ([]*models.DNSCredential, error) {
	var out []*models.DNSCredential
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(dnsCredentialsBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var r dnsCredentialRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			out = append(out, r.toModel())
			return nil
		})
	})
	return out, err
}

// ListDNSCredentialsByUser 获取指定用户有权使用的 DNS 凭证（自己创建的或管理员全局共享的）。
func (s *boltStore) ListDNSCredentialsByUser(userID string) ([]*models.DNSCredential, error) {
	var out []*models.DNSCredential
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(dnsCredentialsBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var r dnsCredentialRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			// 属于该用户，或者全局共享凭据（UserID == ""）
			if r.UserID == userID || r.UserID == "" {
				out = append(out, r.toModel())
			}
			return nil
		})
	})
	return out, err
}

// GetDNSCredential 按 ID 获取单条凭据。
func (s *boltStore) GetDNSCredential(id string) (*models.DNSCredential, error) {
	var out *models.DNSCredential
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(dnsCredentialsBucket)
		if b == nil {
			return ErrDNSCredentialNotFound
		}
		v := b.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrDNSCredentialNotFound, id)
		}
		var r dnsCredentialRecord
		if err := json.Unmarshal(v, &r); err != nil {
			return err
		}
		out = r.toModel()
		return nil
	})
	return out, err
}

// SaveDNSCredential 保存一条 DNS 凭据。
func (s *boltStore) SaveDNSCredential(cred *models.DNSCredential) error {
	if cred == nil || cred.ID == "" {
		return fmt.Errorf("storage: dns credential id is required")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(dnsCredentialsBucket)
		if b == nil {
			var err error
			b, err = tx.CreateBucketIfNotExists(dnsCredentialsBucket)
			if err != nil {
				return err
			}
		}
		rec := toDNSCredentialRecord(cred)
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(cred.ID), data)
	})
}

// UpdateDNSCredential 更新已有凭证（支持敏感密钥留空保留原值，铁律 6）。
func (s *boltStore) UpdateDNSCredential(id string, req *models.SaveDNSCredentialRequest) (*models.DNSCredential, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	var out *models.DNSCredential
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(dnsCredentialsBucket)
		if b == nil {
			return ErrDNSCredentialNotFound
		}
		v := b.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrDNSCredentialNotFound, id)
		}
		var r dnsCredentialRecord
		if err := json.Unmarshal(v, &r); err != nil {
			return err
		}

		if req.Name != "" {
			r.Name = strings.TrimSpace(req.Name)
		}
		if req.Provider != "" {
			r.Provider = strings.ToLower(strings.TrimSpace(req.Provider))
		}
		if req.UserID != "" {
			r.UserID = strings.TrimSpace(req.UserID)
		}
		// 敏感密钥更新：若请求中字段非空，则更新；若留空则保留原值（铁律 6）
		if r.Credentials == nil {
			r.Credentials = make(map[string]string)
		}
		for k, val := range req.Credentials {
			val = strings.TrimSpace(val)
			if val != "" {
				r.Credentials[k] = val
			}
		}
		r.UpdatedAt = time.Now()

		data, err := json.Marshal(&r)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(id), data); err != nil {
			return err
		}
		out = r.toModel()
		return nil
	})
	return out, err
}

// DeleteDNSCredential 删除指定 DNS 凭据。
func (s *boltStore) DeleteDNSCredential(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(dnsCredentialsBucket)
		if b == nil {
			return nil
		}
		if b.Get([]byte(id)) == nil {
			return fmt.Errorf("%w: %s", ErrDNSCredentialNotFound, id)
		}
		return b.Delete([]byte(id))
	})
}
