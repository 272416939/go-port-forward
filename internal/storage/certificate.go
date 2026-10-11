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

// ErrCertNotFound 表示请求的证书不存在。
var ErrCertNotFound = errors.New("certificate not found")

// certRecord 是证书的持久化形态。
//
// 按照铁律 6 规范：models.Certificate 的 KeyPEM、ACMEAccountKey 和 Credentials
// 带有 json:"-"（用于 API 脱敏防泄露），持久化必须使用独立的 certRecord 显式保留
// 私钥与凭证信息。
type certRecord struct {
	ID             string                `json:"id"`
	UserID         string                `json:"user_id"`
	Name           string                `json:"name"`
	SourceType     models.CertSourceType `json:"source_type"`
	SubjectCN      string                `json:"subject_cn"`
	Domains        []string              `json:"domains"`
	Issuer         string                `json:"issuer"`
	NotBefore      time.Time             `json:"not_before"`
	NotAfter       time.Time             `json:"not_after"`
	CertPEM        string                `json:"cert_pem"`
	KeyPEM         string                `json:"key_pem"`
	AutoRenew      bool                  `json:"auto_renew"`
	Provider       models.ACMEProvider   `json:"provider"`
	Email          string                `json:"email"`
	DirectoryURL   string                `json:"directory_url"`
	ACMEAccountKey string                `json:"acme_account_key"`
	Credentials    map[string]string     `json:"credentials"`
	LastRenewAt    time.Time             `json:"last_renew_at"`
	LastError      string                `json:"last_error"`
	CreatedAt      time.Time             `json:"created_at"`
	UpdatedAt      time.Time             `json:"updated_at"`
}

func toCertRecord(c *models.Certificate) *certRecord {
	creds := make(map[string]string)
	for k, v := range c.Credentials {
		creds[k] = v
	}
	return &certRecord{
		ID:             c.ID,
		UserID:         c.UserID,
		Name:           c.Name,
		SourceType:     c.SourceType,
		SubjectCN:      c.SubjectCN,
		Domains:        append([]string(nil), c.Domains...),
		Issuer:         c.Issuer,
		NotBefore:      c.NotBefore,
		NotAfter:       c.NotAfter,
		CertPEM:        c.CertPEM,
		KeyPEM:         c.KeyPEM,
		AutoRenew:      c.AutoRenew,
		Provider:       c.Provider,
		Email:          c.Email,
		DirectoryURL:   c.DirectoryURL,
		ACMEAccountKey: c.ACMEAccountKey,
		Credentials:    creds,
		LastRenewAt:    c.LastRenewAt,
		LastError:      c.LastError,
		CreatedAt:      c.CreatedAt,
		UpdatedAt:      c.UpdatedAt,
	}
}

func (r *certRecord) toModel() *models.Certificate {
	creds := make(map[string]string)
	for k, v := range r.Credentials {
		creds[k] = v
	}
	return &models.Certificate{
		ID:             r.ID,
		UserID:         r.UserID,
		Name:           r.Name,
		SourceType:     r.SourceType,
		SubjectCN:      r.SubjectCN,
		Domains:        append([]string(nil), r.Domains...),
		Issuer:         r.Issuer,
		NotBefore:      r.NotBefore,
		NotAfter:       r.NotAfter,
		CertPEM:        r.CertPEM,
		KeyPEM:         r.KeyPEM,
		AutoRenew:      r.AutoRenew,
		Provider:       r.Provider,
		Email:          r.Email,
		DirectoryURL:   r.DirectoryURL,
		ACMEAccountKey: r.ACMEAccountKey,
		Credentials:    creds,
		HasCredentials: len(creds) > 0,
		LastRenewAt:    r.LastRenewAt,
		LastError:      r.LastError,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
	}
}

func (s *boltStore) ListCertificates() ([]*models.Certificate, error) {
	var out []*models.Certificate
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(certificatesBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var r certRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			out = append(out, r.toModel())
			return nil
		})
	})
	return out, err
}

func (s *boltStore) ListCertificatesByUser(userID string) ([]*models.Certificate, error) {
	var out []*models.Certificate
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(certificatesBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var r certRecord
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

func (s *boltStore) GetCertificate(id string) (*models.Certificate, error) {
	var out *models.Certificate
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(certificatesBucket)
		if b == nil {
			return ErrCertNotFound
		}
		v := b.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrCertNotFound, id)
		}
		var r certRecord
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

var (
	acmeConfigKey  = []byte("acme")
	acmeEABKeysKey = []byte("acme_eab_keys")
)

// FindAccountKeyByEAB 查找指定 CA 目录与 EAB KID 所绑定的 ACME 账户私钥 PEM。
// 依次从：1) settings 桶的 acme_eab_keys 持久映射；2) 全局 ACME 配置的 account_key；
// 3) 历史已签发证书记录的 acme_account_key 中找回，确保删除证书或重启服务后仍能复用同一账户密钥。
func (s *boltStore) FindAccountKeyByEAB(directoryURL, eabKID string) (string, error) {
	dir := strings.TrimSpace(directoryURL)
	kid := strings.TrimSpace(eabKID)
	if kid == "" {
		return "", nil
	}
	var found string
	err := s.db.View(func(tx *bolt.Tx) error {
		if sb := tx.Bucket(settingsBucket); sb != nil {
			if raw := sb.Get(acmeEABKeysKey); raw != nil {
				var m map[string]string
				if json.Unmarshal(raw, &m) == nil {
					if k := strings.TrimSpace(m[kid]); k != "" {
						found = k
						return nil
					}
				}
			}
			if raw := sb.Get(acmeConfigKey); raw != nil {
				var gr globalACMERecord
				if json.Unmarshal(raw, &gr) == nil {
					if strings.TrimSpace(gr.EABKID) == kid && strings.TrimSpace(gr.AccountKey) != "" {
						found = strings.TrimSpace(gr.AccountKey)
						return nil
					}
				}
			}
		}
		b := tx.Bucket(certificatesBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			if found != "" {
				return nil
			}
			var r certRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return nil
			}
			if strings.TrimSpace(r.ACMEAccountKey) == "" {
				return nil
			}
			if dir != "" && strings.TrimSpace(r.DirectoryURL) != "" && !strings.EqualFold(strings.TrimSpace(r.DirectoryURL), dir) {
				return nil
			}
			if r.Credentials != nil && strings.TrimSpace(r.Credentials["eab_kid"]) == kid {
				found = strings.TrimSpace(r.ACMEAccountKey)
			}
			return nil
		})
	})
	return found, err
}

func putEABAccountKeyInTx(tx *bolt.Tx, eabKID, acctKeyPEM string) error {
	kid := strings.TrimSpace(eabKID)
	key := strings.TrimSpace(acctKeyPEM)
	if kid == "" || key == "" {
		return nil
	}
	sb, err := tx.CreateBucketIfNotExists(settingsBucket)
	if err != nil {
		return err
	}
	m := make(map[string]string)
	if raw := sb.Get(acmeEABKeysKey); raw != nil {
		_ = json.Unmarshal(raw, &m)
	}
	if m == nil {
		m = make(map[string]string)
	}
	m[kid] = key
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return sb.Put(acmeEABKeysKey, data)
}

func (s *boltStore) SaveCertificate(cert *models.Certificate) error {
	if cert == nil || cert.ID == "" {
		return fmt.Errorf("storage: certificate id is required")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(certificatesBucket)
		if b == nil {
			var err error
			b, err = tx.CreateBucketIfNotExists(certificatesBucket)
			if err != nil {
				return err
			}
		}
		rec := toCertRecord(cert)
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(cert.ID), data); err != nil {
			return err
		}
		if cert.Credentials != nil {
			_ = putEABAccountKeyInTx(tx, cert.Credentials["eab_kid"], cert.ACMEAccountKey)
		}
		return nil
	})
}

func (s *boltStore) DeleteCertificate(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(certificatesBucket)
		if b == nil {
			return nil
		}
		if b.Get([]byte(id)) == nil {
			return fmt.Errorf("%w: %s", ErrCertNotFound, id)
		}
		return b.Delete([]byte(id))
	})
}

// globalACMERecord 是全局 LiteSSL ACME 配置的持久化形态（存 settingsBucket 的 "acme" 键）。
//
// models.GlobalACMEConfig.EABHMACKey 与 AccountKey 带 json:"-" 防止 API 泄露，
// 持久化必须使用独立的结构体（铁律 6），否则密码与账户密钥永远存不进 bbolt。
type globalACMERecord struct {
	Enabled        bool   `json:"enabled"`
	DirectoryURL   string `json:"directory_url"`
	EABKID         string `json:"eab_kid"`
	EABHMACKey     string `json:"eab_hmac_key"`
	AccountKey     string `json:"account_key"`
	AllowUserApply bool   `json:"allow_user_apply"`
}

func (r *globalACMERecord) toModel() *models.GlobalACMEConfig {
	return &models.GlobalACMEConfig{
		Enabled:        r.Enabled,
		DirectoryURL:   r.DirectoryURL,
		EABKID:         r.EABKID,
		EABHMACKey:     r.EABHMACKey,
		AccountKey:     r.AccountKey,
		AllowUserApply: r.AllowUserApply,
	}
}

func toGlobalACMERecord(c *models.GlobalACMEConfig) *globalACMERecord {
	return &globalACMERecord{
		Enabled:        c.Enabled,
		DirectoryURL:   c.DirectoryURL,
		EABKID:         c.EABKID,
		EABHMACKey:     c.EABHMACKey,
		AccountKey:     c.AccountKey,
		AllowUserApply: c.AllowUserApply,
	}
}

// GlobalACMEConfig 读取全局 ACME 配置；未配置时返回零值。
func (s *boltStore) GlobalACMEConfig() (*models.GlobalACMEConfig, error) {
	var out *models.GlobalACMEConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(settingsBucket)
		if b == nil {
			return nil
		}
		v := b.Get(acmeConfigKey)
		if v == nil {
			return nil
		}
		var r globalACMERecord
		if err := json.Unmarshal(v, &r); err != nil {
			return err
		}
		out = r.toModel()
		return nil
	})
	return out, err
}

// UpdateGlobalACMEConfig 更新全局 ACME 配置。
//
// 密钥字段允许留空（留空 = 保留现有密钥）。在同事务内完成读-改-写以防并发覆盖。
func (s *boltStore) UpdateGlobalACMEConfig(req *models.UpdateGlobalACMEConfigRequest) (*models.GlobalACMEConfig, error) {
	var out *models.GlobalACMEConfig
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(settingsBucket)
		if b == nil {
			var err error
			b, err = tx.CreateBucketIfNotExists(settingsBucket)
			if err != nil {
				return err
			}
		}

		cur := &models.GlobalACMEConfig{
			DirectoryURL:   models.DefaultLiteSSLDirectoryURL,
			AllowUserApply: true,
		}
		if v := b.Get(acmeConfigKey); v != nil {
			var r globalACMERecord
			if err := json.Unmarshal(v, &r); err == nil {
				cur = r.toModel()
			}
		}

		if req.Enabled != nil {
			cur.Enabled = *req.Enabled
		}
		if req.DirectoryURL != nil {
			cur.DirectoryURL = strings.TrimSpace(*req.DirectoryURL)
		}
		if req.EABKID != nil {
			newKID := strings.TrimSpace(*req.EABKID)
			if newKID != cur.EABKID {
				cur.AccountKey = "" // EAB KID 更换时必须重新生成并绑定新的 ACME 账户密钥
			}
			cur.EABKID = newKID
		}
		if req.EABHMACKey != nil && *req.EABHMACKey != "" {
			newHMAC := strings.TrimSpace(*req.EABHMACKey)
			if newHMAC != cur.EABHMACKey {
				cur.AccountKey = ""
			}
			cur.EABHMACKey = newHMAC
		}
		if req.AllowUserApply != nil {
			cur.AllowUserApply = *req.AllowUserApply
		}

		if err := models.ValidateGlobalACMEConfig(cur); err != nil {
			return err
		}

		data, err := json.Marshal(toGlobalACMERecord(cur))
		if err != nil {
			return err
		}
		if err := b.Put(acmeConfigKey, data); err != nil {
			return err
		}
		out = cur
		return nil
	})
	return out, err
}

// SaveGlobalACMEAccountKey 持久化 LiteSSL 绑定的全局 ACME 账户私钥 PEM。
func (s *boltStore) SaveGlobalACMEAccountKey(acctKeyPEM string) error {
	key := strings.TrimSpace(acctKeyPEM)
	if key == "" {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(settingsBucket)
		if err != nil {
			return err
		}
		v := b.Get(acmeConfigKey)
		if v == nil {
			return nil
		}
		var r globalACMERecord
		if err := json.Unmarshal(v, &r); err != nil {
			return err
		}
		r.AccountKey = key
		data, err := json.Marshal(&r)
		if err != nil {
			return err
		}
		if err := b.Put(acmeConfigKey, data); err != nil {
			return err
		}
		if r.EABKID != "" {
			_ = putEABAccountKeyInTx(tx, r.EABKID, key)
		}
		return nil
	})
}

