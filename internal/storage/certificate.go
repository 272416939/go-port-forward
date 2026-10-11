package storage

import (
	"errors"
	"fmt"
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
		return b.Put([]byte(cert.ID), data)
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
