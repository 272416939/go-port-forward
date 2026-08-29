package storage

// SMTP 配置的存取（settings bucket 的第二个键）。

import (
	"fmt"
	"strings"

	"go-port-forward/internal/models"
	"go-port-forward/pkg/serializer/json"

	bolt "go.etcd.io/bbolt"
)

var smtpKey = []byte("smtp")

// smtpRecord 是 SMTP 配置的持久化形态。
//
// models.SMTPConfig.Password 带 json:"-"（防御它被直接当 API 响应体），复用
// 它落盘会把密码跳过——正是 userRecord/codeRecord 踩过的同一个坑（铁律 6）。
// 一套标签服务两个相反的需求必然出错，持久化拆独立结构体。
type smtpRecord struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	From       string `json:"from"`
	FromName   string `json:"from_name"`
	Encryption string `json:"encryption"`
}

func (r *smtpRecord) toModel() *models.SMTPConfig {
	return &models.SMTPConfig{
		Host: r.Host, Port: r.Port, Username: r.Username, Password: r.Password,
		From: r.From, FromName: r.FromName, Encryption: r.Encryption,
	}
}

func toSMTPRecord(c *models.SMTPConfig) *smtpRecord {
	return &smtpRecord{
		Host: c.Host, Port: c.Port, Username: c.Username, Password: c.Password,
		From: c.From, FromName: c.FromName, Encryption: c.Encryption,
	}
}

// SMTPConfig 读取发信配置；未配置时返回零值。
func (s *boltStore) SMTPConfig() (*models.SMTPConfig, error) {
	var out *models.SMTPConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(settingsBucket).Get(smtpKey)
		if v == nil {
			return nil
		}
		var r smtpRecord
		if err := json.Unmarshal(v, &r); err != nil {
			return err
		}
		out = r.toModel()
		return nil
	})
	return out, err
}

// UpdateSMTP 更新发信配置。
//
// req.Password 为 nil 或空串表示保留原值：面板回显时没有密码可显示，提交时
// 也不该强迫管理员重输。判定必须在读-改-写同事务内完成——否则并发更新会把
// 别人刚设置的密码清掉。
func (s *boltStore) UpdateSMTP(req *models.UpdateSMTPRequest) (*models.SMTPConfig, error) {
	var out *models.SMTPConfig
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(settingsBucket)

		// 空配置整体清空 = 停用邮件功能：直接删键，而不是留一份半空的记录。
		if req.Host != nil && strings.TrimSpace(*req.Host) == "" {
			if err := b.Delete(smtpKey); err != nil {
				return err
			}
			out = &models.SMTPConfig{}
			return nil
		}

		cur := &models.SMTPConfig{}
		if v := b.Get(smtpKey); v != nil {
			var r smtpRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			cur = r.toModel()
		}
		applySMTP(cur, req)
		if err := models.ValidateSMTPConfig(cur); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSMTP, err)
		}
		data, err := json.Marshal(toSMTPRecord(cur))
		if err != nil {
			return err
		}
		if err := b.Put(smtpKey, data); err != nil {
			return err
		}
		out = cur
		return nil
	})
	return out, err
}

func applySMTP(cur *models.SMTPConfig, req *models.UpdateSMTPRequest) {
	if req.Host != nil {
		cur.Host = strings.TrimSpace(*req.Host)
	}
	if req.Port != nil {
		cur.Port = *req.Port
	}
	if req.Username != nil {
		cur.Username = strings.TrimSpace(*req.Username)
	}
	if req.Password != nil && *req.Password != "" {
		cur.Password = strings.TrimSpace(*req.Password)
	}
	if req.From != nil {
		cur.From = strings.TrimSpace(*req.From)
	}
	if req.FromName != nil {
		cur.FromName = strings.TrimSpace(*req.FromName)
	}
	if req.Encryption != nil {
		cur.Encryption = strings.ToLower(strings.TrimSpace(*req.Encryption))
	}
}

// ErrInvalidSMTP 表示 SMTP 配置不完整或非法。
var ErrInvalidSMTP = fmt.Errorf("invalid smtp config")
