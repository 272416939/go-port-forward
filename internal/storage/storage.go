package storage

import (
	"errors"
	"fmt"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/pkg/serializer/json"
	"net/netip"
	"time"

	bolt "go.etcd.io/bbolt"
)

var rulesBucket = []byte("rules")

// ErrRuleNotFound indicates the requested rule does not exist in storage.
var ErrRuleNotFound = errors.New("rule not found")

// Store provides persistent storage for forwarding rules, access control and logs.
type Store interface {
	ListRules() ([]*models.ForwardRule, error)
	GetRule(id string) (*models.ForwardRule, error)
	SaveRule(rule *models.ForwardRule) error
	DeleteRule(id string) error

	// Access control entries (IP blacklist/whitelist)
	ListACLEntries() ([]*models.ACLEntry, error)
	SaveACLEntry(entry *models.ACLEntry) error
	DeleteACLEntry(id string) error

	// Connection/session event log（connlogs 父桶下按用户嵌套分桶）
	// userID 为空表示全量（admin 视角）。AppendConnLog 要求 entry.UserID 非空。
	AppendConnLog(entry *models.ConnLogEntry) error
	ListConnLogs(userID string, offset, limit int) ([]*models.ConnLogEntry, int, error)
	DeleteConnLogs(userID string, ids []string) (int, error)
	ClearConnLogs(userID string) (int, error)
	TrimConnLogs(maxEntries int) (int, error)

	// Users (web accounts)
	ListUsers() ([]*models.User, error)
	GetUser(id string) (*models.User, error)
	GetUserByName(name string) (*models.User, error)
	GetUserByEmail(email string) (*models.User, error)
	CreateUser(u *models.User) error
	SaveUser(u *models.User) error
	// SetUserEmail 自助绑定与管理员代设共用：写邮箱 + 激活标志。唯一性检查
	// 必须在同一个写事务内（铁律 4b：读写分处两个事务时，两个并发绑定会同时
	// 通过查重）。email 为空串 = 清空并强制未激活。
	SetUserEmail(id, email string, verified bool) error
	DeleteUser(id string) error
	CountUsers() (int, error)

	// Global settings (singleton)
	Settings() (models.Settings, error)
	SaveSettings(cfg models.Settings) error
	// SMTPConfig / UpdateSMTP：发信配置（第二键）。UpdateSMTP 的密码留空 =
	// 保留原值（事务内读-改-写），整体清空 host = 删除配置。
	SMTPConfig() (*models.SMTPConfig, error)
	UpdateSMTP(req *models.UpdateSMTPRequest) (*models.SMTPConfig, error)

	// User groups (quota carriers)
	ListGroups() ([]*models.UserGroup, error)
	GetGroup(id string) (*models.UserGroup, error)
	SaveGroup(g *models.UserGroup) error
	DeleteGroup(id string) error
	CountGroupMembers() (map[string]int, error)

	// Access codes (tunnel identities)
	ListAccessCodes() ([]*models.AccessCode, error)
	ListAccessCodesByUser(userID string) ([]*models.AccessCode, error)
	GetAccessCode(id string) (*models.AccessCode, error)
	// CreateAccessCode 在同一写事务内检查配额并分配隧道地址（见 accesscode.go）。
	CreateAccessCode(c *models.AccessCode, pool netip.Prefix, gateway netip.Addr, maxCodes int) error
	SaveAccessCode(c *models.AccessCode) error
	DeleteAccessCode(id string) error
	DeleteAccessCodesByUser(userID string) (int, error)
	CountAccessCodesByUser(userID string) (int, error)
	// BindAccessCodeDevice 登记设备指纹；已绑定到别的设备时返回 ErrDeviceMismatch。
	BindAccessCodeDevice(id, fingerprint, label string, at time.Time, addr string) error
	UnbindAccessCodeDevice(id string) (string, error)
	TouchAccessCode(id string, at time.Time, addr string) error

	Close() error
}

type boltStore struct {
	db *bolt.DB
}

// Open opens (or creates) the bbolt database at path.
func Open(path string) (Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("storage: open %s: %w", path, err)
	}
	// Ensure buckets exist
	if err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{
			rulesBucket, aclBucket, connLogsBucket, usersBucket,
			settingsBucket, groupsBucket, codesBucket,
		} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	// 数据模型迁移：bucket 建好之后立刻跑，晚于此处的任何读取都可能看到
	// 半新半旧的记录。
	res, err := migrate(db)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: migrate: %w", err)
	}
	if res.changed() {
		// logger 可能尚未初始化（测试里直接调 Open），迁移日志不该成为新故障点。
		if logger.S != nil {
			logger.S.Infow("数据模型已迁移 | data model migrated",
				"from", res.From, "to", res.To, "groups", res.Groups, "access_codes", res.AccessCodes)
		}
	}
	// 旧版连接日志直接写在 connlogs 父桶里（无用户归属），分桶模型下清理掉。
	if n, err := dropLegacyConnLogs(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: drop legacy conn logs: %w", err)
	} else if n > 0 && logger.S != nil {
		logger.S.Infow("已清理旧版全局连接日志 | legacy global conn logs dropped", "count", n)
	}
	return &boltStore{db: db}, nil
}

func (s *boltStore) ListRules() ([]*models.ForwardRule, error) {
	var rules []*models.ForwardRule
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(rulesBucket)
		return b.ForEach(func(_, v []byte) error {
			var r models.ForwardRule
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			scrubRuntimeFields(&r)
			rules = append(rules, &r)
			return nil
		})
	})
	return rules, err
}

func (s *boltStore) GetRule(id string) (*models.ForwardRule, error) {
	var rule models.ForwardRule
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(rulesBucket).Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrRuleNotFound, id)
		}
		if err := json.Unmarshal(v, &rule); err != nil {
			return err
		}
		scrubRuntimeFields(&rule)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

func (s *boltStore) SaveRule(rule *models.ForwardRule) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		persisted := *rule
		scrubRuntimeFields(&persisted)
		data, err := json.Marshal(&persisted)
		if err != nil {
			return err
		}
		return tx.Bucket(rulesBucket).Put([]byte(rule.ID), data)
	})
}

func (s *boltStore) DeleteRule(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(rulesBucket)
		if b.Get([]byte(id)) == nil {
			return fmt.Errorf("%w: %s", ErrRuleNotFound, id)
		}
		return b.Delete([]byte(id))
	})
}

func scrubRuntimeFields(rule *models.ForwardRule) {
	if rule == nil {
		return
	}
	rule.Status = ""
	rule.ErrorMsg = ""
}

func (s *boltStore) Close() error { return s.db.Close() }
