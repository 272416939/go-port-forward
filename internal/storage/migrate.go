package storage

// 数据模型迁移。
//
// 靠 Settings.SchemaVersion 幂等：每次 Open 都会跑一遍，已到目标版本即空转。
// 没有独立的迁移框架也不打算引入——本项目的 schema 变更频率极低，一个版本号
// 加一串 if 比一套框架更容易看懂出了什么问题。
//
// v1 → v2（多用户 → 访问码实体化）要处理的是：隧道身份从用户下移到访问码，
// 配额从用户下移到用户组。

import (
	"fmt"
	"time"

	"go-port-forward/internal/models"
	"go-port-forward/pkg/serializer/json"

	bolt "go.etcd.io/bbolt"

	"github.com/google/uuid"
)

// migrateResult 汇总一次迁移的结果，供调用方写启动日志。
type migrateResult struct {
	From        int
	To          int
	Groups      int
	AccessCodes int
}

// changed 报告本次迁移是否真的动了数据。
func (r migrateResult) changed() bool { return r.From != r.To }

// migrate 把数据升级到 models.SchemaVersion。
func migrate(db *bolt.DB) (migrateResult, error) {
	res := migrateResult{To: models.SchemaVersion}
	err := db.Update(func(tx *bolt.Tx) error {
		cfg, err := readSettingsTx(tx)
		if err != nil {
			return err
		}
		res.From = cfg.SchemaVersion

		// 首次初始化（空库或 v0）：直接写入默认设置并建默认组。
		if cfg.SchemaVersion < 1 {
			// 库里已有用户说明是 v1 数据（v1 不写 settings），当作 1 处理。
			if tx.Bucket(usersBucket).Stats().KeyN > 0 {
				cfg.SchemaVersion = 1
				res.From = 1
			}
		}

		if cfg.SchemaVersion >= models.SchemaVersion {
			return nil
		}

		if cfg.SchemaVersion < 1 {
			// 全新库：默认设置 + 一个默认组。
			def := models.DefaultSettings()
			def.SchemaVersion = 1
			cfg = def
			gid, gerr := ensureDefaultGroupTx(tx, cfg)
			if gerr != nil {
				return gerr
			}
			cfg.DefaultGroupID = gid
			res.Groups++
			cfg.SchemaVersion = 1
		}

		if cfg.SchemaVersion < 2 {
			n, codes, verr := migrateV1ToV2Tx(tx, &cfg)
			if verr != nil {
				return verr
			}
			res.Groups += n
			res.AccessCodes += codes
			cfg.SchemaVersion = 2
		}

		return writeSettingsTx(tx, cfg)
	})
	return res, err
}

func readSettingsTx(tx *bolt.Tx) (models.Settings, error) {
	var cfg models.Settings
	v := tx.Bucket(settingsBucket).Get(settingsKey)
	if v == nil {
		return models.Settings{}, nil // SchemaVersion 0 = 未初始化
	}
	if err := json.Unmarshal(v, &cfg); err != nil {
		return models.Settings{}, err
	}
	return cfg, nil
}

func writeSettingsTx(tx *bolt.Tx, cfg models.Settings) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return tx.Bucket(settingsBucket).Put(settingsKey, data)
}

// ensureDefaultGroupTx 建一个默认组（配额全取全局值），返回其 ID。
func ensureDefaultGroupTx(tx *bolt.Tx, cfg models.Settings) (string, error) {
	b := tx.Bucket(groupsBucket)
	// 已有默认组就用它。
	var existing string
	if err := b.ForEach(func(k, v []byte) error {
		if existing != "" {
			return nil
		}
		var g models.UserGroup
		if err := json.Unmarshal(v, &g); err != nil {
			return err
		}
		if g.IsDefault {
			existing = g.ID
		}
		return nil
	}); err != nil {
		return "", err
	}
	if existing != "" {
		return existing, nil
	}

	now := time.Now()
	g := models.UserGroup{
		CreatedAt: now, UpdatedAt: now,
		ID:        uuid.NewString(),
		Name:      "default",
		Comment:   "默认组：配额取全局设置 | default group, quotas follow global settings",
		IsDefault: true,
	}
	data, err := json.Marshal(&g)
	if err != nil {
		return "", err
	}
	if err := b.Put([]byte(g.ID), data); err != nil {
		return "", err
	}
	return g.ID, nil
}

// migrateV1ToV2Tx 把 v1 的「用户携带隧道身份与配额」拆成访问码 + 用户组。
//
// 两条关键决定：
//
//  1. 按 (端口区间, 规则上限) 组合去重建组，而不是把所有人丢进默认组。后者会
//     静默改掉现有用户的端口区间——他们下次建规则才会莫名被拒，而那时没人
//     记得是这次迁移引起的。
//  2. 访问码的 ID 沿用原 User.ID，Secret/TunIP 原样继承。这样已经发出去的
//     接入码继续有效，用户不必重新配置客户端（只需升级到支持 v3 握手的版本）。
func migrateV1ToV2Tx(tx *bolt.Tx, cfg *models.Settings) (groups, codes int, err error) {
	users := tx.Bucket(usersBucket)
	groupsB := tx.Bucket(groupsBucket)
	codesB := tx.Bucket(codesBucket)

	type legacy struct {
		key []byte
		rec userRecord
	}
	var all []legacy
	if err := users.ForEach(func(k, v []byte) error {
		var r userRecord
		if uerr := json.Unmarshal(v, &r); uerr != nil {
			return uerr
		}
		all = append(all, legacy{key: append([]byte(nil), k...), rec: r})
		return nil
	}); err != nil {
		return 0, 0, err
	}

	now := time.Now()

	// 全局端口区间取现有用户区间的并集，保证迁移后没人越界。
	minPort, maxPort := 0, 0
	maxRules := 0
	for _, l := range all {
		if l.rec.LegacyPortRangeStart > 0 && (minPort == 0 || l.rec.LegacyPortRangeStart < minPort) {
			minPort = l.rec.LegacyPortRangeStart
		}
		if l.rec.LegacyPortRangeEnd > maxPort {
			maxPort = l.rec.LegacyPortRangeEnd
		}
		if l.rec.LegacyMaxRules > maxRules {
			maxRules = l.rec.LegacyMaxRules
		}
	}
	if cfg.PortRangeStart == 0 && cfg.PortRangeEnd == 0 {
		d := models.DefaultSettings()
		cfg.PortRangeStart, cfg.PortRangeEnd = d.PortRangeStart, d.PortRangeEnd
		cfg.MaxAccessCodesPerUser = d.MaxAccessCodesPerUser
		cfg.MaxTunnelsPerUser = d.MaxTunnelsPerUser
		cfg.MaxRulesPerUser = d.MaxRulesPerUser
	}
	if minPort > 0 && minPort < cfg.PortRangeStart {
		cfg.PortRangeStart = minPort
	}
	if maxPort > cfg.PortRangeEnd {
		cfg.PortRangeEnd = maxPort
	}
	if maxRules > cfg.MaxRulesPerUser {
		cfg.MaxRulesPerUser = maxRules
	}

	// 默认组必须存在：未分组的用户与后续新建用户都要落到它。
	defaultGroupID, err := ensureDefaultGroupTx(tx, *cfg)
	if err != nil {
		return 0, 0, err
	}
	if cfg.DefaultGroupID == "" {
		cfg.DefaultGroupID = defaultGroupID
	}

	// 按配额组合建组。
	type quotaKey struct{ start, end, rules int }
	byQuota := map[quotaKey]string{}
	for _, l := range all {
		r := l.rec
		hasQuota := r.LegacyPortRangeStart > 0 || r.LegacyPortRangeEnd > 0 || r.LegacyMaxRules > 0
		gid := defaultGroupID
		if hasQuota && r.Role != models.RoleAdmin {
			key := quotaKey{r.LegacyPortRangeStart, r.LegacyPortRangeEnd, r.LegacyMaxRules}
			if existing, ok := byQuota[key]; ok {
				gid = existing
			} else {
				g := models.UserGroup{
					CreatedAt: now, UpdatedAt: now,
					ID:             uuid.NewString(),
					Name:           migratedGroupName(key.start, key.end, key.rules),
					Comment:        "由旧版用户配额自动迁移 | migrated from per-user quotas",
					PortRangeStart: key.start,
					PortRangeEnd:   key.end,
					MaxRules:       key.rules,
				}
				data, merr := json.Marshal(&g)
				if merr != nil {
					return 0, 0, merr
				}
				if perr := groupsB.Put([]byte(g.ID), data); perr != nil {
					return 0, 0, perr
				}
				byQuota[key] = g.ID
				gid = g.ID
				groups++
			}
		}

		// 迁移隧道身份到访问码（ID 沿用用户 ID，接入码保持有效）。
		if r.LegacyTunIP != "" && r.LegacyTunnelSecret != "" {
			if codesB.Get([]byte(r.ID)) == nil {
				c := models.AccessCode{
					CreatedAt: r.CreatedAt, UpdatedAt: now,
					ID:     r.ID,
					UserID: r.ID,
					Name:   "默认访问码 | default",
					TunIP:  r.LegacyTunIP,
					Secret: r.LegacyTunnelSecret,
				}
				data, merr := json.Marshal(toCodeRecord(&c))
				if merr != nil {
					return 0, 0, merr
				}
				if perr := codesB.Put([]byte(c.ID), data); perr != nil {
					return 0, 0, perr
				}
				codes++
			}
		}

		// 重写用户记录：挂上组，清掉已下移的字段。
		next := userRecord{
			CreatedAt: r.CreatedAt, UpdatedAt: now,
			ID: r.ID, Username: r.Username, Role: r.Role, Comment: r.Comment,
			GroupID:            gid,
			PasswordHash:       r.PasswordHash,
			Disabled:           r.Disabled,
			MustChangePassword: r.MustChangePassword,
		}
		if r.Role == models.RoleAdmin {
			// 管理员不受配额约束，不必挂组（挂了也无害，但留空更能说明这一点）。
			next.GroupID = ""
		}
		data, merr := json.Marshal(&next)
		if merr != nil {
			return 0, 0, merr
		}
		if perr := users.Put(l.key, data); perr != nil {
			return 0, 0, perr
		}
	}
	return groups, codes, nil
}

func migratedGroupName(start, end, rules int) string {
	if start > 0 && end > 0 {
		return fmt.Sprintf("migrated-%d-%d", start, end)
	}
	return fmt.Sprintf("migrated-rules-%d", rules)
}
