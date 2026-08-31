package storage

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"go-port-forward/internal/models"
	"go-port-forward/pkg/serializer/json"

	bolt "go.etcd.io/bbolt"
)

var usersBucket = []byte("users")

// 用户存储错误。
var (
	ErrUserNotFound = errors.New("user not found")
	ErrUserExists   = errors.New("username already exists")
	ErrEmailExists  = errors.New("email already exists")
	ErrTunPoolFull  = errors.New("tunnel address pool exhausted")
	ErrLastAdmin    = errors.New("cannot remove the last administrator")
)

// userRecord 是用户的持久化形态。
//
// models.User 的 PasswordHash 带 json:"-"（它同时是 API 响应结构体），直接
// 复用它落盘会把密码哈希写成空串。所以持久化走这个独立结构体——一处标签
// 服务两个用途必然出错，把两个用途拆开。
//
// 隧道相关字段（TunIP/TunnelSecret）与配额字段已下移到 AccessCode 与
// UserGroup；这里保留它们的 json tag 只为读取旧数据做迁移（见 migrate.go）。
type userRecord struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	GroupID  string `json:"group_id,omitempty"`
	Email    string `json:"email,omitempty"`
	// EmailVerified 报告邮箱是否通过验证码验证（注册验证/自助绑定/管理员代设）。
	EmailVerified bool   `json:"email_verified,omitempty"`
	Comment       string `json:"comment,omitempty"`

	PasswordHash string `json:"password_hash"`

	Disabled           bool `json:"disabled"`
	MustChangePassword bool `json:"must_change_password"`

	// --- 仅供迁移读取的旧字段（v1 模型），迁移后不再写入 ---
	LegacyTunIP          string `json:"tun_ip,omitempty"`
	LegacyTunnelSecret   string `json:"tunnel_secret,omitempty"`
	LegacyPortRangeStart int    `json:"port_range_start,omitempty"`
	LegacyPortRangeEnd   int    `json:"port_range_end,omitempty"`
	LegacyMaxRules       int    `json:"max_rules,omitempty"`
}

func toRecord(u *models.User) *userRecord {
	return &userRecord{
		CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
		ID: u.ID, Username: u.Username, Role: u.Role, GroupID: u.GroupID, Email: u.Email, Comment: u.Comment,
		EmailVerified:      u.EmailVerified,
		PasswordHash:       u.PasswordHash,
		Disabled:           u.Disabled,
		MustChangePassword: u.MustChangePassword,
	}
}

func (r *userRecord) toModel() *models.User {
	return &models.User{
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		ID: r.ID, Username: r.Username, Role: r.Role, GroupID: r.GroupID, Email: r.Email, Comment: r.Comment,
		EmailVerified:      r.EmailVerified,
		PasswordHash:       r.PasswordHash,
		Disabled:           r.Disabled,
		MustChangePassword: r.MustChangePassword,
	}
}

// ListUsers 返回全部用户（含密钥字段，调用方负责不外泄）。
func (s *boltStore) ListUsers() ([]*models.User, error) {
	var users []*models.User
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(usersBucket).ForEach(func(_, v []byte) error {
			var r userRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			users = append(users, r.toModel())
			return nil
		})
	})
	return users, err
}

// GetUser 按 ID 取用户。
func (s *boltStore) GetUser(id string) (*models.User, error) {
	var out *models.User
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(usersBucket).Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrUserNotFound, id)
		}
		var r userRecord
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

// GetUserByName 按用户名取用户（用户名唯一，比较前统一小写）。
func (s *boltStore) GetUserByName(name string) (*models.User, error) {
	want := models.NormalizeUsername(name)
	var out *models.User
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(usersBucket).ForEach(func(_, v []byte) error {
			if out != nil {
				return nil
			}
			var r userRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if models.NormalizeUsername(r.Username) == want {
				out = r.toModel()
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("%w: %s", ErrUserNotFound, name)
	}
	return out, nil
}

// CreateUser 在单个写事务内完成「用户名与邮箱查重 + 落盘」。
//
// 隧道地址不再在这里分配——它已下移到 AccessCode（见 CreateAccessCode）。
// 邮箱查重必须在同一事务内：注册与找回密码都按邮箱定位唯一用户，两个并发
// 注册若能绑定同一邮箱，找回密码就不知道该重置谁。
func (s *boltStore) CreateUser(u *models.User) error {
	if u.ID == "" {
		return fmt.Errorf("storage: user id is required")
	}
	wantName := models.NormalizeUsername(u.Username)
	wantEmail := strings.ToLower(strings.TrimSpace(u.Email))
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(usersBucket)
		dupName := false
		dupEmail := false
		if err := b.ForEach(func(_, v []byte) error {
			var r userRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if models.NormalizeUsername(r.Username) == wantName {
				dupName = true
			}
			if wantEmail != "" && strings.EqualFold(strings.TrimSpace(r.Email), wantEmail) {
				dupEmail = true
			}
			return nil
		}); err != nil {
			return err
		}
		if dupName {
			return fmt.Errorf("%w: %s", ErrUserExists, u.Username)
		}
		if dupEmail {
			return fmt.Errorf("%w: %s", ErrEmailExists, wantEmail)
		}

		now := time.Now()
		if u.CreatedAt.IsZero() {
			u.CreatedAt = now
		}
		u.UpdatedAt = now

		data, err := json.Marshal(toRecord(u))
		if err != nil {
			return err
		}
		return b.Put([]byte(u.ID), data)
	})
}

// GetUserByEmail 按邮箱查用户（找回密码用）。
//
// 邮箱唯一性由 CreateUser 在事务内保证，这里按全表扫描找第一个匹配即可。
func (s *boltStore) GetUserByEmail(email string) (*models.User, error) {
	want := strings.ToLower(strings.TrimSpace(email))
	if want == "" {
		return nil, fmt.Errorf("%w: empty email", ErrUserNotFound)
	}
	var out *models.User
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(usersBucket).ForEach(func(_, v []byte) error {
			if out != nil {
				return nil
			}
			var r userRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if strings.EqualFold(strings.TrimSpace(r.Email), want) {
				out = r.toModel()
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("%w: %s", ErrUserNotFound, want)
	}
	return out, nil
}

// SaveUser 覆盖写入已存在的用户（不改 CreatedAt）。
func (s *boltStore) SaveUser(u *models.User) error {
	if u.ID == "" {
		return fmt.Errorf("storage: user id is required")
	}
	u.UpdatedAt = time.Now()
	data, err := json.Marshal(toRecord(u))
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(usersBucket)
		if b.Get([]byte(u.ID)) == nil {
			return fmt.Errorf("%w: %s", ErrUserNotFound, u.ID)
		}
		return b.Put([]byte(u.ID), data)
	})
}

// SetUserEmail 设置用户邮箱与激活标志（自助绑定传 verified=true；管理员代设
// 时两者都由管理员决定，email 为空串 = 清空并强制未激活）。与 CreateUser 同
// 一套唯一性纪律：查重与写入必须在同一个写事务里，两个并发绑定同一邮箱只有
// 一方能成功。事务内重读记录只改 Email/EmailVerified 字段——用外部传来的整
// 个模型覆盖会踩掉并发改动的其他字段（丢更新）。
func (s *boltStore) SetUserEmail(id, email string, verified bool) error {
	want := strings.ToLower(strings.TrimSpace(email))
	if want == "" {
		// 清空邮箱等于拆掉找回密码的通路，激活状态必须一并复位。
		verified = false
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(usersBucket)
		v := b.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrUserNotFound, id)
		}
		var r userRecord
		if err := json.Unmarshal(v, &r); err != nil {
			return err
		}
		dup := false
		if want != "" {
			if err := b.ForEach(func(k, ov []byte) error {
				if string(k) == id {
					return nil
				}
				var other userRecord
				if err := json.Unmarshal(ov, &other); err != nil {
					return err
				}
				if strings.EqualFold(strings.TrimSpace(other.Email), want) {
					dup = true
				}
				return nil
			}); err != nil {
				return err
			}
		}
		if dup {
			return fmt.Errorf("%w: %s", ErrEmailExists, want)
		}
		r.Email = want
		r.EmailVerified = verified
		data, err := json.Marshal(&r)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), data)
	})
}

// DeleteUser 删除用户；拒绝删掉最后一个管理员（否则面板将无人可管）。
func (s *boltStore) DeleteUser(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(usersBucket)
		v := b.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("%w: %s", ErrUserNotFound, id)
		}
		var target userRecord
		if err := json.Unmarshal(v, &target); err != nil {
			return err
		}
		if target.Role == models.RoleAdmin {
			admins := 0
			if err := b.ForEach(func(_, raw []byte) error {
				var r userRecord
				if err := json.Unmarshal(raw, &r); err != nil {
					return err
				}
				if r.Role == models.RoleAdmin && !r.Disabled {
					admins++
				}
				return nil
			}); err != nil {
				return err
			}
			if admins <= 1 {
				return ErrLastAdmin
			}
		}
		return b.Delete([]byte(id))
	})
}

// CountUsers 返回用户总数（首启引导用）。
func (s *boltStore) CountUsers() (int, error) {
	n := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(usersBucket).Stats().KeyN
		return nil
	})
	return n, err
}

// allocTunIP 在网段内取最小的未占用地址。
//
// 跳过网络号、广播地址与网关。/24 提供 253 个位置、/16 提供约 6.5 万个；
// 顺序分配（而非随机）让运维能在路由表与抓包里直观对上人。
func allocTunIP(pool netip.Prefix, gateway netip.Addr, used map[netip.Addr]struct{}) (netip.Addr, error) {
	if !pool.IsValid() || !pool.Addr().Is4() {
		return netip.Addr{}, fmt.Errorf("storage: 无效的隧道网段 %v | invalid tunnel prefix", pool)
	}
	network := pool.Masked()
	broadcast := lastAddr(network)
	for addr := network.Addr().Next(); addr.IsValid() && network.Contains(addr); addr = addr.Next() {
		if addr == broadcast {
			break
		}
		if addr == gateway {
			continue
		}
		if _, taken := used[addr]; taken {
			continue
		}
		return addr, nil
	}
	// 地址池耗尽时直接给出可操作的建议：每个访问码占一个地址，/24 只有 253
	// 个位置，很容易在几十个用户时撞上。
	return netip.Addr{}, fmt.Errorf("%w: %s（请把 config.yaml 的 tunnel.tun_addr 换成更大的网段，如 10.66.0.1/16）| enlarge tunnel.tun_addr",
		ErrTunPoolFull, pool)
}

// lastAddr 返回网段内的最后一个地址（IPv4 广播地址）。
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	for i := 0; i < host; i++ {
		b[3-i/8] |= 1 << (i % 8)
	}
	return netip.AddrFrom4(b)
}

// ParseTunnelPrefix 把 config 的 tunnel.tun_addr（如 "10.66.0.1/24"）拆成
// 网段与网关地址。
func ParseTunnelPrefix(cidr string) (netip.Prefix, netip.Addr, error) {
	s := strings.TrimSpace(cidr)
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("无效的隧道网段 %q | invalid tunnel CIDR: %w", cidr, err)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("隧道网段必须是 IPv4 %q | tunnel CIDR must be IPv4", cidr)
	}
	return p.Masked(), p.Addr(), nil
}
