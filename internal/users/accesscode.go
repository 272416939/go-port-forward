package users

// 访问码：隧道身份的 CRUD、接入码生成、设备绑定与解绑。

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
)

// ListAccessCodes 返回某用户的访问码；userID 为空时返回全部（管理员视图）。
func (s *Service) ListAccessCodes(userID string) ([]*models.AccessCode, error) {
	var codes []*models.AccessCode
	var err error
	if userID == "" {
		codes, err = s.store.ListAccessCodes()
	} else {
		codes, err = s.store.ListAccessCodesByUser(userID)
	}
	if err != nil {
		return nil, err
	}
	online := s.onlineCodes()
	names := map[string]string{}
	for _, c := range codes {
		c.Online = online[c.ID]
		c.DeviceLabel = models.FingerprintLabel(c.DeviceFingerprint)
		if userID == "" {
			if _, seen := names[c.UserID]; !seen {
				if u, uerr := s.store.GetUser(c.UserID); uerr == nil {
					names[c.UserID] = u.Username
				} else {
					names[c.UserID] = c.UserID
				}
			}
			c.UserName = names[c.UserID]
		}
	}
	return codes, nil
}

// GetAccessCode 按 ID 取访问码。
func (s *Service) GetAccessCode(id string) (*models.AccessCode, error) {
	return s.store.GetAccessCode(id)
}

// CreateAccessCode 为某用户创建访问码。
//
// 配额检查与地址分配都在存储层的同一个写事务里完成（见 CreateAccessCode）：
// 在这里先查后建会让并发请求同时通过检查、突破上限并撞上同一个隧道地址。
func (s *Service) CreateAccessCode(owner *models.User, req *models.CreateAccessCodeRequest) (*models.AccessCode, error) {
	if owner == nil {
		return nil, fmt.Errorf("%w: 归属用户不能为空 | owner is required", ErrInvalidUser)
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		// 允许不填名字：用户建第一个访问码时通常懒得起名，给一个能看出用途的
		// 默认值比强制他填一个更顺手。
		name = fmt.Sprintf("访问码-%s", time.Now().Format("0102-1504"))
	}
	if err := models.ValidateAccessCodeName(name); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidUser, err)
	}
	quota, err := s.EffectiveQuota(owner)
	if err != nil {
		return nil, err
	}
	secret, err := auth.RandomSecret(TunnelSecretBytes)
	if err != nil {
		return nil, err
	}
	c := &models.AccessCode{
		ID:        uuid.NewString(),
		UserID:    owner.ID,
		Name:      name,
		Secret:    secret,
		CreatedAt: time.Now(),
	}
	pool, gw := s.TunnelPrefix()
	if err := s.store.CreateAccessCode(c, pool, gw, quota.MaxAccessCodes); err != nil {
		if errors.Is(err, storage.ErrCodeQuota) {
			return nil, fmt.Errorf("%w: 访问码数量已达上限 %d 个 | access code quota reached (%d)",
				ErrQuotaExceeded, quota.MaxAccessCodes, quota.MaxAccessCodes)
		}
		return nil, err
	}
	logger.S.Infow("访问码已创建 | access code created",
		"user", owner.Username, "code", c.Name, "tun_ip", c.TunIP)
	return c, nil
}

// UpdateAccessCode 改名或启停。停用会立刻踢掉在线隧道。
func (s *Service) UpdateAccessCode(id string, req *models.UpdateAccessCodeRequest) (*models.AccessCode, error) {
	c, err := s.store.GetAccessCode(id)
	if err != nil {
		return nil, err
	}
	if req.Name != nil {
		c.Name = strings.TrimSpace(*req.Name)
		if verr := models.ValidateAccessCodeName(c.Name); verr != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidUser, verr)
		}
	}
	disableNow := false
	if req.Disabled != nil {
		if *req.Disabled && !c.Disabled {
			disableNow = true
		}
		c.Disabled = *req.Disabled
	}
	if err := s.store.SaveAccessCode(c); err != nil {
		return nil, err
	}
	if disableNow {
		if tun := s.tunnel(); tun != nil {
			tun.EvictCode(c.ID)
		}
	}
	return c, nil
}

// DeleteAccessCode 删除访问码并踢掉在线隧道。
func (s *Service) DeleteAccessCode(id string) error {
	c, err := s.store.GetAccessCode(id)
	if err != nil {
		return err
	}
	if err := s.store.DeleteAccessCode(id); err != nil {
		return err
	}
	if tun := s.tunnel(); tun != nil {
		tun.EvictCode(id)
	}
	logger.S.Infow("访问码已删除 | access code deleted", "code", c.Name, "tun_ip", c.TunIP)
	return nil
}

// RegenerateSecret 重新生成隧道密钥（旧接入码立即失效）并踢掉在线隧道。
//
// 必须踢：旧会话用的是已经作废的密钥派生出来的，留着它跑意味着「重新生成」
// 在下一次重握手之前都不生效——而重握手可能是 30 秒后，也可能因为一直有流量
// 而迟迟不发生。
func (s *Service) RegenerateSecret(id string) (*models.AccessCode, error) {
	c, err := s.store.GetAccessCode(id)
	if err != nil {
		return nil, err
	}
	secret, err := auth.RandomSecret(TunnelSecretBytes)
	if err != nil {
		return nil, err
	}
	c.Secret = secret
	if err := s.store.SaveAccessCode(c); err != nil {
		return nil, err
	}
	if tun := s.tunnel(); tun != nil {
		tun.EvictCode(c.ID)
	}
	logger.S.Infow("隧道密钥已重新生成 | tunnel secret regenerated", "code", c.Name)
	return c, nil
}

// UnbindDevice 解除设备绑定并踢掉在线隧道。
//
// 踢掉是必须的：不踢的话旧设备的隧道还在跑，用户在新机器上连上后两台机器会
// 抢同一个隧道地址——表现为"两边都时断时续"。
func (s *Service) UnbindDevice(id string) (*models.AccessCode, error) {
	prev, err := s.store.UnbindAccessCodeDevice(id)
	if err != nil {
		return nil, err
	}
	if tun := s.tunnel(); tun != nil {
		tun.EvictCode(id)
	}
	c, err := s.store.GetAccessCode(id)
	if err != nil {
		return nil, err
	}
	logger.S.Infow("访问码设备绑定已解除 | access code device unbound",
		"code", c.Name, "previous_device", prev)
	return c, nil
}

// AccessCodeText 生成某访问码的接入码文本。
//
// fallbackAddr 用于 publicAddr 未配置时（通常取自 HTTP 请求的 Host，因为服务端
// 无从知晓自己的公网地址）。
func (s *Service) AccessCodeText(id, fallbackAddr string) (models.AccessCodeView, error) {
	var out models.AccessCodeView
	c, err := s.store.GetAccessCode(id)
	if err != nil {
		return out, err
	}
	addr, err := s.accessCodeAddr(fallbackAddr)
	if err != nil {
		return out, err
	}
	text, err := encodeCode(addr, c)
	if err != nil {
		return out, err
	}
	userName := c.UserID
	if u, uerr := s.store.GetUser(c.UserID); uerr == nil {
		userName = u.Username
	}
	return models.AccessCodeView{
		CodeID:   c.ID,
		Name:     c.Name,
		UserName: userName,
		Addr:     addr,
		Secret:   c.Secret,
		Code:     text,
		TunIP:    c.TunIP,
	}, nil
}

// TunIPsOf 返回某用户名下「启用中的访问码」的隧道地址集合。
//
// 规则的 target_addr 必须落在这个集合里——它是「这条规则喂给哪条隧道」的唯一
// 真相。停用的访问码不算：指向它的规则会把流量发进一个不会有人接的地址。
func (s *Service) TunIPsOf(userID string) (map[string]string, error) {
	codes, err := s.store.ListAccessCodesByUser(userID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(codes))
	for _, c := range codes {
		if c.Disabled || c.TunIP == "" {
			continue
		}
		out[c.TunIP] = c.ID
	}
	return out, nil
}

// AllTunIPs 返回全部访问码的「隧道地址 → 访问码 ID」映射。
//
// 回程路由推送需要它把规则（按 target_addr）归到访问码上。
func (s *Service) AllTunIPs() (map[string]string, error) {
	codes, err := s.store.ListAccessCodes()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(codes))
	for _, c := range codes {
		if c.TunIP != "" {
			out[c.TunIP] = c.ID
		}
	}
	return out, nil
}

// Identity 供隧道服务端查询访问码凭据。
//
// 返回值刻意包含用户与访问码两级的停用状态：客户端要能区分「你的访问码被停了」
// 与「你的账号被停了」，这两件事要找的人不一样。
func (s *Service) Identity(codeID string) (CodeIdentity, bool) {
	c, err := s.store.GetAccessCode(codeID)
	if err != nil {
		return CodeIdentity{}, false
	}
	u, uerr := s.store.GetUser(c.UserID)
	if uerr != nil {
		// 访问码指向一个已不存在的用户：正常流程下删用户会连带删访问码，
		// 走到这里说明数据不一致，按拒绝处理。
		return CodeIdentity{}, false
	}
	quota, qerr := s.EffectiveQuota(u)
	if qerr != nil {
		return CodeIdentity{}, false
	}
	return CodeIdentity{
		CodeID:       c.ID,
		CodeName:     c.Name,
		UserID:       u.ID,
		UserName:     u.Username,
		Secret:       c.Secret,
		TunIP:        c.TunIP,
		CodeDisabled: c.Disabled,
		UserDisabled: u.Disabled,
		Fingerprint:  c.DeviceFingerprint,
		MaxTunnels:   quota.MaxTunnels,
	}, true
}

// CodeIdentity 是 Identity 的返回类型（访问码的接入凭据与约束）。
//
// 不直接用 tunnelapp.Identity：那会让 users 依赖 tunnelapp，而 tunnelapp 已经
// 依赖 users 提供的查询函数——双向依赖。装配层（main.go）负责两者之间的转换。
type CodeIdentity struct {
	CodeID       string
	CodeName     string
	UserID       string
	UserName     string
	Secret       string
	TunIP        string
	CodeDisabled bool
	UserDisabled bool
	Fingerprint  string
	MaxTunnels   int
}

// BindDevice 实现 tunnelapp.DeviceBinder：登记设备指纹。
func (s *Service) BindDevice(codeID, fingerprint, label, addr string) error {
	return s.store.BindAccessCodeDevice(codeID, fingerprint, label, time.Now(), addr)
}

// TouchCode 实现 tunnelapp.DeviceBinder：刷新活跃信息。
//
// 失败只记 debug：这是纯粹的展示信息，写不进去不该影响转发。
func (s *Service) TouchCode(codeID, addr string) {
	if err := s.store.TouchAccessCode(codeID, time.Now(), addr); err != nil {
		logger.S.Debugw("刷新访问码活跃时间失败 | failed to touch access code", "code_id", codeID, "err", err)
	}
}
