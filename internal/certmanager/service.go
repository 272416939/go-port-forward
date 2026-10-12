package certmanager

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
)

const (
	// DefaultRenewBefore 是触发自动续签的剩余有效期阈值（30 天）。
	DefaultRenewBefore = 30 * 24 * time.Hour
	// DefaultCheckInterval 是自动续签后台巡检周期（12 小时）。
	DefaultCheckInterval = 12 * time.Hour
)

// Service 管理 SSL/TLS 证书的生命周期、内存热加载缓存与 ACME 自动续签调度。
type Service struct {
	store         storage.Store
	acme          *ACMEManager
	httpClient    *http.Client
	renewBefore   time.Duration
	checkInterval time.Duration

	mu       sync.RWMutex
	tlsCache map[string]*tls.Certificate

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// New 创建证书管理服务实例。
func New(store storage.Store) *Service {
	return NewWithConfig(store, ACMEConfig{})
}

// NewWithConfig 创建带自定义 ACME 配置的证书管理服务实例（便于测试注入）。
func NewWithConfig(store storage.Store, acmeCfg ACMEConfig) *Service {
	s := &Service{
		store:         store,
		acme:          newACMEManager(acmeCfg),
		httpClient:    acmeCfg.HTTPClient,
		renewBefore:   DefaultRenewBefore,
		checkInterval: DefaultCheckInterval,
		tlsCache:      make(map[string]*tls.Certificate),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	return s
}

// StartScheduler 启动后台自动续签巡检协程。
func (s *Service) StartScheduler() {
	go s.schedulerLoop()
}

// StopScheduler 停止后台自动续签巡检协程。
func (s *Service) StopScheduler() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	select {
	case <-s.doneCh:
	case <-time.After(3 * time.Second):
	}
}

func (s *Service) schedulerLoop() {
	defer close(s.doneCh)

	// 启动后 1 分钟执行首次到期巡检
	initialTimer := time.NewTimer(1 * time.Minute)
	defer initialTimer.Stop()

	select {
	case <-s.stopCh:
		return
	case <-initialTimer.C:
		s.CheckAndRenewAll()
	}

	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.CheckAndRenewAll()
		}
	}
}

// CheckAndRenewAll 扫描所有开启自动续签且剩余有效期不足阈值的证书并执行续签。
func (s *Service) CheckAndRenewAll() {
	certs, err := s.store.ListCertificates()
	if err != nil {
		if logger.S != nil {
			logger.S.Warnw("扫描证书列表失败 | failed to list certificates for auto-renew", "err", err)
		}
		return
	}
	now := time.Now()
	for _, c := range certs {
		select {
		case <-s.stopCh:
			return
		default:
		}
		if c.SourceType != models.CertSourceACME || !c.AutoRenew {
			continue
		}
		if !c.NotAfter.IsZero() && c.NotAfter.Sub(now) > s.renewBefore {
			continue
		}
		if logger.S != nil {
			logger.S.Infow("触发证书自动续签 | starting automatic certificate renewal",
				"id", c.ID, "name", c.Name, "domains", c.Domains, "not_after", c.NotAfter)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		_, rerr := s.Renew(ctx, c.ID)
		cancel()
		if rerr != nil {
			if logger.S != nil {
				logger.S.Warnw("证书自动续签失败 | automatic certificate renewal failed",
					"id", c.ID, "name", c.Name, "err", rerr)
			}
		} else if logger.S != nil {
			logger.S.Infow("证书自动续签成功 | certificate renewed automatically",
				"id", c.ID, "name", c.Name)
		}
	}
}

// HTTP01Handler 供 Web 服务处理 /.well-known/acme-challenge/ 验证请求。
func (s *Service) HTTP01Handler(w http.ResponseWriter, r *http.Request) bool {
	return s.acme.HTTP01Handler(w, r)
}

// GetTLSCertificate 返回已解析的 *tls.Certificate（优先走内存缓存），
// 供转发器/网关在 TLS 握手时通过 GetCertificate 回调实现零中断热重载。
func (s *Service) GetTLSCertificate(certID string) (*tls.Certificate, error) {
	s.mu.RLock()
	cached, ok := s.tlsCache[certID]
	s.mu.RUnlock()
	if ok && cached != nil {
		return cached, nil
	}

	certModel, err := s.store.GetCertificate(certID)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair([]byte(certModel.CertPEM), []byte(certModel.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("解析证书密钥对失败 (%s): %w", certModel.Name, err)
	}

	s.mu.Lock()
	s.tlsCache[certID] = &pair
	s.mu.Unlock()
	return &pair, nil
}

func (s *Service) updateCache(cert *models.Certificate) {
	if cert == nil || cert.CertPEM == "" || cert.KeyPEM == "" {
		return
	}
	if pair, err := tls.X509KeyPair([]byte(cert.CertPEM), []byte(cert.KeyPEM)); err == nil {
		s.mu.Lock()
		s.tlsCache[cert.ID] = &pair
		s.mu.Unlock()
	}
}

func (s *Service) evictCache(certID string) {
	s.mu.Lock()
	delete(s.tlsCache, certID)
	s.mu.Unlock()
}


// List 返回某用户的证书列表；userID 为空时返回全量（管理员视角）。
func (s *Service) List(userID string) ([]*models.Certificate, error) {
	var certs []*models.Certificate
	var err error
	if userID == "" {
		certs, err = s.store.ListCertificates()
	} else {
		certs, err = s.store.ListCertificatesByUser(userID)
	}
	if err != nil {
		return nil, err
	}
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].CreatedAt.After(certs[j].CreatedAt)
	})
	return certs, nil
}

// Get 按 ID 获取单条证书。
func (s *Service) Get(id string) (*models.Certificate, error) {
	return s.store.GetCertificate(id)
}

// Upload 处理用户手动上传 PEM 证书与私钥。
func (s *Service) Upload(owner *models.User, req *models.UploadCertificateRequest) (*models.Certificate, error) {
	if err := models.ValidateUploadCertificateRequest(req); err != nil {
		return nil, err
	}
	now := time.Now()
	userID := ""
	if owner != nil {
		userID = owner.ID
	}
	if req.UserID != "" {
		userID = req.UserID
	}
	cert := &models.Certificate{
		ID:         uuid.NewString(),
		UserID:     userID,
		Name:       req.Name,
		SourceType: models.CertSourceManual,
		CertPEM:    req.CertPEM,
		KeyPEM:     req.KeyPEM,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := cert.ValidateAndParsePEM(); err != nil {
		return nil, err
	}
	if err := s.store.SaveCertificate(cert); err != nil {
		return nil, err
	}
	s.updateCache(cert)
	return cert, nil
}

// ApplyACME 通过 ACME 协议自动验证域名并申请新证书。
func (s *Service) ApplyACME(ctx context.Context, owner *models.User, req *models.ApplyACMERequest) (*models.Certificate, error) {
	if err := s.injectGlobalACME(owner, req); err != nil {
		return nil, err
	}
	if err := s.InjectDNSCredential(owner, req); err != nil {
		return nil, err
	}
	if err := models.ValidateApplyACMERequest(req); err != nil {
		return nil, err
	}
	userID := ""
	if owner != nil {
		userID = owner.ID
	}
	if req.UserID != "" {
		userID = req.UserID
	}

	var dnsProv DNSProvider
	if !req.Provider.IsHTTP01() {
		var err error
		dnsProv, err = newDNSProvider(req.Provider.DNSProvider(), req.Credentials, s.httpClient)
		if err != nil {
			return nil, err
		}
	} else {
		stopHTTP80 := s.tryStartTemporaryHTTP80()
		defer stopHTTP80()
	}

	eab := eabFromCredentials(req.Provider, req.Credentials)
	existingAcctKey := s.resolveAccountKey(req.DirectoryURL, eab)
	certPEM, keyPEM, acctKeyPEM, err := s.acme.ObtainCertificate(ctx, req.DirectoryURL, existingAcctKey, req.Email, req.Domains, dnsProv, eab)
	if acctKeyPEM != "" {
		s.persistAccountKey(eab, acctKeyPEM)
	}
	if err != nil {
		return nil, err
	}

	now := time.Now()
	creds := make(map[string]string)
	for k, v := range req.Credentials {
		creds[k] = strings.TrimSpace(v)
	}
	cert := &models.Certificate{
		ID:             uuid.NewString(),
		UserID:         userID,
		Name:           req.Name,
		SourceType:     models.CertSourceACME,
		CertPEM:        certPEM,
		KeyPEM:         keyPEM,
		AutoRenew:      req.AutoRenew,
		Provider:       req.Provider,
		Email:          req.Email,
		DirectoryURL:   req.DirectoryURL,
		ACMEAccountKey: acctKeyPEM,
		Credentials:    creds,
		HasCredentials: len(creds) > 0,
		LastRenewAt:    now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := cert.ValidateAndParsePEM(); err != nil {
		return nil, err
	}
	if err := s.store.SaveCertificate(cert); err != nil {
		return nil, err
	}
	s.updateCache(cert)
	return cert, nil
}

// Renew 对已有 ACME 证书立即执行续签并热更新缓存。
func (s *Service) Renew(ctx context.Context, id string) (*models.Certificate, error) {
	cert, err := s.store.GetCertificate(id)
	if err != nil {
		return nil, err
	}
	if cert.SourceType != models.CertSourceACME {
		return nil, fmt.Errorf("仅 ACME 类型的证书支持自动续签，手动上传的证书请直接更新 PEM 内容 | only ACME certificates support automatic renewal")
	}
	if len(cert.Domains) == 0 {
		return nil, fmt.Errorf("证书记录中未包含有效域名列表 | certificate has no domains")
	}

	var dnsProv DNSProvider
	if !cert.Provider.IsHTTP01() {
		dnsProv, err = newDNSProvider(cert.Provider.DNSProvider(), cert.Credentials, s.httpClient)
		if err != nil {
			cert.LastError = err.Error()
			_ = s.store.SaveCertificate(cert)
			return nil, err
		}
	} else {
		stopHTTP80 := s.tryStartTemporaryHTTP80()
		defer stopHTTP80()
	}

	eab := eabFromCredentials(cert.Provider, cert.Credentials)
	dirURL := cert.DirectoryURL
	if cert.Provider.IsLiteSSL() {
		dirURL = models.NormalizeLiteSSLDirectoryURL(dirURL)
		cert.DirectoryURL = dirURL
	}
	acctKey := strings.TrimSpace(cert.ACMEAccountKey)
	if acctKey == "" {
		acctKey = s.resolveAccountKey(dirURL, eab)
	}
	certPEM, keyPEM, acctKeyPEM, err := s.acme.ObtainCertificate(ctx, dirURL, acctKey, cert.Email, cert.Domains, dnsProv, eab)
	if acctKeyPEM != "" {
		cert.ACMEAccountKey = acctKeyPEM
		s.persistAccountKey(eab, acctKeyPEM)
	}
	now := time.Now()
	cert.UpdatedAt = now
	if err != nil {
		cert.LastError = err.Error()
		_ = s.store.SaveCertificate(cert)
		return nil, err
	}

	cert.CertPEM = certPEM
	cert.KeyPEM = keyPEM
	cert.LastRenewAt = now
	cert.LastError = ""
	if err := cert.ValidateAndParsePEM(); err != nil {
		return nil, err
	}
	if err := s.store.SaveCertificate(cert); err != nil {
		return nil, err
	}
	s.updateCache(cert)
	return cert, nil
}

// PrepareManualDNS 执行手动 DNS 解析的第一步：创建 Order 并返回待添加的 TXT 记录。
// 不落库——证书要等第二步验证通过后才保存。
func (s *Service) PrepareManualDNS(ctx context.Context, owner *models.User, req *models.ApplyACMERequest) (*ManualDNSPrepareResult, error) {
	if err := s.injectGlobalACME(owner, req); err != nil {
		return nil, err
	}
	if err := s.InjectDNSCredential(owner, req); err != nil {
		return nil, err
	}
	if err := models.ValidateApplyACMERequest(req); err != nil {
		return nil, err
	}
	if !req.Provider.IsManualDNS() {
		return nil, fmt.Errorf("当前验证方式不是手动 DNS 解析 | provider is not manual DNS")
	}
	userID := ""
	if owner != nil {
		userID = owner.ID
	}
	if req.UserID != "" {
		userID = req.UserID
	}
	creds := make(map[string]string)
	for k, v := range req.Credentials {
		creds[k] = strings.TrimSpace(v)
	}
	eab := eabFromCredentials(req.Provider, req.Credentials)
	existingAcctKey := s.resolveAccountKey(req.DirectoryURL, eab)
	meta := certMeta{
		name:         strings.TrimSpace(req.Name),
		userID:       userID,
		autoRenew:    req.AutoRenew,
		provider:     req.Provider,
		email:        req.Email,
		directoryURL: req.DirectoryURL,
		accountKey:   existingAcctKey,
		creds:        creds,
	}
	res, acctKeyPEM, err := s.acme.PrepareManualDNS(ctx, req.DirectoryURL, existingAcctKey, req.Email, req.Domains, eab, meta)
	if acctKeyPEM != "" {
		s.persistAccountKey(eab, acctKeyPEM)
	}
	return res, err
}

// CompleteManualDNS 执行第二步：提交挑战、验证域名并下载证书，随后落库。
// 只需 token——证书元数据在 prepare 阶段已收下。
func (s *Service) CompleteManualDNS(ctx context.Context, token string) (*models.Certificate, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("验证令牌不能为空 | verification token is required")
	}
	certPEM, keyPEM, meta, err := s.acme.CompleteManualDNS(ctx, strings.TrimSpace(token))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	cert := &models.Certificate{
		ID:             uuid.NewString(),
		UserID:         meta.userID,
		Name:           meta.name,
		SourceType:     models.CertSourceACME,
		CertPEM:        certPEM,
		KeyPEM:         keyPEM,
		AutoRenew:      meta.autoRenew,
		Provider:       meta.provider,
		Email:          meta.email,
		DirectoryURL:   meta.directoryURL,
		ACMEAccountKey: meta.accountKey,
		Credentials:    meta.creds,
		HasCredentials: len(meta.creds) > 0,
		LastRenewAt:    now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := cert.ValidateAndParsePEM(); err != nil {
		return nil, err
	}
	if err := s.store.SaveCertificate(cert); err != nil {
		return nil, err
	}
	s.updateCache(cert)
	return cert, nil
}

// resolveAccountKey 查找指定 EAB 凭据已绑定的 ACME 账户私钥 PEM。
func (s *Service) resolveAccountKey(directoryURL string, eab *EABCredentials) string {
	if eab == nil || strings.TrimSpace(eab.KID) == "" {
		return ""
	}
	if key, err := s.store.FindAccountKeyByEAB(directoryURL, eab.KID); err == nil && strings.TrimSpace(key) != "" {
		return strings.TrimSpace(key)
	}
	return ""
}

// persistAccountKey 将全局 EAB 绑定的 ACME 账户私钥持久化到存储层。
func (s *Service) persistAccountKey(eab *EABCredentials, acctKeyPEM string) {
	if eab == nil || strings.TrimSpace(eab.KID) == "" || strings.TrimSpace(acctKeyPEM) == "" {
		return
	}
	gCfg, err := s.store.GlobalACMEConfig()
	if err == nil && gCfg != nil && strings.TrimSpace(gCfg.EABKID) == strings.TrimSpace(eab.KID) {
		_ = s.store.SaveGlobalACMEAccountKey(acctKeyPEM)
	}
}

// eabFromCredentials 在 provider 走 LiteSSL 时构造 EAB 凭据；其余 CA 返回 nil。
// 非 LiteSSL 的 provider 即使误带 eab_* 字段也忽略——EAB 是 LiteSSL 专属路径。
func eabFromCredentials(provider models.ACMEProvider, creds map[string]string) *EABCredentials {
	if !provider.IsLiteSSL() {
		return nil
	}
	kid := strings.TrimSpace(creds["eab_kid"])
	hmacKey := strings.TrimSpace(creds["eab_hmac_key"])
	if kid == "" || hmacKey == "" {
		return nil
	}
	return &EABCredentials{KID: kid, HMACKey: hmacKey}
}

// Update 更新证书名称、手动替换 PEM 或更新自动续签配置。
func (s *Service) Update(id string, req *models.UpdateCertificateRequest) (*models.Certificate, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}
	cert, err := s.store.GetCertificate(id)
	if err != nil {
		return nil, err
	}
	if req.Name != nil && strings.TrimSpace(*req.Name) != "" {
		if err := models.ValidateRuleName(*req.Name); err != nil {
			return nil, err
		}
		cert.Name = strings.TrimSpace(*req.Name)
	}
	if req.AutoRenew != nil {
		cert.AutoRenew = *req.AutoRenew
	}
	if req.Email != nil {
		cert.Email = strings.TrimSpace(*req.Email)
	}
	if req.Provider != nil {
		cert.Provider = *req.Provider
	}
	if req.DirectoryURL != nil && strings.TrimSpace(*req.DirectoryURL) != "" {
		cert.DirectoryURL = strings.TrimSpace(*req.DirectoryURL)
	}
	// provider 被改成 LiteSSL 时，必须有目录地址与 EAB 凭据，否则续签必然失败；
	// 这里提前拦下，避免用户保存后等到续签周期才发现。
	if req.Provider != nil && req.Provider.IsLiteSSL() {
		if cert.DirectoryURL == "" {
			return nil, fmt.Errorf("LiteSSL 需要填写 ACME 目录地址（FreeSSL 控制台「ACME 账号管理」获取）| LiteSSL requires an ACME directory URL")
		}
		kid := strings.TrimSpace(cert.Credentials["eab_kid"])
		hmacKey := strings.TrimSpace(cert.Credentials["eab_hmac_key"])
		if req.Credentials != nil {
			if v := strings.TrimSpace(req.Credentials["eab_kid"]); v != "" {
				kid = v
			}
			if v := strings.TrimSpace(req.Credentials["eab_hmac_key"]); v != "" {
				hmacKey = v
			}
		}
		if kid == "" || hmacKey == "" {
			return nil, fmt.Errorf("LiteSSL 需要 EAB 凭据（KID 与 HMAC Key）| LiteSSL requires EAB credentials (KID and HMAC Key)")
		}
	}
	if req.DNSCredentialID != nil && strings.TrimSpace(*req.DNSCredentialID) != "" {
		cred, err := s.store.GetDNSCredential(strings.TrimSpace(*req.DNSCredentialID))
		if err != nil {
			return nil, err
		}
		if cert.Credentials == nil {
			cert.Credentials = make(map[string]string)
		}
		for k, v := range cred.Credentials {
			cert.Credentials[k] = v
		}
		cert.HasCredentials = len(cert.Credentials) > 0
	}
	if req.Credentials != nil {
		if cert.Credentials == nil {
			cert.Credentials = make(map[string]string)
		}
		for k, v := range req.Credentials {
			v = strings.TrimSpace(v)
			if v != "" {
				cert.Credentials[k] = v
			}
		}
		cert.HasCredentials = len(cert.Credentials) > 0
	}
	if req.CertPEM != nil || req.KeyPEM != nil {
		if req.CertPEM != nil {
			cert.CertPEM = strings.TrimSpace(*req.CertPEM)
		}
		if req.KeyPEM != nil {
			cert.KeyPEM = strings.TrimSpace(*req.KeyPEM)
		}
		if err := cert.ValidateAndParsePEM(); err != nil {
			return nil, err
		}
	}

	cert.UpdatedAt = time.Now()
	if err := s.store.SaveCertificate(cert); err != nil {
		return nil, err
	}
	s.updateCache(cert)
	return cert, nil
}

// Delete 删除指定证书并清理内存缓存。
func (s *Service) Delete(id string) error {
	if err := s.store.DeleteCertificate(id); err != nil {
		return err
	}
	s.evictCache(id)
	return nil
}

// injectGlobalACME 检查申请请求是否需要从全局 LiteSSL 配置中自动补充 EAB 凭据。
// 规则：只要申请走向是 LiteSSL（无论是租户显式指定或使用平台默认 CA），若请求缺少 EAB KID / HMAC Key，
// 且平台已配置全局 LiteSSL 并开放给租户使用，则自动注入平台级 EAB 凭据与目录地址。
// 域名的验证方式（DNS-01 手动解析 / DNS API / HTTP-01）完全由租户在自身申请表单中自选。
func (s *Service) injectGlobalACME(owner *models.User, req *models.ApplyACMERequest) error {
	if req == nil {
		return nil
	}
	gCfg, err := s.store.GlobalACMEConfig()
	if err != nil || gCfg == nil || !gCfg.Configured() {
		return nil
	}
	if !gCfg.AllowUserApply && (owner == nil || !owner.IsAdmin()) {
		return nil
	}

	// 若未指定 provider（或属于 LiteSSL 族），自动注入全局 EAB 账号与官方目录
	if req.Provider == "" {
		req.Provider = models.ACMEProviderLiteSSLManualDNS
	}

	if req.Provider.IsLiteSSL() {
		if req.DirectoryURL == "" && gCfg.DirectoryURL != "" {
			req.DirectoryURL = models.NormalizeLiteSSLDirectoryURL(gCfg.DirectoryURL)
		} else {
			req.DirectoryURL = models.NormalizeLiteSSLDirectoryURL(req.DirectoryURL)
		}
		if req.Credentials == nil {
			req.Credentials = make(map[string]string)
		}
		if req.Credentials["eab_kid"] == "" && gCfg.EABKID != "" {
			req.Credentials["eab_kid"] = gCfg.EABKID
		}
		if req.Credentials["eab_hmac_key"] == "" && gCfg.EABHMACKey != "" {
			req.Credentials["eab_hmac_key"] = gCfg.EABHMACKey
		}
	}

	return nil
}

// GlobalACMEConfig 读取全局 ACME 配置（管理员视角的脱敏视图）。
func (s *Service) GlobalACMEConfig() (models.GlobalACMEView, error) {
	cfg, err := s.store.GlobalACMEConfig()
	if err != nil {
		return models.GlobalACMEView{}, err
	}
	return cfg.View(), nil
}

// UpdateGlobalACMEConfig 更新全局 ACME 配置。
func (s *Service) UpdateGlobalACMEConfig(req *models.UpdateGlobalACMEConfigRequest) (models.GlobalACMEView, error) {
	cfg, err := s.store.UpdateGlobalACMEConfig(req)
	if err != nil {
		return models.GlobalACMEView{}, err
	}
	return cfg.View(), nil
}

// PublicACMEStatus 读取面向普通用户的公共 ACME 状态（无敏感信息）。
func (s *Service) PublicACMEStatus() (models.PublicACMEStatus, error) {
	cfg, err := s.store.GlobalACMEConfig()
	if err != nil {
		return models.PublicACMEStatus{}, err
	}
	return cfg.PublicStatus(), nil
}

// tryStartTemporaryHTTP80 在执行 HTTP-01 验证时，尝试临时监听 0.0.0.0:80 响应挑战；
// 若 80 端口已被外部占用（如已有 Nginx 或规则监听），则静默跳过（依赖外部反代打入本进程）。
func (s *Service) tryStartTemporaryHTTP80() func() {
	ln, err := net.Listen("tcp", "0.0.0.0:80")
	if err != nil {
		return func() {}
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.acme.HTTP01Handler(w, r) {
				return
			}
			http.NotFound(w, r)
		}),
	}
	go func() {
		_ = srv.Serve(ln)
	}()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	}
}
// InjectDNSCredential 检查请求是否引用了已保存的 DNS 凭证，若存在则自动将对应凭证合并进请求。
func (s *Service) InjectDNSCredential(owner *models.User, req *models.ApplyACMERequest) error {
	if req == nil || strings.TrimSpace(req.DNSCredentialID) == "" {
		return nil
	}
	credID := strings.TrimSpace(req.DNSCredentialID)
	cred, err := s.store.GetDNSCredential(credID)
	if err != nil {
		return fmt.Errorf("指定的 DNS 凭证不存在：%w | DNS credential not found", err)
	}
	// 多租户隔离：普通用户只能使用自己的凭证或全局共享凭证
	if owner != nil && !owner.IsAdmin() {
		if cred.UserID != "" && cred.UserID != owner.ID {
			return fmt.Errorf("无权使用该 DNS 凭证 | access denied to DNS credential")
		}
	}
	if req.Credentials == nil {
		req.Credentials = make(map[string]string)
	}
	for k, v := range cred.Credentials {
		// 不覆盖已有设置（例如已注入的 eab_kid）
		if req.Credentials[k] == "" {
			req.Credentials[k] = v
		}
	}
	return nil
}

// ListDNSCredentials 列出当前用户可见的 DNS 凭据（脱敏视图）。
func (s *Service) ListDNSCredentials(userID string, isAdmin bool) ([]models.DNSCredentialView, error) {
	var list []*models.DNSCredential
	var err error
	if isAdmin {
		list, err = s.store.ListDNSCredentials()
	} else {
		list, err = s.store.ListDNSCredentialsByUser(userID)
	}
	if err != nil {
		return nil, err
	}
	out := make([]models.DNSCredentialView, 0, len(list))
	for _, c := range list {
		out = append(out, c.View())
	}
	return out, nil
}

// GetDNSCredential 获取单条 DNS 凭据（含明文，仅内部使用或权限受检）。
func (s *Service) GetDNSCredential(id string) (*models.DNSCredential, error) {
	return s.store.GetDNSCredential(id)
}

// CreateDNSCredential 创建新的 DNS 凭据并返回脱敏视图。
func (s *Service) CreateDNSCredential(owner *models.User, req *models.SaveDNSCredentialRequest) (models.DNSCredentialView, error) {
	if err := models.ValidateSaveDNSCredentialRequest(req, true); err != nil {
		return models.DNSCredentialView{}, err
	}
	userID := ""
	if owner != nil {
		userID = owner.ID
	}
	if owner != nil && owner.IsAdmin() && req.UserID != "" {
		userID = req.UserID
	}
	now := time.Now()
	creds := make(map[string]string)
	for k, v := range req.Credentials {
		creds[k] = strings.TrimSpace(v)
	}
	cred := &models.DNSCredential{
		ID:          uuid.NewString(),
		UserID:      userID,
		Name:        strings.TrimSpace(req.Name),
		Provider:    strings.ToLower(strings.TrimSpace(req.Provider)),
		Credentials: creds,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.store.SaveDNSCredential(cred); err != nil {
		return models.DNSCredentialView{}, err
	}
	return cred.View(), nil
}

// UpdateDNSCredential 更新已有凭据并返回脱敏视图（留空保留原密钥）。
func (s *Service) UpdateDNSCredential(id string, req *models.SaveDNSCredentialRequest) (models.DNSCredentialView, error) {
	if err := models.ValidateSaveDNSCredentialRequest(req, false); err != nil {
		return models.DNSCredentialView{}, err
	}
	cred, err := s.store.UpdateDNSCredential(id, req)
	if err != nil {
		return models.DNSCredentialView{}, err
	}
	return cred.View(), nil
}

// DeleteDNSCredential 删除指定 DNS 凭据。
func (s *Service) DeleteDNSCredential(id string) error {
	return s.store.DeleteDNSCredential(id)
}


