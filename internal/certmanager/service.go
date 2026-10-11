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
	certPEM, keyPEM, acctKeyPEM, err := s.acme.ObtainCertificate(ctx, req.DirectoryURL, "", req.Email, req.Domains, dnsProv, eab)
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
	certPEM, keyPEM, acctKeyPEM, err := s.acme.ObtainCertificate(ctx, cert.DirectoryURL, cert.ACMEAccountKey, cert.Email, cert.Domains, dnsProv, eab)
	now := time.Now()
	cert.UpdatedAt = now
	if err != nil {
		cert.LastError = err.Error()
		_ = s.store.SaveCertificate(cert)
		return nil, err
	}

	cert.CertPEM = certPEM
	cert.KeyPEM = keyPEM
	if acctKeyPEM != "" {
		cert.ACMEAccountKey = acctKeyPEM
	}
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

