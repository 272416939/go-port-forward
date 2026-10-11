package certmanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// ACMEConfig 配置 ACME 客户端参数。
type ACMEConfig struct {
	DirectoryURL string
	HTTPClient   *http.Client
	DNSDelay     time.Duration // DNS 生效等待时间（生产默认 5s，测试可为 0）
}

// ACMEManager 封装基于 RFC 8555 的自动化证书申请流程。
type ACMEManager struct {
	cfg        ACMEConfig
	mu         sync.RWMutex
	httpTokens map[string]string // token -> keyAuth (供 HTTP-01 挑战使用)
}

func newACMEManager(cfg ACMEConfig) *ACMEManager {
	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = acme.LetsEncryptURL
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.DNSDelay <= 0 {
		cfg.DNSDelay = 5 * time.Second
	}
	return &ACMEManager{
		cfg:        cfg,
		httpTokens: make(map[string]string),
	}
}

// HTTP01Handler 处理 /.well-known/acme-challenge/{token} 请求。
func (m *ACMEManager) HTTP01Handler(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	token := strings.TrimPrefix(path, prefix)
	m.mu.RLock()
	keyAuth, ok := m.httpTokens[token]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(keyAuth))
	return true
}

func encodeECPrivateKey(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return string(b), nil
}

func parseECPrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block for EC private key")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func encodeCertificates(derList [][]byte) string {
	var buf strings.Builder
	for _, b := range derList {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: b})
	}
	return buf.String()
}

// ObtainCertificate 执行完整的 ACME 申请流程：
// 1. 生成/加载 ACME 账户密钥并在 CA 注册；
// 2. 针对全部指定域名完成 DNS-01 或 HTTP-01 挑战；
// 3. 生成新的证书私钥与 CSR，提交签发并下载完整证书链。
func (m *ACMEManager) ObtainCertificate(
	ctx context.Context,
	accountKeyPEM string,
	email string,
	domains []string,
	dnsProvider DNSProvider,
) (certPEM, keyPEM, newAccountKeyPEM string, err error) {
	if len(domains) == 0 {
		return "", "", "", errors.New("domains list cannot be empty")
	}

	var acctKey *ecdsa.PrivateKey
	if strings.TrimSpace(accountKeyPEM) != "" {
		acctKey, _ = parseECPrivateKey(accountKeyPEM)
	}
	if acctKey == nil {
		acctKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", "", "", fmt.Errorf("生成 ACME 账户密钥失败: %w", err)
		}
		newAccountKeyPEM, err = encodeECPrivateKey(acctKey)
		if err != nil {
			return "", "", "", err
		}
	} else {
		newAccountKeyPEM = accountKeyPEM
	}

	client := &acme.Client{
		Key:          acctKey,
		DirectoryURL: m.cfg.DirectoryURL,
		HTTPClient:   m.cfg.HTTPClient,
	}

	// 注册 ACME 账户
	var contact []string
	if email != "" {
		contact = []string{"mailto:" + email}
	}
	acct := &acme.Account{Contact: contact}
	_, err = client.Register(ctx, acct, acme.AcceptTOS)
	if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		// 某些 CA 会返回特定错误代码表示账户已存在
		if !strings.Contains(strings.ToLower(err.Error()), "already") && !strings.Contains(strings.ToLower(err.Error()), "existing") {
			return "", "", "", fmt.Errorf("注册 ACME 账户失败 (%s): %w", m.cfg.DirectoryURL, err)
		}
	}

	// 创建 Order
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	if err != nil {
		return "", "", "", fmt.Errorf("创建 ACME Order 失败: %w", err)
	}

	// 完成所有 Authorization 挑战
	for _, authzURL := range order.AuthzURLs {
		if err := m.solveAuthorization(ctx, client, authzURL, dnsProvider); err != nil {
			return "", "", "", err
		}
	}

	// 等待 Order 进入 Ready 状态
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return "", "", "", fmt.Errorf("等待 ACME Order Ready 失败: %w", err)
	}

	// 生成证书私钥与 CSR
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("生成证书私钥失败: %w", err)
	}
	keyPEM, err = encodeECPrivateKey(certKey)
	if err != nil {
		return "", "", "", err
	}

	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, certKey)
	if err != nil {
		return "", "", "", fmt.Errorf("创建 CSR 失败: %w", err)
	}

	// 提交 CSR 并获取证书
	derList, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return "", "", "", fmt.Errorf("签署并下载证书失败: %w", err)
	}
	certPEM = encodeCertificates(derList)
	return certPEM, keyPEM, newAccountKeyPEM, nil
}

func (m *ACMEManager) solveAuthorization(ctx context.Context, client *acme.Client, authzURL string, dnsProvider DNSProvider) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("获取 ACME 授权失败: %w", err)
	}
	if authz.Status == acme.StatusValid {
		return nil
	}

	domain := strings.TrimPrefix(authz.Identifier.Value, "*.")
	if dnsProvider != nil {
		// DNS-01 Challenge
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return fmt.Errorf("域名 %s 未提供 dns-01 挑战类型 | dns-01 challenge not offered for %s", domain, domain)
		}

		txtValue, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return fmt.Errorf("计算 DNS-01 挑战记录失败: %w", err)
		}
		fqdn := "_acme-challenge." + domain
		cleanup, err := dnsProvider.Present(ctx, fqdn, txtValue)
		if err != nil {
			return err
		}
		if cleanup != nil {
			defer cleanup()
		}

		if m.cfg.DNSDelay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(m.cfg.DNSDelay):
			}
		}

		if _, err := client.Accept(ctx, chal); err != nil {
			return fmt.Errorf("提交 DNS-01 挑战验证失败 (%s): %w", domain, err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			return fmt.Errorf("DNS-01 域名所有权验证未通过 (%s): %w", domain, err)
		}
		return nil
	}

	// HTTP-01 Challenge
	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return fmt.Errorf("域名 %s 未提供 http-01 挑战类型 | http-01 challenge not offered for %s", domain, domain)
	}

	keyAuth, err := client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return fmt.Errorf("计算 HTTP-01 响应失败: %w", err)
	}

	m.mu.Lock()
	m.httpTokens[chal.Token] = keyAuth
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.httpTokens, chal.Token)
		m.mu.Unlock()
	}()

	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("提交 HTTP-01 挑战验证失败 (%s): %w", domain, err)
	}
	if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
		return fmt.Errorf("HTTP-01 域名所有权验证未通过 (%s，请确保 80 端口公网可达): %w", domain, err)
	}
	return nil
}

var _ crypto.Signer = (*ecdsa.PrivateKey)(nil)

