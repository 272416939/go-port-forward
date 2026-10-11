package certmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go-port-forward/internal/models"

	"golang.org/x/crypto/acme"
)

// pendingManualTTL 是「已创建 Order、等待用户添加 DNS 记录」的中间状态存活时间。
// ACME Order 本身有有效期，超时后 CA 会拒收挑战；这里取保守值并定期清扫。
const pendingManualTTL = 30 * time.Minute

// DNSChallengeRecord 是手动 DNS 解析模式下需要用户添加的一条 TXT 记录。
type DNSChallengeRecord struct {
	Domain      string `json:"domain"`       // 被验证的域名（通配符已去掉前导 *.）
	RecordName  string `json:"record_name"`  // 主机记录：_acme-challenge.sub.example.com
	RecordType  string `json:"record_type"`  // 固定 TXT
	RecordValue string `json:"record_value"` // 记录值
}

// certMeta 是手动 DNS 解析流程成功后落库所需的证书元数据。
// 在 prepare 阶段一次性收下，verify 阶段只凭 token 就能建证——避免前端在两次
// 请求之间改了口径，也避免用户改个名字就导致第二步对不上。
type certMeta struct {
	name        string
	userID      string
	autoRenew   bool
	provider    models.ACMEProvider
	email       string
	directoryURL string
	creds       map[string]string
}

// pendingManualOrder 是手动 DNS 解析两段式流程的中间状态。
//
// ACME 的 DNS-01 挑战必须先让 TXT 记录在公共 DNS 上生效，CA 才肯验证——所以
// 「创建 Order」和「提交挑战验证」必然是两个用户动作，中间状态必须留存。
// 存在内存而不是 bbolt：Order 本身有有效期、重启后 CA 大概率已拒收，让用户重新
// 点一次「获取记录」比做一次数据迁移更简单，也不会把半成品写进证书表。
type pendingManualOrder struct {
	token        string
	directoryURL string
	accountKey   string
	email        string
	domains      []string
	eab          *EABCredentials
	orderURI     string
	finalizeURL  string
	authzURLs    []string
	meta         certMeta

	createdAt time.Time
}

// ManualDNSPrepareResult 是 prepare 阶段的返回：一个待验证令牌 + 要让用户添加的记录。
type ManualDNSPrepareResult struct {
	Token        string               `json:"token"`
	Records      []DNSChallengeRecord `json:"records"`
	DirectoryURL string               `json:"directory_url"`
	ExpiresAt    time.Time            `json:"expires_at"`
}

// manualStore 保存所有待验证的手动 DNS Order。
type manualStore struct {
	mu     sync.Mutex
	orders map[string]*pendingManualOrder
}

func newManualStore() *manualStore {
	return &manualStore{orders: make(map[string]*pendingManualOrder)}
}

func (s *manualStore) put(o *pendingManualOrder) {
	s.mu.Lock()
	s.orders[o.token] = o
	s.mu.Unlock()
}

func (s *manualStore) take(token string) (*pendingManualOrder, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orders[token]
	if !ok {
		return nil, false
	}
	delete(s.orders, token)
	if time.Since(o.createdAt) > pendingManualTTL {
		return nil, false
	}
	return o, true
}

// sweepExpired 清理过期的中间状态。每次 prepare/verify 时顺带调用即可，
// 不值得单开 goroutine——用量极低（一次人工操作一两条）。
func (s *manualStore) sweepExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, o := range s.orders {
		if time.Since(o.createdAt) > pendingManualTTL {
			delete(s.orders, k)
		}
	}
}


// PrepareManualDNS 创建 ACME Order 并算出每个域名需要添加的 TXT 记录，
// 但**不提交挑战**——记录还没在公共 DNS 上生效，提交只会失败。
func (m *ACMEManager) PrepareManualDNS(
	ctx context.Context,
	directoryURL string,
	accountKeyPEM string,
	email string,
	domains []string,
	eab *EABCredentials,
	meta certMeta,
) (*ManualDNSPrepareResult, string, error) {
	if len(domains) == 0 {
		return nil, "", errors.New("domains list cannot be empty")
	}
	m.manual.sweepExpired()

	dirURL := strings.TrimSpace(directoryURL)
	if dirURL == "" {
		dirURL = m.cfg.DirectoryURL
	}

	client, newAccountKeyPEM, err := m.registerClient(ctx, dirURL, accountKeyPEM, email, eab)
	if err != nil {
		return nil, "", err
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	if err != nil {
		return nil, "", fmt.Errorf("创建 ACME Order 失败: %w", err)
	}

	// 逐个 authorization 取 DNS-01 挑战的记录值。通配符域名的 identifier 不带
	// 前导 *（ACME 规范如此），所以记录名直接拼 _acme-challenge.<identifier>。
	records := make([]DNSChallengeRecord, 0, len(order.AuthzURLs))
	for _, authzURL := range order.AuthzURLs {
		authz, aerr := client.GetAuthorization(ctx, authzURL)
		if aerr != nil {
			return nil, "", fmt.Errorf("获取 ACME 授权失败: %w", aerr)
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return nil, "", fmt.Errorf("域名 %s 未提供 dns-01 挑战类型 | dns-01 challenge not offered for %s", authz.Identifier.Value, authz.Identifier.Value)
		}
		txtValue, terr := client.DNS01ChallengeRecord(chal.Token)
		if terr != nil {
			return nil, "", fmt.Errorf("计算 DNS-01 挑战记录失败: %w", terr)
		}
		records = append(records, DNSChallengeRecord{
			Domain:      authz.Identifier.Value,
			RecordName:  "_acme-challenge." + authz.Identifier.Value,
			RecordType:  "TXT",
			RecordValue: txtValue,
		})
	}
	if len(records) == 0 {
		return nil, "", errors.New("ACME 未返回任何待验证的域名授权 | no pending authorizations returned")
	}

	token, err := newManualToken()
	if err != nil {
		return nil, "", err
	}
	m.manual.put(&pendingManualOrder{
		token:        token,
		directoryURL: dirURL,
		accountKey:   newAccountKeyPEM,
		email:        email,
		domains:      append([]string(nil), domains...),
		eab:          eab,
		orderURI:     order.URI,
		finalizeURL:  order.FinalizeURL,
		authzURLs:    append([]string(nil), order.AuthzURLs...),
		meta:         meta,
		createdAt:    time.Now(),
	})

	return &ManualDNSPrepareResult{
		Token:        token,
		Records:      records,
		DirectoryURL: dirURL,
		ExpiresAt:    time.Now().Add(pendingManualTTL),
	}, newAccountKeyPEM, nil
}

// CompleteManualDNS 在用户添加完 TXT 记录后提交挑战、等待验证并下载证书，
// 连同 prepare 阶段收下的证书元数据一并返回。
func (m *ACMEManager) CompleteManualDNS(ctx context.Context, token string) (certPEM, keyPEM string, meta certMeta, err error) {
	pending, ok := m.manual.take(token)
	if !ok {
		return "", "", certMeta{}, errors.New("验证令牌不存在或已过期，请重新获取 DNS 记录 | verification token not found or expired")
	}
	meta = pending.meta
	if meta.name == "" && len(pending.domains) > 0 {
		meta.name = pending.domains[0]
	}

	client, _, err := m.registerClient(ctx, pending.directoryURL, pending.accountKey, pending.email, pending.eab)
	if err != nil {
		return "", "", meta, err
	}

	for _, authzURL := range pending.authzURLs {
		authz, aerr := client.GetAuthorization(ctx, authzURL)
		if aerr != nil {
			return "", "", meta, fmt.Errorf("获取 ACME 授权失败: %w", aerr)
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return "", "", meta, fmt.Errorf("域名 %s 未提供 dns-01 挑战类型 | dns-01 challenge not offered for %s", authz.Identifier.Value, authz.Identifier.Value)
		}
		if _, aerr := client.Accept(ctx, chal); aerr != nil {
			return "", "", meta, fmt.Errorf("提交 DNS-01 挑战验证失败 (%s)：%v（请确认 TXT 记录已添加且已生效）| failed to submit challenge: %v",
				authz.Identifier.Value, aerr, aerr)
		}
		if _, werr := client.WaitAuthorization(ctx, authzURL); werr != nil {
			return "", "", meta, fmt.Errorf("域名所有权验证未通过 (%s)：%v（TXT 记录未生效或值不正确）| authorization failed: %v",
				authz.Identifier.Value, werr, werr)
		}
	}

	order, oerr := client.WaitOrder(ctx, pending.orderURI)
	if oerr != nil {
		return "", "", meta, fmt.Errorf("等待 ACME Order Ready 失败: %w", oerr)
	}

	certPEM, keyPEM, err = m.finalizeOrder(ctx, client, order.FinalizeURL, pending.domains)
	return certPEM, keyPEM, meta, err
}

// registerClient 构造并注册 ACME 客户端。有 EAB 时 contact 留空——外部账户绑定
// 本身就是账号身份，这也是 LiteSSL 免邮箱的原因。
func (m *ACMEManager) registerClient(
	ctx context.Context,
	dirURL string,
	accountKeyPEM string,
	email string,
	eab *EABCredentials,
) (*acme.Client, string, error) {
	acctKey, err := parseECPrivateKey(accountKeyPEM)
	if err != nil {
		return nil, "", fmt.Errorf("解析 ACME 账户密钥失败: %w", err)
	}
	client := &acme.Client{
		Key:          acctKey,
		DirectoryURL: dirURL,
		HTTPClient:   m.cfg.HTTPClient,
	}

	var contact []string
	if email != "" {
		contact = []string{"mailto:" + email}
	}
	acct := &acme.Account{Contact: contact}
	if eab != nil {
		eab.KID = strings.TrimSpace(eab.KID)
		eab.HMACKey = strings.TrimSpace(eab.HMACKey)
		if eab.KID == "" || eab.HMACKey == "" {
			return nil, "", errors.New("EAB 凭据不完整（KID 与 HMAC Key 均必填）| incomplete EAB credentials")
		}
		hmacKey, kerr := DecodeEABHMACKey(eab.HMACKey)
		if kerr != nil {
			return nil, "", fmt.Errorf("解析 EAB HMAC Key 失败: %w", kerr)
		}
		acct.ExternalAccountBinding = &acme.ExternalAccountBinding{KID: eab.KID, Key: hmacKey}
	}
	if _, rerr := client.Register(ctx, acct, acme.AcceptTOS); rerr != nil && !errors.Is(rerr, acme.ErrAccountAlreadyExists) {
		msg := strings.ToLower(rerr.Error())
		if !strings.Contains(msg, "already") && !strings.Contains(msg, "existing") {
			return nil, "", fmt.Errorf("注册 ACME 账户失败 (%s): %w", dirURL, rerr)
		}
	}
	return client, accountKeyPEM, nil
}

// finalizeOrder 生成证书私钥与 CSR，提交并下载完整证书链。
func (m *ACMEManager) finalizeOrder(ctx context.Context, client *acme.Client, finalizeURL string, domains []string) (certPEM, keyPEM string, err error) {
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("生成证书私钥失败: %w", err)
	}
	keyPEM, err = encodeECPrivateKey(certKey)
	if err != nil {
		return "", "", err
	}
	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, certKey)
	if err != nil {
		return "", "", fmt.Errorf("创建 CSR 失败: %w", err)
	}
	derList, _, err := client.CreateOrderCert(ctx, finalizeURL, csrDER, true)
	if err != nil {
		return "", "", fmt.Errorf("签署并下载证书失败: %w", err)
	}
	return encodeCertificates(derList), keyPEM, nil
}

func newManualToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("生成验证令牌失败: %w", err)
	}
	return hex.EncodeToString(b), nil
}
