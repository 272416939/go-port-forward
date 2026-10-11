package models

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// CertSourceType 标识证书来源：手动上传或 ACME 自动签发。
type CertSourceType string

const (
	CertSourceManual CertSourceType = "manual"
	CertSourceACME   CertSourceType = "acme"
)

// ACMEProvider 标识 ACME 的 CA 与验证方式组合。
//
// 取值分两族：
//   - Let's Encrypt（国际，需注册邮箱）：cloudflare / aliyun / dnspod / http01
//   - LiteSSL（TrustAsia 运营，经 FreeSSL 控制台获取 ACME 目录 + EAB 凭据，
//     免邮箱、国内 DCV 节点）：litessl_http01 / litessl_cloudflare /
//     litessl_aliyun / litessl_dnspod
//
// 前缀 litessl_ 之后的部分即 DNS-01 所用服务商；http01 表示 HTTP-01 验证。
type ACMEProvider string

const (
	ACMEProviderCloudflare ACMEProvider = "cloudflare"
	ACMEProviderAliyun     ACMEProvider = "aliyun"
	ACMEProviderDNSPod     ACMEProvider = "dnspod"
	ACMEProviderHTTP01     ACMEProvider = "http01"

	// LiteSSL（TrustAsia · 国内节点 · 免邮箱 · 需 EAB 凭据）
	ACMEProviderLiteSSLHTTP01     ACMEProvider = "litessl_http01"
	ACMEProviderLiteSSLCloudflare ACMEProvider = "litessl_cloudflare"
	ACMEProviderLiteSSLAliyun     ACMEProvider = "litessl_aliyun"
	ACMEProviderLiteSSLDNSPod     ACMEProvider = "litessl_dnspod"
	ACMEProviderLiteSSLManualDNS  ACMEProvider = "litessl_manualdns"

	// manualdns：DNS-01 手动解析。不需要任何 DNS API 凭据——系统给出 TXT
	// 记录，用户去自己的 DNS 服务商添加后点「验证」。这是宝塔「DNS验证 +
	// 手动解析」的同款实现，也是唯一能同时做到零凭据 + 支持泛域名 + 不限
	// DNS 服务商的模式。
	ACMEProviderManualDNS ACMEProvider = "manualdns"
)

// DefaultLiteSSLDirectoryURL 是 LiteSSL 的 ACME 目录地址默认值。
//
// 该地址由 FreeSSL 官方固定（见 blog.freessl.cn「FreeSSL.cn 的 ACME 服务器
// 地址」），因此可安全地作为默认值预填——用户只有在自建/代理 ACME 端点时才
// 需要改动。宝塔正是把这个地址写死在代码里，用户才看不到这一项。
const DefaultLiteSSLDirectoryURL = "https://acme.freessl.cn/directory"

// litesslPrefix 是 LiteSSL 族 provider 取值的前缀。
const litesslPrefix = "litessl"

// IsLiteSSL 报告该 provider 是否走 LiteSSL（TrustAsia）CA。
func (p ACMEProvider) IsLiteSSL() bool {
	return strings.HasPrefix(strings.ToLower(string(p)), litesslPrefix)
}

// IsHTTP01 报告该 provider 是否用 HTTP-01 验证（无 DNS 服务商）。
func (p ACMEProvider) IsHTTP01() bool {
	return strings.HasSuffix(strings.ToLower(string(p)), "http01")
}

// IsManualDNS 报告该 provider 是否为 DNS-01 手动解析模式（无需 DNS API 凭据）。
func (p ACMEProvider) IsManualDNS() bool {
	return strings.HasSuffix(strings.ToLower(string(p)), "manualdns")
}

// DNSProvider 返回该 provider 使用的 DNS-01 服务商；HTTP-01 与手动解析返回空串。
func (p ACMEProvider) DNSProvider() ACMEProvider {
	if p.IsHTTP01() || p.IsManualDNS() {
		return ""
	}
	s := strings.ToLower(string(p))
	switch {
	case strings.HasSuffix(s, "cloudflare"):
		return ACMEProviderCloudflare
	case strings.HasSuffix(s, "aliyun"):
		return ACMEProviderAliyun
	case strings.HasSuffix(s, "dnspod"):
		return ACMEProviderDNSPod
	}
	return ""
}

// CAProvider 把 provider 归一到「面向用户的 CA 选项」：
// litessl_* 一律折叠为 litessl（其余保持原值）。
func (p ACMEProvider) CAProvider() ACMEProvider {
	if p.IsLiteSSL() {
		return ACMEProvider(litesslPrefix)
	}
	return p
}

// BuildProvider 由「CA + 验证方式/DNS 服务商」拼出内部 provider 取值。
// ca 为 litessl 时走 LiteSSL 族；challenge 为空表示默认 DNS-01。
func BuildProvider(ca ACMEProvider, challenge ACMEProvider) ACMEProvider {
	ch := ACMEProvider(strings.ToLower(strings.TrimSpace(string(challenge))))
	ca = ACMEProvider(strings.ToLower(strings.TrimSpace(string(ca))))
	if ca.IsLiteSSL() {
		if ch == "" || ch == ACMEProviderHTTP01 {
			if ch == ACMEProviderHTTP01 {
				return ACMEProviderLiteSSLHTTP01
			}
			return ACMEProviderLiteSSLManualDNS
		}
		if ch == ACMEProviderManualDNS {
			return ACMEProviderLiteSSLManualDNS
		}
		return ACMEProvider(litesslPrefix + "_" + string(ch))
	}
	if ch == "" || ch == ACMEProviderManualDNS {
		if ch == ACMEProviderManualDNS {
			return ACMEProviderManualDNS
		}
		return ACMEProviderCloudflare
	}
	return ch
}

// Certificate 表示证书管理中的一条 SSL/TLS 证书记录。
//
// 敏感字段（KeyPEM、ACMEAccountKey、Credentials）均标记 json:"-" 防止通过
// REST 响应泄漏（铁律 6）；存储层使用独立的 certRecord 结构体持久化完整内容。
type Certificate struct {
	ID         string         `json:"id"`
	UserID     string         `json:"user_id"`
	UserName   string         `json:"user_name,omitempty"` // 展示用，不持久化
	Name       string         `json:"name"`
	SourceType CertSourceType `json:"source_type"`

	// 证书解析元数据
	SubjectCN string    `json:"subject_cn"`
	Domains   []string  `json:"domains"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`

	// PEM 内容（CertPEM 可用于详情查看，KeyPEM 永不经 API 列表回显）
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"-"`

	// ACME 自动续签配置
	AutoRenew      bool              `json:"auto_renew"`
	Provider       ACMEProvider      `json:"provider,omitempty"`
	Email          string            `json:"email,omitempty"`
	// DirectoryURL 是 ACME 目录地址（LiteSSL 由 FreeSSL 控制台按账号下发）。
	DirectoryURL   string            `json:"directory_url,omitempty"`
	ACMEAccountKey string            `json:"-"`
	Credentials    map[string]string `json:"-"`
	HasCredentials bool              `json:"has_credentials"`
	LastRenewAt    time.Time         `json:"last_renew_at,omitempty"`
	LastError      string            `json:"last_error,omitempty"`

	// 运行时统计（展示用，不持久化）
	UsedCount int `json:"used_count"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UploadCertificateRequest 是手动上传证书的请求载荷。
type UploadCertificateRequest struct {
	Name    string `json:"name"`
	UserID  string `json:"user_id"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// ApplyACMERequest 是通过 ACME 自动申请证书的请求载荷。
type ApplyACMERequest struct {
	Name        string            `json:"name"`
	UserID      string            `json:"user_id"`
	Domains     []string          `json:"domains"`
	Email       string            `json:"email"`
	Provider    ACMEProvider      `json:"provider"`
	// DirectoryURL 仅 LiteSSL 需要：FreeSSL 控制台「ACME 账号管理」下发的目录地址。
	DirectoryURL string            `json:"directory_url"`
	Credentials  map[string]string `json:"credentials"`
	AutoRenew    bool              `json:"auto_renew"`
}

// UpdateCertificateRequest 是更新已有证书的请求载荷。
type UpdateCertificateRequest struct {
	Name        *string           `json:"name"`
	CertPEM     *string           `json:"cert_pem"`
	KeyPEM      *string           `json:"key_pem"`
	AutoRenew   *bool             `json:"auto_renew"`
	Email       *string           `json:"email"`
	Provider    *ACMEProvider     `json:"provider"`
	DirectoryURL *string          `json:"directory_url"`
	Credentials map[string]string `json:"credentials"`
}

// ValidateAndParsePEM 校验 CertPEM 与 KeyPEM 能否配成合法的 X509 密钥对，
// 并自动填充证书的域名、颁发者与有效期元数据。
func (c *Certificate) ValidateAndParsePEM() error {
	c.CertPEM = strings.TrimSpace(c.CertPEM)
	c.KeyPEM = strings.TrimSpace(c.KeyPEM)
	if c.CertPEM == "" || c.KeyPEM == "" {
		return fmt.Errorf("证书内容与私钥内容不能为空 | certificate and private key are required")
	}
	if len(c.CertPEM) > MaxNetherNetPEMBytes || len(c.KeyPEM) > MaxNetherNetPEMBytes {
		return fmt.Errorf("证书或私钥内容过大（上限 %d KB）| certificate or key content too large (limit %d KB)",
			MaxNetherNetPEMBytes>>10, MaxNetherNetPEMBytes>>10)
	}

	pair, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
	if err != nil {
		return fmt.Errorf("证书与私钥无法配对：%v（请确认两者属于同一证书且私钥未加密）| certificate and key do not match: %v", err, err)
	}
	if len(pair.Certificate) == 0 {
		return fmt.Errorf("未找到有效的证书数据 | no certificate found in PEM")
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("解析 X.509 证书失败：%v | failed to parse X.509 certificate: %v", err, err)
	}

	c.SubjectCN = leaf.Subject.CommonName
	seen := make(map[string]struct{})
	var domains []string
	for _, d := range leaf.DNSNames {
		d = strings.TrimSpace(d)
		if d != "" {
			if _, ok := seen[d]; !ok {
				seen[d] = struct{}{}
				domains = append(domains, d)
			}
		}
	}
	for _, ip := range leaf.IPAddresses {
		s := ip.String()
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			domains = append(domains, s)
		}
	}
	if len(domains) == 0 && c.SubjectCN != "" {
		domains = []string{c.SubjectCN}
	}
	if len(domains) > 0 {
		c.Domains = domains
	}
	if c.SubjectCN == "" && len(c.Domains) > 0 {
		c.SubjectCN = c.Domains[0]
	}

	issuer := leaf.Issuer.CommonName
	if issuer == "" && len(leaf.Issuer.Organization) > 0 {
		issuer = leaf.Issuer.Organization[0]
	}
	c.Issuer = issuer
	c.NotBefore = leaf.NotBefore
	c.NotAfter = leaf.NotAfter
	return nil
}

// ValidateUploadCertificateRequest 校验手动上传证书请求。
func ValidateUploadCertificateRequest(req *UploadCertificateRequest) error {
	if req == nil {
		return fmt.Errorf("请求不能为空 | request is required")
	}
	req.Name = strings.TrimSpace(req.Name)
	req.CertPEM = strings.TrimSpace(req.CertPEM)
	req.KeyPEM = strings.TrimSpace(req.KeyPEM)
	if err := ValidateRuleName(req.Name); err != nil {
		return err
	}
	tmp := &Certificate{CertPEM: req.CertPEM, KeyPEM: req.KeyPEM}
	return tmp.ValidateAndParsePEM()
}

// ValidateApplyACMERequest 校验 ACME 自动申请证书请求。
func ValidateApplyACMERequest(req *ApplyACMERequest) error {
	if req == nil {
		return fmt.Errorf("请求不能为空 | request is required")
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	if err := ValidateRuleName(req.Name); err != nil {
		return err
	}
	var cleaned []string
	seen := make(map[string]struct{})
	for _, d := range req.Domains {
		for _, part := range strings.FieldsFunc(d, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
		}) {
			part = strings.ToLower(strings.TrimSpace(part))
			if part == "" {
				continue
			}
			if _, ok := seen[part]; !ok {
				seen[part] = struct{}{}
				cleaned = append(cleaned, part)
			}
		}
	}
	if len(cleaned) == 0 {
		return fmt.Errorf("请至少填写一个要申请证书的域名 | at least one domain is required")
	}
	req.Domains = cleaned

	// LiteSSL 走 EAB（外部账户绑定）替代邮箱注册；Let's Encrypt 仍要求邮箱。
	if !req.Provider.IsLiteSSL() {
		if req.Email == "" || !strings.Contains(req.Email, "@") {
			return fmt.Errorf("请填写有效的通知邮箱（用于 Let's Encrypt 账户注册）| a valid email address is required")
		}
	} else {
		// 目录地址留空时用官方固定地址兜底——宝塔正是把它写死在代码里，用户才
		// 看不到这一项。只有自建/代理 ACME 端点时才需要改动。
		req.DirectoryURL = strings.TrimSpace(req.DirectoryURL)
		if req.DirectoryURL == "" {
			req.DirectoryURL = DefaultLiteSSLDirectoryURL
		}
		if !strings.HasPrefix(strings.ToLower(req.DirectoryURL), "http") {
			return fmt.Errorf("LiteSSL 的 ACME 目录地址必须以 http(s) 开头 | LiteSSL ACME directory URL must start with http(s)")
		}
		if strings.TrimSpace(req.Credentials["eab_kid"]) == "" || strings.TrimSpace(req.Credentials["eab_hmac_key"]) == "" {
			return fmt.Errorf("请填写 LiteSSL 的 EAB 凭据（KID 与 HMAC Key，FreeSSL 控制台获取，密钥仅显示一次）| LiteSSL EAB credentials (KID and HMAC Key) are required")
		}
	}

	// LiteSSL 目录地址留空时用官方固定地址兜底（自建/代理 ACME 端点才需改动）。
	dnsProv := req.Provider.DNSProvider()
	switch {
	case dnsProv == ACMEProviderCloudflare:
		if strings.TrimSpace(req.Credentials["api_token"]) == "" {
			return fmt.Errorf("Cloudflare DNS 验证需要填写 API Token | Cloudflare API Token is required")
		}
	case dnsProv == ACMEProviderAliyun:
		if strings.TrimSpace(req.Credentials["access_key_id"]) == "" || strings.TrimSpace(req.Credentials["access_key_secret"]) == "" {
			return fmt.Errorf("阿里云 DNS 验证需要填写 AccessKey ID 与 AccessKey Secret | Aliyun AccessKey ID and Secret are required")
		}
	case dnsProv == ACMEProviderDNSPod:
		if strings.TrimSpace(req.Credentials["secret_id"]) == "" || strings.TrimSpace(req.Credentials["secret_key"]) == "" {
			return fmt.Errorf("腾讯云 DNSPod 验证需要填写 SecretId 与 SecretKey | Tencent Cloud SecretId and SecretKey are required")
		}
	case req.Provider.IsHTTP01():
		for _, d := range req.Domains {
			if strings.HasPrefix(d, "*.") {
				return fmt.Errorf("HTTP-01 验证不支持泛域名 (%s)，泛域名请使用 DNS-01 验证 | wildcard domain requires DNS-01 validation", d)
			}
		}
	case req.Provider.IsManualDNS():
		// 手动 DNS 解析：无需任何 DNS API 凭据。TXT 记录由 ACME 流程算出后
		// 展示给用户，去自己的 DNS 服务商添加即可。
	default:
		return fmt.Errorf("不支持的 ACME 验证方式：%s | unsupported ACME provider: %s", req.Provider, req.Provider)
	}
	return nil
}
