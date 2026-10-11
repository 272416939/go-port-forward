package models

import (
	"fmt"
	"strings"
	"time"
)

// DNSProviderType 表示受支持的 DNS-01 服务商类型。
const (
	DNSProviderTypeCloudflare = "cloudflare"
	DNSProviderTypeAliyun     = "aliyun"
	DNSProviderTypeDNSPod     = "dnspod"
)

// IsValidDNSProviderType 检查服务商类型是否受支持。
func IsValidDNSProviderType(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case DNSProviderTypeCloudflare, DNSProviderTypeAliyun, DNSProviderTypeDNSPod:
		return true
	default:
		return false
	}
}

// DNSCredential 表示保存的 DNS 服务商 API 凭证。
//
// 敏感凭证字段（Credentials）标记 json:"-" 防止通过 REST API 明文泄漏（铁律 6）；
// 存储层使用独立 Record 结构体持久化，API 响应统一使用脱敏后的 DNSCredentialView。
type DNSCredential struct {
	ID          string            `json:"id"`
	UserID      string            `json:"user_id"` // 所属用户 ID，空字符串表示全局共享/管理员
	Name        string            `json:"name"`    // 凭据别名，如“我的 Cloudflare”
	Provider    string            `json:"provider"`// cloudflare | aliyun | dnspod
	Credentials map[string]string `json:"-"`       // 敏感密钥凭证（永不经 API 回显）
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// DNSCredentialView 是面向前端与 API 响应的 DNS 凭证脱敏视图。
type DNSCredentialView struct {
	ID                string            `json:"id"`
	UserID            string            `json:"user_id"`
	Name              string            `json:"name"`
	Provider          string            `json:"provider"`
	MaskedCredentials map[string]string `json:"masked_credentials"` // 脱敏展示的键值摘要
	HasCredentials    bool              `json:"has_credentials"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// maskSecret 对敏感字符串进行脱敏处理（保留末尾4位，其余打星号）。
func maskSecret(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return "••••••••"
	}
	return "••••••••" + s[len(s)-4:]
}

// View 生成脱敏视图。
func (c *DNSCredential) View() DNSCredentialView {
	if c == nil {
		return DNSCredentialView{}
	}
	masked := make(map[string]string)
	for k, v := range c.Credentials {
		masked[k] = maskSecret(v)
	}
	return DNSCredentialView{
		ID:                c.ID,
		UserID:            c.UserID,
		Name:              c.Name,
		Provider:          c.Provider,
		MaskedCredentials: masked,
		HasCredentials:    len(c.Credentials) > 0,
		CreatedAt:         c.CreatedAt,
		UpdatedAt:         c.UpdatedAt,
	}
}

// SaveDNSCredentialRequest 是创建或更新 DNS 凭据的请求载荷。
type SaveDNSCredentialRequest struct {
	Name        string            `json:"name"`
	UserID      string            `json:"user_id"`
	Provider    string            `json:"provider"`
	Credentials map[string]string `json:"credentials"`
}

// ValidateSaveDNSCredentialRequest 校验请求载荷。
// isCreate 为 true 时校验必填凭据；为 false（更新）时允许留空凭据以保留原值。
func ValidateSaveDNSCredentialRequest(req *SaveDNSCredentialRequest, isCreate bool) error {
	if req == nil {
		return fmt.Errorf("请求不能为空 | request is required")
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return fmt.Errorf("请填写凭据别名 | credential name is required")
	}
	if err := ValidateRuleName(req.Name); err != nil {
		return err
	}
	req.Provider = strings.ToLower(strings.TrimSpace(req.Provider))
	if !IsValidDNSProviderType(req.Provider) {
		return fmt.Errorf("不支持的 DNS 服务商类型：%s | unsupported DNS provider type", req.Provider)
	}

	if req.Credentials == nil {
		req.Credentials = make(map[string]string)
	}

	if isCreate {
		switch req.Provider {
		case DNSProviderTypeCloudflare:
			if strings.TrimSpace(req.Credentials["api_token"]) == "" {
				return fmt.Errorf("Cloudflare 需要填写 API Token | Cloudflare API Token is required")
			}
		case DNSProviderTypeAliyun:
			if strings.TrimSpace(req.Credentials["access_key_id"]) == "" || strings.TrimSpace(req.Credentials["access_key_secret"]) == "" {
				return fmt.Errorf("阿里云需要填写 AccessKey ID 与 AccessKey Secret | Aliyun credentials are required")
			}
		case DNSProviderTypeDNSPod:
			if strings.TrimSpace(req.Credentials["secret_id"]) == "" || strings.TrimSpace(req.Credentials["secret_key"]) == "" {
				return fmt.Errorf("腾讯云 DNSPod 需要填写 SecretId 与 SecretKey | Tencent Cloud credentials are required")
			}
		}
	}
	return nil
}
