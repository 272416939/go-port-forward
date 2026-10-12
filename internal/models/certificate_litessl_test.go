package models

import (
	"testing"
)

// TestACMEProviderLiteSSLFamily 锁 LiteSSL 族的 provider 归一化与判别逻辑。
// 这些 helper 是 UI 两层下拉（CA + 验证方式）与内部复合 provider 值的唯一映射点。
func TestACMEProviderLiteSSLFamily(t *testing.T) {
	cases := []struct {
		p          ACMEProvider
		isLiteSSL  bool
		isHTTP01   bool
		isManual   bool
		dns        ACMEProvider
		ca         ACMEProvider
	}{
		{ACMEProviderLiteSSLHTTP01, true, true, false, "", ACMEProvider("litessl")},
		{ACMEProviderLiteSSLCloudflare, true, false, false, ACMEProviderCloudflare, ACMEProvider("litessl")},
		{ACMEProviderLiteSSLAliyun, true, false, false, ACMEProviderAliyun, ACMEProvider("litessl")},
		{ACMEProviderLiteSSLDNSPod, true, false, false, ACMEProviderDNSPod, ACMEProvider("litessl")},
		{ACMEProviderLiteSSLManualDNS, true, false, true, "", ACMEProvider("litessl")},
		// Let's Encrypt 族必须全部判为「非 LiteSSL」，否则会被误要求填 EAB。
		{ACMEProviderCloudflare, false, false, false, ACMEProviderCloudflare, ACMEProviderCloudflare},
		{ACMEProviderAliyun, false, false, false, ACMEProviderAliyun, ACMEProviderAliyun},
		{ACMEProviderDNSPod, false, false, false, ACMEProviderDNSPod, ACMEProviderDNSPod},
		{ACMEProviderHTTP01, false, true, false, "", ACMEProviderHTTP01},
		{ACMEProviderManualDNS, false, false, true, "", ACMEProviderManualDNS},
	}
	for _, c := range cases {
		if got := c.p.IsLiteSSL(); got != c.isLiteSSL {
			t.Errorf("%s.IsLiteSSL() = %v, want %v", c.p, got, c.isLiteSSL)
		}
		if got := c.p.IsHTTP01(); got != c.isHTTP01 {
			t.Errorf("%s.IsHTTP01() = %v, want %v", c.p, got, c.isHTTP01)
		}
		if got := c.p.IsManualDNS(); got != c.isManual {
			t.Errorf("%s.IsManualDNS() = %v, want %v", c.p, got, c.isManual)
		}
		if got := c.p.DNSProvider(); got != c.dns {
			t.Errorf("%s.DNSProvider() = %q, want %q", c.p, got, c.dns)
		}
		if got := c.p.CAProvider(); got != c.ca {
			t.Errorf("%s.CAProvider() = %q, want %q", c.p, got, c.ca)
		}
	}

	// BuildProvider：LiteSSL + 各挑战
	if got := BuildProvider("litessl", "cloudflare"); got != ACMEProviderLiteSSLCloudflare {
		t.Errorf("BuildProvider(litessl, cloudflare) = %q", got)
	}
	if got := BuildProvider("litessl", "http01"); got != ACMEProviderLiteSSLHTTP01 {
		t.Errorf("BuildProvider(litessl, http01) = %q", got)
	}
	if got := BuildProvider("litessl", "manualdns"); got != ACMEProviderLiteSSLManualDNS {
		t.Errorf("BuildProvider(litessl, manualdns) = %q", got)
	}
	if got := BuildProvider("litessl", ""); got != ACMEProviderLiteSSLManualDNS {
		t.Errorf("BuildProvider(litessl, '') = %q, want manualdns as default", got)
	}
	// BuildProvider：Let's Encrypt 族保持原值（存量数据兼容）
	if got := BuildProvider("letsencrypt", "aliyun"); got != ACMEProviderAliyun {
		t.Errorf("BuildProvider(letsencrypt, aliyun) = %q", got)
	}
	if got := BuildProvider("letsencrypt", "manualdns"); got != ACMEProviderManualDNS {
		t.Errorf("BuildProvider(letsencrypt, manualdns) = %q", got)
	}
	if got := BuildProvider("letsencrypt", ""); got != ACMEProviderCloudflare {
		t.Errorf("BuildProvider(letsencrypt, '') = %q", got)
	}

	// 目录地址留空时校验必须兜底为官方固定地址
	if DefaultLiteSSLDirectoryURL != "https://acme.litessl.com/acme/v2/directory" {
		t.Fatalf("DefaultLiteSSLDirectoryURL = %q", DefaultLiteSSLDirectoryURL)
	}
}

// TestValidateApplyACMERequestLiteSSL 验证 LiteSSL 路径：免邮箱，但必须有
// ACME 目录地址与 EAB 凭据；Let's Encrypt 路径仍强制邮箱。
func TestValidateApplyACMERequestLiteSSL(t *testing.T) {
	base := func() *ApplyACMERequest {
		return &ApplyACMERequest{
			Name: "nn", Domains: []string{"mc.example.com"},
			Provider:     ACMEProviderLiteSSLCloudflare,
			DirectoryURL: "https://acme.example.com/directory",
			Credentials: map[string]string{
				"api_token":    "cf-token",
				"eab_kid":      "kid-1",
				"eab_hmac_key": "aGVsbG8",
			},
			AutoRenew: true,
		}
	}

	// 合法：无邮箱、目录地址与 EAB 凭据齐全
	req := base()
	if err := ValidateApplyACMERequest(req); err != nil {
		t.Fatalf("valid LiteSSL request rejected: %v", err)
	}

	// 缺 directory_url：现在会用官方固定地址兜底（宝塔正是这么做的，用户无感）
	req = base()
	req.DirectoryURL = ""
	if err := ValidateApplyACMERequest(req); err != nil {
		t.Fatalf("empty directory URL must fall back to the official default: %v", err)
	}
	if req.DirectoryURL != DefaultLiteSSLDirectoryURL {
		t.Fatalf("directory URL not defaulted: %q", req.DirectoryURL)
	}

	// 目录地址不是 http(s) 开头：拒绝
	req = base()
	req.DirectoryURL = "ftp://acme.example.com"
	if err := ValidateApplyACMERequest(req); err == nil {
		t.Fatal("non-http directory URL must be rejected")
	}

	// 缺 EAB
	req = base()
	req.DirectoryURL = "https://acme.example.com/directory"
	delete(req.Credentials, "eab_kid")
	if err := ValidateApplyACMERequest(req); err == nil {
		t.Fatal("LiteSSL without eab_kid must be rejected")
	}

	// 缺 DNS 凭据（DNS-01 必须有）
	req = base()
	req.DirectoryURL = "https://acme.example.com/directory"
	delete(req.Credentials, "api_token")
	if err := ValidateApplyACMERequest(req); err == nil {
		t.Fatal("LiteSSL DNS-01 without DNS credentials must be rejected")
	}

	// HTTP-01 + 泛域名：拒绝（与 Let's Encrypt 同一约束）
	req = base()
	req.Provider = ACMEProviderLiteSSLHTTP01
	req.Domains = []string{"*.example.com"}
	if err := ValidateApplyACMERequest(req); err == nil {
		t.Fatal("LiteSSL HTTP-01 with wildcard must be rejected")
	}

	// 手动 DNS 解析：无需任何 DNS API 凭据（这是宝塔同款的零凭据模式）
	manual := base()
	manual.Provider = ACMEProviderLiteSSLManualDNS
	delete(manual.Credentials, "api_token")
	if err := ValidateApplyACMERequest(manual); err != nil {
		t.Fatalf("LiteSSL manual DNS without DNS credentials must be accepted: %v", err)
	}
	// 手动 DNS 但缺 EAB：仍拒绝（EAB 是账号身份，与验证方式无关）
	manual2 := base()
	manual2.Provider = ACMEProviderLiteSSLManualDNS
	delete(manual2.Credentials, "eab_kid")
	if err := ValidateApplyACMERequest(manual2); err == nil {
		t.Fatal("LiteSSL manual DNS without EAB must be rejected")
	}

	// 目录地址留空：必须兜底为官方固定地址（用户无感）
	noDir := base()
	noDir.Provider = ACMEProviderLiteSSLManualDNS
	noDir.DirectoryURL = ""
	if err := ValidateApplyACMERequest(noDir); err != nil {
		t.Fatalf("empty directory URL must fall back to the official default: %v", err)
	}
	if noDir.DirectoryURL != DefaultLiteSSLDirectoryURL {
		t.Fatalf("directory URL not defaulted: %q", noDir.DirectoryURL)
	}

	// Let's Encrypt 族仍然强制邮箱
	le := &ApplyACMERequest{
		Name: "le", Domains: []string{"mc.example.com"},
		Provider: ACMEProviderCloudflare,
		Credentials: map[string]string{"api_token": "cf-token"},
	}
	if err := ValidateApplyACMERequest(le); err == nil {
		t.Fatal("Let's Encrypt without email must still be rejected")
	}
	le.Email = "admin@example.com"
	if err := ValidateApplyACMERequest(le); err != nil {
		t.Fatalf("valid Let's Encrypt request rejected: %v", err)
	}

	// Let's Encrypt 手动 DNS：同样零 DNS 凭据，但仍要邮箱
	leManual := &ApplyACMERequest{
		Name: "le-manual", Domains: []string{"mc.example.com"},
		Provider: ACMEProviderManualDNS, Email: "admin@example.com",
	}
	if err := ValidateApplyACMERequest(leManual); err != nil {
		t.Fatalf("Let's Encrypt manual DNS rejected: %v", err)
	}
}
