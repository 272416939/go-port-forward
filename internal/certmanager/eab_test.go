package certmanager

import (
	"encoding/base64"
	"testing"

	"go-port-forward/internal/models"
)

// TestDecodeEABHMACKey 验证 EAB HMAC Key 的多种 Base64 变体都能解出原始字节。
// 各 CA 控制台的编码习惯不一（base64url 无填充/带填充/标准 base64），
// 解错的表现是 CA 拒绝注册而不是静默失败，但这里仍要覆盖全部常见形态。
func TestDecodeEABHMACKey(t *testing.T) {
	raw := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	cases := map[string]string{
		"rawurl":    base64.RawURLEncoding.EncodeToString(raw),
		"url":       base64.URLEncoding.EncodeToString(raw),
		"rawstd":    base64.RawStdEncoding.EncodeToString(raw),
		"std":       base64.StdEncoding.EncodeToString(raw),
		"plaintext": "not-base64-at-all!!!", // 无法解码时退回原样字节
	}
	for name, in := range cases {
		got, err := DecodeEABHMACKey(in)
		if err != nil {
			t.Fatalf("%s: DecodeEABHMACKey(%q) error: %v", name, in, err)
		}
		if name == "plaintext" {
			if string(got) != in {
				t.Fatalf("%s: fallback to raw bytes failed: got %q want %q", name, got, in)
			}
			continue
		}
		if string(got) != string(raw) {
			t.Fatalf("%s: decoded %q, want %q", name, got, raw)
		}
	}

	if _, err := DecodeEABHMACKey("   "); err == nil {
		t.Fatal("empty EAB HMAC key must return an error")
	}
}

// TestNewDNSProviderWithCompositeProvider 验证复合 provider（litessl_cloudflare 等）
// 能归一化到正确的 DNS 服务商，非 DNS provider 返回错误。
func TestNewDNSProviderWithCompositeProvider(t *testing.T) {
	cases := []struct {
		provider models.ACMEProvider
		wantType string
		wantErr  bool
	}{
		{models.ACMEProviderLiteSSLCloudflare, "*certmanager.cloudflareProvider", false},
		{models.ACMEProviderCloudflare, "*certmanager.cloudflareProvider", false},
		{models.ACMEProviderLiteSSLAliyun, "*certmanager.aliyunProvider", false},
		{models.ACMEProviderLiteSSLDNSPod, "*certmanager.dnspodProvider", false},
		{models.ACMEProviderHTTP01, "", true},
		{models.ACMEProviderLiteSSLHTTP01, "", true},
	}
	for _, c := range cases {
		prov, err := newDNSProvider(c.provider, map[string]string{
			"api_token": "t", "access_key_id": "i", "access_key_secret": "s",
			"secret_id": "i", "secret_key": "k",
		}, nil)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected error, got provider %T", c.provider, prov)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", c.provider, err)
		}
		if got := typeName(prov); got != c.wantType {
			t.Errorf("%s: provider type = %s, want %s", c.provider, got, c.wantType)
		}
	}
}

func typeName(v interface{}) string {
	switch v.(type) {
	case *cloudflareProvider:
		return "*certmanager.cloudflareProvider"
	case *aliyunProvider:
		return "*certmanager.aliyunProvider"
	case *dnspodProvider:
		return "*certmanager.dnspodProvider"
	}
	return "unknown"
}
