package certmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
)

func generateTestCert(t *testing.T, cn string, dnsNames []string, validDays int) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestCertificateUploadAndHotReloadCache(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	svc := New(store)
	certPEM1, keyPEM1 := generateTestCert(t, "mc1.example.com", []string{"mc1.example.com", "*.mc1.example.com"}, 90)

	cert, err := svc.Upload(&models.User{ID: "u1"}, &models.UploadCertificateRequest{
		Name:    "mc-cert",
		CertPEM: certPEM1,
		KeyPEM:  keyPEM1,
	})
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}
	if cert.SubjectCN != "mc1.example.com" || len(cert.Domains) != 2 {
		t.Fatalf("unexpected parsed cert metadata: %+v", cert)
	}

	tlsCert1, err := svc.GetTLSCertificate(cert.ID)
	if err != nil {
		t.Fatalf("GetTLSCertificate: %v", err)
	}
	leaf1, _ := x509.ParseCertificate(tlsCert1.Certificate[0])
	if leaf1.Subject.CommonName != "mc1.example.com" {
		t.Fatalf("leaf1 CN = %s, want mc1.example.com", leaf1.Subject.CommonName)
	}

	// 更新证书内容（模拟续期替换），验证 GetTLSCertificate 内存缓存热刷新
	certPEM2, keyPEM2 := generateTestCert(t, "mc2.example.com", []string{"mc2.example.com"}, 180)
	_, err = svc.Update(cert.ID, &models.UpdateCertificateRequest{
		CertPEM: &certPEM2,
		KeyPEM:  &keyPEM2,
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	tlsCert2, err := svc.GetTLSCertificate(cert.ID)
	if err != nil {
		t.Fatalf("GetTLSCertificate after update: %v", err)
	}
	leaf2, _ := x509.ParseCertificate(tlsCert2.Certificate[0])
	if leaf2.Subject.CommonName != "mc2.example.com" {
		t.Fatalf("hot reload failed: leaf2 CN = %s, want mc2.example.com", leaf2.Subject.CommonName)
	}
}

func TestSplitDomainAndRR(t *testing.T) {
	root, rr, err := splitDomainAndRR("_acme-challenge.play.example.com.")
	if err != nil || root != "example.com" || rr != "_acme-challenge.play" {
		t.Fatalf("got (%q, %q, %v), want (example.com, _acme-challenge.play, nil)", root, rr, err)
	}

	root2, rr2, err := splitDomainAndRR("_acme-challenge.mc.server.com.cn")
	if err != nil || root2 != "server.com.cn" || rr2 != "_acme-challenge.mc" {
		t.Fatalf("got (%q, %q, %v), want (server.com.cn, _acme-challenge.mc, nil)", root2, rr2, err)
	}
}

func TestCloudflareDNSProviderPresentAndCleanup(t *testing.T) {
	var created atomic.Bool
	var deleted atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-cf-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/zones"):
			if r.URL.Query().Get("name") == "example.com" {
				_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zone-123"}]}`))
			} else {
				_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
			}
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-123/dns_records":
			created.Store(true)
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"rec-456"}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/zones/zone-123/dns_records/rec-456":
			deleted.Store(true)
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"rec-456"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	prov, err := newDNSProvider(models.ACMEProviderCloudflare, map[string]string{
		"api_token": "test-cf-token",
		"base_url":  srv.URL,
	}, srv.Client())
	if err != nil {
		t.Fatalf("newDNSProvider: %v", err)
	}

	cleanup, err := prov.Present(context.Background(), "_acme-challenge.mc.example.com", "challenge-token-val")
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if !created.Load() {
		t.Fatal("expected TXT record to be created")
	}
	cleanup()
	if !deleted.Load() {
		t.Fatal("expected TXT record to be deleted on cleanup")
	}
}


// TestInjectGlobalACMEDefaults 验证：
// 当全局 LiteSSL ACME 平台账号就绪且开放给普通租户时，租户申请证书自动继承 LiteSSL EAB 凭据与官方目录，
// 而验证方式（如 Manual DNS 或填写自己的 DNS Token）仍由租户自主设置。
func TestInjectGlobalACMEDefaults(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	svc := New(store)

	// 1. 管理员保存全局 LiteSSL 账号
	enabled := true
	allowUser := true
	dir := "https://acme.freessl.cn/directory"
	kid := "global-eab-kid"
	hmac := "global-eab-hmac"
	_, err = svc.UpdateGlobalACMEConfig(&models.UpdateGlobalACMEConfigRequest{
		Enabled:        &enabled,
		AllowUserApply: &allowUser,
		DirectoryURL:   &dir,
		EABKID:         &kid,
		EABHMACKey:     &hmac,
	})
	if err != nil {
		t.Fatalf("UpdateGlobalACMEConfig: %v", err)
	}

	// 2. 普通租户发起申请请求：自主选择 Cloudflare DNS 验证，自带自己的 DNS Token，但无需填写 EAB
	userReq := &models.ApplyACMERequest{
		Name:        "tenant-cert",
		Domains:     []string{"tenant.example.com"},
		Provider:    models.ACMEProviderLiteSSLCloudflare,
		Credentials: map[string]string{"api_token": "user-cf-token"},
	}
	user := &models.User{ID: "user-1", Role: models.RoleUser}

	if err := svc.injectGlobalACME(user, userReq); err != nil {
		t.Fatalf("injectGlobalACME failed: %v", err)
	}

	if userReq.DirectoryURL != dir {
		t.Fatalf("expected injected dir %s, got %s", dir, userReq.DirectoryURL)
	}
	if userReq.Credentials["eab_kid"] != kid || userReq.Credentials["eab_hmac_key"] != hmac {
		t.Fatalf("expected injected EAB credentials, got %+v", userReq.Credentials)
	}
	// 租户自身的 DNS 验证凭据保留
	if userReq.Credentials["api_token"] != "user-cf-token" {
		t.Fatalf("user dns credentials should remain intact, got %+v", userReq.Credentials)
	}

	// 3. 校验通过（无需租户输入 EAB）
	if err := models.ValidateApplyACMERequest(userReq); err != nil {
		t.Fatalf("request after global injection must pass validation: %v", err)
	}
}
// TestEABAccountKeyReuseAndPersistenceAcrossDeletions 验证：
// 1. 同一 EAB KID 绑定账户私钥后，持久化到存储层；
// 2. 多次申请时自动复用同一已绑定账户私钥（防止 CA 因每次生成新私钥而报 400 malformed）；
// 3. 即使删除了现有证书，同一 EAB KID 依然能找回之前绑定的私钥；
// 4. 管理员更换 EAB KID 时，旧账户私钥安全重置以防错绑。
func TestEABAccountKeyReuseAndPersistenceAcrossDeletions(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	svc := New(store)

	enabled := true
	allowUser := true
	dir := "https://acme.freessl.cn/directory"
	kid := "test-kid-123"
	hmac := "test-hmac-456"

	_, err = svc.UpdateGlobalACMEConfig(&models.UpdateGlobalACMEConfigRequest{
		Enabled:        &enabled,
		AllowUserApply: &allowUser,
		DirectoryURL:   &dir,
		EABKID:         &kid,
		EABHMACKey:     &hmac,
	})
	if err != nil {
		t.Fatalf("UpdateGlobalACMEConfig failed: %v", err)
	}

	eab := &EABCredentials{KID: kid, HMACKey: hmac}

	// 1. 首次查找，未绑定，返回空
	if key := svc.resolveAccountKey(dir, eab); key != "" {
		t.Fatalf("expected empty key initially, got %q", key)
	}

	// 2. 模拟首次注册成功，持久化绑定的账户密钥
	fakeAcctKey := "-----BEGIN EC PRIVATE KEY-----\nFAKEACCOUNTKEY123\n-----END EC PRIVATE KEY-----"
	svc.persistAccountKey(eab, fakeAcctKey)

	// 3. 再次查找，应能立即找回并复用同一私钥
	resolvedKey := svc.resolveAccountKey(dir, eab)
	if resolvedKey != fakeAcctKey {
		t.Fatalf("resolveAccountKey got %q, want %q", resolvedKey, fakeAcctKey)
	}

	// 4. 保存一张证书（携带此账户密钥）
	cert := &models.Certificate{
		ID:             "cert-1",
		Name:           "cert-1",
		SourceType:     models.CertSourceACME,
		CertPEM:        "fake-cert",
		KeyPEM:         "fake-key",
		DirectoryURL:   dir,
		ACMEAccountKey: fakeAcctKey,
		Credentials:    map[string]string{"eab_kid": kid},
	}
	if err := store.SaveCertificate(cert); err != nil {
		t.Fatalf("SaveCertificate failed: %v", err)
	}

	// 5. 用户删除了该证书
	if err := store.DeleteCertificate("cert-1"); err != nil {
		t.Fatalf("DeleteCertificate failed: %v", err)
	}

	// 6. 证书删除后，再次使用同一 EAB KID 申请，仍能找回绑定的私钥（彻底杜绝删证书后重申请报错）
	resolvedKeyAfterDelete := svc.resolveAccountKey(dir, eab)
	if resolvedKeyAfterDelete != fakeAcctKey {
		t.Fatalf("resolveAccountKey after cert deletion got %q, want %q", resolvedKeyAfterDelete, fakeAcctKey)
	}

	// 7. 管理员在全局配置中更换了新的 EAB KID，旧密钥应被安全清空以防冲突
	newKID := "different-kid-789"
	_, err = svc.UpdateGlobalACMEConfig(&models.UpdateGlobalACMEConfigRequest{
		EABKID: &newKID,
	})
	if err != nil {
		t.Fatalf("update with new KID failed: %v", err)
	}
	newEAB := &EABCredentials{KID: newKID, HMACKey: hmac}
	if key := svc.resolveAccountKey(dir, newEAB); key != "" {
		t.Fatalf("expected empty key for new KID, got %q", key)
	}
}

