package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go-port-forward/internal/models"
)

func genSelfSignedPair(t *testing.T, cn string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// TestCertificateLifecycleAndRuleDropdownBinding 验证：
// 1. 用户上传证书到证书管理，响应中绝不泄露私钥（铁律 6），但持久化保留私钥；
// 2. 创建规则时仅通过 cert_id 下拉关联证书即可保存成功；
// 3. 多租户隔离：Bob 无法查看、删除或在他自己的规则中偷用 Alice 的证书；
// 4. 引用保护：证书仍被规则引用时禁止删除（409 Conflict），删除规则后允许删除证书。
func TestCertificateLifecycleAndRuleDropdownBinding(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	certPEM, keyPEM := genSelfSignedPair(t, "alice.mc.example.com")

	// 1. Alice 上传证书
	uploadReq := models.UploadCertificateRequest{
		Name:    "alice-ssl",
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}
	b, _ := json.Marshal(uploadReq)
	rec := httptest.NewRecorder()
	f.h.uploadCertificate(rec, postJSON("/api/certificates", string(b), f.alice))
	if rec.Code != http.StatusCreated {
		t.Fatalf("uploadCertificate status=%d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatalf("API 响应泄漏了私钥内容：%s", rec.Body.String())
	}

	var uploadResp struct {
		Data models.Certificate `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &uploadResp); err != nil {
		t.Fatal(err)
	}
	certID := uploadResp.Data.ID
	if certID == "" || uploadResp.Data.SubjectCN != "alice.mc.example.com" {
		t.Fatalf("unexpected uploaded cert: %+v", uploadResp.Data)
	}

	// 2. Bob 查询证书列表：看不到 Alice 的证书
	rec = httptest.NewRecorder()
	f.h.listCertificates(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/certificates", nil), f.bob))
	if strings.Contains(rec.Body.String(), certID) {
		t.Fatalf("Bob 不应看到 Alice 的证书：%s", rec.Body.String())
	}

	// 3. Bob 尝试在自己的规则里引用 Alice 的 cert_id：被 rule_guard 拦截（400）
	bobRuleBody := `{"name":"bob-steal","listen_addr":"0.0.0.0","listen_port":21010,"protocol":"udp","transparent":true,"nethernet":true,"target_addr":"` + f.bobCode.TunIP + `","target_port":19132,"enabled":false,"nethernet_tls":{"enabled":true,"dual":true,"cert_id":"` + certID + `"}}`
	rec = httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", bobRuleBody, f.bob))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Bob 偷用 Alice 证书应被拒，status=%d, body=%s", rec.Code, rec.Body.String())
	}

	// 4. Alice 在自己的 NetherNet 规则中通过 cert_id 选择该证书：保存成功（201）
	aliceRuleBody := `{"name":"alice-nethernet","listen_addr":"0.0.0.0","listen_port":20010,"protocol":"udp","transparent":true,"nethernet":true,"target_addr":"` + f.aliceCode.TunIP + `","target_port":19132,"enabled":false,"nethernet_tls":{"enabled":true,"dual":true,"cert_id":"` + certID + `"}}`
	rec = httptest.NewRecorder()
	f.h.createRule(rec, postJSON("/api/rules", aliceRuleBody, f.alice))
	if rec.Code != http.StatusCreated {
		t.Fatalf("Alice 使用自己的 cert_id 创建规则应成功，status=%d, body=%s", rec.Code, rec.Body.String())
	}
	var ruleResp struct {
		Data models.ForwardRule `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &ruleResp)
	ruleID := ruleResp.Data.ID

	// 5. Alice 试图删除仍在被规则使用的证书：返回 409 Conflict 并提示规则名
	delReq := asUser(httptest.NewRequest(http.MethodDelete, "/api/certificates/"+certID, nil), f.alice)
	delReq.SetPathValue("id", certID)
	rec = httptest.NewRecorder()
	f.h.deleteCertificate(rec, delReq)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "alice-nethernet") {
		t.Fatalf("删除被引用证书应返回 409 且含规则名，status=%d, body=%s", rec.Code, rec.Body.String())
	}

	// 6. 删除规则后再次删除证书：成功（200）
	delRuleReq := asUser(httptest.NewRequest(http.MethodDelete, "/api/rules/"+ruleID, nil), f.alice)
	delRuleReq.SetPathValue("id", ruleID)
	rec = httptest.NewRecorder()
	f.h.deleteRule(rec, delRuleReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("deleteRule status=%d, body=%s", rec.Code, rec.Body.String())
	}

	delReq2 := asUser(httptest.NewRequest(http.MethodDelete, "/api/certificates/"+certID, nil), f.alice)
	delReq2.SetPathValue("id", certID)
	rec = httptest.NewRecorder()
	f.h.deleteCertificate(rec, delReq2)
	if rec.Code != http.StatusOK {
		t.Fatalf("解除引用后删除证书应成功，status=%d, body=%s", rec.Code, rec.Body.String())
	}
}

// TestGlobalACMEConfigAndSecretMasking 验证：
// 1. 管理员更新平台全局 ACME 配置后，API 响应绝不回显 eab_hmac_key 或 credentials 敏感密钥；
// 2. 再次更新时若敏感密钥留空，自动保留原值（铁律 6）；
// 3. /api/settings 携带 acme_configured 状态徽章标识；
// 4. 普通用户调用 /api/certificates/acme/status 可获取就绪状态且不含任何敏感凭据。
func TestGlobalACMEConfigAndSecretMasking(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	// 1. 管理员保存全局 LiteSSL ACME 配置
	putBody := `{
		"enabled": true,
		"allow_user_apply": true,
		"directory_url": "https://acme.freessl.cn/directory",
		"eab_kid": "kid-global-123",
		"eab_hmac_key": "dGVzdC1zZWNyZXQtaG1hYy1rZXk="
	}`
	rec := httptest.NewRecorder()
	f.h.updateACMEConfig(rec, postJSON("/api/acme-config", putBody, f.admin))
	if rec.Code != http.StatusOK {
		t.Fatalf("updateACMEConfig status=%d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "dGVzdC1zZWNyZXQtaG1hYy1rZXk=") {
		t.Fatalf("API 响应泄露了全局 ACME 敏感密钥：%s", body)
	}

	// 2. 管理员读取全局 ACME 配置：同样不回显密钥，但布尔标志为 true
	rec = httptest.NewRecorder()
	f.h.getACMEConfig(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/acme-config", nil), f.admin))
	if rec.Code != http.StatusOK {
		t.Fatalf("getACMEConfig status=%d", rec.Code)
	}
	var viewResp struct {
		Data models.GlobalACMEView `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &viewResp); err != nil {
		t.Fatal(err)
	}
	if !viewResp.Data.Configured || !viewResp.Data.HasEABHMACKey {
		t.Fatalf("expected configured=true, has_eab_hmac_key=true, got %+v", viewResp.Data)
	}

	// 3. 二次更新时密钥留空 = 保留原值
	putBody2 := `{
		"enabled": true,
		"allow_user_apply": true,
		"eab_kid": "kid-global-456",
		"eab_hmac_key": ""
	}`
	rec = httptest.NewRecorder()
	f.h.updateACMEConfig(rec, postJSON("/api/acme-config", putBody2, f.admin))
	if rec.Code != http.StatusOK {
		t.Fatalf("second updateACMEConfig failed: %d %s", rec.Code, rec.Body.String())
	}
	rawCfg, err := f.store.GlobalACMEConfig()
	if err != nil {
		t.Fatal(err)
	}
	if rawCfg.EABKID != "kid-global-456" || rawCfg.EABHMACKey != "dGVzdC1zZWNyZXQtaG1hYy1rZXk=" {
		t.Fatalf("空密钥更新覆盖了已保存的敏感凭据: %+v", rawCfg)
	}

	// 4. /api/settings 包含 acme_configured: true
	rec = httptest.NewRecorder()
	f.h.getSettings(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/settings", nil), f.admin))
	if !strings.Contains(rec.Body.String(), `"acme_configured":true`) {
		t.Fatalf("expected acme_configured:true in /api/settings, got %s", rec.Body.String())
	}

	// 5. 普通租户 Alice 查询公共状态：看到已就绪，且无任何敏感信息
	rec = httptest.NewRecorder()
	f.h.getPublicACMEStatus(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/certificates/acme/status", nil), f.alice))
	if rec.Code != http.StatusOK {
		t.Fatalf("getPublicACMEStatus status=%d", rec.Code)
	}
	pubBody := rec.Body.String()
	if strings.Contains(pubBody, "kid-global") || strings.Contains(pubBody, "dGVzdC") {
		t.Fatalf("public status leaked credentials: %s", pubBody)
	}
	var pubResp struct {
		Data models.PublicACMEStatus `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &pubResp)
	if !pubResp.Data.Configured || !pubResp.Data.AllowUserApply || pubResp.Data.CA != "litessl" {
		t.Fatalf("unexpected public status: %+v", pubResp.Data)
	}
}
// TestDNSCredentialLifecycleAndSecretMasking 验证：
// 1. 创建 DNS 凭据后，API 响应脱敏（保留末4位打星号），绝不泄漏明文 Token / Secret；
// 2. 更新凭证时敏感密钥留空，自动保留原值（铁律 6）；
// 3. 多租户隔离：租户只能访问自己的凭据，越权返回 404；
// 4. 证书申请时传 dns_credential_id 可自动继承已存 DNS 凭据。
func TestDNSCredentialLifecycleAndSecretMasking(t *testing.T) {
	f := newTenantFixture(t)
	defer f.cleanup()

	// 1. Alice 创建 Cloudflare 凭据
	createBody := `{
		"name": "Alice-Cloudflare",
		"provider": "cloudflare",
		"credentials": {
			"api_token": "my-super-secret-cf-token-1234"
		}
	}`
	rec := httptest.NewRecorder()
	f.h.createDNSCredential(rec, postJSON("/api/dns-credentials", createBody, f.alice))
	if rec.Code != http.StatusOK {
		t.Fatalf("createDNSCredential status=%d, body=%s", rec.Code, rec.Body.String())
	}
	respStr := rec.Body.String()
	if strings.Contains(respStr, "my-super-secret-cf-token-1234") {
		t.Fatalf("API response leaked plaintext token: %s", respStr)
	}
	var createResp struct {
		Data models.DNSCredentialView `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createResp); err != nil {
		t.Fatal(err)
	}
	credID := createResp.Data.ID
	if credID == "" {
		t.Fatal("expected non-empty credential ID")
	}
	if createResp.Data.MaskedCredentials["api_token"] != "••••••••1234" {
		t.Fatalf("expected masked token, got %q", createResp.Data.MaskedCredentials["api_token"])
	}

	// 2. Alice 更新名称，Token 留空 -> 原值保留
	updateBody := `{
		"name": "Alice-Cloudflare-Renamed",
		"provider": "cloudflare",
		"credentials": {
			"api_token": ""
		}
	}`
	putReq := postJSON("/api/dns-credentials/"+credID, updateBody, f.alice)
	putReq.Method = http.MethodPut
	putReq.SetPathValue("id", credID)
	rec = httptest.NewRecorder()
	f.h.updateDNSCredential(rec, putReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("updateDNSCredential status=%d, body=%s", rec.Code, rec.Body.String())
	}
	rawCred, err := f.store.GetDNSCredential(credID)
	if err != nil {
		t.Fatal(err)
	}
	if rawCred.Name != "Alice-Cloudflare-Renamed" {
		t.Fatalf("expected updated name, got %s", rawCred.Name)
	}
	if rawCred.Credentials["api_token"] != "my-super-secret-cf-token-1234" {
		t.Fatalf("empty token in update wiped out original credential: %+v", rawCred.Credentials)
	}

	// 3. Bob 访问 Alice 的凭据 -> 404
	getReq := asUser(httptest.NewRequest(http.MethodGet, "/api/dns-credentials/"+credID, nil), f.bob)
	getReq.SetPathValue("id", credID)
	rec = httptest.NewRecorder()
	f.h.getDNSCredential(rec, getReq)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("Bob accessing Alice's credential expected 404, got %d", rec.Code)
	}

	// 4. Bob 列表不包含 Alice 的凭据
	rec = httptest.NewRecorder()
	f.h.listDNSCredentials(rec, asUser(httptest.NewRequest(http.MethodGet, "/api/dns-credentials", nil), f.bob))
	if rec.Code != http.StatusOK {
		t.Fatalf("Bob list status=%d", rec.Code)
	}
	var bobListResp struct {
		Data []models.DNSCredentialView `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &bobListResp)
	if len(bobListResp.Data) != 0 {
		t.Fatalf("Bob should see 0 credentials, got %d", len(bobListResp.Data))
	}

	// 5. Alice 申请证书时携带 dns_credential_id -> 后端注入成功
	applyReq := &models.ApplyACMERequest{
		Name:            "test-auto-cert",
		Domains:         []string{"test.example.com"},
		Provider:        models.ACMEProviderCloudflare,
		Email:           "alice@example.com",
		DNSCredentialID: credID,
	}
	if err := f.h.certs.InjectDNSCredential(f.alice, applyReq); err != nil {
		t.Fatalf("InjectDNSCredential failed: %v", err)
	}
	if applyReq.Credentials["api_token"] != "my-super-secret-cf-token-1234" {
		t.Fatalf("injected token mismatch: %+v", applyReq.Credentials)
	}

	// 6. Alice 删除凭据
	delReq := asUser(httptest.NewRequest(http.MethodDelete, "/api/dns-credentials/"+credID, nil), f.alice)
	delReq.SetPathValue("id", credID)
	rec = httptest.NewRecorder()
	f.h.deleteDNSCredential(rec, delReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status=%d", rec.Code)
	}
}

