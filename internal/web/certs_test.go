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
