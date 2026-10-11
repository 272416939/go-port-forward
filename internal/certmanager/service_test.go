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
