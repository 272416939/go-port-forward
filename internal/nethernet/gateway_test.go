package nethernet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go.uber.org/zap"
)

func init() {
	// Initialize logger for tests
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()
}

// testKeyPair 生成一张自签名证书，模拟用户在面板里粘贴的 PEM 内容。
func testKeyPair(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mc.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"mc.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestRewriteSDP(t *testing.T) {
	g := &Gateway{
		publicIP: "1.2.3.4",
		dataPort: 19131,
	}

	input := `v=0
o=- 1234567890 1234567890 IN IP4 10.66.0.3
s=-
c=IN IP4 10.66.0.3
t=0 0
a=ice-ufrag:test123
a=ice-pwd:testpassword
a=candidate:1 1 UDP 2130706431 10.66.0.3 19132 typ host`

	expected := `v=0
o=- 1234567890 1234567890 IN IP4 10.66.0.3
s=-
c=IN IP4 1.2.3.4
t=0 0
a=ice-ufrag:test123
a=ice-pwd:testpassword
a=candidate:1 1 UDP 2130706431 1.2.3.4 19131 typ host`

	output := g.rewriteSDP(input)

	if output != expected {
		t.Errorf("SDP rewrite failed\nExpected:\n%s\n\nGot:\n%s", expected, output)
	}
}

func TestExtractIceUfrag(t *testing.T) {
	sdp := `v=0
a=ice-ufrag:test123
a=ice-pwd:testpassword`

	ufrag := extractIceUfrag(sdp)
	if ufrag != "test123" {
		t.Errorf("Expected ice-ufrag 'test123', got '%s'", ufrag)
	}

	// Test missing ufrag
	sdp2 := `v=0
a=ice-pwd:testpassword`
	ufrag2 := extractIceUfrag(sdp2)
	if ufrag2 != "" {
		t.Errorf("Expected empty ufrag, got '%s'", ufrag2)
	}
}

func TestNewGateway(t *testing.T) {
	tests := []struct {
		name      string
		rule      *models.ForwardRule
		expectErr bool
	}{
		{
			name: "valid nethernet rule",
			rule: &models.ForwardRule{
				NetherNet:   true,
				Transparent: true,
				ListenPort:  19130,
				TargetAddr:  "10.66.0.3",
				TargetPort:  19132,
			},
			expectErr: false,
		},
		{
			name: "not nethernet mode",
			rule: &models.ForwardRule{
				NetherNet:   false,
				Transparent: true,
				TargetAddr:  "10.66.0.3",
			},
			expectErr: true,
		},
		{
			name: "not transparent mode",
			rule: &models.ForwardRule{
				NetherNet:   true,
				Transparent: false,
				TargetAddr:  "10.66.0.3",
			},
			expectErr: true,
		},
		{
			name: "invalid target address",
			rule: &models.ForwardRule{
				NetherNet:   true,
				Transparent: true,
				TargetAddr:  "invalid",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := NewMultiplexer(":19131", nil)
			_, err := NewGateway(tt.rule, mux, "1.2.3.4")
			if (err != nil) != tt.expectErr {
				t.Errorf("NewGateway() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

// 粘贴的 PEM 内容必须真的能起一个可用的 HTTPS 服务端——这是「用户自带证书」
// 这条路的端到端验证：证书从内容来（不是服务器路径），信令能透传到后端 BDS。
func TestGatewayServesHTTPSFromPastedPEM(t *testing.T) {
	certPEM, keyPEM := testKeyPair(t)

	// 假 BDS：充当内网后端，验证信令真的被透传过去（而不是网关自己造响应）。
	bds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"motd":"from-bds"}`))
	}))
	defer bds.Close()
	bdsHost, bdsPortStr, _ := net.SplitHostPort(bds.Listener.Addr().String())
	var bdsPort int
	_, _ = fmt.Sscanf(bdsPortStr, "%d", &bdsPort)

	// 先探一个空闲端口：双模式用裸 listener，端口必须真实可用。
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe port: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	rule := &models.ForwardRule{
		Name:        "nn-tls",
		NetherNet:   true,
		Transparent: true,
		ListenAddr:  "127.0.0.1",
		ListenPort:  port,
		TargetAddr:  bdsHost,
		TargetPort:  bdsPort,
		NetherNetTLS: &models.NetherNetTLS{
			Enabled: true, Dual: true, CertPEM: certPEM, KeyPEM: keyPEM,
		},
	}

	mux := NewMultiplexer(":0", nil)
	gw, err := NewGateway(rule, mux, "203.0.113.9")
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	if err := gw.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer gw.Stop()

	// 自签名证书，客户端必须跳过校验；这里只验证「TLS 握手能完成 + HTTP 能通」。
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/v1/join", port))
	if err != nil {
		t.Fatalf("HTTPS GET through the gateway failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.TLS == nil {
		t.Fatal("response was not served over TLS")
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "from-bds") {
		t.Fatalf("MOTD was not passed through from the backend, got %q", body)
	}
}

// 双模式的另一半：同一个端口上的明文 HTTP 也要能通（安卓客户端走这条）。
// 少测这一半，「iOS 能进、安卓进不去」这类回归就不会被发现。
func TestGatewayDualModeServesPlainHTTPToo(t *testing.T) {
	certPEM, keyPEM := testKeyPair(t)

	bds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"motd":"plain-ok"}`))
	}))
	defer bds.Close()

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe port: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	bdsHost, bdsPortStr, err := net.SplitHostPort(bds.Listener.Addr().String())
	if err != nil {
		t.Fatalf("bds addr: %v", err)
	}
	bdsPort, err := strconv.Atoi(bdsPortStr)
	if err != nil {
		t.Fatalf("bds port: %v", err)
	}

	rule := &models.ForwardRule{
		Name: "nn-dual", NetherNet: true, Transparent: true,
		ListenAddr: "127.0.0.1", ListenPort: port,
		TargetAddr: bdsHost, TargetPort: bdsPort,
		NetherNetTLS: &models.NetherNetTLS{
			Enabled: true, Dual: true, CertPEM: certPEM, KeyPEM: keyPEM,
		},
	}

	gw, err := NewGateway(rule, NewMultiplexer(":0", nil), "203.0.113.9")
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	if err := gw.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer gw.Stop()

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(fmt.Sprintf("http://127.0.0.1:%d/v1/join", port))
	if err != nil {
		t.Fatalf("plain HTTP GET through dual-mode gateway failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "plain-ok") {
		t.Fatalf("plain HTTP MOTD not passed through, got %q", body)
	}
}

