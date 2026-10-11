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
	"sync/atomic"
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
m=application 19137 UDP/DTLS/SCTP webrtc-datachannel
a=ice-ufrag:test123
a=ice-pwd:testpassword
a=candidate:1 1 UDP 2130706431 10.66.0.3 19137 typ host`

	expected := `v=0
o=- 1234567890 1234567890 IN IP4 10.66.0.3
s=-
c=IN IP4 1.2.3.4
t=0 0
m=application 19131 UDP/DTLS/SCTP webrtc-datachannel
a=ice-ufrag:test123
a=ice-pwd:testpassword
a=candidate:1 1 UDP 2130706431 1.2.3.4 19131 typ host`

	output := g.rewriteSDP(input)

	if output != expected {
		t.Errorf("SDP rewrite failed\nExpected:\n%s\n\nGot:\n%s", expected, output)
	}
}

// rewriteSDP 必须保留 BDS answer 的行尾（CRLF）。基岩版 NetherNet 客户端对 SDP
// 行尾敏感：把 CRLF 改成 LF 会让客户端解析不到 candidate、静默不进 ICE（症状=信令通
// 但数据面一个 STUN 都收不到）。锁住：CRLF 输入 → CRLF 输出，且 c=/m=/candidate 仍
// 被重写成公网地址。
func TestRewriteSDPPreservesCRLF(t *testing.T) {
	g := &Gateway{publicIP: "1.2.3.4", dataPort: 19131}

	crlf := "v=0\r\n" +
		"o=- 0 0 IN IP4 10.66.0.3\r\n" +
		"c=IN IP4 10.66.0.3\r\n" +
		"m=application 19137 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
		"a=ice-ufrag:test123\r\n" +
		"a=candidate:1 1 UDP 2130706431 10.66.0.3 19137 typ host\r\n"

	out := g.rewriteSDP(crlf)

	if !strings.Contains(out, "\r\n") {
		t.Fatalf("CRLF 未保留，客户端 SDP 解析器可能拒绝该 answer：\n%q", out)
	}
	// 注意：o= 行的 origin 地址是会话元数据、不用于建连，NetherProxy 同样不改它，
	// 这里只校验真正决定连接目标的 c=/m=/candidate 三处被重写成公网地址。
	for _, want := range []string{
		"c=IN IP4 1.2.3.4\r\n",
		"m=application 19131 UDP/DTLS/SCTP webrtc-datachannel\r\n",
		"a=candidate:1 1 UDP 2130706431 1.2.3.4 19131 typ host\r\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("重写后的 answer 缺少 %q：\n%s", want, out)
		}
	}
}

// BDS answer 常带多条 host candidate（回环/内网/IPv6）。重写必须折叠成一条公网候选：
// 多条重复候选、以及把 IPv6 候选改成 IPv4 地址的畸形候选会让 Bedrock 客户端 ICE 解析
// 混乱、静默不发 STUN。锁住：只保留一条、指向公网地址，内网/IPv6 地址不残留。
func TestRewriteSDPCollapsesCandidatesToOne(t *testing.T) {
	g := &Gateway{publicIP: "120.25.168.24", dataPort: 39042}

	answer := "v=0\r\n" +
		"m=application 39042 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
		"c=IN IP4 10.66.0.3\r\n" +
		"a=candidate:435801835 1 udp 2122260223 10.66.0.3 39042 typ host generation 0 network-id 1 network-cost 50\r\n" +
		"a=candidate:855127124 1 udp 2121998079 172.16.0.88 39042 typ host generation 0 network-id 2\r\n" +
		"a=candidate:4033773935 1 udp 2122197247 2408:8360:e601:e581:9b5c:96bc:af5d:6b25 39042 typ host generation 0 network-id 3\r\n" +
		"a=ice-ufrag:bDQt\r\n"

	out := g.rewriteSDP(answer)

	if n := strings.Count(out, "a=candidate:"); n != 1 {
		t.Fatalf("candidate 数量 = %d, want 1（折叠成一条公网候选）:\n%s", n, out)
	}
	for _, bad := range []string{"10.66.0.3", "172.16.0.88", "2408:8360"} {
		if strings.Contains(out, bad) {
			t.Errorf("重写后仍残留内网/IPv6 地址 %q:\n%s", bad, out)
		}
	}
	want := "a=candidate:435801835 1 udp 2122260223 120.25.168.24 39042 typ host generation 0 network-id 1 network-cost 50\r\n"
	if !strings.Contains(out, want) {
		t.Errorf("保留的候选不是模板候选重写成公网地址:\nwant %q\ngot:\n%s", want, out)
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

// backendDataPort 必须从 candidate 里读 BDS 数据面端口，而不是信令端口。
func TestBackendDataPort(t *testing.T) {
	g := &Gateway{targetPort: 19132} // 信令端口

	// 非回环 host candidate → 用 candidate 端口 19137，不是信令端口 19132。
	sdp := "v=0\n" +
		"a=ice-ufrag:x\n" +
		"a=candidate:1 1 UDP 2122260223 10.66.0.3 19137 typ host\n"
	if got := g.backendDataPort(sdp); got != 19137 {
		t.Errorf("backendDataPort = %d, want 19137 (candidate), not signaling port 19132", got)
	}

	// 只有回环 candidate（代理与 BDS 同机）也照样可用。
	loop := "a=candidate:1 1 UDP 2122260223 127.0.0.1 19139 typ host\n"
	if got := g.backendDataPort(loop); got != 19139 {
		t.Errorf("backendDataPort loopback = %d, want 19139", got)
	}

	// 非 UDP / 非 host 的 candidate 应被忽略，回退到信令端口。
	bad := "a=candidate:1 1 TCP 2122260223 10.66.0.3 19137 typ host\n" +
		"a=candidate:2 1 UDP 2122260223 10.66.0.3 19138 typ srflx raddr 1.2.3.4 rport 9\n"
	if got := g.backendDataPort(bad); got != 19132 {
		t.Errorf("backendDataPort with no usable candidate = %d, want fallback 19132", got)
	}
}

// 数据面必须注册成 BDS 在 candidate 里 advertises 的数据端口，而不是信令端口。
// 这是打到 RegisterSession 调用点的回归测试：转发错端口时 BDS 的 ICE 栈收不到
// STUN，玩家拿到 InitialConnection-115，而纯谓词单测探不到这种调用点回归。
func TestHandleJoinRegistersBackendDataPort(t *testing.T) {
	// 假 BDS：POST /v1/join/:id 返回 candidate 指向数据端口 19137 的 SDP answer。
	bds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/sdp")
		_, _ = w.Write([]byte("v=0\r\n" +
			"o=- 0 0 IN IP4 10.66.0.3\r\n" +
			"s=-\r\n" +
			"c=IN IP4 10.66.0.3\r\n" +
			"t=0 0\r\n" +
			"m=application 19137 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
			"a=ice-ufrag:srvfrag1234\r\n" +
			"a=ice-pwd:abcdef0123456789\r\n" +
			"a=candidate:1 1 UDP 2122260223 10.66.0.3 19137 typ host\r\n"))
	}))
	defer bds.Close()
	bdsHost, bdsPortStr, _ := net.SplitHostPort(bds.Listener.Addr().String())
	bdsPort, _ := strconv.Atoi(bdsPortStr)

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	rule := &models.ForwardRule{
		Name: "nn-data", NetherNet: true, Transparent: true,
		ListenAddr: "127.0.0.1", ListenPort: port,
		TargetAddr: bdsHost, TargetPort: bdsPort,
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

	resp, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d/v1/join/net1", port),
		"application/sdp", strings.NewReader("v=0\r\na=ice-ufrag:clifrag\r\n"))
	if err != nil {
		t.Fatalf("POST join: %v", err)
	}
	defer resp.Body.Close()

	mux.mu.RLock()
	sess, ok := mux.sessions["srvfrag1234"]
	mux.mu.RUnlock()
	if !ok {
		t.Fatal("session not registered by ufrag")
	}
	if sess.targetPort != 19137 {
		t.Fatalf("data-plane target port = %d, want 19137 (from SDP candidate), signaling port was %d",
			sess.targetPort, bdsPort)
	}
	if !sess.targetIP.Equal(net.ParseIP(bdsHost)) {
		t.Fatalf("target IP = %s, want %s (tunnel IP, not the candidate IP)", sess.targetIP, bdsHost)
	}

	// 客户端必须拿到完整、未被 Content-Length 截断的重写 answer。改写后 body 长度与
	// BDS 原始不一致，必须删掉透传的 Content-Length，否则客户端按旧长度读、answer 被
	// 截断/挂起，setRemoteDescription 失败、静默不进 ICE（数据面零 STUN）。
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "203.0.113.9") {
		t.Fatalf("重写未生效（answer 里没有公网 IP 203.0.113.9）：\n%s", bodyStr)
	}
	// candidate 是 answer 的最后一行；若 Content-Length 未删导致 body 被截断，结尾的
	// "typ host" 会被切掉。
	if !strings.HasSuffix(strings.TrimRight(bodyStr, "\r\n"), "typ host") {
		t.Fatalf("客户端拿到的 answer 不完整（疑似 Content-Length 未删导致截断）：\n%s", bodyStr)
	}
}

// TestGatewayCertResolverHotReload 锁证书管理的核心收益：规则只引用 cert_id，
// 证书续签/更新后**不需要重启网关**——下一个进来的 TLS 连接立即拿到新证书。
// 这是 certmanager.Service 续签后热重载的数据面落点。
func TestGatewayCertResolverHotReload(t *testing.T) {
	certPEM1, keyPEM1 := testKeyPair(t)
	certPEM2, keyPEM2 := testKeyPair(t)

	pair1, err := tls.X509KeyPair([]byte(certPEM1), []byte(keyPEM1))
	if err != nil {
		t.Fatalf("X509KeyPair v1: %v", err)
	}
	pair2, err := tls.X509KeyPair([]byte(certPEM2), []byte(keyPEM2))
	if err != nil {
		t.Fatalf("X509KeyPair v2: %v", err)
	}
	leaf1, _ := x509.ParseCertificate(pair1.Certificate[0])
	leaf2, _ := x509.ParseCertificate(pair2.Certificate[0])
	// testKeyPair 的序列号是固定的 1，改用公钥指纹区分两张证书
	if leaf1.PublicKey.(*ecdsa.PublicKey).Equal(leaf2.PublicKey.(*ecdsa.PublicKey)) {
		t.Fatal("两张测试证书公钥相同，无法区分")
	}

	// 可变的解析器：模拟 certmanager 续签后缓存被替换（同一 certID → 不同证书）
	var current atomic.Value // holds tls.Certificate
	current.Store(pair1)
	resolve := func(certID string) (*tls.Certificate, error) {
		if certID != "cert-x" {
			return nil, fmt.Errorf("unknown cert id %q", certID)
		}
		c := current.Load().(tls.Certificate)
		return &c, nil
	}

	rule := &models.ForwardRule{
		Name: "nn-cert", NetherNet: true, Transparent: true,
		ListenAddr: "127.0.0.1", ListenPort: 0,
		TargetAddr: "127.0.0.1", TargetPort: 19132,
		NetherNetTLS: &models.NetherNetTLS{
			Enabled: true, Dual: true, CertID: "cert-x",
			CertPEM: certPEM1, KeyPEM: keyPEM1,
		},
	}
	mux := NewMultiplexer(":0", nil)
	gw, err := NewGatewayWithResolver(rule, mux, "203.0.113.9", resolve)
	if err != nil {
		t.Fatalf("NewGatewayWithResolver: %v", err)
	}
	// 手动监听以拿到真实端口（Start 用的是 g.listenAddr，这里换成探测端口）
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	rule.ListenPort = port
	gw.listenAddr = fmt.Sprintf("127.0.0.1:%d", port)
	if err := gw.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer gw.Stop()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			// 每次请求都必须新建连接做完整 TLS 握手，否则第二次会复用 keep-alive
			// 连接、根本不会触发 GetCertificate 回调（测不出热重载）。
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		},
	}

	fetchLeaf := func() *x509.Certificate {
		t.Helper()
		resp, rerr := client.Get(fmt.Sprintf("https://127.0.0.1:%d/v1/join", port))
		if rerr != nil {
			t.Fatalf("GET https: %v", rerr)
		}
		defer resp.Body.Close()
		if len(resp.TLS.PeerCertificates) == 0 {
			t.Fatal("no peer certificates in TLS handshake")
		}
		return resp.TLS.PeerCertificates[0]
	}

	// 1. 首个连接拿到的是初始证书（CertID 对应的解析结果，而非内联 PEM）
	got1 := fetchLeaf()
	if !got1.PublicKey.(*ecdsa.PublicKey).Equal(leaf1.PublicKey.(*ecdsa.PublicKey)) {
		t.Fatal("first handshake served the wrong certificate (expected v1)")
	}

	// 2. 证书续签：替换解析器返回值，**不重启网关**
	current.Store(pair2)

	// 3. 下一个连接立即拿到新证书（GetCertificate 回调路径，非 Certificates 静态切片）
	got2 := fetchLeaf()
	if !got2.PublicKey.(*ecdsa.PublicKey).Equal(leaf2.PublicKey.(*ecdsa.PublicKey)) {
		t.Fatal("hot reload failed: second handshake still served the old certificate")
	}
}


