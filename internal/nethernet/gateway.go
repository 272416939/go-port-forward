package nethernet

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
)

// Gateway handles NetherNet HTTP/HTTPS signaling endpoints:
// - GET /v1/join - returns MOTD (server list entry)
// - POST /v1/join/:networkID - SDP negotiation
type Gateway struct {
	rule       *models.ForwardRule
	listenAddr string
	targetAddr string
	targetIP   net.IP
	targetPort int
	publicIP   string
	dataPort   int
	mux        *Multiplexer
	server     *http.Server
	tlsConfig  *tls.Config

	// dualListener 是双模式（同端口 HTTP+HTTPS）自持的监听器。必须由 Stop
	// 关闭——它是裸 net.Listener，不走 http.Server.Shutdown 的管辖，不关
	// 就等于规则停了端口还占着，重启必然 bind 失败。
	dualListener net.Listener
	mu           sync.RWMutex
	stopOnce     sync.Once
}

// NewGateway creates a NetherNet gateway for the given rule.
//
// publicIP 是写进 SDP candidate 的公网地址（玩家连这个地址）。
func NewGateway(rule *models.ForwardRule, mux *Multiplexer, publicIP string) (*Gateway, error) {
	if !rule.NetherNet {
		return nil, fmt.Errorf("rule is not NetherNet mode")
	}
	if !rule.Transparent {
		return nil, fmt.Errorf("NetherNet requires transparent mode")
	}

	// 透明规则的目标地址与端口是**两个独立字段**：TargetAddr 只是 IP（访问码的
	// 隧道地址，如 10.66.0.3），端口在 TargetPort。不能用 SplitHostPort 解析
	// TargetAddr——那里本来就不带端口，硬解析只会得到 "missing port" 而让整条
	// 规则进错误态（症状是多路复用器起来了、网关从没启动）。
	targetIP := net.ParseIP(strings.TrimSpace(rule.TargetAddr))
	if targetIP == nil {
		return nil, fmt.Errorf("目标地址必须是 IP（访问码的隧道地址），得到 %q | target must be the access code's tunnel IP, got %q", rule.TargetAddr, rule.TargetAddr)
	}
	if rule.TargetPort < 1 || rule.TargetPort > 65535 {
		return nil, fmt.Errorf("目标端口超出范围（1-65535）：%d | target port out of range: %d", rule.TargetPort, rule.TargetPort)
	}

	// Determine signaling port and data port
	signalPort := rule.ListenPort
	dataPort := rule.ListenPort + 1
	if rule.NetherNetTLS != nil {
		if rule.NetherNetTLS.SignalPort > 0 {
			signalPort = rule.NetherNetTLS.SignalPort
		}
		if rule.NetherNetTLS.DataPort > 0 {
			dataPort = rule.NetherNetTLS.DataPort
		}
	}

	listenAddr := fmt.Sprintf("%s:%d", rule.ListenAddr, signalPort)
	if rule.ListenAddr == "" {
		listenAddr = fmt.Sprintf(":%d", signalPort)
	}

	g := &Gateway{
		rule:       rule,
		listenAddr: listenAddr,
		targetAddr: net.JoinHostPort(targetIP.String(), strconv.Itoa(rule.TargetPort)),
		targetIP:   targetIP,
		targetPort: rule.TargetPort,
		publicIP:   publicIP,
		dataPort:   dataPort,
		mux:        mux,
	}

	// Setup TLS if enabled. 证书是用户粘贴的 PEM 内容（每人一套），不是服务器
	// 路径——这里直接 X509KeyPair 解析内容。
	if rule.NetherNetTLS != nil && rule.NetherNetTLS.Enabled {
		cert, err := tls.X509KeyPair([]byte(rule.NetherNetTLS.CertPEM), []byte(rule.NetherNetTLS.KeyPEM))
		if err != nil {
			return nil, fmt.Errorf("证书与私钥无法配对（请检查粘贴内容）| certificate/key pair invalid: %w", err)
		}
		
		g.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	// Setup HTTP handlers
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/v1/join", g.handleMOTD)
	mux2.HandleFunc("/v1/join/", g.handleJoin)

	g.server = &http.Server{
		Addr:         listenAddr,
		Handler:      mux2,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return g, nil
}


// Start starts the gateway server.
//
// 三种监听形态，都由规则的同一个监听端口承载：
//   - TLS + dual ：同端口嗅探首字节，TLS 走 HTTPS、其余走 HTTP（推荐）
//   - TLS only   ：同端口只收 HTTPS（安卓客户端将无法加入）
//   - 无 TLS     ：同端口只收 HTTP（iOS 客户端将无法加入）
func (g *Gateway) Start() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	dual := g.tlsConfig != nil && g.rule.NetherNetTLS != nil && g.rule.NetherNetTLS.Dual
	logger.S.Infow("starting NetherNet gateway",
		"rule", g.rule.Name,
		"listen", g.listenAddr,
		"target", g.targetAddr,
		"tls", g.tlsConfig != nil,
		"dual", dual,
	)

	if dual {
		listener, err := net.Listen("tcp", g.listenAddr)
		if err != nil {
			return fmt.Errorf("监听信令端口失败 | failed to listen on %s: %w", g.listenAddr, err)
		}
		g.dualListener = listener
		go g.acceptLoop(listener)
		return nil
	}

	// 单协议形态交给 http.Server：Stop 时 Shutdown 能把它一起收干净。
	if g.tlsConfig != nil {
		g.server.TLSConfig = g.tlsConfig
		go func() {
			if err := g.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				logger.S.Errorw("NetherNet 信令网关（HTTPS）异常 | NetherNet HTTPS gateway error", "err", err)
			}
		}()
		return nil
	}

	go func() {
		if err := g.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.S.Errorw("NetherNet 信令网关（HTTP）异常 | NetherNet HTTP gateway error", "err", err)
		}
	}()

	return nil
}

// acceptLoop 双模式的接受循环：每个连接先嗅探首字节再决定走哪条协议。
func (g *Gateway) acceptLoop(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return // 监听器已关闭（Stop）或 accept 失败：退出即可
		}
		go g.handleDualConn(conn)
	}
}

// handleDualConn 在同一连接上判断协议：TLS ClientHello 首字节是 0x16。
//
// ⚠️ 连接的生命周期完全交给 http.Serve（它serve 完会自己 Close）。这里绝不能
// defer conn.Close()：http.Serve 在 Accept 返回 EOF 后就返回，而真正的 serve 在
// 它 spawn 的 goroutine 里——外层一关就把还在读写的连接掐了，客户端看到的是
// 「连接被强制关闭」。
func (g *Gateway) handleDualConn(conn net.Conn) {
	buf := make([]byte, 1)
	// 只等首字节：连上但不发数据的扫描器不该占住一个 goroutine。
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	wrapped := &prefixConn{Conn: conn, prefix: buf[:n]}
	if buf[0] != 0x16 {
		// 明文 HTTP（安卓客户端）
		_ = http.Serve(&singleConnListener{conn: wrapped}, g.server.Handler)
		return
	}

	tlsConn := tls.Server(wrapped, g.tlsConfig)
	// 握手失败（例如客户端把明文打到了只期望 TLS 的端口）自己收尾。
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return
	}
	_ = http.Serve(&singleConnListener{conn: tlsConn}, g.server.Handler)
}

// prefixConn wraps a connection and replays a prefix
type prefixConn struct {
	net.Conn
	prefix []byte
	offset int
}

func (c *prefixConn) Read(b []byte) (n int, err error) {
	if c.offset < len(c.prefix) {
		n = copy(b, c.prefix[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.Conn.Read(b)
}

// singleConnListener 把单条已建立的连接包装成 net.Listener，供 http.Serve 使用。
//
// ⚠️ Accept 第二次起必须返回 io.EOF。http.Serve 会在一个连接 serve 完后继续
// 调 Accept，若此时还把同一条连接交出去，它会被并发 serve 第二次——两个 reader
// 抢同一条 TLS 连接的字节，表现为客户端拿到 EOF 或乱码响应。
type singleConnListener struct {
	conn net.Conn
	done bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, io.EOF
	}
	l.done = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// Stop stops the gateway. 双模式的裸 listener 必须显式关闭，否则规则停了
// 端口还占着（重启必然 bind 失败）。
func (g *Gateway) Stop() error {
	var err error
	g.stopOnce.Do(func() {
		g.mu.Lock()
		if g.dualListener != nil {
			err = g.dualListener.Close()
			g.dualListener = nil
		}
		g.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if serr := g.server.Shutdown(ctx); serr != nil && err == nil {
			err = serr
		}
	})
	return err
}


// handleMOTD handles GET /v1/join - server list query
func (g *Gateway) handleMOTD(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Forward request to BDS
	client := &http.Client{Timeout: 5 * time.Second}
	targetURL := fmt.Sprintf("http://%s/v1/join", g.targetAddr)
	
	resp, err := client.Get(targetURL)
	if err != nil {
		logger.S.Warnw("failed to fetch MOTD from BDS", "err", err)
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	// Copy response
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleJoin handles POST /v1/join/:networkID - SDP negotiation
func (g *Gateway) handleJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract network ID from URL path
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/join/"), "/")
	if len(pathParts) == 0 || pathParts[0] == "" {
		http.Error(w, "Missing network ID", http.StatusBadRequest)
		return
	}
	networkID := pathParts[0]

	// Read SDP offer from client
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}

	// Forward SDP offer to BDS
	client := &http.Client{Timeout: 10 * time.Second}
	targetURL := fmt.Sprintf("http://%s/v1/join/%s", g.targetAddr, networkID)
	
	resp, err := client.Post(targetURL, r.Header.Get("Content-Type"), strings.NewReader(string(body)))
	if err != nil {
		logger.S.Warnw("failed to forward SDP to BDS", "err", err)
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	answerBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read BDS response", http.StatusInternalServerError)
		return
	}

	// Rewrite SDP answer (replace BDS internal address with public address)
	rewrittenAnswer := g.rewriteSDP(string(answerBody))

	// Register session with multiplexer
	ufrag := extractIceUfrag(rewrittenAnswer)
	if ufrag != "" {
		// 数据面必须转发到 BDS 在 SDP candidate 里 advertises 的数据端口，而不是
		// 我们转发 /v1/join 信令时用的 g.targetPort。BDS 的 WebRTC 数据面监听在
		// 它按连接 advertises 的端口（19132–19139 池），与信令端口是两回事；转发到
		// 信令端口会让 BDS 的 ICE 栈一个包都收不到，玩家拿到 InitialConnection-115。
		forwardPort := g.backendDataPort(string(answerBody))
		g.mux.RegisterSession(ufrag, g.targetIP, forwardPort)
		// 打到 info：数据面其余事件都是 debug，info 级下玩家加入完全不落日志，
		// 排障时无法判断 STUN 有没有到中转机。按连接（低频）记录，留下 data_port。
		logger.S.Infow("registered NetherNet session",
			"ufrag", ufrag,
			"target", g.targetAddr,
			"data_port", forwardPort,
		)
	}

	// Send rewritten answer back to client
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	w.Write([]byte(rewrittenAnswer))
}

// rewriteSDP rewrites SDP answer to replace internal candidate with public address
func (g *Gateway) rewriteSDP(sdp string) string {
	lines := strings.Split(sdp, "\n")
	var result []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Replace connection line: c=IN IP4 <internal_ip>
		if strings.HasPrefix(line, "c=IN IP4 ") {
			result = append(result, fmt.Sprintf("c=IN IP4 %s", g.publicIP))
			continue
		}

		// Rewrite m= line port. BDS puts its real data-plane port here (not the
		// discard placeholder 9); keep it in sync with the rewritten candidate so
		// the client's default candidate and explicit candidate agree on the port.
		if strings.HasPrefix(line, "m=") {
			result = append(result, rewriteMLinePort(line, g.dataPort))
			continue
		}

		// Replace candidate line: a=candidate:... <internal_ip> <port> ...
		if strings.HasPrefix(line, "a=candidate:") {
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				// parts[4] is IP, parts[5] is port
				parts[4] = g.publicIP
				parts[5] = fmt.Sprintf("%d", g.dataPort)
				result = append(result, strings.Join(parts, " "))
				continue
			}
		}

		result = append(result, line)
	}

	return strings.Join(result, "\n")
}

// backendDataPort 返回 BDS WebRTC 数据面真正监听的 UDP 端口，取自 SDP answer 的
// host candidate。找不到可用的 UDP host candidate 时退化为 g.targetPort（信令端口）。
//
// BDS 把数据面端口写进 candidate，且该端口取自一个池（19132–19139），与我们转发
// /v1/join 信令用的端口不是一回事。从 candidate 读它——而不是想当然用信令端口——
// 才能让多路复用器把玩家数据发到 BDS 上正确的 socket。
func (g *Gateway) backendDataPort(sdp string) int {
	fallback := 0
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "a=candidate:") {
			continue
		}
		fields := strings.Fields(line)
		// a=candidate:{foundation} {component} {proto} {priority} {ip} {port} typ {type} ...
		if len(fields) < 8 || !strings.EqualFold(fields[2], "udp") {
			continue
		}
		if fields[6] != "typ" || !strings.EqualFold(fields[7], "host") {
			continue
		}
		port, err := strconv.Atoi(fields[5])
		if err != nil || port == 0 {
			continue
		}
		// 优先非回环 host candidate；把首个回环 candidate 留作兜底（代理与 BDS
		// 同机的场景只有回环候选）。
		if ip := net.ParseIP(fields[4]); ip != nil && !ip.IsLoopback() {
			return port
		}
		if fallback == 0 {
			fallback = port
		}
	}
	if fallback != 0 {
		return fallback
	}
	logger.S.Warnw("BDS SDP answer 没有可用的 UDP host candidate，数据面退化为信令端口（玩家可能连不上）| no UDP host candidate in BDS answer; falling back to the signaling port for the data plane",
		"target", g.targetAddr, "fallback_port", g.targetPort)
	return g.targetPort
}

// rewriteMLinePort 重写 m= 行的端口字段，其余保持不变。
// 行格式：m=application 19137 UDP/DTLS/SCTP webrtc-datachannel
func rewriteMLinePort(line string, port int) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return line
	}
	fields[1] = strconv.Itoa(port)
	return strings.Join(fields, " ")
}

// extractIceUfrag extracts ice-ufrag from SDP
func extractIceUfrag(sdp string) string {
	lines := strings.Split(sdp, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "a=ice-ufrag:") {
			return strings.TrimPrefix(line, "a=ice-ufrag:")
		}
	}
	return ""
}
