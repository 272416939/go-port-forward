package models

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"go-port-forward/pkg/os/wsl"
)

// Protocol represents the network protocol for forwarding
type Protocol string

const (
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
	ProtocolBoth Protocol = "both"
)

// RuleStatus represents the runtime status of a forwarding rule
type RuleStatus string

const (
	StatusActive   RuleStatus = "active"
	StatusInactive RuleStatus = "inactive"
	StatusError    RuleStatus = "error"
)

// ForwardRule represents a single port forwarding rule
type ForwardRule struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	ID         string   `json:"id"`
	Name       string   `json:"name"`
	ListenAddr string   `json:"listen_addr"` // "" or "0.0.0.0" means all interfaces
	Protocol   Protocol `json:"protocol"`
	TargetAddr string   `json:"target_addr"`
	Comment    string   `json:"comment"`
	// UserID 是规则的归属用户（隧道用户 == Web 账号）。空值表示由管理员
	// 直接维护的共享规则，不受任何用户配额约束。
	UserID string `json:"user_id,omitempty"`

	// Runtime stats — not persisted
	Status        RuleStatus `json:"status"`
	ErrorMsg      string     `json:"error_msg,omitempty"` // reason the forwarder failed to start
	UserName      string     `json:"user_name,omitempty"` // 归属用户名（展示用，不持久化）
	ListenPort    int        `json:"listen_port"`
	TargetPort    int        `json:"target_port"`
	BytesIn       int64      `json:"bytes_in"`
	BytesOut      int64      `json:"bytes_out"`
	ActiveConns   int64      `json:"active_conns"`
	TotalConns    int64      `json:"total_conns"`
	Enabled       bool       `json:"enabled"`
	AddFirewall   bool       `json:"add_firewall"`   // auto-add firewall rule on creation
	ProxyProtocol bool       `json:"proxy_protocol"` // prepend PROXY Protocol v2 header with real client IP toward target
	Transparent   bool       `json:"transparent"`    // bind real client source IP toward target (Linux+root only; pair with tunnel)
	NetherNet     bool       `json:"nethernet"`      // NetherNet proxy mode: HTTP/HTTPS signaling + UDP multiplexer (requires transparent mode)
	// NetherNet TLS configuration (only when NetherNet=true)
	NetherNetTLS *NetherNetTLS `json:"nethernet_tls,omitempty"`
}

// NetherNetTLS holds TLS configuration for NetherNet proxy mode.
//
// 证书是**用户粘贴进来的 PEM 内容**，不是服务器上的路径：每个用户有自己的域名
// 与自己的证书，服务端只负责把内容加载成 keypair。存的是内容而非引用，所以
// bbolt 里会随规则一起持久化（rules.db 已是 0600）。
type NetherNetTLS struct {
	Enabled bool `json:"enabled"` // Enable TLS
	Dual    bool `json:"dual"`    // Dual mode: same port for HTTP (Android) + HTTPS (iOS)
	// CertID 引用证书管理中的证书 ID；为空时使用手动粘贴的 CertPEM 与 KeyPEM。
	CertID string `json:"cert_id,omitempty"`
	// CertPEM 是证书内容（PEM；含中间证书时贴整条链）。用户从面板粘贴。
	CertPEM string `json:"cert_pem,omitempty"`
	// KeyPEM 是配套私钥内容（PEM）。
	KeyPEM string `json:"key_pem,omitempty"`
	// SignalPort 留 0 表示用规则的监听端口。
	SignalPort int `json:"signal_port"`
	// DataPort 留 0 表示用规则的监听端口。
	DataPort int `json:"data_port"`
}

// NetherNetPorts 计算 NetherNet 规则实际使用的信令端口（TCP）与数据端口（UDP）。
func NetherNetPorts(listenPort int, tls *NetherNetTLS) (signalPort int, dataPort int) {
	signalPort = listenPort
	if tls != nil && tls.SignalPort > 0 {
		signalPort = tls.SignalPort
	}
	dataPort = listenPort
	if tls != nil && tls.DataPort > 0 {
		dataPort = tls.DataPort
	}
	return signalPort, dataPort
}

// MaxNetherNetPEMBytes 限制单份 PEM 的长度。完整证书链通常几 KB，128KB 足够
// 宽裕；上限的意义是防止把规则当成任意文件的存储位（bbolt 单值过大也会拖慢
// 每次规则列表查询）。
const MaxNetherNetPEMBytes = 128 << 10

// Validate checks the NetherNet TLS configuration.
//
// TLS 启用时证书与私钥不仅必填，还必须**真的能配成一对**——粘贴时最常见的错误
// 是证书与私钥不配对、或只贴了一半。在这里用 tls.X509KeyPair 试解析，用户保存
// 时就能看到明确错误；否则要等规则启动失败（进入 error 态）才发现，而那距离
// 粘贴已经过了好几步。
func (t *NetherNetTLS) Validate() error {
	if t == nil {
		return nil
	}
	if t.DataPort < 0 || t.DataPort > 65535 {
		return fmt.Errorf("NetherNet 数据端口超出范围（1-65535，0 表示默认）| data port out of range")
	}
	if t.SignalPort < 0 || t.SignalPort > 65535 {
		return fmt.Errorf("NetherNet 信令端口超出范围（1-65535，0 表示默认）| signal port out of range")
	}
	if !t.Enabled {
		return nil
	}
	if strings.TrimSpace(t.CertID) != "" {
		return nil
	}
	if strings.TrimSpace(t.CertPEM) == "" || strings.TrimSpace(t.KeyPEM) == "" {
		return fmt.Errorf("已启用 NetherNet TLS：请选择证书或粘贴证书内容与私钥内容 | NetherNet TLS enabled: select a certificate or paste both the certificate and the private key")
	}
	if len(t.CertPEM) > MaxNetherNetPEMBytes || len(t.KeyPEM) > MaxNetherNetPEMBytes {
		return fmt.Errorf("证书或私钥内容过大（上限 %d KB）| certificate or key content too large (limit %d KB)", MaxNetherNetPEMBytes>>10, MaxNetherNetPEMBytes>>10)
	}
	if _, err := tls.X509KeyPair([]byte(t.CertPEM), []byte(t.KeyPEM)); err != nil {
		return fmt.Errorf("证书与私钥无法配对：%v（请确认两者属于同一个证书，且私钥未被加密）| certificate and key do not form a pair: %v", err, err)
	}
	return nil
}

// Normalize trims surrounding whitespace on the pasted PEM blocks. 粘贴板内容
// 常带首尾空白与 CRLF；trim 后既让存储干净，也让 requiresForwarderRestart 的
// 比较稳定（否则只改空白也会被判定为「证书变了」而重启数据面）。
func (t *NetherNetTLS) Normalize() *NetherNetTLS {
	if t == nil {
		return nil
	}
	out := *t
	out.CertID = strings.TrimSpace(out.CertID)
	out.CertPEM = strings.TrimSpace(out.CertPEM)
	out.KeyPEM = strings.TrimSpace(out.KeyPEM)
	return &out
}

// ListenKey returns a unique key for the listen address+port+protocol combination
func (r *ForwardRule) ListenKey() string {
	return fmt.Sprintf("%s:%d/%s", r.ListenAddr, r.ListenPort, r.Protocol)
}

// Stats represents aggregated statistics across all rules
type Stats struct {
	TotalRules    int   `json:"total_rules"`
	EnabledRules  int   `json:"enabled_rules"`
	ActiveRules   int   `json:"active_rules"`
	TotalBytesIn  int64 `json:"total_bytes_in"`
	TotalBytesOut int64 `json:"total_bytes_out"`
	TotalConns    int64 `json:"total_conns"`
}

// RuleHealthSummary summarizes rule status counts for diagnostics.
type RuleHealthSummary struct {
	Active   int `json:"active"`
	Inactive int `json:"inactive"`
	Error    int `json:"error"`
}

// RuntimeDiagnostics captures process-level runtime signals.
type RuntimeDiagnostics struct {
	LastGC             time.Time `json:"last_gc,omitempty"`
	Goroutines         int       `json:"goroutines"`
	HeapAllocBytes     uint64    `json:"heap_alloc_bytes"`
	HeapInuseBytes     uint64    `json:"heap_inuse_bytes"`
	HeapObjects        uint64    `json:"heap_objects"`
	PauseTotalNs       uint64    `json:"pause_total_ns"`
	GoroutinesRunning  uint64    `json:"goroutines_running"`
	GoroutinesRunnable uint64    `json:"goroutines_runnable"`
	GoroutinesWaiting  uint64    `json:"goroutines_waiting"`
	GoroutinesSyscall  uint64    `json:"goroutines_syscall"`
	ThreadsLive        uint64    `json:"threads_live"`
	NumGC              uint32    `json:"num_gc"`
}

// PoolDiagnostics captures goroutine pool state.
type PoolDiagnostics struct {
	Running int `json:"running"`
	Free    int `json:"free"`
	Cap     int `json:"cap"`
}

// ProtocolTrafficDiagnostics captures protocol-specific forwarding activity.
type ProtocolTrafficDiagnostics struct {
	ConfiguredRules  int   `json:"configured_rules"`
	ActiveForwarders int   `json:"active_forwarders"`
	BytesIn          int64 `json:"bytes_in"`
	BytesOut         int64 `json:"bytes_out"`
	ActiveConns      int64 `json:"active_conns"`
	TotalConns       int64 `json:"total_conns"`
}

// ProtocolBreakdownDiagnostics groups protocol-specific diagnostics.
type ProtocolBreakdownDiagnostics struct {
	TCP ProtocolTrafficDiagnostics `json:"tcp"`
	UDP ProtocolTrafficDiagnostics `json:"udp"`
}

// RuleErrorSummary captures a single rule error for diagnostics display.
type RuleErrorSummary struct {
	UpdatedAt          time.Time  `json:"updated_at,omitempty"`
	LastErrorAt        time.Time  `json:"last_error_at,omitempty"`
	LastStatusChangeAt time.Time  `json:"last_status_change_at,omitempty"`
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	Protocol           Protocol   `json:"protocol"`
	Status             RuleStatus `json:"status"`
	ListenAddr         string     `json:"listen_addr"`
	Error              string     `json:"error"`
	ListenPort         int        `json:"listen_port"`
	ErrorCount         int64      `json:"error_count"`
}

// RuleTrafficSummary captures a rule-level traffic/activity summary.
type RuleTrafficSummary struct {
	UpdatedAt          time.Time  `json:"updated_at,omitempty"`
	LastErrorAt        time.Time  `json:"last_error_at,omitempty"`
	LastStatusChangeAt time.Time  `json:"last_status_change_at,omitempty"`
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	Protocol           Protocol   `json:"protocol"`
	Status             RuleStatus `json:"status"`
	ListenAddr         string     `json:"listen_addr"`
	ListenPort         int        `json:"listen_port"`
	BytesIn            int64      `json:"bytes_in"`
	BytesOut           int64      `json:"bytes_out"`
	TotalBytes         int64      `json:"total_bytes"`
	ActiveConns        int64      `json:"active_conns"`
	TotalConns         int64      `json:"total_conns"`
}

// ManagerDiagnostics captures manager/cache/runtime forwarding state.
type ManagerDiagnostics struct {
	Stats            *Stats                       `json:"stats"`
	HotRules         []RuleTrafficSummary         `json:"hot_rules"`
	TopActiveRules   []RuleTrafficSummary         `json:"top_active_rules"`
	TopTrafficRules  []RuleTrafficSummary         `json:"top_traffic_rules"`
	TopErrorRules    []RuleErrorSummary           `json:"top_error_rules"`
	Errors           []RuleErrorSummary           `json:"errors,omitempty"`
	Protocols        ProtocolBreakdownDiagnostics `json:"protocols"`
	RuleHealth       RuleHealthSummary            `json:"rule_health"`
	CachedRules      int                          `json:"cached_rules"`
	ActiveForwarders int                          `json:"active_forwarders"`
	ErrorRules       int                          `json:"error_rules"`
}

// DiagnosticsResponse is the payload returned by the diagnostics endpoint.
type DiagnosticsResponse struct {
	Timestamp time.Time          `json:"timestamp"`
	Runtime   RuntimeDiagnostics `json:"runtime"`
	Manager   ManagerDiagnostics `json:"manager"`
	Pool      PoolDiagnostics    `json:"pool"`
}

// WSLDistro is a type alias for wsl.Distro (WSL2 distribution)
type WSLDistro = wsl.Distro

// WSLPort is a type alias for wsl.Port (WSL2 listening port)
type WSLPort = wsl.Port

// WSLCapability is a type alias for wsl.Capability (WSL feature detection result).
type WSLCapability = wsl.Capability

// CreateRuleRequest is the API request for creating a new rule
type CreateRuleRequest struct {
	Name          string   `json:"name"`
	ListenAddr    string   `json:"listen_addr"`
	Protocol      Protocol `json:"protocol"`
	TargetAddr    string   `json:"target_addr"`
	Comment       string   `json:"comment"`
	UserID        string   `json:"user_id"`
	ListenPort    int      `json:"listen_port"`
	TargetPort    int      `json:"target_port"`
	AddFirewall   bool     `json:"add_firewall"`
	ProxyProtocol bool     `json:"proxy_protocol"`
	Transparent   bool     `json:"transparent"`
	Enabled       bool     `json:"enabled"`
	// NetherNet 开启 Minecraft 基岩版 NetherNet（WebRTC）代理：HTTP/HTTPS 信令
	// + UDP 数据面多路复用。必须配合透明模式（transparent=true）与 UDP 协议。
	NetherNet bool `json:"nethernet"`
	// NetherNetTLS 是该规则自己的 TLS 配置（每个用户填自己的证书路径），
	// 仅 NetherNet=true 时有意义。
	NetherNetTLS *NetherNetTLS `json:"nethernet_tls,omitempty"`
}

// UpdateRuleRequest is the API request for updating a rule
type UpdateRuleRequest struct {
	Name          *string   `json:"name"`
	ListenAddr    *string   `json:"listen_addr"`
	ListenPort    *int      `json:"listen_port"`
	Protocol      *Protocol `json:"protocol"`
	TargetAddr    *string   `json:"target_addr"`
	TargetPort    *int      `json:"target_port"`
	UserID        *string   `json:"user_id"`
	AddFirewall   *bool     `json:"add_firewall"`
	ProxyProtocol *bool     `json:"proxy_protocol"`
	Transparent   *bool     `json:"transparent"`
	Comment       *string   `json:"comment"`
	Enabled       *bool     `json:"enabled"`
	// NetherNet 同 CreateRuleRequest；指针 nil 表示本次不修改该字段。
	NetherNet *bool `json:"nethernet"`
	// NetherNetTLS 为 nil 表示不修改；非 nil 则整体替换（用户重新填了一套证书）。
	NetherNetTLS *NetherNetTLS `json:"nethernet_tls,omitempty"`
}

// WSLImportRequest is the API request for importing WSL2 ports
type WSLImportRequest struct {
	Distro     string    `json:"distro"`
	TargetAddr string    `json:"target_addr"` // WSL2 IP to forward to
	Ports      []WSLPort `json:"ports"`
}

// --- Access control (ACL) & connection sessions ---

// ACL entry actions.
const (
	ACLActionAllow = "allow"
	ACLActionDeny  = "deny"
)

// ConnEvent classifies a connection log row.
type ConnEvent string

const (
	ConnEventJoin   ConnEvent = "join"
	ConnEventLeave  ConnEvent = "leave"
	ConnEventDenied ConnEvent = "denied"
)

// ACLEntry is one IP-based access control rule. CIDR accepts a bare IP or a
// CIDR block (IPv4/IPv6); it is normalized on save. Empty RuleID means the
// entry applies to every forwarding rule; otherwise only to that rule.
type ACLEntry struct {
	ID        string    `json:"id"`
	CIDR      string    `json:"cidr"`
	Action    string    `json:"action"` // allow | deny
	RuleID    string    `json:"rule_id,omitempty"`
	Comment   string    `json:"comment,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ConnLogEntry records one connection/session event observed by a forwarder.
// BytesIn/BytesOut are filled when the session ends (leave). UserID 决定日志
// 落在哪个用户的桶里（存储按用户分桶），写入时由转发器按规则归属填好。
type ConnLogEntry struct {
	ID       string    `json:"id"`
	UserID   string    `json:"user_id,omitempty"`
	Time     time.Time `json:"time"`
	Protocol Protocol  `json:"protocol"`
	RuleID   string    `json:"rule_id,omitempty"`
	RuleName string    `json:"rule_name,omitempty"`
	SrcIP    string    `json:"src_ip"`
	SrcPort  int       `json:"src_port"`
	Event    ConnEvent `json:"event"`
	BytesIn  int64     `json:"bytes_in"`
	BytesOut int64     `json:"bytes_out"`
}

// ConnLogsResponse 是 GET /api/logs 的分页响应。Retention 是管理员配置的
// 每用户保留上限，前端用它动态显示「最多保留 N 条」。
type ConnLogsResponse struct {
	Logs      []*ConnLogEntry `json:"logs"`
	Total     int             `json:"total"`
	Page      int             `json:"page"`
	PerPage   int             `json:"per_page"`
	Retention int             `json:"retention"`
}

// ConnLogDeleteRequest 是 POST /api/logs/delete 的输入：按 ID 批量删除。
type ConnLogDeleteRequest struct {
	IDs []string `json:"ids"`
}

// SessionEntry is the live view of one tracked client session (conntrack style).
type SessionEntry struct {
	Key       string    `json:"key"` // unique per protocol+rule+client tuple
	Protocol  Protocol  `json:"protocol"`
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	SrcIP     string    `json:"src_ip"`
	SrcPort   int       `json:"src_port"`
	Since     time.Time `json:"since"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
}

// SessionsResponse wraps GET /api/sessions data.
type SessionsResponse struct {
	Sessions []SessionEntry `json:"sessions"`
}

// CreateACLRequest is the API request for adding an IP access-control entry.
type CreateACLRequest struct {
	CIDR    string `json:"cidr"`
	Action  string `json:"action"`
	RuleID  string `json:"rule_id"`
	Comment string `json:"comment"`
}

// NormalizeAndValidateACL normalizes a create request in place and validates it.
func NormalizeAndValidateACL(req *CreateACLRequest) (*ACLEntry, error) {
	if req == nil {
		return nil, fmt.Errorf("请求不能为空 | request is required")
	}
	cidr := strings.TrimSpace(req.CIDR)
	if cidr == "" {
		return nil, fmt.Errorf("IP 或 CIDR 不能为空 | cidr is required")
	}
	if !strings.Contains(cidr, "/") {
		// 裸 IP 自动补全长度的前缀 | append full-length prefix for bare IPs
		ip := net.ParseIP(cidr)
		if ip == nil {
			return nil, fmt.Errorf("无效的 IP 或 CIDR： %s | invalid IP or CIDR: %s", req.CIDR, cidr)
		}
		if ipv4 := ip.To4(); ipv4 != nil {
			cidr = fmt.Sprintf("%s/32", ipv4.String())
		} else {
			cidr = fmt.Sprintf("%s/128", ip.String())
		}
	}
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return nil, fmt.Errorf("无效的 IP 或 CIDR： %s | invalid IP or CIDR: %s", req.CIDR, cidr)
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action != ACLActionAllow && action != ACLActionDeny {
		return nil, fmt.Errorf("动作必须为 allow 或 deny | action must be allow or deny")
	}
	return &ACLEntry{
		CIDR:    cidr,
		Action:  action,
		RuleID:  strings.TrimSpace(req.RuleID),
		Comment: strings.TrimSpace(req.Comment),
	}, nil
}

// APIResponse is a generic JSON API response wrapper
type APIResponse struct {
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
	Success bool        `json:"success"`
}

// NormalizeProtocol normalizes a protocol value for API and storage use.
func NormalizeProtocol(p Protocol) Protocol {
	return Protocol(strings.ToLower(strings.TrimSpace(string(p))))
}

// NormalizeListenAddr normalizes a listen address; empty means all interfaces.
func NormalizeListenAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "0.0.0.0"
	}
	return addr
}

// maxRuleNameRunes 限制规则名长度。防火墙同步会把 "go-port-forward: <名>"
// 写进 iptables --comment（单条注释 128 字节上限）与 netsh 规则名，超长名
// 会造成「加得进、清理时对不上」的规则残留。
const maxRuleNameRunes = 64

// ruleNameAllowedPunct 是规则名允许的标点。WSL 导入自动生成
// "发行版:进程:tcp/端口" 形态的名字，冒号与斜杠必须放行；全角括号/冒号是
// 中文命名常见字符。引号、反斜杠、$、; 等会进 iptables/netsh/pfctl 的参数
// （argv 直传没有 shell 注入风险，但这些工具自己的解析层可能被搅乱），白名单一次性排除。
const ruleNameAllowedPunct = "._-:/()（）【】:：、"

// ValidateRuleName 校验规则名：非空、长度上限、字符白名单。
func ValidateRuleName(name string) error {
	if name == "" {
		return fmt.Errorf("规则名称不能为空 | name is required")
	}
	if n := utf8.RuneCountInString(name); n > maxRuleNameRunes {
		return fmt.Errorf("规则名称过长（最多 %d 个字符）| name is too long (max %d characters)", maxRuleNameRunes, maxRuleNameRunes)
	}
	for _, r := range name {
		// 空白只放行普通空格：\t\n\r 属于 unicode.IsSpace，但控制字符进
		// 防火墙工具的参数值没有意义，统一拒绝。
		if r == ' ' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		if strings.ContainsRune(ruleNameAllowedPunct, r) {
			continue
		}
		return fmt.Errorf("规则名称含有不允许的字符 %q（可用：中英文、数字、空格与 ._-:/()）| name contains unsupported character %q", r, r)
	}
	return nil
}

// ValidateCreateRuleRequest normalizes and validates a create request in-place.
func ValidateCreateRuleRequest(req *CreateRuleRequest) error {
	if req == nil {
		return fmt.Errorf("请求不能为空 | request is required")
	}
	req.Name = strings.TrimSpace(req.Name)
	req.TargetAddr = strings.TrimSpace(req.TargetAddr)
	req.ListenAddr = NormalizeListenAddr(req.ListenAddr)
	req.Comment = strings.TrimSpace(req.Comment)
	req.Protocol = NormalizeProtocol(req.Protocol)
	if req.Protocol == "" {
		req.Protocol = ProtocolTCP
	}

	if err := ValidateRuleName(req.Name); err != nil {
		return err
	}
	if req.TargetAddr == "" {
		return fmt.Errorf("目标地址不能为空 | target_addr is required")
	}
	if err := validatePort("监听端口 | listen_port", req.ListenPort); err != nil {
		return err
	}
	if err := validatePort("目标端口 | target_port", req.TargetPort); err != nil {
		return err
	}
	if !IsValidProtocol(req.Protocol) {
		return fmt.Errorf("协议必须为 tcp、udp 或 both | protocol must be tcp, udp, or both")
	}
	if req.Transparent && req.ProxyProtocol {
		return fmt.Errorf("透明模式与 PROXY 协议互斥，只能二选一 | transparent and proxy_protocol are mutually exclusive")
	}
	// 透明模式 UDP-only 在创建时就拒绝，而不是等启动转发器时进 error 态——
	// TCP 的回包无法送达透明 socket，这样的规则从来不可能工作。
	if req.Transparent && req.Protocol != ProtocolUDP {
		return fmt.Errorf("透明模式仅支持 UDP 规则（TCP 回包无法送达透明 socket）| transparent mode only supports UDP rules")
	}
	// NetherNet 依赖透明模式的源地址保真（玩家真实 IP）与 UDP-only，缺一不可。
	if req.NetherNet {
		if !req.Transparent {
			return fmt.Errorf("NetherNet 模式必须开启透明模式（否则后端看不到玩家真实 IP）| NetherNet mode requires transparent mode")
		}
		if req.Protocol != ProtocolUDP {
			return fmt.Errorf("NetherNet 模式仅支持 UDP 协议 | NetherNet mode only supports UDP")
		}
		_, dataPort := NetherNetPorts(req.ListenPort, req.NetherNetTLS)
		if dataPort > 65535 {
			return fmt.Errorf("NetherNet 数据端口超出范围（1-65535）| NetherNet data port out of range (1-65535)")
		}
	}
	if err := req.NetherNetTLS.Validate(); err != nil {
		return err
	}
	req.NetherNetTLS = req.NetherNetTLS.Normalize()
	return nil
}

// ValidateForwardRule normalizes and validates a persisted rule in-place.
func ValidateForwardRule(rule *ForwardRule) error {
	if rule == nil {
		return fmt.Errorf("规则不能为空 | rule is required")
	}
	rule.Name = strings.TrimSpace(rule.Name)
	rule.TargetAddr = strings.TrimSpace(rule.TargetAddr)
	rule.ListenAddr = NormalizeListenAddr(rule.ListenAddr)
	rule.Comment = strings.TrimSpace(rule.Comment)
	rule.Protocol = NormalizeProtocol(rule.Protocol)

	if err := ValidateRuleName(rule.Name); err != nil {
		return err
	}
	if rule.TargetAddr == "" {
		return fmt.Errorf("目标地址不能为空 | target_addr is required")
	}
	if err := validatePort("监听端口 | listen_port", rule.ListenPort); err != nil {
		return err
	}
	if err := validatePort("目标端口 | target_port", rule.TargetPort); err != nil {
		return err
	}
	if !IsValidProtocol(rule.Protocol) {
		return fmt.Errorf("协议必须为 tcp、udp 或 both | protocol must be tcp, udp, or both")
	}
	if rule.Transparent && rule.ProxyProtocol {
		return fmt.Errorf("透明模式与 PROXY 协议互斥，只能二选一 | transparent and proxy_protocol are mutually exclusive")
	}
	if rule.Transparent && rule.Protocol != ProtocolUDP {
		return fmt.Errorf("透明模式仅支持 UDP 规则（TCP 回包无法送达透明 socket）| transparent mode only supports UDP rules")
	}
	// 与 ValidateCreateRuleRequest 同源：NetherNet 的三项前置条件在合并后的
	// 规则上再校验一次——更新请求可以只改 transparent/protocol，逐字段校验会漏。
	if rule.NetherNet {
		if !rule.Transparent {
			return fmt.Errorf("NetherNet 模式必须开启透明模式（否则后端看不到玩家真实 IP）| NetherNet mode requires transparent mode")
		}
		if rule.Protocol != ProtocolUDP {
			return fmt.Errorf("NetherNet 模式仅支持 UDP 协议 | NetherNet mode only supports UDP")
		}
		_, dataPort := NetherNetPorts(rule.ListenPort, rule.NetherNetTLS)
		if dataPort > 65535 {
			return fmt.Errorf("NetherNet 数据端口超出范围（1-65535）| NetherNet data port out of range (1-65535)")
		}
	}
	if err := rule.NetherNetTLS.Validate(); err != nil {
		return err
	}
	rule.NetherNetTLS = rule.NetherNetTLS.Normalize()
	return nil
}

// IsValidProtocol reports whether p is a supported transport selection.
func IsValidProtocol(p Protocol) bool {
	switch NormalizeProtocol(p) {
	case ProtocolTCP, ProtocolUDP, ProtocolBoth:
		return true
	default:
		return false
	}
}

func validatePort(name string, port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("%s 超出范围 (1-65535) | out of range (1-65535)", name)
	}
	return nil
}
