package models

import (
	"fmt"
	"net"
	"strings"
	"time"

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

	// Runtime stats — not persisted
	Status        RuleStatus `json:"status"`
	ErrorMsg      string     `json:"error_msg,omitempty"` // reason the forwarder failed to start
	ListenPort    int        `json:"listen_port"`
	TargetPort    int        `json:"target_port"`
	BytesIn       int64      `json:"bytes_in"`
	BytesOut      int64      `json:"bytes_out"`
	ActiveConns   int64      `json:"active_conns"`
	TotalConns    int64      `json:"total_conns"`
	Enabled       bool       `json:"enabled"`
	AddFirewall   bool       `json:"add_firewall"`   // auto-add firewall rule on creation
	ProxyProtocol bool       `json:"proxy_protocol"` // prepend PROXY Protocol v2 header with real client IP toward target
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
	ListenPort    int      `json:"listen_port"`
	TargetPort    int      `json:"target_port"`
	AddFirewall   bool     `json:"add_firewall"`
	ProxyProtocol bool     `json:"proxy_protocol"`
	Enabled       bool     `json:"enabled"`
}

// UpdateRuleRequest is the API request for updating a rule
type UpdateRuleRequest struct {
	Name          *string   `json:"name"`
	ListenAddr    *string   `json:"listen_addr"`
	ListenPort    *int      `json:"listen_port"`
	Protocol      *Protocol `json:"protocol"`
	TargetAddr    *string   `json:"target_addr"`
	TargetPort    *int      `json:"target_port"`
	AddFirewall   *bool     `json:"add_firewall"`
	ProxyProtocol *bool     `json:"proxy_protocol"`
	Comment       *string   `json:"comment"`
	Enabled       *bool     `json:"enabled"`
}

// WSLImportRequest is the API request for importing WSL2 ports
type WSLImportRequest struct {
	Distro     string    `json:"distro"`
	TargetAddr string    `json:"target_addr"` // WSL2 IP to forward to
	Ports      []WSLPort `json:"ports"`
}

// --- Access control (ACL) & player identity ---

// ACL entry actions.
const (
	ACLActionAllow = "allow"
	ACLActionDeny  = "deny"
)

// PlayerBan match types.
const (
	PlayerBanTypeGamertag = "gamertag"
	PlayerBanTypeXUID     = "xuid"
)

// ConnEvent classifies a connection log row.
type ConnEvent string

const (
	ConnEventJoin   ConnEvent = "join"
	ConnEventLeave  ConnEvent = "leave"
	ConnEventDenied ConnEvent = "denied"
	ConnEventKick   ConnEvent = "kick" // session cut because the player is banned
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

// PlayerBan blocks a Bedrock player at the relay layer by gamertag or XUID;
// the matching session is cut as soon as the login handshake is observed.
type PlayerBan struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // gamertag | xuid
	Value     string    `json:"value"`
	Comment   string    `json:"comment,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ConnLogEntry records one connection/session event observed by a forwarder.
// BytesIn/BytesOut are filled when the session ends (leave/kick).
type ConnLogEntry struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Protocol Protocol  `json:"protocol"`
	RuleID   string    `json:"rule_id,omitempty"`
	RuleName string    `json:"rule_name,omitempty"`
	SrcIP    string    `json:"src_ip"`
	SrcPort  int       `json:"src_port"`
	Player   string    `json:"player,omitempty"`
	XUID     string    `json:"xuid,omitempty"`
	Event    ConnEvent `json:"event"`
	BytesIn  int64     `json:"bytes_in"`
	BytesOut int64     `json:"bytes_out"`
}

// OnlinePlayer is the live view of an identified UDP client session.
type OnlinePlayer struct {
	SessionKey string    `json:"session_key"` // unique per rule+client tuple
	RuleID     string    `json:"rule_id"`
	RuleName   string    `json:"rule_name"`
	Player     string    `json:"player,omitempty"`
	XUID       string    `json:"xuid,omitempty"`
	SrcIP      string    `json:"src_ip"`
	SrcPort    int       `json:"src_port"`
	Since      time.Time `json:"since"`
	BytesIn    int64     `json:"bytes_in"`
	BytesOut   int64     `json:"bytes_out"`
}

// CreateACLRequest is the API request for adding an IP access-control entry.
type CreateACLRequest struct {
	CIDR    string `json:"cidr"`
	Action  string `json:"action"`
	RuleID  string `json:"rule_id"`
	Comment string `json:"comment"`
}

// CreatePlayerBanRequest is the API request for banning a Bedrock player.
type CreatePlayerBanRequest struct {
	Type    string `json:"type"` // gamertag | xuid
	Value   string `json:"value"`
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

// NormalizeAndValidatePlayerBan normalizes a ban request in place and validates it.
func NormalizeAndValidatePlayerBan(req *CreatePlayerBanRequest) (*PlayerBan, error) {
	if req == nil {
		return nil, fmt.Errorf("请求不能为空 | request is required")
	}
	banType := strings.ToLower(strings.TrimSpace(req.Type))
	if banType != PlayerBanTypeGamertag && banType != PlayerBanTypeXUID {
		return nil, fmt.Errorf("类型必须为 gamertag 或 xuid | type must be gamertag or xuid")
	}
	value := strings.TrimSpace(req.Value)
	if value == "" {
		return nil, fmt.Errorf("封禁值不能为空 | value is required")
	}
	if len(value) > 128 {
		return nil, fmt.Errorf("封禁值过长 | value too long")
	}
	return &PlayerBan{
		Type:    banType,
		Value:   value,
		Comment: strings.TrimSpace(req.Comment),
	}, nil
}

// OnlinePlayersResponse wraps GET /api/players data.
type OnlinePlayersResponse struct {
	Players []OnlinePlayer `json:"players"`
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

	if req.Name == "" {
		return fmt.Errorf("规则名称不能为空 | name is required")
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

	if rule.Name == "" {
		return fmt.Errorf("规则名称不能为空 | name is required")
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
