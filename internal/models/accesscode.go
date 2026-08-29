package models

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// DeviceFingerprintBytes 是设备指纹的长度（客户端上报的 machineid 派生值）。
const DeviceFingerprintBytes = 32

// AccessCode 是一个隧道身份：一份密钥 + 一个隧道内地址 + 一台绑定的设备。
//
// 隧道身份从用户下移到访问码，是为了让「一个用户接多台后端机」成为常规操作
// 而不是要多开账号。每个访问码独占一个隧道地址，因此可以并存。
//
// Secret 与 DeviceFingerprint 带 json:"-"：本结构体直接作为 API 响应体。
// 指纹同样不外泄——它由机器标识派生，泄漏出去可用于跨用户关联同一台机器。
// 持久化走 storage 里的独立 record 结构体。
type AccessCode struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	ID     string `json:"id"` // uuid，同时是握手包里的线上标识
	UserID string `json:"user_id"`
	Name   string `json:"name"`   // 用户自取的名字，如「家里的服务器」
	TunIP  string `json:"tun_ip"` // 分配到的隧道内地址，全局唯一

	Secret string `json:"-"`

	Disabled bool `json:"disabled"`

	// --- 设备绑定 ---
	// 首次握手成功时登记指纹，之后其它设备一律拒绝。指纹为空 = 尚未绑定。
	DeviceFingerprint string    `json:"-"`
	DeviceLabel       string    `json:"device_label,omitempty"` // 展示用摘要
	BoundAt           time.Time `json:"bound_at,omitempty"`
	LastSeenAt        time.Time `json:"last_seen_at,omitempty"`
	LastSeenAddr      string    `json:"last_seen_addr,omitempty"`

	// 运行时字段，不持久化
	Online   bool   `json:"online"`
	UserName string `json:"user_name,omitempty"`
}

// Bound 报告该访问码是否已绑定设备。
func (c *AccessCode) Bound() bool { return c != nil && c.DeviceFingerprint != "" }

// CreateAccessCodeRequest 是创建访问码的请求。
//
// 不含 TunIP 与 Secret：地址由服务端在存储事务内分配，密钥由服务端生成。
// 让调用方指定会引入撞号与「占用了别人地址」两种问题。
type CreateAccessCodeRequest struct {
	Name string `json:"name"`
	// UserID 仅管理员可用：为他人创建访问码。普通用户提交的值会被忽略。
	UserID string `json:"user_id"`
}

// UpdateAccessCodeRequest 是更新访问码的请求（指针 = 未提供即不改）。
type UpdateAccessCodeRequest struct {
	Name     *string `json:"name"`
	Disabled *bool   `json:"disabled"`
}

// AccessCodeView 是「取接入码」接口的响应。
type AccessCodeView struct {
	CodeID   string `json:"code_id"`
	Name     string `json:"name"`
	UserName string `json:"user_name"`
	Addr     string `json:"addr"`
	Secret   string `json:"secret"`
	Code     string `json:"code"`
	TunIP    string `json:"tun_ip"`
}

// ValidateAccessCodeName 校验访问码名称。
func ValidateAccessCodeName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("访问码名称不能为空 | access code name is required")
	}
	if len(name) > 64 {
		return fmt.Errorf("访问码名称不能超过 64 个字符 | name must not exceed 64 characters")
	}
	return nil
}

// ParseFingerprint 解析客户端上报的设备指纹（64 位小写 hex）。
func ParseFingerprint(s string) ([]byte, error) {
	clean := strings.ToLower(strings.TrimSpace(s))
	if len(clean) != DeviceFingerprintBytes*2 {
		return nil, fmt.Errorf("设备指纹长度无效 | invalid device fingerprint length")
	}
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("设备指纹格式无效 | invalid device fingerprint")
	}
	return raw, nil
}

// FingerprintLabel 生成指纹的展示摘要（首 4 + 末 4 位）。
//
// 只展示摘要而不是全值：用户报障时要能和面板上的记录对上，但完整指纹不该
// 出现在界面、日志或截图里。
func FingerprintLabel(fp string) string {
	fp = strings.ToLower(strings.TrimSpace(fp))
	if fp == "" {
		return ""
	}
	if len(fp) <= 12 {
		return fp
	}
	return fp[:4] + "…" + fp[len(fp)-4:]
}
