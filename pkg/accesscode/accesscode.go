// Package accesscode 编解码 pf-client 的「接入码」。
//
// 接入码把用户接入隧道所需的三样东西打成一个可复制的字符串：中转机地址、
// 用户 ID、隧道密钥。让用户粘贴一次，而不是在界面上手抄三个字段——手抄
// 32 字节 base64 密钥是最容易出错、也最难排查的一步。
//
// 格式：pf1.<base64url(json)>，无填充。载荷刻意用短键名，因为整串要靠用户
// 手动复制粘贴，短一点少一点截断风险。
//
// 这不是加密，只是编码：接入码本身就是凭据，必须按密码级别对待。
package accesscode

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Prefix 是接入码的版本前缀。
const Prefix = "pf1."

// Code 是接入码承载的内容。
// CodeID 的 json 键沿用 "u"：格式没变（仍是三个字段），语义从「用户 ID」变成
// 「访问码 ID」。迁移时访问码 ID 沿用了原用户 ID，所以已经发出去的接入码在
// 升级后依然指向同一条隧道，用户不必重新配置客户端。
type Code struct {
	Addr   string `json:"h"` // 中转机地址（host 或 host:port）
	CodeID string `json:"u"` // 访问码 ID（uuid 文本）
	Secret string `json:"k"` // 隧道密钥（标准 base64）
}

// Encode 生成接入码文本。
func Encode(c Code) (string, error) {
	c.Addr = strings.TrimSpace(c.Addr)
	c.CodeID = strings.TrimSpace(c.CodeID)
	c.Secret = strings.TrimSpace(c.Secret)
	if c.Addr == "" || c.CodeID == "" || c.Secret == "" {
		return "", fmt.Errorf("accesscode: 地址、访问码 ID 与密钥都不能为空 | addr, code id and secret are all required")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// Decode 解析接入码文本。
//
// 容忍用户复制时带上的空白与换行（从网页复制经常粘到换行），也容忍带填充的
// base64——两种 base64 变体的解码结果一致，没有理由为此拒绝用户。
func Decode(s string) (Code, error) {
	var c Code
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
	if s == "" {
		return c, fmt.Errorf("accesscode: 接入码为空 | access code is empty")
	}
	if !strings.HasPrefix(s, Prefix) {
		return c, fmt.Errorf("accesscode: 不是有效的接入码（应以 %s 开头）| not an access code", Prefix)
	}
	body := strings.TrimSuffix(s[len(Prefix):], "=")
	body = strings.TrimSuffix(body, "=")
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return c, fmt.Errorf("accesscode: 接入码已损坏 | access code is corrupted")
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("accesscode: 接入码已损坏 | access code is corrupted")
	}
	c.Addr = strings.TrimSpace(c.Addr)
	c.CodeID = strings.TrimSpace(c.CodeID)
	c.Secret = strings.TrimSpace(c.Secret)
	if c.Addr == "" || c.CodeID == "" || c.Secret == "" {
		return c, fmt.Errorf("accesscode: 接入码内容不完整 | access code is incomplete")
	}
	return c, nil
}

// Looks 报告一段文本看起来是否是接入码（用于界面上区分「接入码」与「地址」）。
func Looks(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), Prefix)
}
