//go:build windows

package main

// 客户端本地配置。
//
// 原先 pf-client.conf 就是一行裸地址。多用户之后客户端必须携带身份（用户 ID
// 与隧道密钥），一行文本装不下，改成 YAML。
//
// 迁移：旧格式那一行地址本身是合法的 YAML 标量，所以解析成 mapping 失败并不
// 等于文件损坏——先按 mapping 试，失败就当作 legacy 地址收下，只是没有凭据，
// 需要用户补一次接入码。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"go-port-forward/pkg/accesscode"
)

// clientConfig 是落盘的客户端配置。
type clientConfig struct {
	Addr   string `yaml:"addr"`    // 中转机地址（host 或 host:port）
	UserID string `yaml:"user_id"` // 隧道用户 ID
	Secret string `yaml:"secret"`  // 隧道密钥（base64）
}

// complete 报告凭据是否齐备（可以发起握手）。
func (c clientConfig) complete() bool {
	return c.Addr != "" && c.UserID != "" && c.Secret != ""
}

// normalized 返回补全默认端口后的副本。
func (c clientConfig) normalized() clientConfig {
	c.Addr = withDefaultPort(strings.TrimSpace(c.Addr))
	c.UserID = strings.TrimSpace(c.UserID)
	c.Secret = strings.TrimSpace(c.Secret)
	return c
}

// withDefaultPort 给缺端口的地址补上隧道默认端口。
func withDefaultPort(addr string) string {
	if addr == "" || strings.Contains(addr, ":") {
		return addr
	}
	return fmt.Sprintf("%s:%d", addr, defaultTunnelPort)
}

var confMu sync.Mutex

func confPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "pf-client.conf"
	}
	return filepath.Join(filepath.Dir(exe), "pf-client.conf")
}

// loadConfig 读取配置。文件不存在、为空或损坏都返回零值而不是错误——配置只是
// 「记住上次填的东西」，读不出来只该让界面回到空白，不该阻止程序启动。
func loadConfig() clientConfig {
	confMu.Lock()
	defer confMu.Unlock()

	raw, err := os.ReadFile(confPath())
	if err != nil {
		return clientConfig{}
	}
	return parseConfigBytes(raw)
}

// parseConfigBytes 解析配置内容，兼容旧版的单行裸地址格式。
func parseConfigBytes(raw []byte) clientConfig {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return clientConfig{}
	}

	var cfg clientConfig
	if err := yaml.Unmarshal(raw, &cfg); err == nil &&
		(cfg.Addr != "" || cfg.UserID != "" || cfg.Secret != "") {
		return cfg.normalized()
	}
	// 旧版格式：整个文件就是一行中转机地址。它本身是合法的 YAML 标量，
	// 所以"解析成 mapping 失败"不代表文件损坏——不兼容这一步会让升级后
	// 用户保存的地址凭空消失。
	if !strings.ContainsAny(text, "\r\n") {
		return clientConfig{Addr: withDefaultPort(text)}
	}
	return clientConfig{}
}

// marshalConfig 序列化配置（与 parseConfigBytes 成对，供测试验证往返一致）。
func marshalConfig(cfg clientConfig) ([]byte, error) {
	return yaml.Marshal(cfg.normalized())
}

// saveConfig 覆盖写入配置。
func saveConfig(cfg clientConfig) {
	confMu.Lock()
	defer confMu.Unlock()

	data, err := marshalConfig(cfg)
	if err != nil {
		return
	}
	// 文件含隧道密钥，权限收紧到仅所有者可读写。
	_ = os.WriteFile(confPath(), data, 0o600)
}

// parseConnectInput 把用户在界面里输入的内容解析成配置。
//
// 接受两种形态：完整接入码（一次粘贴含地址、用户 ID、密钥），或手工分别填写
// 三个字段。接入码优先——那是正常路径，手工填写是接入码丢了之后的兜底。
func parseConnectInput(code, addr, userID, secret string) (clientConfig, error) {
	code = strings.TrimSpace(code)
	if code != "" {
		c, err := accesscode.Decode(code)
		if err != nil {
			return clientConfig{}, err
		}
		out := clientConfig{Addr: c.Addr, UserID: c.UserID, Secret: c.Secret}
		// 手工填的地址可以覆盖接入码里的：接入码由服务端生成，若管理员没配
		// tunnel.public_addr，里面的地址可能是内网的或不可达的。
		if a := strings.TrimSpace(addr); a != "" {
			out.Addr = a
		}
		return out.normalized(), nil
	}

	out := clientConfig{
		Addr:   strings.TrimSpace(addr),
		UserID: strings.TrimSpace(userID),
		Secret: strings.TrimSpace(secret),
	}
	if out.Addr == "" {
		return clientConfig{}, fmt.Errorf("请填写中转机地址")
	}
	if out.UserID == "" || out.Secret == "" {
		return clientConfig{}, fmt.Errorf("请粘贴接入码，或同时填写用户 ID 与隧道密钥（可在面板的用户管理中获取）")
	}
	return out.normalized(), nil
}
