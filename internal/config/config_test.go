package config

// 配置文件版本升级的用例。
//
// 行为承诺（README 对用户写的就是这三条，测试逐条锁死）：
//   1. 首次运行生成的文件带 version 与全部配置项；
//   2. 旧版本文件（无 version 或 version < 当前）在 Load 时被合并重写：
//      新键补全、用户自定义值原样保留、原文件备份为 .v<N>.bak；
//   3. 已是当前版本的文件**不被重写**（否则每次启动都会丢一次用户注释）。
//
// 测试全部传显式 configPath：默认路径锚定在可执行文件目录（go test 的二进制
// 在缓存目录里，写进去既不可预测也污染缓存）。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v1StyleConfig 模拟一份升级前的真实存量文件：没有 version 键、没有 v2 新增的
// tunnel 子键，且带着运维的自定义值（改过端口、手写过应急后门账号——后者是
// README 明确教用户手工加的键，升级绝不能弄丢它）。
const v1StyleConfig = `forward:
    buffer_size: 8192
    udp_timeout: 60
log:
    level: debug
storage:
    path: /srv/pf/data/rules.db
tunnel:
    enabled: true
    listen: :7947
    tun_addr: 10.66.0.1/16
web:
    host: 0.0.0.0
    password: rescue-s3cret
    port: 9000
    username: rescue
`

func TestLoadFreshWritesVersionAndAllKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, key := range []string{"version: 2", "io_mode: batch", "fec: false",
		"tail_dup: false", "udp_gro: false", "udp_gso: false"} {
		if !strings.Contains(text, key) {
			t.Fatalf("新生成的文件缺少 %q：\n%s", key, text)
		}
	}
	// 应急后门账号默认不写入（仅回环生效的救急通道，README 教用户手工加）。
	if strings.Contains(text, "username") || strings.Contains(text, "password") {
		t.Fatalf("默认文件不应包含应急后门账号：\n%s", text)
	}
	// 首次生成不算升级。
	if note := TakeUpgradeNote(); note != "" {
		t.Fatalf("首次生成不应记为升级：%s", note)
	}
}

func TestLoadUpgradesV1FileInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(v1StyleConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)

	// 新键补全。
	if !strings.Contains(text, "version: 2") {
		t.Fatalf("升级后的文件应带当前版本号：\n%s", text)
	}
	for _, key := range []string{"io_mode:", "fec:", "tail_dup:", "udp_gro:", "udp_gso:"} {
		if !strings.Contains(text, key) {
			t.Fatalf("升级后的文件缺少新键 %q：\n%s", key, text)
		}
	}
	// 用户自定义值必须原样保留：改过的端口、超时、日志级别、应急后门账号。
	if !strings.Contains(text, "port: 9000") || !strings.Contains(text, "username: rescue") ||
		!strings.Contains(text, "password: rescue-s3cret") || !strings.Contains(text, "udp_timeout: 60") ||
		!strings.Contains(text, "level: debug") {
		t.Fatalf("升级弄丢了用户自定义值：\n%s", text)
	}
	// 运行时配置同样以用户的值为准（不是默认值）。
	if cfg.Web.Port != 9000 || cfg.Web.Username != "rescue" {
		t.Fatalf("运行时值未取文件自定义值: %+v", cfg.Web)
	}
	if cfg.Tunnel.IOMode != "batch" || cfg.Tunnel.FEC {
		t.Fatalf("新增键应按默认值生效: %+v", cfg.Tunnel)
	}

	// 原文件备份为 .v1.bak，内容是升级前的原文。
	bak, err := os.ReadFile(path + ".v1.bak")
	if err != nil {
		t.Fatalf("未生成备份: %v", err)
	}
	if string(bak) != v1StyleConfig {
		t.Fatalf("备份内容与原文件不一致（丢了找回注释的途径）")
	}

	// 升级说明被记录（main 在日志可用后打印）。
	if note := TakeUpgradeNote(); !strings.Contains(note, "v1 升级到 v2") {
		t.Fatalf("升级说明不符: %q", note)
	}
	// 取过即清空，避免下次启动重复打印。
	if note := TakeUpgradeNote(); note != "" {
		t.Fatalf("说明应取后即空: %q", note)
	}
}

func TestLoadDoesNotRewriteCurrentVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if _, err := Load(path); err != nil { // 先生成一份当前版本的文件
		t.Fatal(err)
	}
	// 在文件里手写一段注释——用户的真实习惯；当前版本下重写会把它弄丢。
	raw, _ := os.ReadFile(path)
	annotated := strings.Replace(string(raw), "version: 2",
		"# 这个端口是公网入口，改动前先看运维手册\nversion: 2", 1)
	if err := os.WriteFile(path, []byte(annotated), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != annotated {
		t.Fatal("当前版本的文件被重写了：用户注释会每次启动丢一次")
	}
	if _, err := os.Stat(path + ".v2.bak"); !os.IsNotExist(err) {
		t.Fatal("当前版本不应产生备份")
	}
	if note := TakeUpgradeNote(); note != "" {
		t.Fatalf("当前版本不应记为升级: %s", note)
	}
}

// 备份只保留最早那份：跨多个版本升级（v1→v2→v3…）时，.v1.bak 记录的始终是
// 最初的原文，不会被后续升级覆盖成中间态。
func TestUpgradeBackupKeepsEarliestCopy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(v1StyleConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	bakPath := path + ".v1.bak"
	first, _ := os.ReadFile(bakPath)

	// 模拟运维在升级后的文件里继续自定义，然后「降级回 v1」再次触发升级路径：
	// 备份必须仍是第一次那份（最早的原文）。
	tweaked := strings.Replace(string(v1StyleConfig), "port: 9000", "port: 9100", 1)
	if err := os.WriteFile(path, []byte(tweaked), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(bakPath)
	if string(second) != string(first) {
		t.Fatal("备份被后续升级覆盖了：最早原文是注释的唯一找回途径")
	}
}
