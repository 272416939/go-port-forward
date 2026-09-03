package config

// 带注释的配置文件渲染器。
//
// 此前生成的 config.yaml 是无注释的扁平 YAML（Viper 直接序列化），运维要开一个
// 开关就得来回翻文档——用户明确要求把说明写进文件里。
//
// 两条设计约束：
//   1. **值永远从 viper 取**（默认值或用户文件值），注释只是布局的一部分——
//      这样升级合并写回时用户值与注释一起保留，我们自己写的注释不再丢；
//   2. **键序保持字母序、4 空格缩进**，与旧版生成文件同构——升级重写的 diff
//      里只会出现新增的键，运维扫一眼就知道改了什么。
//
// 注释文案与 README 的字段讲解表同源；改配置项含义时两处一起改。

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type keyDoc struct {
	key string // viper 全键名，如 "tunnel.fec"
	// skipEmpty 为 true 时仅在值非空时写入（应急后门账号：默认不进文件，
	// 用户手写或升级合并后保留）。
	skipEmpty bool
	comment   string
}

type sectionDoc struct {
	name string // 段名；空串 = 顶层键（version）
	head string // 段头注释
	keys []keyDoc
}

// configLayout 是生成文件的唯一布局真相：段序、键序、注释都在这里。
// 段序与键序保持字母序（与旧版 Viper 输出一致）。
var configLayout = []sectionDoc{
	{
		name: "forward",
		head: "── 通用转发引擎 ──",
		keys: []keyDoc{
			{key: "forward.buffer_size", comment: "转发读写缓冲（字节）"},
			{key: "forward.connlog_max_entries", comment: "连接日志保留上限的兜底值；正式生效值在\n# 面板「全局设置 → 每用户日志保留上限」（默认 10000 条，环形裁剪最旧）"},
			{key: "forward.dial_timeout", comment: "出站连接超时（秒）"},
			{key: "forward.pool_size", comment: "转发协程池容量；0 = 自动（CPU 数 × 64）"},
			{key: "forward.udp_timeout", comment: "UDP 会话空闲超时（秒）：超时会话回收，下个包新建"},
		},
	},
	{
		name: "gc",
		head: "── 垃圾回收 ──",
		keys: []keyDoc{
			{key: "gc.enable_monitoring", comment: "性能监控"},
			{key: "gc.enabled", comment: "周期性 GC 开关"},
			{key: "gc.interval_seconds", comment: "GC 扫描间隔（秒）"},
			{key: "gc.memory_threshold_mb", comment: "内存阈值触发 GC（MB）；0 = 关闭"},
			{key: "gc.strategy", comment: "standard 标准 / aggressive 激进（GC 后归还内存）/\n# gentle 温和（仅内存压力大时） / adaptive 自适应"},
		},
	},
	{
		name: "log",
		head: "── 日志（path 是绝对路径，锚定可执行文件所在目录）──",
		keys: []keyDoc{
			{key: "log.compress", comment: "归档压缩"},
			{key: "log.level", comment: "debug / info / warn / error"},
			{key: "log.max_age_days", comment: "归档保留天数"},
			{key: "log.max_backups", comment: "归档保留份数"},
			{key: "log.max_size_mb", comment: "单文件大小上限（MB），超出滚动"},
			{key: "log.path", comment: "日志文件路径"},
		},
	},
	{
		name: "pool",
		head: "── 全局协程池 ──",
		keys: []keyDoc{
			{key: "pool.pre_alloc", comment: "启动时预分配"},
			{key: "pool.size", comment: "容量"},
		},
	},
	{
		name: "storage",
		head: "── bbolt 存储（path 是绝对路径，锚定可执行文件所在目录；\n# 规则/用户/访问码/连接日志/SMTP 配置全部在此文件）──",
		keys: []keyDoc{
			{key: "storage.path", comment: "数据库路径"},
		},
	},
	{
		name: "tunnel",
		head: "── 内置隧道服务端（配合 Windows 端 pf-client；完整回程配置仅 Linux）──",
		keys: []keyDoc{
			{key: "tunnel.enabled", comment: "开启后隧道服务端随主程序常驻"},
			{key: "tunnel.fec", comment: "前向纠错：每 8 个数据包附 1 个校验包，组内丢 1 个可无损补回\n# （省掉应用层重传的一个 RTT）。代价：下行冗余 12.5%、隧道 MTU 让出 83 字节。\n# 默认关：丢包率 <1% 的链路上是纯浪费——先看客户端面板「链路质量」再开"},
			{key: "tunnel.io_mode", comment: "UDP 收发方式：batch 走 recvmmsg（每批 2 次系统调用，默认）/\n# simple 逐包。数据面出问题改成 simple 即回退，无需换二进制；非 Linux 自动降级"},
			{key: "tunnel.listen", comment: "隧道 UDP 监听，防火墙记得放行"},
			{key: "tunnel.nat", comment: "自动配置回程路径（ip_forward + fwmark 策略路由；不用 MASQUERADE）"},
			{key: "tunnel.psk", comment: "已废弃：多用户协议为每个访问码分配独立密钥，此项被忽略并告警一次"},
			{key: "tunnel.public_addr", comment: "兜底写进接入码的中转机地址（如 1.2.3.4:7947）；\n# 优先用面板「全局设置 → 中转机地址」"},
			{key: "tunnel.tail_dup", comment: "小包冗余副本：≤256 字节的包发两份（限频 20ms），接收端靠重放窗口\n# 去重。补的是纠错的盲区——组尾小包（玩家操作指令、RakNet 探测）"},
			{key: "tunnel.tun_addr", comment: "服务端隧道地址 + 访问码地址池（一个访问码占一个地址；\n# /16 约 6.5 万个位置，/24 的 253 个很快耗尽）"},
			{key: "tunnel.tun_name", comment: "TUN 设备名"},
			{key: "tunnel.udp_gro", comment: "Linux UDP 接收聚合（内核 ≥ 5.0）；默认关，等链路质量数据证明需要再开"},
			{key: "tunnel.udp_gso", comment: "Linux UDP 发送分段卸载；**不建议开**：内核要求一条消息内各段等长，\n# 游戏流量包长参差不齐，命中率天然很低"},
		},
	},
	{
		name: "",
		head: "",
		keys: []keyDoc{
			{key: "version", comment: "配置文件模式版本（程序维护，勿手改）：\n# 升级程序后自动补全新增配置项，原文件备份为 config.yaml.v<N>.bak"},
		},
	},
	{
		name: "web",
		head: "── 管理面板 ──",
		keys: []keyDoc{
			{key: "web.host", comment: "监听地址；对外服务改 0.0.0.0 并置于 TLS 反代之后"},
			{key: "web.password", skipEmpty: true, comment: "应急后门密码（与 username 配对，仅本机回环访问生效；留空即关闭）"},
			{key: "web.port", comment: "面板端口"},
			{key: "web.secure_cookie", comment: "会话 cookie 加 Secure 标记；仅在 HTTPS 访问时开启，\n# 否则浏览器拒存 cookie、登录直接失败"},
			{key: "web.username", skipEmpty: true, comment: "应急后门账号（忘记管理员密码时救急用；默认不写入文件）"},
		},
	},
}

// renderConfigYAML 把 viper 当前合并结果（默认值 + 文件值）渲染成带注释的 YAML。
func renderConfigYAML(v *viper.Viper) ([]byte, error) {
	var b strings.Builder
	b.WriteString("# go-port-forward 配置文件（程序生成并维护）\n")
	b.WriteString("#\n")
	b.WriteString("# 删除或缺失的配置项一律按程序默认值生效。\n")
	b.WriteString("# 升级程序后首次启动会自动补全新增配置项：自定义值原样保留、原文件备份为\n")
	b.WriteString("# config.yaml.v<N>.bak；注释会刷新为程序的标准注释，自行追加的注释不会保留。\n")
	for _, sec := range configLayout {
		if sec.head != "" {
			for _, line := range strings.Split(sec.head, "\n") {
				// 段头字符串里的续行可自带 "# " 前缀（源码里更好读），渲染时归一。
				fmt.Fprintf(&b, "# %s\n", strings.TrimPrefix(line, "# "))
			}
		}
		if sec.name != "" {
			fmt.Fprintf(&b, "%s:\n", sec.name)
		}
		for _, k := range sec.keys {
			val := v.Get(k.key)
			if k.skipEmpty {
				if s, ok := val.(string); !ok || s == "" {
					continue
				}
			}
			for _, line := range strings.Split(k.comment, "\n") {
				fmt.Fprintf(&b, "# %s\n", strings.TrimPrefix(line, "# "))
			}
			scalar, err := yamlScalar(val)
			if err != nil {
				return nil, fmt.Errorf("render %s: %w", k.key, err)
			}
			leaf := k.key
			if i := strings.LastIndexByte(leaf, '.'); i >= 0 {
				leaf = leaf[i+1:]
			}
			if sec.name != "" {
				fmt.Fprintf(&b, "    %s: %s\n", leaf, scalar)
			} else {
				fmt.Fprintf(&b, "%s: %s\n", leaf, scalar)
			}
		}
	}
	return []byte(b.String()), nil
}

// yamlScalar 把单个值序列化成 YAML 标量（让 yaml 库处理引号等转义细节）。
func yamlScalar(x any) (string, error) {
	out, err := yaml.Marshal(x)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
