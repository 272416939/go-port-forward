package config

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// AppConfig holds all application configuration.
type AppConfig struct {
	Web     WebConfig     `mapstructure:"web"`
	Storage StorageConfig `mapstructure:"storage"`
	GC      GCConfig      `mapstructure:"gc"`
	Log     LogConfig     `mapstructure:"log"`
	Forward ForwardConfig `mapstructure:"forward"`
	Pool    PoolConfig    `mapstructure:"pool"`
	Tunnel  TunnelConfig  `mapstructure:"tunnel"`
}

// TunnelConfig holds the built-in tunnel server (for Windows pf-client peers).
type TunnelConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Listen  string `mapstructure:"listen"` // UDP listen, default ":7947"
	// PSK is deprecated since the multi-user protocol (v2): every tunnel user
	// carries its own secret. Kept so old config files still load; ignored.
	PSK        string `mapstructure:"psk"`
	TunName    string `mapstructure:"tun_name"`
	TunAddr    string `mapstructure:"tun_addr"`    // e.g. "10.66.0.1/16" — also the access-code address pool
	PublicAddr string `mapstructure:"public_addr"` // relay address embedded in access codes, e.g. "1.2.3.4:7947"
	NAT        bool   `mapstructure:"nat"`         // ip_forward + MASQUERADE + FORWARD accept

	// IOMode 选择 UDP 收发方式："batch"（recvmmsg/sendmmsg，默认）或 "simple"
	// （逐包）。批量化把「每包 2 次 syscall」压到「每批 2 次」，是高 pps 下
	// 吞吐的最大杠杆；留开关是因为它也是数据面上最脆弱的一处改动——回退不必
	// 换二进制。非 Linux 自动降级为 simple。
	IOMode string `mapstructure:"io_mode"`
	// FEC 启用前向纠错：每 8 个数据包附 1 个 XOR 校验包，组内丢 1 个可无损
	// 补回（省掉应用层重传的一个 RTT，跨网玩家 80~150ms）。代价是下行冗余
	// 12.5%，且隧道 MTU 要让出 83 字节给校验包（不让它就会被 IP 分片，而
	// 分片丢一片等于整包全损，正是 FEC 想解决的问题）。
	//
	// 默认关闭是有意的：丢包率低于 1% 的链路上这是纯浪费，还会掩盖真实的
	// 网络问题。先看面板里的丢包率，再决定要不要开。
	FEC bool `mapstructure:"fec"`
	// TailDup 启用小包冗余副本：≤256 字节的数据包发两份（限频 20ms），接收端
	// 靠重放窗口免费去重。补的是 FEC 的盲区——组尾小包（组没满就没有校验包），
	// 而玩家操作指令、RakNet 探测恰好落在那里。
	TailDup bool `mapstructure:"tail_dup"`
	// UDPGRO / UDPGSO 是 Linux 的 UDP 聚合/分段卸载（需内核 ≥ 5.0）。
	// 默认关闭：收益要等观测数据证明「批量化之后单核仍是瓶颈」才成立，而 GSO
	// 要求一条消息内各段等长，游戏流量的包长参差不齐，命中率天然很低。
	UDPGRO bool `mapstructure:"udp_gro"`
	UDPGSO bool `mapstructure:"udp_gso"`
}

// WebConfig holds web server configuration.
type WebConfig struct {
	Host string `mapstructure:"host"`
	// Username/Password 是应急后门账号：多用户改造后正式账号存在 bbolt 里，
	// 这对凭据只在回环访问时生效（见 internal/web/server.go），用于忘记
	// 管理员密码时救急。留空即关闭。
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Port     int    `mapstructure:"port"`
	// SecureCookie 给会话 cookie 打 Secure 标记。仅在通过 HTTPS（通常是 TLS
	// 反向代理）访问面板时开启，否则浏览器会拒绝保存 cookie、登录直接失败。
	SecureCookie bool `mapstructure:"secure_cookie"`
}

// StorageConfig holds storage configuration.
type StorageConfig struct {
	Path string `mapstructure:"path"`
}

// LogConfig holds logging configuration.
type LogConfig struct {
	Level      string `mapstructure:"level"`
	Path       string `mapstructure:"path"`
	MaxSizeMB  int    `mapstructure:"max_size_mb"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAgeDays int    `mapstructure:"max_age_days"`
	Compress   bool   `mapstructure:"compress"`
}

// ForwardConfig holds forwarding tuning parameters.
type ForwardConfig struct {
	PoolSize          int `mapstructure:"pool_size"`           // goroutine pool size (0 = NumCPU*64)
	BufferSize        int `mapstructure:"buffer_size"`         // I/O buffer size in bytes
	UDPTimeout        int `mapstructure:"udp_timeout"`         // UDP session idle timeout (seconds)
	DialTimeout       int `mapstructure:"dial_timeout"`        // outbound dial timeout (seconds)
	ConnLogMaxEntries int `mapstructure:"connlog_max_entries"` // connection log retention cap (rows)
}

// GCConfig holds garbage collection management configuration.
type GCConfig struct {
	Strategy          string `mapstructure:"strategy"`            // standard, aggressive, gentle, adaptive
	IntervalSeconds   int    `mapstructure:"interval_seconds"`    // GC interval in seconds
	MemoryThresholdMB int    `mapstructure:"memory_threshold_mb"` // memory threshold in MB (0 = disabled)
	Enabled           bool   `mapstructure:"enabled"`             // enable periodic GC
	EnableMonitoring  bool   `mapstructure:"enable_monitoring"`   // enable performance monitoring
}

// PoolConfig holds goroutine pool configuration.
type PoolConfig struct {
	Size     int  `mapstructure:"size"`      // goroutine pool capacity (0 = 10000)
	PreAlloc bool `mapstructure:"pre_alloc"` // pre-allocate goroutine pool
}

var global *AppConfig

// Load reads configuration from disk, writing defaults on first run.
func Load(configPath string) (*AppConfig, error) {
	v := viper.New()
	setDefaults(v)

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		dir := appDataDir()
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(dir)
		v.AddConfigPath(".")
	}

	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		if _, ok := errors.AsType[viper.ConfigFileNotFoundError](err); !ok {
			return nil, err
		}
		// First run – persist defaults so users can see the config file.
		if e2 := writeDefaults(v, configPath); e2 != nil {
			return nil, e2
		}
	}

	cfg := &AppConfig{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}

	_ = os.MkdirAll(filepath.Dir(cfg.Storage.Path), 0o755)
	_ = os.MkdirAll(filepath.Dir(cfg.Log.Path), 0o755)

	global = cfg
	return cfg, nil
}

// Get returns the global AppConfig (Load must be called first).
func Get() *AppConfig { return global }

func setDefaults(v *viper.Viper) {
	dir := appDataDir()
	v.SetDefault("web.host", "127.0.0.1")
	v.SetDefault("web.port", 8989)
	v.SetDefault("web.secure_cookie", false)
	v.SetDefault("storage.path", filepath.Join(dir, "data", "rules.db"))
	v.SetDefault("log.level", "info")
	v.SetDefault("log.path", filepath.Join(dir, "logs", "app.log"))
	v.SetDefault("log.max_size_mb", 50)
	v.SetDefault("log.max_backups", 5)
	v.SetDefault("log.max_age_days", 30)
	v.SetDefault("log.compress", true)
	v.SetDefault("forward.pool_size", 0)
	v.SetDefault("forward.buffer_size", 32768)
	v.SetDefault("forward.udp_timeout", 30)
	v.SetDefault("forward.dial_timeout", 10)
	v.SetDefault("forward.connlog_max_entries", 2000)

	v.SetDefault("tunnel.enabled", false)
	v.SetDefault("tunnel.listen", ":7947")
	v.SetDefault("tunnel.psk", "")
	v.SetDefault("tunnel.tun_name", "pftun0")
	// /16 而不是 /24：隧道地址按访问码分配（一个访问码一台设备），/24 的
	// 253 个位置在几十个用户时就会耗尽。已写死 /24 的旧部署不受影响。
	v.SetDefault("tunnel.tun_addr", "10.66.0.1/16")
	v.SetDefault("tunnel.public_addr", "")
	v.SetDefault("tunnel.nat", true)
	// 批量收发默认开启（非 Linux 自动降级）；纠错与卸载默认关闭，理由见
	// TunnelConfig 上的注释。
	v.SetDefault("tunnel.io_mode", "batch")
	v.SetDefault("tunnel.fec", false)
	v.SetDefault("tunnel.tail_dup", false)
	v.SetDefault("tunnel.udp_gro", false)
	v.SetDefault("tunnel.udp_gso", false)

	// GC defaults
	v.SetDefault("gc.enabled", true)
	v.SetDefault("gc.interval_seconds", 300) // 5 minutes
	v.SetDefault("gc.strategy", "standard")
	v.SetDefault("gc.memory_threshold_mb", 100)
	v.SetDefault("gc.enable_monitoring", true)

	// Pool defaults
	v.SetDefault("pool.size", 10000)
	v.SetDefault("pool.pre_alloc", true)
}

func writeDefaults(v *viper.Viper, configPath string) error {
	dir := appDataDir()
	_ = os.MkdirAll(dir, 0o755)
	if configPath == "" {
		configPath = filepath.Join(dir, "config.yaml")
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return err
	}
	return v.WriteConfigAs(configPath)
}

// appDataDir returns the directory of the running executable.
func appDataDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}
