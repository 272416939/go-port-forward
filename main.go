package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/config"
	"go-port-forward/internal/firewall"
	"go-port-forward/internal/forward"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
	"go-port-forward/internal/svc"
	"go-port-forward/internal/tunnelapp"
	"go-port-forward/internal/users"
	"go-port-forward/internal/web"
	"go-port-forward/pkg/gc"
	pkglogger "go-port-forward/pkg/logger"
	"go-port-forward/pkg/pool"
)

// version and buildTime are set via ldflags at build time:
//
//	go build -ldflags "-X main.version=v1.0.0 -X main.buildTime=2025-01-01T00:00:00Z"
var (
	version   = "dev"
	buildTime = "unknown"
)

const (
	serviceName    = "go-port-forward"
	serviceDisplay = "Go Port Forward"
	serviceDesc    = "Cross-platform TCP/UDP port forwarder with web UI"
)

func main() {
	var (
		configPath = flag.String("config", "", "path to config.yaml (default: next to executable)")
		serviceCmd = flag.String("service", "", "service command: install | uninstall | run")
	)
	flag.Parse()

	// Service install/uninstall don't need the full app to start.
	sc := svc.Config{Name: serviceName, DisplayName: serviceDisplay, Description: serviceDesc}
	switch *serviceCmd {
	case "install":
		if err := svc.Install(sc); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "install service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Service installed.")
		return
	case "uninstall":
		if err := svc.Uninstall(sc); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "uninstall service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Service uninstalled.")
		return
	}

	// --- Normal / "run" path ---
	app := &application{configPath: *configPath}

	if *serviceCmd == "run" {
		// Hand control to service manager (blocks until stopped by OS).
		if err := svc.Run(sc, app); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "service run: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Interactive foreground run.
	if err := app.Start(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "start: %v\n", err)
		os.Exit(1)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// 关停要有兜底：任何一处清理卡住（外部命令挂起、阻塞读没被唤醒等）都不该
	// 让进程停不下来。超时或再按一次 Ctrl+C 都直接退出。
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := app.Stop(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "stop: %v\n", err)
		}
	}()
	select {
	case <-done:
	case <-quit:
		_, _ = fmt.Fprintln(os.Stderr, "收到第二次中断信号，强制退出。")
		os.Exit(1)
	case <-time.After(shutdownTimeout):
		_, _ = fmt.Fprintf(os.Stderr, "关停超过 %s 未完成，强制退出。\n", shutdownTimeout)
		os.Exit(1)
	}
}

// shutdownTimeout 是整个关停流程的硬上限。比内部各步骤的超时之和略宽即可。
const shutdownTimeout = 15 * time.Second

// application wires all subsystems together and implements svc.Runner.
type application struct {
	store       storage.Store
	cfg         *config.AppConfig
	mgr         *forward.Manager
	webSrv      *web.Server
	gcSvc       *gc.Service
	tunnelSrv   *tunnelapp.Server
	users       *users.Service
	sessions    *auth.Store
	sessionStop chan struct{}
	configPath  string
}

// sweepSessions 周期清理已过期的会话。
// 会话在查询时就会检查过期，这里只是防止长期运行下 map 只增不减。
func sweepSessions(store *auth.Store, stop <-chan struct{}) {
	tick := time.NewTicker(30 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			store.Sweep()
		}
	}
}

func (a *application) Start() error {
	// Config
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	a.cfg = cfg

	// Logger
	if err := logger.Init(cfg.Log); err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	logger.S.Infow("starting", "name", serviceDisplay, "version", version, "build", buildTime)

	// Bridge internal logger to pkg/logger so pkg/gc etc. can log
	pkglogger.SetLogger(logger.L)

	// Goroutine pool (global, used by forward and gc)
	poolSize := cfg.Pool.Size
	if poolSize <= 0 {
		poolSize = 10000
	}
	if err := pool.InitGoroutinePool(poolSize, cfg.Pool.PreAlloc); err != nil {
		return fmt.Errorf("goroutine pool: %w", err)
	}
	logger.S.Infow("goroutine pool initialized", "size", poolSize, "preAlloc", cfg.Pool.PreAlloc)

	// Storage
	store, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		return fmt.Errorf("storage: %w", err)
	}
	a.store = store

	// Forward manager
	mgr, err := forward.NewManager(store, cfg.Forward)
	if err != nil {
		return fmt.Errorf("forward manager: %w", err)
	}
	a.mgr = mgr

	// 用户与会话（Web 账号 == 隧道身份）
	a.sessions = auth.NewStore(cfg.Web.SecureCookie)
	a.sessionStop = make(chan struct{})
	go sweepSessions(a.sessions, a.sessionStop)
	usrs, uerr := users.New(store, a.sessions, cfg.Tunnel.TunAddr, cfg.Tunnel.PublicAddr)
	if uerr != nil {
		return fmt.Errorf("user service: %w", uerr)
	}
	a.users = usrs
	if _, _, _, berr := usrs.Bootstrap(); berr != nil {
		return fmt.Errorf("bootstrap admin: %w", berr)
	}
	if cfg.Tunnel.PSK != "" {
		logger.S.Warnw("配置项 tunnel.psk 已废弃并被忽略：多用户协议为每个用户分配独立密钥，请在面板的用户管理中获取接入码 | tunnel.psk is deprecated and ignored")
	}

	// 内置隧道服务端（配合 Windows pf-client，透明模式回程）
	if cfg.Tunnel.Enabled {
		tsrv, terr := tunnelapp.Start(tunnelapp.Options{
			Config: tunnelapp.Config{
				Enabled: true,
				Listen:  cfg.Tunnel.Listen,
				TunName: cfg.Tunnel.TunName,
				TunAddr: cfg.Tunnel.TunAddr,
				NAT:     cfg.Tunnel.NAT,
			},
			Identity: func(codeID string) (tunnelapp.Identity, bool) {
				// 服务端拿到的是握手包里声称的访问码 ID；查到密钥后由协议层验 MAC。
				ci, found := usrs.Identity(codeID)
				if !found {
					return tunnelapp.Identity{}, false
				}
				tunIP, valid := models.ParseTunIP(ci.TunIP)
				if !valid {
					return tunnelapp.Identity{}, false
				}
				return tunnelapp.Identity{
					CodeID:       ci.CodeID,
					CodeName:     ci.CodeName,
					UserID:       ci.UserID,
					UserName:     ci.UserName,
					Secret:       []byte(ci.Secret),
					TunIP:        tunIP,
					CodeDisabled: ci.CodeDisabled,
					UserDisabled: ci.UserDisabled,
					Fingerprint:  ci.Fingerprint,
					MaxTunnels:   ci.MaxTunnels,
				}, true
			},
			Binder: usrs,
			SessionIPs: func() map[string][]string {
				// 「隧道地址 → 访问码」是用户服务的知识；manager 只按目标地址
				// 分组，不需要知道访问码的存在。
				tunIPs, err := usrs.AllTunIPs()
				if err != nil {
					return nil
				}
				return mgr.SessionIPsByCode(tunIPs)
			},
		})
		if terr != nil {
			return fmt.Errorf("tunnel server: %w", terr)
		}
		a.tunnelSrv = tsrv
		// 反向注入：停用/解绑/删除访问码时用户服务要能踢掉在线隧道。
		usrs.SetEvictor(tsrv)
		logger.S.Infow("tunnel server started", "listen", cfg.Tunnel.Listen, "tun", cfg.Tunnel.TunName)
	}

	// GC service
	gcCfg := &gc.Config{
		Enabled:          cfg.GC.Enabled,
		Interval:         time.Duration(cfg.GC.IntervalSeconds) * time.Second,
		Strategy:         gc.StrategyType(cfg.GC.Strategy),
		MemoryThreshold:  uint64(cfg.GC.MemoryThresholdMB) * 1024 * 1024,
		EnableStats:      true,
		EnableMonitoring: cfg.GC.EnableMonitoring,
		MaxRetries:       2,
		RetryInterval:    10 * time.Second,
		ExecutionTimeout: 60 * time.Second,
	}
	gcSvc, err := gc.NewService(gcCfg)
	if err != nil {
		logger.S.Warnw("GC service init failed, continuing without GC management", "err", err)
	} else {
		if err := gcSvc.Start(); err != nil {
			logger.S.Warnw("GC service start failed", "err", err)
		} else {
			a.gcSvc = gcSvc
			logger.S.Infow("GC service started",
				"strategy", cfg.GC.Strategy,
				"interval", gcCfg.Interval)
		}
	}

	// Web server
	fw := firewall.New()
	var tunStatus web.TunnelStatus
	if a.tunnelSrv != nil {
		tunStatus = a.tunnelSrv
	}
	srv := web.New(cfg.Web, mgr, fw, a.users, a.sessions, tunStatus)
	if err := srv.Start(); err != nil {
		return fmt.Errorf("web server: %w", err)
	}
	a.webSrv = srv

	return nil
}

func (a *application) Stop() error {
	logger.S.Info("shutting down …")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if a.webSrv != nil {
		_ = a.webSrv.Shutdown(ctx)
	}
	if a.mgr != nil {
		a.mgr.Shutdown()
	}
	if a.sessionStop != nil {
		close(a.sessionStop)
		a.sessionStop = nil
	}
	if a.tunnelSrv != nil {
		a.tunnelSrv.Stop()
	}
	if a.gcSvc != nil {
		_ = a.gcSvc.Stop()
	}
	if a.store != nil {
		_ = a.store.Close()
	}

	// Release global goroutine pool
	pool.Release()

	logger.Sync()
	pkglogger.Sync()
	return nil
}
