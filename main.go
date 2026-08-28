package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-port-forward/internal/config"
	"go-port-forward/internal/firewall"
	"go-port-forward/internal/forward"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/storage"
	"go-port-forward/internal/tunnelapp"
	"go-port-forward/internal/svc"
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
	store      storage.Store
	cfg        *config.AppConfig
	mgr        *forward.Manager
	webSrv     *web.Server
	gcSvc      *gc.Service
	tunnelSrv  *tunnelapp.Server
	configPath string
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

	// 内置隧道服务端（配合 Windows pf-client，透明模式回程）
	if cfg.Tunnel.Enabled {
		tsrv, terr := tunnelapp.Start(tunnelapp.Config{
			Enabled: true,
			Listen:  cfg.Tunnel.Listen,
			PSK:     cfg.Tunnel.PSK,
			TunName: cfg.Tunnel.TunName,
			TunAddr: cfg.Tunnel.TunAddr,
			NAT:     cfg.Tunnel.NAT,
		}, func() []string {
			// 从活跃会话提取来源 IP（去重由调用方内部处理）
			var ips []string
			seen := map[string]bool{}
			for _, s := range mgr.Sessions() {
				if s.SrcIP != "" && !seen[s.SrcIP] {
					seen[s.SrcIP] = true
					ips = append(ips, s.SrcIP)
				}
			}
			return ips
		})
		if terr != nil {
			return fmt.Errorf("tunnel server: %w", terr)
		}
		a.tunnelSrv = tsrv
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
	srv := web.New(cfg.Web, mgr, fw)
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
