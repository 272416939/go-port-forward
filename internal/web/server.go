package web

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"go-port-forward/internal/auth"
	"go-port-forward/internal/config"
	"go-port-forward/internal/firewall"
	"go-port-forward/internal/forward"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/users"
	"io/fs"
	"net"
	"net/http"
	"path"
	"strings"
	"time"
)

// staticMIME maps file extensions to correct MIME types, derived from the
// official Nginx mime.types with additions for modern web formats.
// This bypasses mime.TypeByExtension which on Windows reads from the registry
// and may return text/plain, causing browsers to reject resources when
// X-Content-Type-Options: nosniff is set.
//
// Reference: https://github.com/nginx/nginx/blob/master/conf/mime.types
var staticMIME = map[string]string{
	// ── Text ──
	".html":     "text/html; charset=utf-8",
	".htm":      "text/html; charset=utf-8",
	".shtml":    "text/html; charset=utf-8",
	".css":      "text/css; charset=utf-8",
	".xml":      "text/xml; charset=utf-8",
	".csv":      "text/csv; charset=utf-8",
	".txt":      "text/plain; charset=utf-8",
	".vtt":      "text/vtt; charset=utf-8",
	".mml":      "text/mathml",
	".htc":      "text/x-component",
	".ics":      "text/calendar; charset=utf-8",
	".vcf":      "text/vcard; charset=utf-8",
	".md":       "text/markdown; charset=utf-8",
	".markdown": "text/markdown; charset=utf-8",
	".yaml":     "text/yaml; charset=utf-8",
	".yml":      "text/yaml; charset=utf-8",
	".jad":      "text/vnd.sun.j2me.app-descriptor",
	".wml":      "text/vnd.wap.wml",

	// ── JavaScript / JSON / WASM ──
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".json":        "application/json; charset=utf-8",
	".jsonld":      "application/ld+json; charset=utf-8",
	".geojson":     "application/geo+json; charset=utf-8",
	".map":         "application/json",
	".webmanifest": "application/manifest+json",
	".wasm":        "application/wasm",

	// ── XML-based ──
	".atom":  "application/atom+xml",
	".rss":   "application/rss+xml",
	".xhtml": "application/xhtml+xml",
	".xspf":  "application/xspf+xml",
	".xslt":  "application/xslt+xml",
	".kml":   "application/vnd.google-earth.kml+xml",
	".kmz":   "application/vnd.google-earth.kmz",

	// ── Images ──
	".apng": "image/apng",
	".avif": "image/avif",
	".bmp":  "image/x-ms-bmp",
	".cur":  "image/x-icon",
	".gif":  "image/gif",
	".heic": "image/heic",
	".heif": "image/heif",
	".ico":  "image/x-icon",
	".jpeg": "image/jpeg",
	".jpg":  "image/jpeg",
	".jng":  "image/x-jng",
	".jxl":  "image/jxl",
	".png":  "image/png",
	".svg":  "image/svg+xml",
	".svgz": "image/svg+xml",
	".tif":  "image/tiff",
	".tiff": "image/tiff",
	".wbmp": "image/vnd.wap.wbmp",
	".webp": "image/webp",

	// ── Fonts ──
	".eot":   "application/vnd.ms-fontobject",
	".otf":   "font/otf",
	".ttf":   "font/ttf",
	".ttc":   "font/collection",
	".woff":  "font/woff",
	".woff2": "font/woff2",

	// ── Audio ──
	".aac":  "audio/aac",
	".flac": "audio/flac",
	".kar":  "audio/midi",
	".m4a":  "audio/x-m4a",
	".mid":  "audio/midi",
	".midi": "audio/midi",
	".mp3":  "audio/mpeg",
	".oga":  "audio/ogg",
	".ogg":  "audio/ogg",
	".opus": "audio/opus",
	".ra":   "audio/x-realaudio",
	".wav":  "audio/wav",
	".weba": "audio/webm",

	// ── Video ──
	".3gp":  "video/3gpp",
	".3gpp": "video/3gpp",
	".asf":  "video/x-ms-asf",
	".asx":  "video/x-ms-asf",
	".avi":  "video/x-msvideo",
	".flv":  "video/x-flv",
	".m4v":  "video/x-m4v",
	".mkv":  "video/x-matroska",
	".mng":  "video/x-mng",
	".mov":  "video/quicktime",
	".mp4":  "video/mp4",
	".mpeg": "video/mpeg",
	".mpg":  "video/mpeg",
	".ogv":  "video/ogg",
	".ts":   "video/mp2t",
	".webm": "video/webm",
	".wmv":  "video/x-ms-wmv",

	// ── Archives / Packages ──
	".7z":  "application/x-7z-compressed",
	".br":  "application/brotli",
	".bz2": "application/x-bzip2",
	".deb": "application/vnd.debian.binary-package",
	".dmg": "application/x-apple-diskimage",
	".gz":  "application/gzip",
	".iso": "application/x-iso9660-image",
	".rar": "application/x-rar-compressed",
	".rpm": "application/x-redhat-package-manager",
	".tar": "application/x-tar",
	".tgz": "application/gzip",
	".xz":  "application/x-xz",
	".zip": "application/zip",
	".zst": "application/zstd",

	// ── Documents / Office ──
	".doc":  "application/msword",
	".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".epub": "application/epub+zip",
	".odg":  "application/vnd.oasis.opendocument.graphics",
	".odp":  "application/vnd.oasis.opendocument.presentation",
	".ods":  "application/vnd.oasis.opendocument.spreadsheet",
	".odt":  "application/vnd.oasis.opendocument.text",
	".pdf":  "application/pdf",
	".ppt":  "application/vnd.ms-powerpoint",
	".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	".rtf":  "application/rtf",
	".xls":  "application/vnd.ms-excel",
	".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",

	// ── Security / Certificates ──
	".crt": "application/x-x509-ca-cert",
	".der": "application/x-x509-ca-cert",
	".p7s": "application/pkcs7-signature",
	".pem": "application/x-x509-ca-cert",

	// ── Binary / Executable ──
	".bin": "application/octet-stream",
	".dll": "application/octet-stream",
	".exe": "application/octet-stream",
	".msi": "application/octet-stream",

	// ── Other Application ──
	".ai":      "application/postscript",
	".apk":     "application/vnd.android.package-archive",
	".cbor":    "application/cbor",
	".cco":     "application/x-cocoa",
	".ear":     "application/java-archive",
	".eps":     "application/postscript",
	".hqx":     "application/mac-binhex40",
	".jar":     "application/java-archive",
	".jardiff": "application/x-java-archive-diff",
	".jnlp":    "application/x-java-jnlp-file",
	".m3u8":    "application/vnd.apple.mpegurl",
	".mpd":     "application/dash+xml",
	".pl":      "application/x-perl",
	".pm":      "application/x-perl",
	".ps":      "application/postscript",
	".run":     "application/x-makeself",
	".sea":     "application/x-sea",
	".sit":     "application/x-stuffit",
	".sqlite":  "application/vnd.sqlite3",
	".swf":     "application/x-shockwave-flash",
	".torrent": "application/x-bittorrent",
	".war":     "application/java-archive",
	".wmlc":    "application/vnd.wap.wmlc",
	".xpi":     "application/x-xpinstall",
}

//go:embed static
var staticFiles embed.FS

// Server is the HTTP API + UI server.
type Server struct {
	fw       firewall.Manager
	manager  *forward.Manager
	users    *users.Service
	sessions *auth.Store
	tunnel   TunnelStatus
	httpSrv  *http.Server
	cfg      config.WebConfig
}

// TunnelStatus 暴露隧道服务端的在线状态（避免 web 直接依赖 tunnelapp）。
//
// 在线判定已下移到 users.Service（它需要把访问码与在线状态拼在一起），这里
// 只留一个总数给诊断页。
type TunnelStatus interface {
	PeerCount() int
}

// New creates a configured Server.
func New(cfg config.WebConfig, mgr *forward.Manager, fw firewall.Manager,
	usrs *users.Service, sessions *auth.Store, tun TunnelStatus) *Server {
	return &Server{cfg: cfg, manager: mgr, fw: fw, users: usrs, sessions: sessions, tunnel: tun}
}

// Start begins listening on the configured address (non-blocking).
func (s *Server) Start() error {
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	s.httpSrv = &http.Server{
		Addr:         addr,
		Handler:      s.middlewareChain(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.S.Infow("Web UI listening", "addr", "http://"+addr)
		if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.S.Errorw("HTTP server error", "err", err)
		}
	}()
	return nil
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	h := &handler{
		mgr:     s.manager,
		fw:      s.fw,
		users:   s.users,
		sessions: s.sessions,
		tunnel:  s.tunnel,
		// 登录防爆破：IP 维度放宽些（办公室 NAT 后多人共用），用户名维度收紧；
		// 验证码端点按 IP 限发送量，防被当垃圾邮件中继。
		loginIPFail:   users.NewRateLimiter(30, 15*time.Minute),
		loginUserFail: users.NewRateLimiter(10, 15*time.Minute),
		emailCodeIP:   users.NewRateLimiter(20, time.Hour),
	}

	// 认证（公开 + 登录后）
	mux.HandleFunc("POST /api/auth/login", h.login)
	mux.HandleFunc("POST /api/auth/logout", h.logout)
	mux.HandleFunc("GET /api/auth/me", s.authed(h.me))
	mux.HandleFunc("POST /api/auth/password", s.authed(h.changePassword))

	// 自助注册与找回密码（公开；注册受全局开关控制）
	mux.HandleFunc("GET /api/auth/public-config", h.publicConfig)
	mux.HandleFunc("POST /api/auth/register", h.register)
	mux.HandleFunc("POST /api/auth/email-code", h.emailCode)
	mux.HandleFunc("POST /api/auth/forgot-password", h.forgotPassword)

	// REST API — 规则按归属过滤/校验，任何登录用户可访问
	mux.HandleFunc("GET /api/rules", s.authed(h.listRules))
	mux.HandleFunc("POST /api/rules", s.authed(h.createRule))
	mux.HandleFunc("GET /api/rules/{id}", s.authed(h.getRule))
	mux.HandleFunc("PUT /api/rules/{id}", s.authed(h.updateRule))
	mux.HandleFunc("DELETE /api/rules/{id}", s.authed(h.deleteRule))
	mux.HandleFunc("PUT /api/rules/{id}/toggle", s.authed(h.toggleRule))
	mux.HandleFunc("GET /api/dashboard", s.authed(h.dashboard))
	mux.HandleFunc("GET /api/stats", s.authed(h.globalStats))

	// 访问控制 / 连接日志 / 活跃会话
	mux.HandleFunc("GET /api/acl", s.adminOnly(h.listACL))
	mux.HandleFunc("POST /api/acl", s.adminOnly(h.createACL))
	mux.HandleFunc("DELETE /api/acl/{id}", s.adminOnly(h.deleteACL))
	mux.HandleFunc("GET /api/logs", s.authed(h.listConnLogs))
	mux.HandleFunc("GET /api/sessions", s.authed(h.listSessions))

	// 端口检测与随机（登录即可；检测范围受配额区间约束）
	mux.HandleFunc("GET /api/ports/check", s.authed(h.checkPort))
	mux.HandleFunc("GET /api/ports/random", s.authed(h.randomPort))

	// 用户管理（仅管理员）
	mux.HandleFunc("GET /api/users", s.adminOnly(h.listUsers))
	mux.HandleFunc("POST /api/users", s.adminOnly(h.createUser))
	mux.HandleFunc("PUT /api/users/{id}", s.adminOnly(h.updateUser))
	mux.HandleFunc("DELETE /api/users/{id}", s.adminOnly(h.deleteUser))

	// 访问码：登录即可，作用域默认为自己；管理员可带 ?user_id= 管理他人。
	mux.HandleFunc("GET /api/access-codes", s.authed(h.listAccessCodes))
	mux.HandleFunc("POST /api/access-codes", s.authed(h.createAccessCode))
	mux.HandleFunc("PUT /api/access-codes/{id}", s.authed(h.updateAccessCode))
	mux.HandleFunc("DELETE /api/access-codes/{id}", s.authed(h.deleteAccessCode))
	mux.HandleFunc("GET /api/access-codes/{id}/code", s.authed(h.accessCodeText))
	mux.HandleFunc("POST /api/access-codes/{id}/regenerate", s.authed(h.regenerateAccessCode))
	mux.HandleFunc("POST /api/access-codes/{id}/unbind", s.authed(h.unbindAccessCode))

	// 用户组与全局设置（仅管理员）
	mux.HandleFunc("GET /api/groups", s.adminOnly(h.listGroups))
	mux.HandleFunc("POST /api/groups", s.adminOnly(h.createGroup))
	mux.HandleFunc("PUT /api/groups/{id}", s.adminOnly(h.updateGroup))
	mux.HandleFunc("DELETE /api/groups/{id}", s.adminOnly(h.deleteGroup))
	mux.HandleFunc("GET /api/settings", s.adminOnly(h.getSettings))
	mux.HandleFunc("PUT /api/settings", s.adminOnly(h.updateSettings))

	// SMTP 邮件设置（仅管理员；密码永不回显）
	mux.HandleFunc("GET /api/smtp", s.adminOnly(h.getSMTP))
	mux.HandleFunc("PUT /api/smtp", s.adminOnly(h.updateSMTP))
	mux.HandleFunc("POST /api/smtp/test", s.adminOnly(h.testSMTP))

	// 诊断与系统级操作（仅管理员）
	mux.HandleFunc("GET /api/diagnostics", s.adminOnly(h.diagnostics))
	mux.HandleFunc("GET /api/wsl/capability", s.adminOnly(h.wslCapability))
	mux.HandleFunc("GET /api/wsl/distros", s.adminOnly(h.wslListDistros))
	mux.HandleFunc("GET /api/wsl/ports/{distro}", s.adminOnly(h.wslListPorts))
	mux.HandleFunc("POST /api/wsl/import", s.adminOnly(h.wslImport))

	// Embedded SPA — wrap with fixMIME to guarantee correct Content-Type
	staticFS, _ := fs.Sub(staticFiles, "static")
	spa := fixMIME(http.FileServer(http.FS(staticFS)))
	// SPA 入口网关：未登录的访客直接 302 到登录页，浏览器不再短暂渲染面板
	// 骨架后靠 JS 跳转（index.html 的身份校验仍保留，兜住「有 cookie 但
	// 会话已过期」的情况——进程重启会使全部会话失效）。
	mux.Handle("/", s.spaGate(spa))
}

// spaGate 把未登录的 SPA 入口请求重定向到登录页。
//
// 只拦 SPA 入口（/ 与 /index.html）：其余静态资源（login.html 自身、css/js、
// 图标）保持公开。判定是「有没有凭据的痕迹」——cookie 存在（有效性由 API 层
// 校验）或带 Authorization 头（应急后门的 Basic Auth 用法）即放行，避免在
// 静态文件路径上做完整的会话校验。
func (s *Server) spaGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			p := r.URL.Path
			if p == "/" || p == "/index.html" {
				if auth.TokenFromRequest(r) == "" && r.Header.Get("Authorization") == "" {
					http.Redirect(w, r, "/login.html", http.StatusFound)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// fixMIME wraps a handler to force correct Content-Type for known static file
// extensions. This bypasses http.FileServer's reliance on mime.TypeByExtension
// (which reads from the Windows registry and may return text/plain).
func fixMIME(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct, ok := staticMIME[strings.ToLower(path.Ext(r.URL.Path))]; ok {
			next.ServeHTTP(&mimeLockedWriter{ResponseWriter: w, contentType: ct}, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// mimeLockedWriter wraps http.ResponseWriter and forces the Content-Type
// header on the first WriteHeader/Write, preventing http.FileServer from
// overwriting it with an OS-derived value.
type mimeLockedWriter struct {
	http.ResponseWriter
	contentType string
	wroteHeader bool
}

func (w *mimeLockedWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.ResponseWriter.Header().Set("Content-Type", w.contentType)
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *mimeLockedWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.ResponseWriter.Header().Set("Content-Type", w.contentType)
	}
	return w.ResponseWriter.Write(b)
}

// middlewareChain wraps the mux with logging and security headers.
//
// 认证不再放在这里：多用户下「谁在访问」决定了「能看到什么数据」，判定必须
// 发生在能拿到 handler 上下文的地方（见 authed/adminOnly）。原先的全局
// Basic Auth 退位为仅回环生效的应急后门。
func (s *Server) middlewareChain(next http.Handler) http.Handler {
	next = requestLogger(next)
	next = securityHeaders(next)
	return next
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.S.Debugw("HTTP", "method", r.Method, "path", r.URL.Path,
			"duration", time.Since(start).String())
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
