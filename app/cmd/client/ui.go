//go:build windows

package main

// 本地控制面：给 UI 提供状态轮询与连接/断开操作。
//
// 只监听 127.0.0.1 的随机端口，不对外暴露；每次启动生成一次性 token，
// 所有写操作都要求匹配。这样即使本机上有其他程序探测到端口，也无法在
// 用户不知情的情况下建立隧道或改动系统路由。

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"
)

//go:embed ui
var uiFS embed.FS

type uiServer struct {
	eng   *Engine
	token string
	quit  chan struct{}
}

// startUI 在本地随机端口起 HTTP 服务，返回带 token 的入口 URL，以及一个
// 在用户点击「退出程序」后关闭的通道。
func startUI(eng *Engine) (string, <-chan struct{}, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("无法启动本地界面服务：%w", err)
	}

	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, err
	}
	s := &uiServer{eng: eng, token: hex.EncodeToString(buf), quit: make(chan struct{})}

	assets, err := fs.Sub(uiFS, "ui")
	if err != nil {
		return "", nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(assets)))
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/connect", s.handleConnect)
	mux.HandleFunc("/api/disconnect", s.handleDisconnect)
	mux.HandleFunc("/api/quit", s.handleQuit)

	// 超时只收紧读头部与空闲连接：/api/connect 的 Start 里可能含隧道握手
	// 甚至人机交互（等用户确认），不能给它套整个请求级的 WriteTimeout。
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()

	return fmt.Sprintf("http://%s/?t=%s", ln.Addr().String(), s.token), s.quit, nil
}

// authed 校验一次性 token（常量时间比较，避免时序泄漏）。
func (s *uiServer) authed(r *http.Request) bool {
	got := r.URL.Query().Get("t")
	if got == "" {
		got = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *uiServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid token"})
		return
	}
	snap := s.eng.Snapshot()
	if snap.Addr == "" {
		// 尚未连接过：把上次记住的凭据回填给界面，用户不必重新粘贴接入码。
		last := loadConfig()
		snap.Addr = last.Addr
		snap.CodeID = last.CodeID
		snap.HasCred = last.complete()
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *uiServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) || r.Method != http.MethodPost {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid request"})
		return
	}
	var req struct {
		Code   string `json:"code"`
		Addr   string `json:"addr"`
		CodeID string `json:"code_id"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
		return
	}
	// 三个字段都空时沿用已保存的凭据（界面上的「连接」按钮不必每次重填）。
	if strings.TrimSpace(req.Code) == "" && strings.TrimSpace(req.CodeID) == "" && strings.TrimSpace(req.Secret) == "" {
		saved := loadConfig()
		if saved.complete() {
			if a := strings.TrimSpace(req.Addr); a != "" {
				saved.Addr = a
			}
			s.start(w, saved)
			return
		}
	}
	conf, err := parseConnectInput(req.Code, req.Addr, req.CodeID, req.Secret)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.start(w, conf)
}

func (s *uiServer) start(w http.ResponseWriter, conf clientConfig) {
	if err := s.eng.Start(conf); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"addr": conf.normalized().Addr})
}

func (s *uiServer) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) || r.Method != http.MethodPost {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid request"})
		return
	}
	s.eng.Stop()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleQuit 退出整个程序。关掉浏览器标签页不会结束进程（隧道要在后台继续
// 工作），所以界面上需要一个明确的出口来触发路由与防火墙规则的清理。
//
// **必须先同步停完隧道再发退出信号**：窗口（含本页面）随 WM_CLOSE 立即消失，
// 而路由删除（每个玩家一次 route.exe）要在这之后才执行。若先关窗口，用户看到
// 「已退出」就会去复制新版本 exe——进程仍在清理中被锁定，复制失败后用户去
// 任务管理器杀进程，清理被拦腰截断，残留路由让老玩家全部连不上（2026-09-03
// 实测事故）。停完再关窗：窗口消失 = 清理已完成。
func (s *uiServer) handleQuit(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) || r.Method != http.MethodPost {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid request"})
		return
	}
	s.eng.Stop()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	close(s.quit)
}
