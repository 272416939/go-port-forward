package web

// 端口相关的多租户脱敏与检测端点。

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strconv"

	"go-port-forward/internal/auth"
	"go-port-forward/internal/forward"
	"go-port-forward/internal/models"
)

// maskPortConflict 对端口冲突错误做按身份脱敏。
//
// ErrPortConflict 的原文含占用者的规则名——普通用户撞上别人的端口时不能看到
// 对方的命名（跨租户信息泄漏）；「端口被占用」这一事实本身无法隐藏（创建时
// 必须告知冲突），隐藏的是"被谁占用"。管理员保留完整信息用于排障。
//
// port 来自调用方自己的请求（不是占用者的信息，可以回显）。
func maskPortConflict(me *models.User, err error, port int) error {
	if err == nil || !errors.Is(err, forward.ErrPortConflict) {
		return err
	}
	if me != nil && me.IsAdmin() {
		return err
	}
	// 保留 ErrPortConflict 的身份：writeAPIError 靠 errors.Is 映射 409，
	// 换成裸 error 会让状态码退化成 500。
	return fmt.Errorf("%w: 监听端口 %d 已被占用，请更换端口或使用随机端口 | listen port %d is already in use",
		forward.ErrPortConflict, port, port)
}

// checkPort handles GET /api/ports/check?port=12345
//
// 服务端真实 bind 测试（TCP+UDP 各试绑后立即关闭）：浏览器无法探测服务器
// 端口，必须在这里做。普通用户只能检测自己配额区间内的端口——否则这个端点
// 会被用来探测中转机上任意端口（22/3306 空闲与否），绘制服务面。
func (h *handler) checkPort(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		unauthorized(w)
		return
	}
	port, err := strconv.Atoi(r.URL.Query().Get("port"))
	if err != nil || port <= 0 || port > 65535 {
		fail(w, http.StatusBadRequest, "端口无效 | invalid port")
		return
	}
	quota, err := h.users.EffectiveQuota(me)
	if err != nil {
		writeUserError(w, err)
		return
	}
	if !quota.PortAllowed(port) {
		writeGuardError(w, fmt.Errorf("端口 %d 超出你的配额区间 | port %d is outside your quota range", port, port))
		return
	}
	ok(w, PortCheckResult{Port: port, Available: portBindable(port)})
}

// randomPort handles GET /api/ports/random
//
// 在调用者的配额区间内随机找一个可用端口。与 check 一样受配额区间约束；
// 随机起点 + 线性探测，避开"总是返回同一个端口"造成的抢端口热点。
func (h *handler) randomPort(w http.ResponseWriter, r *http.Request) {
	me := auth.UserFrom(r.Context())
	if me == nil {
		unauthorized(w)
		return
	}
	quota, err := h.users.EffectiveQuota(me)
	if err != nil {
		writeUserError(w, err)
		return
	}
	start, end := quota.PortRangeStart, quota.PortRangeEnd
	if me.IsAdmin() {
		// 管理员没有配额区间，给一个避开系统常用端口的默认范围。
		start, end = 10000, 65535
	}
	if start <= 0 || end <= 0 || start > end {
		fail(w, http.StatusBadRequest,
			"尚未为你分配可用的端口区间 | no port range available for your account")
		return
	}

	origin := start + rand.Intn(end-start+1)
	for i := 0; i < 50; i++ {
		p := start + (origin-start+i)%(end-start+1)
		if portBindable(p) {
			ok(w, PortCheckResult{Port: p, Available: true})
			return
		}
	}
	fail(w, http.StatusServiceUnavailable,
		"端口区间内暂时找不到可用端口，请稍后重试或联系管理员 | no free port found in the range")
}

// portBindable 试绑 TCP 与 UDP（所有接口，与规则 listen_addr 0.0.0.0 的默认
// 行为一致），立即关闭。
//
// 存在 TOCTOU 窗口（检测后、保存前被其它进程抢占），响应文案需注明仅供参考。
func portBindable(port int) bool {
	tcpLn, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	tcpLn.Close()

	udpLn, err := net.ListenPacket("udp", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	udpLn.Close()
	return true
}

// PortCheckResult 是端口检测/随机端口的响应。
type PortCheckResult struct {
	Port      int  `json:"port"`
	Available bool `json:"available"`
}
