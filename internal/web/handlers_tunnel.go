package web

// 隧道链路质量端点（OPT-12 的面板出口）。
//
// 为什么是 admin-only：链路数据按访问码聚合，但同一个用户的多个访问码、乃至
// 全部用户的在线情况对管理员都是运维信息；普通用户看自己的链路质量走 pf-client
// 的面板（那里本来就有一份更细的）。普通用户请求返回 403，与其它 admin 端点
// 一致（由 adminOnly 包装保证）。

import (
	"net/http"
)

// tunnelStatus 处理 GET /api/tunnel/status。
//
// 隧道未开启时返回 enabled=false（而不是 404 或空表格）——面板据此显示
// 「隧道未开启」，运维不会把它误读成「所有玩家都断了」。
func (h *handler) tunnelStatus(w http.ResponseWriter, r *http.Request) {
	report := func() *TunnelLinkReport {
		if h.tunnel == nil {
			return nil
		}
		return h.tunnel.TunnelLink()
	}()
	if report == nil {
		ok(w, map[string]any{"enabled": false})
		return
	}
	if report.Peers == nil {
		report.Peers = []TunnelLinkPeer{}
	}
	ok(w, map[string]any{"enabled": true, "report": report})
}
