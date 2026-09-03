package tunnelapp

// 面板侧的隧道链路视图（OPT-12 的服务端出口）。
//
// 数据在 peerSession 的 Stats 里每包都在累积，这里只做一次快照转换。端点是
// admin-only 的 /api/tunnel/status，由 web 包经 TunnelStatus 接口取数——web
// 不直接依赖 tunnelapp，视图结构体放在 web 侧、main.go 做适配。

import (
	"time"

	"go-port-forward/pkg/tunnel"
)

// TunnelLinkSample 是一条在线隧道链路质量的摘要。
//
// 与 PeerView 的区别：这是给面板的扁平结构，只保留「诊断链路要看的字段」，
// 不暴露会话的归属细节以外的任何东西。字段含义与客户端面板一致。
type TunnelLinkSample struct {
	UserName string    `json:"user_name"`
	CodeName string    `json:"code_name"`
	TunIP    string    `json:"tun_ip"`
	Addr     string    `json:"addr"`
	Since    time.Time `json:"since"`
	IdleSec  int64     `json:"idle_sec"`
	MTU      int       `json:"mtu"`

	LossPPM    int64   `json:"loss_ppm"`
	ReorderPPM int64   `json:"reorder_ppm"`
	JitterMS   float64 `json:"jitter_ms"`
	RTTMS      float64 `json:"rtt_ms"`

	FECEnabled   bool   `json:"fec_enabled"`
	FECRecovered uint64 `json:"fec_recovered"`
	DupEnabled   bool   `json:"dup_enabled"`
	TxDropped    uint64 `json:"tx_dropped"`
	TunDropped   uint64 `json:"tun_dropped"`
}

// TunnelLinkReport 是 /api/tunnel/status 的响应体。
type TunnelLinkReport struct {
	Peers       []TunnelLinkSample `json:"peers"`
	KernelDrops uint64             `json:"kernel_drops"` // 内核 UDP 收缓冲累计丢包（0 = 非 Linux 或无数据）
	TunDrops    int64              `json:"tun_drops"`    // TUN 读侧超出缓冲的丢弃数
	IOMode      string             `json:"io_mode"`      // 实际生效的收发模式（batch/simple/...）
	MTU         int                `json:"mtu"`          // 服务端隧道 MTU
	FEC         bool               `json:"fec"`          // 服务端是否开启了前向纠错
}

// LinkReport 汇总当前全部在线隧道的链路质量与丢包观测。
func (s *Server) LinkReport() TunnelLinkReport {
	now := time.Now()
	snap := s.peers.snapshot()
	peers := make([]TunnelLinkSample, 0, len(snap))
	for _, ps := range snap {
		v := ps.sess.Stats().View()
		peers = append(peers, TunnelLinkSample{
			UserName: ps.userName,
			CodeName: ps.codeName,
			TunIP:    ps.tunIP.String(),
			Addr:     ps.addrPort.String(),
			Since:    ps.since,
			IdleSec:  int64(ps.idleFor(now).Seconds()),
			MTU:      ps.mtu,

			LossPPM:    v.LossPPM,
			ReorderPPM: v.ReorderPPM,
			JitterMS:   v.JitterMS,
			RTTMS:      v.RTTMS,

			FECEnabled:   ps.sess.Features()&tunnel.FeatFEC != 0,
			FECRecovered: v.FECRecovered,
			DupEnabled:   ps.sess.Features()&tunnel.FeatTailDup != 0,
			TxDropped:    v.TxDropped,
			TunDropped:   v.TunDropped,
		})
	}
	return TunnelLinkReport{
		Peers:       peers,
		KernelDrops: s.kernelDrops.Load(),
		TunDrops:    s.dev.Dropped(),
		IOMode:      s.io.Mode,
		MTU:         s.tunMTU,
		FEC:         s.cfg.FEC,
	}
}
