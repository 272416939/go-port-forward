package tunnel

// 隧道会话的包级观测（OPT-12）。
//
// 为什么需要它：改造之前两端对丢包完全没有观测——公网丢包、内核缓冲丢包、
// 应用层丢弃（源地址校验 / 重放窗口 / 无回程路由）在日志里混成一团，无法归因。
// 没有分层数据，FEC 冗余度、冗余副本次数、缓冲深度全是猜。
//
// 成本：每包 3~4 次 atomic.Add（亚微秒），不涉及锁、不涉及分配。

import (
	"sync/atomic"
	"time"
)

// jitterShift 是抖动平滑的指数因子（1/16，与 RTP 惯例一致）。
const jitterShift = 4

// Stats 是一个会话的收发计数。全部字段用原子操作访问，读到的是弱一致快照
// （各字段可能来自相邻的不同瞬间），用于展示与趋势判断，不做精确对账。
type Stats struct {
	// --- 接收侧 ---
	// rxHigh 是已见的最高发送计数。发送计数每包 +1 且不跳号，所以它约等于
	// 「对端到此刻为止发了多少包」，是丢包率的分母。
	rxHigh atomic.Uint64
	// rxAccepted 是通过认证与重放窗口的包数（丢包率的分子）。
	rxAccepted atomic.Uint64
	// rxReordered 是计数小于当时最高水位、但仍在窗口内被接受的包数。
	// 高乱序链路上它会很大而丢包率很低——两个数必须分开看。
	rxReordered atomic.Uint64
	// rxReplayed 是被重放窗口拒绝的包数（重复包或已滑出窗口的陈旧包）。
	// 开启冗余副本后这里必然上升，那是设计预期（副本靠窗口去重）。
	rxReplayed atomic.Uint64
	// rxAuthFail 是 AEAD 认证失败的包数。非零就值得警惕：正常链路上损坏的
	// 包会被 UDP 校验和先拦掉，能走到这里说明有人在发东西。
	rxAuthFail atomic.Uint64
	// rxBad 是格式不合法（长度不足、类型不符）的包数。
	rxBad atomic.Uint64

	// lastArrivalNanos / lastGapNanos 是抖动估算的状态。
	lastArrivalNanos atomic.Int64
	lastGapNanos     atomic.Int64
	// jitterNanos 是**包间隔**的平滑平均绝对偏差。
	//
	// 刻意不叫「RFC 3550 jitter」：那个口径需要发端时间戳来抵消发送侧的
	// 疏密，我们的协议里没有。这里量的是「到达节奏的抖动」，游戏流量本身
	// 疏密不均，所以它是网络抖动 + 应用抖动的合成值，只适合看相对变化。
	jitterNanos atomic.Int64
	// rttNanos 是平滑后的心跳往返时延（Ping→Pong）。
	rttNanos atomic.Int64

	// --- 发送侧 ---
	txPackets atomic.Uint64
	// txDropped 是发送失败丢弃的包数（socket 缓冲满 / ENOBUFS 等）。
	// 绝不为此阻塞：阻塞一个客户端会拖死全体。
	txDropped atomic.Uint64

	// --- 纠错与冗余 ---
	fecSent      atomic.Uint64 // 已发出的 FEC 校验包
	fecRecovered atomic.Uint64 // 靠 FEC 补回的 Data 包（每个都是一次没卡的手感）
	fecGiveUp    atomic.Uint64 // 组内丢 ≥2、无法补回而放弃的组数
	dupSent      atomic.Uint64 // 已发出的冗余副本

	// --- 设备侧 ---
	tunDropped atomic.Uint64 // 超出隧道 MTU 无法转发的出向包
}

// StatsView 是 Stats 的可序列化快照（面板与诊断接口用）。
type StatsView struct {
	RxAccepted   uint64  `json:"rx_accepted"`
	RxExpected   uint64  `json:"rx_expected"`
	RxReordered  uint64  `json:"rx_reordered"`
	RxReplayed   uint64  `json:"rx_replayed"`
	RxAuthFail   uint64  `json:"rx_auth_fail"`
	RxBad        uint64  `json:"rx_bad"`
	TxPackets    uint64  `json:"tx_packets"`
	TxDropped    uint64  `json:"tx_dropped"`
	FECSent      uint64  `json:"fec_sent"`
	FECRecovered uint64  `json:"fec_recovered"`
	FECGiveUp    uint64  `json:"fec_give_up"`
	DupSent      uint64  `json:"dup_sent"`
	TunDropped   uint64  `json:"tun_dropped"`
	LossPPM      int64   `json:"loss_ppm"` // 丢包率，百万分之（避免浮点在 JSON 里抖动）
	ReorderPPM   int64   `json:"reorder_ppm"`
	JitterMS     float64 `json:"jitter_ms"`
	RTTMS        float64 `json:"rtt_ms"`
}

// View 返回当前计数的快照。
func (s *Stats) View() StatsView {
	high := s.rxHigh.Load()
	acc := s.rxAccepted.Load()
	v := StatsView{
		RxAccepted:   acc,
		RxExpected:   high,
		RxReordered:  s.rxReordered.Load(),
		RxReplayed:   s.rxReplayed.Load(),
		RxAuthFail:   s.rxAuthFail.Load(),
		RxBad:        s.rxBad.Load(),
		TxPackets:    s.txPackets.Load(),
		TxDropped:    s.txDropped.Load(),
		FECSent:      s.fecSent.Load(),
		FECRecovered: s.fecRecovered.Load(),
		FECGiveUp:    s.fecGiveUp.Load(),
		DupSent:      s.dupSent.Load(),
		TunDropped:   s.tunDropped.Load(),
		JitterMS:     float64(s.jitterNanos.Load()) / float64(time.Millisecond),
		RTTMS:        float64(s.rttNanos.Load()) / float64(time.Millisecond),
	}
	// 分子可能瞬时大于分母（补回的包先记 accepted、水位后更新），钳到 0。
	if high > 0 && high >= acc {
		v.LossPPM = int64((high - acc) * 1_000_000 / high)
		v.ReorderPPM = int64(v.RxReordered * 1_000_000 / high)
	}
	return v
}

// observeArrival 记录一个被接受包的到达时刻并更新抖动估算。
func (s *Stats) observeArrival(now int64) {
	prev := s.lastArrivalNanos.Swap(now)
	if prev == 0 || now <= prev {
		return
	}
	gap := now - prev
	last := s.lastGapNanos.Swap(gap)
	if last == 0 {
		return
	}
	d := gap - last
	if d < 0 {
		d = -d
	}
	j := s.jitterNanos.Load()
	s.jitterNanos.Store(j + (d-j)>>jitterShift)
}

// ObserveRTT 把一次心跳往返时延并入平滑值。
func (s *Stats) ObserveRTT(d time.Duration) {
	if d <= 0 {
		return
	}
	cur := s.rttNanos.Load()
	if cur == 0 {
		s.rttNanos.Store(int64(d))
		return
	}
	s.rttNanos.Store(cur + (int64(d)-cur)>>jitterShift)
}

// AddTxDropped 记录一次发送失败丢包（socket 缓冲满等）。
func (s *Stats) AddTxDropped(n uint64) { s.txDropped.Add(n) }

// AddTunDropped 记录一次因超出隧道 MTU 而无法转发的出向包。
func (s *Stats) AddTunDropped(n uint64) { s.tunDropped.Add(n) }

// Stats 返回会话的观测计数（可直接读，指针稳定）。
func (s *Session) Stats() *Stats { return &s.stats }
