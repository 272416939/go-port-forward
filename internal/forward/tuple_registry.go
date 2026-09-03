package forward

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/pkg/pool"

	"go.uber.org/zap"
)

// errTupleRegistryClosed 注册表已关停（进程/管理器退出期间的 acquire 一律失败）。
var errTupleRegistryClosed = errors.New("透明绑定注册表已关闭 | tuple registry closed")

// tupleFactory 以指定源地址（玩家 IP:端口）创建透明 UDP socket；测试可注入替身。
type tupleFactory func(srcAddr *net.UDPAddr) (*net.UDPConn, error)

// transparentUDPFactory 生产默认工厂：IP_TRANSPARENT 绑定玩家源元组（Linux+root）。
// 不调用 Connect，发送统一由会话按各自 target 走 WriteToUDP。
func transparentUDPFactory(srcAddr *net.UDPAddr) (*net.UDPConn, error) {
	pc, err := transparentListenPacket(srcAddr.String())
	if err != nil {
		return nil, err
	}
	udp, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("透明模式：上游 socket 类型异常 | unexpected packet conn type")
	}
	return udp, nil
}

// tupleRegistry 是全机唯一的「玩家元组 → 透明 socket」注册表。
//
// 背景：透明模式以玩家 IP:端口 为源绑定（源地址保真，后端零插件看到玩家真实
// IP），该绑定在内核层面全机独占。旧实现按「每转发器 × 每玩家元组」各自 bind，
// 两条透明规则服务同一批玩家时（EIM NAT 端口复用 + 基岩加服器 ping 全列表，
// 同一玩家的包打到多个透明端口）互相抢绑，输家 bind: address already in use
// 被丢弃，且绑定被赢家的会话持续刷新，输家在玩家持续探测期间是永久失败
// （2026-09 两次现形）。注册表让每个玩家元组全机只绑一个 socket，由所有
// 规则的会话共享：
//   - 正向：各会话经共享 socket 以各自 target 调 WriteToUDP（源=玩家元组不变）；
//   - 回程：fwmark 策略路由把后端回包「本机投递」进共享 socket（conntrack 按
//     反向元组送入），每条目单一读循环按「包源地址（=后端=客户端隧道地址:端口）」
//     分发给订阅会话，各自经自己的转发口发回玩家（源端口=各自监听端口，玩家
//     NAT 各自成立）。
//
// 不变量（全部状态迁移在 r.mu 同一临界区内完成）：
//   - entries 中存在的（非 creating）条目 fd 必然打开；条目被摘除时 fd 必然
//     已关闭。「条目已删、fd 还绑着」的窗口会让同元组新 bind 撞 EADDRINUSE
//     （635bf3b 在会话表上修过的同构竞态），因此 Close 与 delete 必须成对。
//   - refs 等于持有该条目的活跃会话数；归零才关 fd（规则 A 的会话回收不得
//     拆掉规则 B 还在用的绑定）。创建（creating）中的条目以占位符形式存在，
//     并发 acquire 在 ready 上等待 bind 落定，杜绝「竞建输家」撞 EADDRINUSE。
type tupleRegistry struct {
	mu           sync.Mutex
	entries      map[udpAddrKey]*tupleEntry
	factory      tupleFactory
	wg           sync.WaitGroup
	closed       bool
	lastDeadWarn atomic.Int64 // 异常死亡日志限频锚点 | dead-socket warn anchor
}

// tupleSub 是一条回程订阅：回程包源==backendKey 时，经 sub.fwd 的转发口
// 发回 sub.clientAddr（玩家）。字段创建后不可变（detach 只改 slice），
// 分发器持锁取快照后可在锁外安全使用。
type tupleSub struct {
	fwd        *UDPForwarder
	sess       *udpSession // 用于 bytesOut 计数；注册表单测可为 nil
	clientAddr *net.UDPAddr
	backendKey udpAddrKey
}

// tupleEntry 是一个玩家元组的共享绑定。creating 阶段 socket 尚未建好
// （conn 为 nil），并发 acquire 在 ready 上等待。
type tupleEntry struct {
	key      udpAddrKey
	conn     *net.UDPConn
	refs     int
	subs     map[udpAddrKey][]*tupleSub
	creating bool
	ready    chan struct{} // creating 结束（成功/失败/关停）时关闭
}

func newTupleRegistry(factory tupleFactory) *tupleRegistry {
	return &tupleRegistry{
		entries: make(map[udpAddrKey]*tupleEntry),
		factory: factory,
	}
}

// acquire 为转发器 f 的玩家会话取得（或共享）以 srcAddr 为源的透明绑定。
// 返回的 handle 必须在会话结束时恰好 release 一次；会话落位后调用 attach
// 登记回程订阅（可省略——不 attach 则收不到回程，仅供测试/竞建输家路径）。
func (r *tupleRegistry) acquire(f *UDPForwarder, srcAddr *net.UDPAddr) (*tupleHandle, error) {
	key := makeUDPAddrKey(srcAddr)
	for {
		r.mu.Lock()
		if e, ok := r.entries[key]; ok {
			if e.creating {
				ready := e.ready
				r.mu.Unlock()
				<-ready // bind 落定后重查：成功则并入，失败则自己重试创建
				continue
			}
			e.refs++
			h := &tupleHandle{reg: r, entry: e, fwd: f}
			r.mu.Unlock()
			return h, nil
		}
		if r.closed {
			r.mu.Unlock()
			return nil, errTupleRegistryClosed
		}
		// 未命中：先占位（creating），再把 bind 放到锁外执行——bind 是系统
		// 调用，持锁会拖住全部条目的分发热路径。
		e := &tupleEntry{
			key:      key,
			subs:     make(map[udpAddrKey][]*tupleSub),
			creating: true,
			ready:    make(chan struct{}),
		}
		r.entries[key] = e
		r.mu.Unlock()

		conn, err := r.factory(srcAddr)

		r.mu.Lock()
		switch {
		case err == nil && !r.closed && r.entries[key] == e:
			e.conn = conn
			e.creating = false
			e.refs++
			close(e.ready)
			r.wg.Add(1)
			go r.dispatch(e)
			h := &tupleHandle{reg: r, entry: e, fwd: f}
			r.mu.Unlock()
			return h, nil
		case r.entries[key] == e:
			// 工厂失败或注册表已关（占位仍是我们的）：摘占位、唤醒等待者
			delete(r.entries, key)
			close(e.ready)
			r.mu.Unlock()
			if conn != nil {
				_ = conn.Close()
			}
			if err != nil {
				return nil, err
			}
			return nil, errTupleRegistryClosed
		default:
			// 占位已被 Close 摘走（关停竞态）
			r.mu.Unlock()
			if conn != nil {
				_ = conn.Close()
			}
			if err != nil {
				return nil, err
			}
			return nil, errTupleRegistryClosed
		}
	}
}

// tupleHandle 是一次会话对共享绑定的持有凭证：一次 acquire 对应恰好一次
// release。conn() 的读方向完全归注册表分发器所有，调用方禁止 Read——多个
// 读者会互抢包而不是广播。
type tupleHandle struct {
	reg      *tupleRegistry
	entry    *tupleEntry
	fwd      *UDPForwarder
	sub      *tupleSub
	released bool // 仅在 r.mu 内读写
}

// conn 返回共享的透明 socket。写方向由会话按各自 target 走 WriteToUDP
// （*net.UDPConn 并发写安全）。
func (h *tupleHandle) conn() *net.UDPConn { return h.entry.conn }

// attach 登记回程订阅：回程包源==本规则 target 时，包经本规则的转发口发回
// clientAddr（玩家）。会话建立后恰好调用一次。
func (h *tupleHandle) attach(sess *udpSession, clientAddr *net.UDPAddr) {
	sub := &tupleSub{
		fwd:        h.fwd,
		sess:       sess,
		clientAddr: cloneUDPAddr(clientAddr),
		backendKey: makeUDPAddrKey(h.fwd.targetAddr),
	}
	r := h.reg
	r.mu.Lock()
	h.sub = sub
	e := h.entry
	e.subs[sub.backendKey] = append(e.subs[sub.backendKey], sub)
	total := 0
	for _, list := range e.subs {
		total += len(list)
	}
	shared := total == 2 // 1→2 的状态变化才打 info（降噪纪律）
	r.mu.Unlock()
	if shared {
		logger.S.Infow("透明绑定已被第二条规则共享 | transparent binding now shared across rules",
			"player", h.entry.key, "rule", h.fwd.rule.Name)
	}
}

// release 释放持有引用并摘除本 handle 的回程订阅（幂等）。归零时关闭绑定：
// 先关 fd 再摘条目，同一临界区（见注册表不变量）。
func (h *tupleHandle) release() {
	r := h.reg
	r.mu.Lock()
	defer r.mu.Unlock()
	if h.released {
		return
	}
	h.released = true
	if h.sub != nil {
		list := h.entry.subs[h.sub.backendKey]
		for i, s := range list {
			if s == h.sub {
				h.entry.subs[h.sub.backendKey] = append(list[:i], list[i+1:]...)
				break
			}
		}
		if len(h.entry.subs[h.sub.backendKey]) == 0 {
			delete(h.entry.subs, h.sub.backendKey)
		}
		h.sub = nil
	}
	e := h.entry
	e.refs--
	if e.refs == 0 {
		_ = e.conn.Close()
		delete(r.entries, e.key)
	}
}

// dispatch 是条目的回程读循环（每条目恰好一个）——透明模式回程的最后一跳，
// 绝不可省。
//
// 完整链路：玩家包 → 转发器 → 共享透明 socket（以玩家 IP:端口 为源）写入
// 隧道 → 后端。后端回包沿隧道回到中转机后被写进 pftun0，fwmark 策略路由把它
// 「本机投递」（setup_linux.go 的 local 表 + INPUT 只放行 ESTABLISHED），
// conntrack 按反向元组把它送进这个共享 socket 的接收队列——就是这里读出的
// 那个包。读出后按包源地址（=后端=客户端隧道地址:端口）分发给订阅会话，
// 各自经自己的转发口发回玩家（源端口=各自监听端口，玩家才认这个源端口）。
// 删掉读循环，所有透明回包会静默烂在接收队列里：入向照常、回程全灭、日志
// 零痕迹（2026-09-02 全服进不去事故的根因，当时的注释误称「回包不经过此
// socket」，未实测即删码，教训见 LESSONS#15）。
func (r *tupleRegistry) dispatch(e *tupleEntry) {
	defer r.wg.Done()
	buf := pool.GetBuffer(65535)
	defer pool.PutBuffer(buf)
	for {
		n, src, err := e.conn.ReadFromUDP(buf)
		if err != nil {
			// release/Close 主动关闭走 ErrClosed 静默退出；外部原因导致
			// socket 死亡时摘除死条目（否则后续 acquire 会拿到死 socket），
			// 会话按原空闲超时自然回收——与旧实现 socket 损坏行为一致。
			if !errors.Is(err, net.ErrClosed) {
				r.dropDeadEntry(e, err)
			}
			return
		}
		r.deliver(e, src, buf[:n])
	}
}

// deliver 按包源地址分发回程包。单订阅零分配直发；多订阅（存量「同后端端口
// 重复配置」的兜底，新配置已被 Manager 的同目标端口拒绝拦住）逐个独立缓冲
// 广播——广播是安全的：各订阅者经各自转发口发回，玩家侧 NAT 映射各自成立。
func (r *tupleRegistry) deliver(e *tupleEntry, src *net.UDPAddr, data []byte) {
	key := makeUDPAddrKey(src)
	r.mu.Lock()
	list, ok := e.subs[key]
	if !ok || len(list) == 0 {
		r.mu.Unlock()
		return // 无人认领（会话刚回收等）：丢弃
	}
	if len(list) == 1 {
		sub := list[0]
		r.mu.Unlock()
		sub.send(data)
		return
	}
	subs := make([]*tupleSub, len(list))
	copy(subs, list)
	r.mu.Unlock()
	for _, sub := range subs {
		// 铁律 8：额外订阅者独立缓冲，不共享存活到本轮之后的切片
		buf := pool.GetBuffer(len(data))[:len(data)]
		copy(buf, data)
		sub.send(buf)
		pool.PutBuffer(buf)
	}
}

// send 把回程包经订阅者所属转发器的监听口发回玩家（src=监听端口）。转发器
// 已停止时 socket 已关，写入静默失败——与旧实现关闭竞态的行为一致。
func (sub *tupleSub) send(data []byte) {
	if sub.fwd.conn == nil {
		return
	}
	out, _ := sub.fwd.conn.WriteToUDP(data, sub.clientAddr)
	if sub.sess != nil && sub.sess.sinfo != nil {
		sub.sess.sinfo.bytesOut.Add(int64(out))
	}
	sub.fwd.bytesOut.Add(int64(out))
}

// dropDeadEntry 外部原因导致 socket 死亡时摘除条目。与 release 的关闭竞态
// 安全：仅当条目仍在 map 且就是本条目时才删（release 的删除与其同临界区，
// 重复 Close 幂等）。
func (r *tupleRegistry) dropDeadEntry(e *tupleEntry, cause error) {
	nowUnix := time.Now().Unix()
	last := r.lastDeadWarn.Load()
	if nowUnix-last >= 5 && r.lastDeadWarn.CompareAndSwap(last, nowUnix) {
		logger.L.Warn("透明绑定 socket 异常死亡，条目已摘除 | transparent socket died unexpectedly",
			zap.Error(cause))
	}
	r.mu.Lock()
	if cur, ok := r.entries[e.key]; ok && cur == e {
		_ = e.conn.Close() // 幂等
		delete(r.entries, e.key)
	}
	r.mu.Unlock()
}

// Close 关闭全部绑定并等待分发器退出（铁律 3：先关 fd 再等 goroutine）。
// 正常关停路径会话已各自 release、entries 已空；这里兜底回收残留条目，
// 并让创建中的占位失败返回。幂等。
func (r *tupleRegistry) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	for key, e := range r.entries {
		if e.creating {
			delete(r.entries, key)
			close(e.ready) // 等待者醒来重查后拿 errTupleRegistryClosed
			continue
		}
		_ = e.conn.Close()
		delete(r.entries, key)
	}
	r.mu.Unlock()
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		logger.L.Warn("透明绑定分发器退出超时（3s），继续关停 | tuple dispatchers did not exit in time")
	}
}
