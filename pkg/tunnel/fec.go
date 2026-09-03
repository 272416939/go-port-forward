package tunnel

// 前向纠错（OPT-13）。
//
// 为什么值得做：游戏流量是小包、高频、单包价值高。丢 1 个包的代价是应用层
// （RakNet）重传一个 RTT——跨网玩家 80~150ms，玩家感受是「卡一下」。隧道层
// 用 12.5% 冗余把这一次卡顿吃掉，是专业游戏加速器的标配做法。
//
// 四条设计决策是安全与手感的底线，改动本文件前先读完：
//
//  1. **XOR 的是密文盒，不是明文**。还原出来的是完整密文盒，必须走正常的
//     OpenData——AEAD 认证、重放窗口、解密全部原样生效，安全语义零损失。
//     若对明文做 XOR，还原出的包未经认证就能进 TUN，等于在安全墙上开个洞。
//  2. **组描述符本身是加密的**。FEC 包走同一条 AEAD 通道，所以成员计数表
//     受认证保护，中间人改不了「这个组由哪些包组成」。
//  3. **滑动组，绝不主动等待**。收到组内任一包即开始记录；凑到「7 个成员 +
//     校验包」立刻还原。丢 ≥2 就彻底放弃这一组、下组重来。**任何形式的
//     等待都会把 FEC 从「省一个 RTT」变成「加一份延迟」**，那就完全失去了
//     做它的理由。
//  4. **不改重放窗口**。还原包用它本来的计数进窗口：重放一个还原包 = 正常
//     的重放拒绝。窗口只管安全，不管恢复，两者正交。
//
// 只对 Data 做。Ping/Pong 丢了等下个周期，Ctrl 有客户端宽限期兜底，FEC 包
// 自己丢了等下一组——都不值得再套一层冗余。

import (
	"encoding/binary"
	"sync"
)

const (
	// fecGroup 是组深度：每 8 个 Data 包附 1 个校验包，冗余 12.5%。
	fecGroup = 8
	// fecSlots 是接收侧密文盒缓存槽位数。必须明显大于组深度：校验包到达时
	// 组内成员要都还在缓存里，而成员计数并不连续（心跳与控制消息也消耗
	// 发送计数）。32 槽给了三倍余量，代价是每方向约 45KB（仅启用时分配）。
	fecSlots = 32
	// fecPendingMax 是同时待定的组描述符上限。校验包可能先于最后一个成员
	// 到达（乱序），必须存着；但存太多等于给伪造流量攒内存。
	fecPendingMax = 2
	// fecRecoveredMax 是已还原包的出队缓冲深度。
	fecRecoveredMax = 2
	// fecFrameHeader 是成员帧的长度前缀字节数。
	fecFrameHeader = 2
)

// fecMaxBox 是单个密文盒（ciphertext+tag）的容量上限。
const fecMaxBox = MaxTunMTU + TagSize

// FECOverhead 是启用 FEC 后隧道 MTU 必须额外让出的字节数。
//
// 校验包的明文 = 组头(1 + 8×8) + 成员帧(2 + 最长盒)。最长盒 = MTU + 16，
// 所以校验包明文比最大 Data 明文多出 fecFrameHeader + 1 + 8×CounterSize +
// TagSize = 2 + 1 + 64 + 16 = 83 字节。不把这部分从隧道 MTU 里让出来，校验包
// 自己就会被 IP 分片——而分片丢失是整包全损，正是 FEC 想解决的问题。
const FECOverhead = fecFrameHeader + 1 + fecGroup*CounterSize + TagSize

// fecSlot 是一个缓存的密文盒。
type fecSlot struct {
	counter uint64 // 0 = 空槽
	box     []byte
}

// fecPending 是一个待定的组描述符（校验包已到、成员未齐）。
type fecPending struct {
	used     bool
	count    int
	counters [fecGroup]uint64
	maxSeen  uint64 // 组内最大计数，用于过期判定
	xorFrame []byte // 容量固定，frameLen 之外的部分恒为零
	frameLen int
}

// fecState 持有一个会话的 FEC 收发状态。
//
// 发送侧由 sendMu 保护（Data 封装实际上是单 goroutine，但锁的成本相对
// 1.4KB 的 XOR 可以忽略，不值得为它赌一个将来的误用）。
// 接收侧无锁：文档约定 Open*/HandleFEC 只在接收泵单 goroutine 调用。
type fecState struct {
	sendMu   sync.Mutex
	acc      []byte // 帧累加器：[len(2 BE)][盒，按最长补零]
	counters [fecGroup]uint64
	n        int
	maxBox   int
	groupBuf []byte // 校验载荷暂存（组头 + 累加帧）
	sendBuf  []byte // 已封装的校验包暂存

	slots   [fecSlots]fecSlot
	pending [fecPendingMax]fecPending
	scratch []byte // 还原用暂存，避免每次补包分配
	// recovered 是已还原的 Data 包（线上形态）的 FIFO。缓冲预分配复用：
	// 补包发生在丢包时，那正是不该再给 GC 添活的时刻。
	recovered [fecRecoveredMax][]byte
	recHead   int
	recCount  int
}

func newFECState() *fecState {
	frame := fecFrameHeader + fecMaxBox
	f := &fecState{
		acc:      make([]byte, frame),
		groupBuf: make([]byte, 0, 1+fecGroup*CounterSize+frame),
		sendBuf:  make([]byte, 0, SealOverhead+1+fecGroup*CounterSize+frame+NonceSize),
		scratch:  make([]byte, frame),
	}
	for i := range f.pending {
		f.pending[i].xorFrame = make([]byte, frame)
	}
	for i := range f.recovered {
		f.recovered[i] = make([]byte, 0, 1+CounterSize+fecMaxBox)
	}
	return f
}

// addMember 把一个刚封装好的 Data 密文盒并入当前组。
// 返回 true 表示组已满，调用方应立刻发出校验包。
func (f *fecState) addMember(counter uint64, box []byte) bool {
	if len(box) > fecMaxBox {
		return false // 超出容量上限的包不参与纠错（MTU 协商后不该出现）
	}
	f.sendMu.Lock()
	defer f.sendMu.Unlock()
	// 长度前缀进 XOR：还原方靠它知道缺失成员的真实盒长（各成员长度不同，
	// 短的成员在累加器里天然按零补齐，XOR 零是恒等操作）。
	var lenBE [fecFrameHeader]byte
	binary.BigEndian.PutUint16(lenBE[:], uint16(len(box)))
	f.acc[0] ^= lenBE[0]
	f.acc[1] ^= lenBE[1]
	dst := f.acc[fecFrameHeader:]
	for i, b := range box {
		dst[i] ^= b
	}
	if len(box) > f.maxBox {
		f.maxBox = len(box)
	}
	f.counters[f.n] = counter
	f.n++
	return f.n >= fecGroup
}

// takeGroup 取出当前组的校验载荷并重置累加器。载荷写在 fecState 自己的暂存
// 里，仅在下一次 takeGroup 之前有效——调用方必须立刻封装发出。
func (f *fecState) takeGroup() []byte {
	f.sendMu.Lock()
	defer f.sendMu.Unlock()
	if f.n == 0 {
		return nil
	}
	out := append(f.groupBuf[:0], byte(f.n))
	for i := 0; i < f.n; i++ {
		out = binary.BigEndian.AppendUint64(out, f.counters[i])
	}
	out = append(out, f.acc[:fecFrameHeader+f.maxBox]...)
	f.groupBuf = out
	clear(f.acc)
	f.n, f.maxBox = 0, 0
	return out
}

// cacheBox 缓存一个已通过认证的 Data 密文盒，并尝试补全待定组。
func (f *fecState) cacheBox(counter uint64, box []byte, stats *Stats) {
	if counter == 0 || len(box) > fecMaxBox {
		return
	}
	slot := &f.slots[counter%fecSlots]
	slot.counter = counter
	slot.box = append(slot.box[:0], box...)
	f.tryRecoverAll(counter, stats)
}

// lookup 返回缓存中该计数的盒；不在缓存里返回 nil。
func (f *fecState) lookup(counter uint64) []byte {
	slot := &f.slots[counter%fecSlots]
	if slot.counter != counter {
		return nil
	}
	return slot.box
}

// addGroup 登记一个校验组。payload 是 FEC 包的明文。
func (f *fecState) addGroup(payload []byte, stats *Stats) bool {
	if len(payload) < 1 {
		return false
	}
	count := int(payload[0])
	if count < 2 || count > fecGroup {
		return false
	}
	head := 1 + count*CounterSize
	if len(payload) < head+fecFrameHeader {
		return false
	}
	frame := payload[head:]
	if len(frame) > fecFrameHeader+fecMaxBox {
		return false
	}

	slot := f.freePending(stats)
	slot.used = true
	slot.count = count
	slot.maxSeen = 0
	for i := 0; i < count; i++ {
		c := binary.BigEndian.Uint64(payload[1+i*CounterSize:])
		slot.counters[i] = c
		if c > slot.maxSeen {
			slot.maxSeen = c
		}
	}
	clear(slot.xorFrame)
	copy(slot.xorFrame, frame)
	slot.frameLen = len(frame)
	// 立刻试一次：校验包最常在组内最后一个成员之后到达（顺序链路上就是这样），
	// 那一刻组已经差一个包，正是该还原的时候。只在 cacheBox 里试会让顺序链路
	// 上的纠错完全失效——每组都要等下一组的成员到达才触发。
	f.tryRecover(slot)
	return true
}

// freePending 找一个可用的描述符槽位：优先空槽，否则淘汰组内计数最小的那个
// （最老、最不可能再补齐）并记一次放弃。
func (f *fecState) freePending(stats *Stats) *fecPending {
	for i := range f.pending {
		if !f.pending[i].used {
			return &f.pending[i]
		}
	}
	oldest := 0
	for i := 1; i < len(f.pending); i++ {
		if f.pending[i].maxSeen < f.pending[oldest].maxSeen {
			oldest = i
		}
	}
	if stats != nil {
		stats.fecGiveUp.Add(1)
	}
	p := &f.pending[oldest]
	p.used = false
	return p
}

// tryRecoverAll 对全部待定组尝试还原，并淘汰已经不可能补齐的组。
func (f *fecState) tryRecoverAll(newest uint64, stats *Stats) {
	for i := range f.pending {
		p := &f.pending[i]
		if !p.used {
			continue
		}
		// 组内最大计数已滑出缓存窗口：成员再也不会补齐，放弃。
		if newest > p.maxSeen && newest-p.maxSeen > fecSlots {
			p.used = false
			if stats != nil {
				stats.fecGiveUp.Add(1)
			}
			continue
		}
		f.tryRecover(p)
	}
}

// tryRecover 在「恰好缺 1 个成员」时还原它。
func (f *fecState) tryRecover(p *fecPending) {
	missing := -1
	for i := 0; i < p.count; i++ {
		if f.lookup(p.counters[i]) == nil {
			if missing >= 0 {
				return // 缺 2 个以上：XOR 无解，继续等（或等过期）
			}
			missing = i
		}
	}
	if missing < 0 {
		p.used = false // 组已收齐，校验包用不上了
		return
	}
	if f.recCount >= fecRecoveredMax {
		return // 出队缓冲已满，等调用方取走
	}

	// frame = xorFrame ⊕ 全部已到成员的帧 = 缺失成员的帧。
	frame := f.scratch[:p.frameLen]
	copy(frame, p.xorFrame[:p.frameLen])
	for i := 0; i < p.count; i++ {
		if i == missing {
			continue
		}
		box := f.lookup(p.counters[i])
		if fecFrameHeader+len(box) > len(frame) {
			p.used = false // 成员比校验帧还长：组信息不自洽
			return
		}
		var lenBE [fecFrameHeader]byte
		binary.BigEndian.PutUint16(lenBE[:], uint16(len(box)))
		frame[0] ^= lenBE[0]
		frame[1] ^= lenBE[1]
		for j, b := range box {
			frame[fecFrameHeader+j] ^= b
		}
	}
	boxLen := int(binary.BigEndian.Uint16(frame[:fecFrameHeader]))
	if boxLen < TagSize || fecFrameHeader+boxLen > len(frame) {
		// 载荷被篡改或组信息不自洽。丢弃即可——伪造的还原盒过不了 AEAD，
		// 但没必要把明显不自洽的东西送进解密路径。
		p.used = false
		return
	}

	// 还原成线上形态 [TypeData][counter][盒]，由调用方走一遍正常接收路径
	// （AEAD 认证 + 重放窗口），所以伪造的 FEC 载荷只会得到一次解密失败。
	idx := (f.recHead + f.recCount) % fecRecoveredMax
	wire := f.recovered[idx][:0]
	wire = append(wire, TypeData)
	wire = binary.BigEndian.AppendUint64(wire, p.counters[missing])
	wire = append(wire, frame[fecFrameHeader:fecFrameHeader+boxLen]...)
	f.recovered[idx] = wire
	f.recCount++
	p.used = false
}

// popRecovered 取出一个已还原的包。返回的切片在下一次 popRecovered 循环回到
// 同一槽位前有效——调用方必须在本轮处理完毕（与两端数据泵「同步消费」的既有
// 约定一致）。
func (f *fecState) popRecovered() []byte {
	if f.recCount == 0 {
		return nil
	}
	out := f.recovered[f.recHead]
	f.recHead = (f.recHead + 1) % fecRecoveredMax
	f.recCount--
	return out
}
