package tunnelapp

// 隧道 UDP 收发的读源抽象（OPT-6 批量化）。
//
// 为什么要抽象：批量化的价值全在 syscall 数量上（pps 上去之后 recvfrom/sendto
// 的开销超过加解密本身），但**逐包处理逻辑一个字节都不该改**——握手入队、
// 源/目的四条隔离校验、活跃刷新都是踩过坑才定型的。所以这里只把「包从哪来」
// 换成接口，处理逻辑在 loop 里原样保留。
//
// 两条硬约束：
//
//  1. **批的边界 = 一次系统调用返回多少包**。不定时、不等待、不凑批。为了几个
//     包的合并去等几毫秒，对游戏流量是纯损失——隧道层省下的 syscall 远不值
//     一次人为延迟。
//  2. **必须有逐包回退路径**。x/net 的 ReadBatch/WriteBatch 只在 Linux（及部分
//     BSD）走 recvmmsg/sendmmsg，其余平台退化成单包；而服务端的通用代理模式
//     在 Windows/macOS 上是支持的。运行时探测失败即降级，不靠构建标签。

import (
	"errors"
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"

	"go-port-forward/pkg/tunnel"
)

// udpBatch 是一次批量收发的包数上限。
//
// 64 是上限不是目标：内核有多少包就给多少，一个也不等。批内解密 + 校验 +
// 写 TUN 是串行的，批太大会让批尾的包多等一会儿（满批百微秒级），所以不追求
// 更大的值。
const udpBatch = 64

// udpReadBuf 是单个收包缓冲的长度。
const udpReadBuf = tunnel.MaxPacket + 64

// udpReader 是隧道入向的读源。
type udpReader interface {
	// read 取出一个包。返回的切片在下一次 read 之前有效（复用缓冲）。
	read() (pkt []byte, from netip.AddrPort, err error)
	// buffered 返回本批中尚未交付的包数。==0 表示「内核当前能给的包已全部
	// 消费完」，是出向批冲刷的时机信号。
	buffered() int
	// mode 返回可读的模式名（日志用）。
	mode() string
}

// udpWriter 是隧道出向的写出口。
type udpWriter interface {
	// add 把一个包加入发送批。返回 false 表示批已满，调用方应先 flush。
	add(pkt []byte, to netip.AddrPort) bool
	// flush 冲刷发送批，返回成功发出的包数。
	flush() (int, error)
	// pending 返回批中待发的包数。
	pending() int
}

// simpleReader 是逐包读源（ReadFromUDP），全平台可用。
type simpleReader struct {
	conn *net.UDPConn
	buf  []byte
}

func newSimpleReader(conn *net.UDPConn) *simpleReader {
	return &simpleReader{conn: conn, buf: make([]byte, udpReadBuf)}
}

func (r *simpleReader) read() ([]byte, netip.AddrPort, error) {
	n, from, err := r.conn.ReadFromUDPAddrPort(r.buf)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	// v4-in-v6 归一：监听的是双栈 "udp"，同一个 IPv4 客户端在不同内核路径下
	// 可能以 ::ffff:1.2.3.4 或 1.2.3.4 的形态出现，不归一会在会话表里占两个
	// 键——症状是换端口重连后包发到旧地址。
	return r.buf[:n], normalizeAddrPort(from), nil
}

func (r *simpleReader) buffered() int { return 0 }
func (r *simpleReader) mode() string  { return "simple" }

// simpleWriter 是逐包写出口（WriteToUDPAddrPort）。
type simpleWriter struct {
	conn *net.UDPConn
}

func (w *simpleWriter) add(pkt []byte, to netip.AddrPort) bool {
	_, _ = w.conn.WriteToUDPAddrPort(pkt, to)
	return true
}

func (w *simpleWriter) flush() (int, error) { return 0, nil }
func (w *simpleWriter) pending() int        { return 0 }

// batchReader 用 recvmmsg 一次取多个包，再逐包交付。
//
// 逐包交付的形态与 tunnet.ReadPacket 一致：调用方看不到批的存在，只多了一个
// buffered() 信号。这样 loop 的处理逻辑不必为批量化改写。
//
// 开启 GRO 时单条消息可能是多个背靠背隧道包的聚合，需要按内核给出的分段大小
// 在用户态拆开——拆包也在这里完成，对调用方同样透明。
type batchReader struct {
	pc    *ipv4.PacketConn
	msgs  []ipv4.Message
	store [][]byte
	oob   [][]byte
	gro   bool

	nRead int
	next  int
	// 当前消息的 GRO 拆包进度。
	segTotal int
	segSize  int
	segCount int
	segNext  int
}

func newBatchReader(conn *net.UDPConn, gro bool) *batchReader {
	r := &batchReader{
		pc:    ipv4.NewPacketConn(conn),
		msgs:  make([]ipv4.Message, udpBatch),
		store: make([][]byte, udpBatch),
		gro:   gro,
	}
	bufSize := udpReadBuf
	if gro {
		// 聚合消息可以携带多个背靠背的包，缓冲要按突发上限备量。
		bufSize = gsoMaxBurst
		r.oob = make([][]byte, udpBatch)
	}
	for i := range r.msgs {
		r.store[i] = make([]byte, bufSize)
		r.msgs[i].Buffers = [][]byte{r.store[i]}
		if gro {
			r.oob[i] = make([]byte, oobBufSize())
			r.msgs[i].OOB = r.oob[i]
		}
	}
	return r
}

func (r *batchReader) read() ([]byte, netip.AddrPort, error) {
	for {
		// 先把当前消息剩余的 GRO 分段交付完。
		if r.segNext < r.segCount {
			i := r.next - 1
			start, end := groSegmentAt(r.segTotal, r.segSize, r.segNext)
			r.segNext++
			if end > start {
				ua, ok := r.msgs[i].Addr.(*net.UDPAddr)
				if !ok {
					continue
				}
				return r.store[i][start:end], addrPortOf(ua), nil
			}
			continue
		}
		for r.next >= r.nRead {
			// Buffers/OOB 会被 unpack 改写（长度置为实际读入的字节数），每轮
			// 必须恢复成完整缓冲，否则第二批开始只能读进上一批的包长。
			for i := range r.msgs {
				r.msgs[i].Buffers[0] = r.store[i]
				if r.gro {
					r.msgs[i].OOB = r.oob[i]
				}
			}
			n, err := r.pc.ReadBatch(r.msgs, 0)
			if err != nil {
				return nil, netip.AddrPort{}, err
			}
			r.nRead, r.next = n, 0
		}
		i := r.next
		r.next++
		m := &r.msgs[i]
		if m.N <= 0 {
			continue
		}
		r.segTotal, r.segSize, r.segNext = m.N, 0, 0
		if r.gro && m.NN > 0 {
			r.segSize = groSegmentSize(m.OOB[:m.NN])
		}
		r.segCount = groSegments(r.segTotal, r.segSize)
	}
}

func (r *batchReader) buffered() int {
	n := r.segCount - r.segNext
	if n < 0 {
		n = 0
	}
	if r.nRead > r.next {
		n += r.nRead - r.next
	}
	return n
}

func (r *batchReader) mode() string {
	if r.gro {
		return "batch+gro"
	}
	return "batch"
}

// batchWriter 攒批后用 sendmmsg 一次发出。
//
// 开启 GSO 时会把「同目的、连续、等长」的包合并进一条消息由内核分段。游戏
// 流量的包长参差不齐，这一条命中率天然很低，所以它默认关闭；合并判定见 gso.go。
type batchWriter struct {
	pc    *ipv4.PacketConn
	msgs  []ipv4.Message
	store [][]byte
	addrs []net.UDPAddr
	oob   [][]byte
	runs  []segRun
	gso   bool
	n     int
}

func newBatchWriter(conn *net.UDPConn, gso bool) *batchWriter {
	w := &batchWriter{
		pc:    ipv4.NewPacketConn(conn),
		msgs:  make([]ipv4.Message, udpBatch),
		store: make([][]byte, udpBatch),
		addrs: make([]net.UDPAddr, udpBatch),
		runs:  make([]segRun, udpBatch),
		gso:   gso,
	}
	bufSize := tunnel.MaxPacket
	if gso {
		bufSize = gsoMaxBurst
		w.oob = make([][]byte, udpBatch)
	}
	for i := range w.msgs {
		w.store[i] = make([]byte, bufSize)
		w.msgs[i].Buffers = [][]byte{nil}
		if gso {
			w.oob[i] = make([]byte, oobBufSize())
		}
	}
	return w
}

func (w *batchWriter) add(pkt []byte, to netip.AddrPort) bool {
	if len(pkt) == 0 {
		return true
	}
	// GSO：尝试并入上一条消息（同目的 + 等长 + 未封口）。
	if w.gso && w.n > 0 {
		i := w.n - 1
		if w.addrs[i].Port == int(to.Port()) &&
			w.addrs[i].IP.Equal(net.IP(to.Addr().AsSlice())) &&
			w.runs[i].canAppend(len(pkt)) &&
			w.runs[i].total+len(pkt) <= len(w.store[i]) {
			copy(w.store[i][w.runs[i].total:], pkt)
			w.runs[i] = w.runs[i].append(len(pkt))
			w.msgs[i].Buffers[0] = w.store[i][:w.runs[i].total]
			return true
		}
	}
	if w.n >= len(w.msgs) {
		return false
	}
	if len(pkt) > len(w.store[w.n]) {
		return true // 超规格包丢弃：让它卡住整批等于一个畸形包拖停全体
	}
	i := w.n
	n := copy(w.store[i], pkt)
	w.msgs[i].Buffers[0] = w.store[i][:n]
	w.runs[i] = segRun{total: n}
	w.msgs[i].OOB = nil
	// 地址存在预分配的数组里，只写字段不新建对象——每包一次 &net.UDPAddr{}
	// 就是又一处热路径分配。
	w.addrs[i].IP = append(w.addrs[i].IP[:0], to.Addr().AsSlice()...)
	w.addrs[i].Port = int(to.Port())
	w.addrs[i].Zone = to.Addr().Zone()
	w.msgs[i].Addr = &w.addrs[i]
	w.n++
	return true
}

func (w *batchWriter) flush() (int, error) {
	if w.n == 0 {
		return 0, nil
	}
	n := w.n
	w.n = 0
	if w.gso {
		for i := 0; i < n; i++ {
			if seg := w.runs[i].controlSize(); seg > 0 {
				w.msgs[i].OOB = gsoControl(w.oob[i], seg)
			} else {
				w.msgs[i].OOB = nil
			}
		}
	}
	sent, err := w.pc.WriteBatch(w.msgs[:n], 0)
	if err != nil {
		return sent, err
	}
	if sent < n {
		// 部分发出：剩下的包丢弃（UDP 语义允许），但要让调用方能计数。
		return sent, errPartialBatch
	}
	return sent, nil
}

func (w *batchWriter) pending() int { return w.n }

// errPartialBatch 表示 sendmmsg 只发出了批中的一部分（socket 缓冲压力）。
var errPartialBatch = errors.New("tunnelapp: udp 批量发送部分完成")

// normalizeAddrPort 把 v4-in-v6 映射地址归一成 IPv4。
func normalizeAddrPort(ap netip.AddrPort) netip.AddrPort {
	addr := ap.Addr()
	if addr.Is4In6() {
		return netip.AddrPortFrom(addr.Unmap(), ap.Port())
	}
	return ap
}

// ioSetup 描述实际生效的收发配置（日志与诊断用）。
type ioSetup struct {
	Mode  string
	Batch bool
	GRO   bool
	GSO   bool
	Notes []string
}

// newUDPIO 按配置与平台能力选择收发实现。
//
// batch 模式在非 Linux 上会退化成逐包（x/net 只为 Linux/部分 BSD 实现了
// recvmmsg），所以这里直接探测一次：真正能批量才用批量，否则降级并让日志
// 说清楚——沉默的降级会让人对着「改了没效果」查半天。
func newUDPIO(conn *net.UDPConn, wantBatch, wantGRO, wantGSO bool) (udpReader, udpWriter, ioSetup) {
	setup := ioSetup{}
	if !wantBatch {
		setup.Mode = "simple"
		return newSimpleReader(conn), &simpleWriter{conn: conn}, setup
	}
	if !batchSupported() {
		setup.Mode = "simple"
		setup.Notes = append(setup.Notes, "本平台无 recvmmsg/sendmmsg，已降级为逐包收发")
		return newSimpleReader(conn), &simpleWriter{conn: conn}, setup
	}
	setup.Batch = true
	if wantGRO {
		if err := enableUDPGRO(conn); err != nil {
			setup.Notes = append(setup.Notes, "UDP GRO 开启失败（需 Linux ≥ 5.0），已按关闭处理："+err.Error())
		} else {
			setup.GRO = true
		}
	}
	setup.GSO = wantGSO
	r := newBatchReader(conn, setup.GRO)
	w := newBatchWriter(conn, setup.GSO)
	setup.Mode = r.mode()
	if setup.GSO {
		setup.Mode += "+gso"
	}
	return r, w, setup
}
