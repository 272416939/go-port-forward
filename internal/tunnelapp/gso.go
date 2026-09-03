package tunnelapp

// UDP 分段卸载（GSO）的合并判定与 GRO 拆包的边界计算。
//
// 这两段逻辑与平台无关且极易写错（内核对 UDP_SEGMENT 的等长约束是硬性的，
// 违反了会得到一堆长度错乱的包而不是报错），所以从 sockopt_linux.go 里摘出来
// 单独放，便于在任意平台上跑单测。

// gsoMaxBurst 是一条 GSO 消息允许携带的最大字节数。
//
// 上限来自内核对分段卸载的整体长度约束（一条消息拆出的段数不能超过 64），
// 这里用一个保守的绝对上限而不是去算段数——超了只会得到 EINVAL，不值得为几个
// 包的合并去踩这条边界。
const gsoMaxBurst = 32 * 1024

// segRun 描述一条 GSO 消息当前的分段状态。
type segRun struct {
	total   int  // 已合并的总字节数
	segSize int  // 段长（0 = 只有一个包，尚未确定段长）
	closed  bool // 已出现短尾段，不能再合并
}

// canAppend 报告长度为n 的包能否并入当前消息。
//
// 内核约束：除最后一段外所有段必须等长。于是只有两种情况可以合并：
//   - n == segSize：继续等长序列；
//   - n < segSize：作为短尾段并入，随后这条消息必须封口。
//
// n > segSize 一律不合并（那会让内核按 segSize 切出错乱的包）。
func (r segRun) canAppend(n int) bool {
	if r.closed || n <= 0 || r.total == 0 {
		return false
	}
	if r.total+n > gsoMaxBurst {
		return false
	}
	seg := r.segSize
	if seg == 0 {
		seg = r.total // 目前只有一个包，它的长度就是候选段长
	}
	return n <= seg
}

// append 记录一次合并，返回更新后的状态。调用方须先用 canAppend 判定。
func (r segRun) append(n int) segRun {
	seg := r.segSize
	if seg == 0 {
		seg = r.total
	}
	out := segRun{total: r.total + n, segSize: seg}
	if n < seg {
		out.closed = true // 短尾段之后不能再有分段
	}
	return out
}

// controlSize 返回该消息需要下发的分段大小；0 表示无需 GSO 控制数据。
func (r segRun) controlSize() int {
	if r.segSize == 0 || r.total <= r.segSize {
		return 0
	}
	return r.segSize
}

// groSegments 按 GRO 给出的分段大小切分一条聚合消息，返回各段在缓冲中的边界。
//
// segSize <= 0 或 >= total 表示这条消息没有被聚合，按单包处理。
func groSegments(total, segSize int) int {
	if segSize <= 0 || segSize >= total {
		return 1
	}
	n := total / segSize
	if total%segSize != 0 {
		n++
	}
	return n
}

// groSegmentAt 返回第 i 段在聚合缓冲里的 [start, end)。
func groSegmentAt(total, segSize, i int) (int, int) {
	if segSize <= 0 || segSize >= total {
		return 0, total
	}
	start := i * segSize
	end := start + segSize
	if end > total {
		end = total
	}
	return start, end
}
