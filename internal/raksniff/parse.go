package raksniff

// RakNet 数据报/封装帧的最小解析器（被动只读）。
// Minimal RakNet datagram / encapsulated-frame parser (passive, read-only).
//
// 生态里存在两种帧编码流派（可靠性位在高位 5-7 或低位 0-2；split 字段在
// 可选序号之前或之后）。解析器对同一数据报按 2×2 组合逐一"整包验证"，
// 接受恰好消费完全部字节的那个组合；都不匹配则放弃该包 —— 只损失一次
// 嗅探机会，绝不影响转发。

import (
	"encoding/binary"
)

const (
	flagValid  = 0x80 // 置位表示这是游戏数据报（否则是 ACK/NAK 控制包）
	flagSplit  = 0x10 // 分片标志 | frame carries split info
	maxFrames  = 32   // 单数据报合理帧数上限
	maxSplitFrags = 512
)

// frameKind 枚举两种帧编码流派。
type frameKind int

const (
	kindReliabilityHigh splitAndRel = iota // reliability 在 bit7-5，split 字段在 length 之后
	kindReliabilityLow                     // reliability 在 bit3-0，split 字段在 length 之后
	kindSplitEarly                         // reliability 在 bit7-5，split 字段紧跟 flags
	kindReserved                           // 仅占位
)

type splitAndRel = frameKind

type frame struct {
	payload []byte
	split   bool
	total   uint32
	index   uint32
	id      uint16
}

// cursor 是带边界检查的字节读取器。
type cursor struct {
	b   []byte
	off int
}

func (c *cursor) remaining() int { return len(c.b) - c.off }

func (c *cursor) byteVal() (byte, bool) {
	if c.off >= len(c.b) {
		return 0, false
	}
	v := c.b[c.off]
	c.off++
	return v, true
}

func (c *cursor) uint16BE() (uint16, bool) {
	if c.off+2 > len(c.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint16(c.b[c.off:])
	c.off += 2
	return v, true
}

func (c *cursor) uint24LE() (uint32, bool) {
	if c.off+3 > len(c.b) {
		return 0, false
	}
	v := uint32(c.b[c.off]) | uint32(c.b[c.off+1])<<8 | uint32(c.b[c.off+2])<<16
	c.off += 3
	return v, true
}

func (c *cursor) uint32BE() (uint32, bool) {
	if c.off+4 > len(c.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint32(c.b[c.off:])
	c.off += 4
	return v, true
}

func (c *cursor) skip(n int) bool {
	if c.off+n > len(c.b) {
		return false
	}
	c.off += n
	return true
}

// accept consumes one raw datagram body and returns complete application
// payloads discovered (after de-fragmentation).
func (s *Session) accept(datagram []byte) [][]byte {
	var out [][]byte
	frames, ok := parseDatagram(datagram)
	if !ok {
		return nil
	}
	for _, f := range frames {
		if !f.split {
			out = append(out, f.payload)
			continue
		}
		if p, done := s.acceptFragment(f); done {
			out = append(out, p)
		}
	}
	return out
}

// parseDatagram 按四种流派组合依次尝试整包解析。
func parseDatagram(d []byte) ([]frame, bool) {
	if len(d) < 5 {
		return nil, false
	}
	if d[0]&flagValid == 0 {
		return nil, false // ACK/NAK 或非游戏流量 | control packet or foreign traffic
	}
	for _, kind := range []frameKind{kindReliabilityHigh, kindReliabilityLow, kindSplitEarly, kindReserved} {
		if frames, ok := parseDatagramKind(d, kind); ok {
			return frames, true
		}
	}
	return nil, false
}

func parseDatagramKind(d []byte, kind frameKind) ([]frame, bool) {
	c := &cursor{b: d, off: 4} // flags(1) + sequence(3)
	splitEarly := kind == kindSplitEarly
	highBits := kind == kindReliabilityHigh || kind == kindSplitEarly

	var frames []frame
	for c.remaining() > 0 && len(frames) < maxFrames {
		f, ok := parseFrame(c, highBits, splitEarly)
		if !ok {
			return nil, false // 该流派解释不下：立即判负
		}
		frames = append(frames, f)
	}
	if len(frames) == 0 {
		return nil, false
	}
	return frames, true
}

// parseFrame 解析单个封装帧。字段顺序：
//   - split-late：reliability → msgIdx → [seqIdx] → [ordIdx+ch] → [split] → length → payload
//   - split-early：reliability → split → msgIdx → [seqIdx] → [ordIdx+ch] → length → payload
func parseFrame(c *cursor, highBits, splitEarly bool) (frame, bool) {
	flags, ok := c.byteVal()
	if !ok {
		return frame{}, false
	}
	split := flags&flagSplit != 0

	var rel byte
	if highBits {
		rel = flags >> 5
	} else {
		rel = flags & 0x0F
	}
	if rel > 7 {
		return frame{}, false
	}

	f := frame{}

	readOptionals := func() bool {
		// reliable 家族（2,3,4,5,6）带 messageIndex(3)
		if rel >= 2 && rel != 7 {
			if !c.skip(3) {
				return false
			}
		}
		// sequenced（1,5,6）带 sequencedIndex(3)
		if rel == 1 || rel == 5 || rel == 6 {
			if !c.skip(3) {
				return false
			}
		}
		// ordered（3,4,5,6）带 orderIndex(3) + channel(1)
		if rel >= 3 && rel <= 6 {
			if !c.skip(4) {
				return false
			}
		}
		return true
	}

	if splitEarly {
		if split {
			total, ok1 := c.uint32BE()
			id, ok2 := c.uint16BE()
			index, ok3 := c.uint32BE()
			if !ok1 || !ok2 || !ok3 {
				return frame{}, false
			}
			if total == 0 || total > maxSplitFrags || index >= total {
				return frame{}, false
			}
			f.split, f.total, f.id, f.index = true, total, id, index
		}
		if !readOptionals() {
			return frame{}, false
		}
	} else {
		if !readOptionals() {
			return frame{}, false
		}
		if split {
			total, ok1 := c.uint32BE()
			id, ok2 := c.uint16BE()
			index, ok3 := c.uint32BE()
			if !ok1 || !ok2 || !ok3 {
				return frame{}, false
			}
			if total == 0 || total > maxSplitFrags || index >= total {
				return frame{}, false
			}
			f.split, f.total, f.id, f.index = true, total, id, index
		}
	}

	lengthBits, ok := c.uint16BE()
	if !ok {
		return frame{}, false
	}
	plen := int(lengthBits >> 3)
	if plen <= 0 || plen > maxPayloadSize {
		return frame{}, false
	}

	if plen > c.remaining() {
		return frame{}, false
	}
	f.payload = make([]byte, plen)
	copy(f.payload, c.b[c.off:c.off+plen])
	c.off += plen
	return f, true
}

// acceptFragment inserts a fragment and returns the joined payload once a
// group completes. Stale groups are replaced aggressively to bound memory.
func (s *Session) acceptFragment(f frame) ([]byte, bool) {
	ps, exists := s.splits[f.id]
	if !exists {
		ps = &pendingSplit{
			total: f.total,
			frags: make(map[uint32][]byte, f.total),
		}
		s.splits[f.id] = ps
		// 每会话只保留最近一组分片 | keep only the newest fragment group
		for id := range s.splits {
			if id != f.id {
				delete(s.splits, id)
			}
		}
	}
	if ps.total != f.total {
		return nil, false // 组参数冲突，视为脏数据
	}
	if _, dup := ps.frags[f.index]; !dup {
		ps.frags[f.index] = f.payload
		ps.received++
		ps.bytes += len(f.payload)
		if ps.bytes > maxPayloadSize*2 {
			delete(s.splits, f.id)
			return nil, false
		}
	}
	if ps.received != ps.total {
		return nil, false
	}
	delete(s.splits, f.id)
	joined := make([]byte, 0, ps.bytes)
	for i := uint32(0); i < ps.total; i++ {
		frag, ok := ps.frags[i]
		if !ok {
			return nil, false // 缺片（不应发生，防御性检查）
		}
		joined = append(joined, frag...)
	}
	if len(joined) > maxPayloadSize {
		return nil, false
	}
	return joined, true
}
