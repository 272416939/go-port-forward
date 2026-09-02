package tunnel

import (
	"math/rand"
	"testing"
)

// mapOracle 是旧版重放检查（map + 全表清理）的等价复刻，用作位图实现的
// oracle：任何输入序列下两者判定必须完全一致。
//
// 旧的判定语义：c <= stale 拒绝；已见拒绝；否则接受，且 c > max 时窗口前移
// （floor = max(0, c-recvWindow)，淘汰 <= floor 的旧计数）。
type mapOracle struct {
	max   uint64
	stale uint64
	seen  map[uint64]struct{}
}

func newMapOracle() *mapOracle {
	return &mapOracle{seen: map[uint64]struct{}{}}
}

func (o *mapOracle) accept(c uint64) bool {
	if c <= o.stale {
		return false
	}
	if _, dup := o.seen[c]; dup {
		return false
	}
	o.seen[c] = struct{}{}
	if c > o.max {
		o.max = c
		var floor uint64
		if c > recvWindow {
			floor = c - recvWindow
		}
		for k := range o.seen {
			if k <= floor {
				delete(o.seen, k)
			}
		}
		o.stale = floor
	}
	return true
}

// 位图实现与旧 map 实现必须在任意输入序列下判定一致：防重放是安全边界，
// 等价性用随机序列对拍锁死，而不是靠人脑枚举边界。
func TestReplayWindowBitmapMatchesMapOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(7947))
	newSession := func() *Session {
		return NewSession(&[32]byte{})
	}

	for round := 0; round < 200; round++ {
		s, o := newSession(), newMapOracle()
		next := uint64(1)
		for step := 0; step < 5000; step++ {
			var c uint64
			switch rng.Intn(10) {
			case 0, 1, 2, 3, 4: // 顺序推进
				c = next
				next++
			case 5: // 小幅乱序
				c = uint64(int64(next) - rng.Int63n(64))
			case 6: // 重放最近见过的包
				c = s.recvMax - uint64(rng.Intn(100))
			case 7: // 大跳变
				c = next + uint64(rng.Intn(1_000_000))
				next = c + 1
			case 8: // 早已滑出窗口的旧计数
				if s.recvMax > recvWindow*2 {
					c = s.recvMax - recvWindow - uint64(rng.Intn(1000))
				} else {
					c = next
					next++
				}
			default: // 非法 0
				c = 0
			}

			got, want := s.acceptCounter(c), o.accept(c)
			if got != want {
				t.Fatalf("round %d step %d: acceptCounter(%d) = %v, oracle = %v (max=%d base=%d)",
					round, step, c, got, want, s.recvMax, s.recvBase)
			}
		}
	}
}

// 每包只清一位：顺序流量下窗口前移的清理成本必须是 O(1)，不能退化成
// O(窗口)。这里无法直接测指令数，改测行为侧面——连续推进一大段后，
// 窗口之外的陈旧计数必须被拒绝（位确实被清掉了）。
func TestReplayWindowEvictsOldCounters(t *testing.T) {
	s := NewSession(&[32]byte{})
	// 隔一个跳一个：偶数计数从未到达，留给「窗口内未见」分支。
	for c := uint64(1); c <= recvWindow*3; c += 2 {
		if !s.acceptCounter(c) {
			t.Fatalf("顺序计数 %d 应被接受", c)
		}
	}
	top := uint64(recvWindow*3 - 1) // 已接受的最高计数（奇数）
	base := top - recvWindow + 1
	// 窗口下界之下全部拒绝（无论是否见过）。
	for _, c := range []uint64{1, 8191, 8192, uint64(recvWindow), base - 1} {
		if s.acceptCounter(c) {
			t.Fatalf("窗口下界之下的计数 %d 应被拒绝", c)
		}
	}
	// 窗口之内的未见计数（乱序到达的偶数）必须被接受。
	for _, c := range []uint64{base, base + 2, top - 1} {
		if !s.acceptCounter(c) {
			t.Fatalf("窗口内的未见计数 %d 应被接受", c)
		}
	}
	// 窗口之内的已见计数（奇数）重复必须拒绝。
	for _, c := range []uint64{top, top - 2, base + 1} {
		if s.acceptCounter(c) {
			t.Fatalf("窗口内的重复计数 %d 应被拒绝", c)
		}
	}
}
