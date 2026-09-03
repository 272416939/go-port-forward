package tunnel

// 会话层的纠错与冗余接口（OPT-13 / OPT-15）。
//
// 这一层的职责是把 fec.go 的组状态机接进发送/接收路径，并保持一条不变量：
// **还原出来的包与冗余副本都必须走正常的 OpenData**。纠错只负责把「本该到达
// 的密文盒」补齐，认证、重放窗口、解密一律照原路走。

import "time"

const (
	// dupMaxSize 是触发冗余副本的明文上限。只保护小包：玩家操作指令、
	// RakNet unconnected ping 这类一来一回的关键交互恰好落在组尾——组没满
	// 就没有校验包，FEC 保护不到它们。
	dupMaxSize = 256
	// dupMinInterval 是副本的最小间隔。不限频的话持续小包流会让上行翻倍，
	// 弱网用户反而更差。
	dupMinInterval = 20 * time.Millisecond
)

// SealDataFEC 封装一个 Data 包，并按会话特性附带纠错/冗余包。
//
// 返回 wire（必须发送）与 extra（非 nil 时也要发送）。extra 有两种形态：
//   - FEC 校验包：独立的一份密文，写在会话自己的发送暂存里；
//   - 冗余副本：**就是 wire 本身**（同一个切片），调用方把它再发一遍即可。
//
// extra 为什么不与 wire 合并成一个数据报：UDP 数据报是原子的，合并等于让
// 校验包与数据包同生共死，一次丢包同时带走两者，纠错就白做了。
func (s *Session) SealDataFEC(dst, ipPacket []byte) (wire, extra []byte) {
	base := len(dst)
	counter := s.nextCounter()
	out := s.sealCounter(dst, TypeData, counter, ipPacket)
	wire = out[base:]

	if s.feats&FeatFEC != 0 && s.fec != nil {
		if s.fec.addMember(counter, wire[1+CounterSize:]) {
			if group := s.sealGroup(); group != nil {
				return wire, group
			}
		}
	}
	if s.feats&FeatTailDup != 0 && len(ipPacket) <= dupMaxSize && s.allowDup() {
		// 副本 = 同一密文盒原样再发一份。接收侧零改动：第二份是同计数的重放，
		// 被现有窗口免费拒绝，先到的那份生效，代价仅一次失败的解密尝试。
		s.stats.dupSent.Add(1)
		return wire, wire
	}
	return wire, nil
}

// sealGroup 封装当前组的 FEC 校验包，结果在会话的发送暂存里，有效期到下一次
// SealDataFEC（与两端数据泵「同步消费当前包」的既有约定一致）。
func (s *Session) sealGroup() []byte {
	payload := s.fec.takeGroup()
	if len(payload) == 0 {
		return nil
	}
	out := s.sealCounter(s.fec.sendBuf[:0], TypeFEC, s.nextCounter(), payload)
	s.fec.sendBuf = out
	s.stats.fecSent.Add(1)
	return out
}

// allowDup 报告距上一个副本是否已超过限频间隔。
func (s *Session) allowDup() bool {
	now := time.Now()
	s.dupMu.Lock()
	defer s.dupMu.Unlock()
	if now.Sub(s.lastDupAt) < dupMinInterval {
		return false
	}
	s.lastDupAt = now
	return true
}

// HandleFEC 处理一个 FEC 校验包。返回 true 表示登记成功，调用方随后应循环
// 调用 Recover 取出可能被补回的 Data 包。
//
// 与 Open* 同属接收泵单 goroutine 路径。
func (s *Session) HandleFEC(p []byte) bool {
	if s.fec == nil || len(p) < 1 || p[0] != TypeFEC {
		return false
	}
	payload, _, err := s.OpenInto(s.ctrlBuf[:0], p)
	if err != nil {
		return false
	}
	return s.fec.addGroup(payload, &s.stats)
}

// Recover 取出一个由 FEC 补回的 Data 包（线上形态 [type][counter][盒]）。
// nil 表示暂无。返回的切片必须在本轮处理完毕（缓冲循环复用）。
//
// 调用方拿到它之后走与普通 Data 完全相同的路径：OpenData → 源/目的校验 →
// 写 TUN。安全语义因此与未启用 FEC 时逐条一致。
func (s *Session) Recover() []byte {
	if s.fec == nil {
		return nil
	}
	out := s.fec.popRecovered()
	if out != nil {
		s.stats.fecRecovered.Add(1)
	}
	return out
}

// FECEnabled 报告本会话是否启用了前向纠错。
func (s *Session) FECEnabled() bool { return s.fec != nil }
