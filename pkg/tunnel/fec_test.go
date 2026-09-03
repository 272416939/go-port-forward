package tunnel

// FEC 与冗余副本的用例矩阵（OPT-13 / OPT-15）。
//
// 每条都对应一个具体的失效模式，不是凑覆盖率：还原出的密文盒必须逐字节等于
// 原包（否则解密失败，纠错等于没做）、丢 ≥2 必须干净放弃（否则组状态泄漏或
// 误还原）、篡改载荷必须解不开（否则纠错成了绕过认证的通道）。

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// fecSend 封装 n 个 Data 包，返回 wire 副本序列与被触发的 FEC 校验包序列。
func fecSend(t testing.TB, s *Session, payloads [][]byte) (wires, groups [][]byte) {
	t.Helper()
	for _, p := range payloads {
		wire, extra := s.SealDataFEC(sealBuf(), p)
		wires = append(wires, append([]byte(nil), wire...))
		if extra != nil {
			groups = append(groups, append([]byte(nil), extra...))
		}
	}
	return wires, groups
}

func fecPayloads(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		// 长度刻意不等：长度前缀进 XOR 才能还原出正确的盒长，等长会让这条
		// 逻辑的 bug 完全测不出来。
		p := bytes.Repeat([]byte{byte(0x40 + i)}, 60+i*37)
		p[0] = 0x45
		out[i] = p
	}
	return out
}

// 组内丢任意 1 个包都必须能补回，且补回的包与原包逐字节一致。
func TestFECRecoversSingleLoss(t *testing.T) {
	for missing := 0; missing < fecGroup; missing++ {
		client, server := sessionPair(t, FeatFEC)
		if !client.FECEnabled() || !server.FECEnabled() {
			t.Fatal("FeatFEC 下两端都应启用纠错")
		}
		payloads := fecPayloads(fecGroup)
		wires, groups := fecSend(t, client, payloads)
		if len(groups) != 1 {
			t.Fatalf("组满应恰好产出 1 个校验包，得到 %d", len(groups))
		}

		// 除 missing 之外的成员正常送达。
		for i, w := range wires {
			if i == missing {
				continue
			}
			plain, err := server.OpenData(sealBuf(), w)
			if err != nil {
				t.Fatalf("missing=%d: 成员 %d 解密失败: %v", missing, i, err)
			}
			if !bytes.Equal(plain, payloads[i]) {
				t.Fatalf("missing=%d: 成员 %d 明文不符", missing, i)
			}
		}

		if !server.HandleFEC(groups[0]) {
			t.Fatalf("missing=%d: 校验包应被登记", missing)
		}
		rec := server.Recover()
		if rec == nil {
			t.Fatalf("missing=%d: 应补回一个包", missing)
		}
		// 还原盒必须逐字节等于原始线上包：差一个字节就解不开。
		if !bytes.Equal(rec, wires[missing]) {
			t.Fatalf("missing=%d: 还原盒与原包不一致\n got %x\nwant %x",
				missing, rec[:min(32, len(rec))], wires[missing][:min(32, len(wires[missing]))])
		}
		// 走正常接收路径：认证 + 重放窗口 + 解密全部照原路生效。
		plain, err := server.OpenData(sealBuf(), rec)
		if err != nil {
			t.Fatalf("missing=%d: 还原包必须能走正常解密路径: %v", missing, err)
		}
		if !bytes.Equal(plain, payloads[missing]) {
			t.Fatalf("missing=%d: 还原明文不符", missing)
		}
		if v := server.Stats().View(); v.FECRecovered != 1 {
			t.Fatalf("missing=%d: FECRecovered = %d", missing, v.FECRecovered)
		}
		if server.Recover() != nil {
			t.Fatalf("missing=%d: 不应有第二个还原包", missing)
		}
	}
}

// 丢 ≥2 时 XOR 无解：必须干净放弃，不得误还原，也不得影响下一组。
func TestFECGivesUpOnDoubleLoss(t *testing.T) {
	client, server := sessionPair(t, FeatFEC)
	payloads := fecPayloads(fecGroup)
	wires, groups := fecSend(t, client, payloads)

	for i, w := range wires {
		if i == 2 || i == 5 {
			continue // 丢两个
		}
		if _, err := server.OpenData(sealBuf(), w); err != nil {
			t.Fatalf("成员 %d: %v", i, err)
		}
	}
	server.HandleFEC(groups[0])
	if rec := server.Recover(); rec != nil {
		t.Fatalf("丢 2 个包时不得还原，却得到 %x", rec[:min(16, len(rec))])
	}

	// 下一组必须完全正常——组状态不能被上一组的失败污染。
	next := fecPayloads(fecGroup)
	wires2, groups2 := fecSend(t, client, next)
	for i, w := range wires2 {
		if i == 0 {
			continue
		}
		if _, err := server.OpenData(sealBuf(), w); err != nil {
			t.Fatalf("下一组成员 %d: %v", i, err)
		}
	}
	if !server.HandleFEC(groups2[0]) {
		t.Fatal("下一组的校验包应被登记")
	}
	rec := server.Recover()
	if rec == nil || !bytes.Equal(rec, wires2[0]) {
		t.Fatal("上一组放弃后，下一组必须照常补回")
	}
}

// 校验包先到（乱序）：必须存着，等最后一个缺失成员到达时立即触发还原。
// 这是「滑动组、绝不等待」的核心行为。
func TestFECHandlesOutOfOrderGroupPacket(t *testing.T) {
	client, server := sessionPair(t, FeatFEC)
	payloads := fecPayloads(fecGroup)
	wires, groups := fecSend(t, client, payloads)

	// 校验包最先到达，此时组内一个成员都还没来。
	if !server.HandleFEC(groups[0]) {
		t.Fatal("校验包应被登记")
	}
	if rec := server.Recover(); rec != nil {
		t.Fatal("成员一个都没到时不得还原")
	}
	// 依次送达除最后一个之外的成员。
	for i := 0; i < fecGroup-1; i++ {
		if _, err := server.OpenData(sealBuf(), wires[i]); err != nil {
			t.Fatalf("成员 %d: %v", i, err)
		}
	}
	// 第 7 个成员到达的那一刻就该触发还原，不需要任何额外的等待或轮询。
	rec := server.Recover()
	if rec == nil || !bytes.Equal(rec, wires[fecGroup-1]) {
		t.Fatal("凑齐 7 个成员时必须立即还原最后一个")
	}
}

// 校验包本身丢失：不得有任何副作用，组内已到的包照常处理。
func TestFECGroupPacketLossIsHarmless(t *testing.T) {
	client, server := sessionPair(t, FeatFEC)
	payloads := fecPayloads(fecGroup)
	wires, _ := fecSend(t, client, payloads) // 校验包直接丢掉

	for i, w := range wires {
		plain, err := server.OpenData(sealBuf(), w)
		if err != nil || !bytes.Equal(plain, payloads[i]) {
			t.Fatalf("成员 %d: %v", i, err)
		}
	}
	if server.Recover() != nil {
		t.Fatal("没有校验包时不应产出还原包")
	}
	if v := server.Stats().View(); v.FECRecovered != 0 {
		t.Fatalf("stats = %+v", v)
	}
}

// 篡改校验载荷 1 bit：FEC 包自己走 AEAD，所以篡改必须在登记之前就失败——
// 纠错通道不能成为绕过认证的口子。
func TestFECTamperedGroupRejected(t *testing.T) {
	client, server := sessionPair(t, FeatFEC)
	payloads := fecPayloads(fecGroup)
	_, groups := fecSend(t, client, payloads)

	tampered := append([]byte(nil), groups[0]...)
	tampered[len(tampered)/2] ^= 0x01
	if server.HandleFEC(tampered) {
		t.Fatal("篡改过的校验包必须被认证拒绝")
	}
	if server.Recover() != nil {
		t.Fatal("认证失败的校验包不得产出还原包")
	}
	if v := server.Stats().View(); v.RxAuthFail == 0 {
		t.Fatalf("认证失败应被计数: %+v", v)
	}
}

// 重放一个已还原的包：它带的是本来的计数，必须被重放窗口正常拒绝。
// 窗口只管安全、不管恢复，两者正交。
func TestFECRecoveredPacketStillHitsReplayWindow(t *testing.T) {
	client, server := sessionPair(t, FeatFEC)
	payloads := fecPayloads(fecGroup)
	wires, groups := fecSend(t, client, payloads)

	for i := 1; i < len(wires); i++ {
		if _, err := server.OpenData(sealBuf(), wires[i]); err != nil {
			t.Fatalf("成员 %d: %v", i, err)
		}
	}
	server.HandleFEC(groups[0])
	rec := append([]byte(nil), server.Recover()...)
	if len(rec) == 0 {
		t.Fatal("应补回第 0 个包")
	}
	if _, err := server.OpenData(sealBuf(), rec); err != nil {
		t.Fatalf("首次打开还原包: %v", err)
	}
	if _, err := server.OpenData(sealBuf(), rec); !errors.Is(err, ErrReplay) {
		t.Fatalf("重放还原包必须被窗口拒绝，得到 %v", err)
	}
	// 原始包若随后姗姗来迟，同样是重放。
	if _, err := server.OpenData(sealBuf(), wires[0]); !errors.Is(err, ErrReplay) {
		t.Fatalf("迟到的原包必须被窗口拒绝，得到 %v", err)
	}
}

// FEC 关闭时 TypeFEC 一律不处理：这是「不认识就丢弃」的兼容路径，
// 也是 tunnel.fec 开关能安全回退的前提。
func TestFECDisabledIgnoresGroupPackets(t *testing.T) {
	client, _ := sessionPair(t, FeatFEC)
	_, groups := fecSend(t, client, fecPayloads(fecGroup))

	_, plain := sessionPair(t, 0)
	if plain.FECEnabled() {
		t.Fatal("未协商 FeatFEC 的会话不应启用纠错")
	}
	if plain.HandleFEC(groups[0]) {
		t.Fatal("未启用纠错时不得处理校验包")
	}
	if plain.Recover() != nil {
		t.Fatal("未启用纠错时不得产出还原包")
	}
}

// 组过期：连续跑很多组之后，早期未补齐的组必须被淘汰而不是无限攒着。
func TestFECPendingGroupsExpire(t *testing.T) {
	client, server := sessionPair(t, FeatFEC)
	// 第一组丢两个成员并送达校验包 → 该组永远补不齐。
	payloads := fecPayloads(fecGroup)
	wires, groups := fecSend(t, client, payloads)
	for i := 2; i < len(wires); i++ {
		if _, err := server.OpenData(sealBuf(), wires[i]); err != nil {
			t.Fatalf("成员 %d: %v", i, err)
		}
	}
	server.HandleFEC(groups[0])

	// 之后连续跑满若干组：过期淘汰必须发生，并被计入 FECGiveUp。
	for round := 0; round < 6; round++ {
		next := fecPayloads(fecGroup)
		w2, g2 := fecSend(t, client, next)
		for i := 1; i < len(w2); i++ {
			if _, err := server.OpenData(sealBuf(), w2[i]); err != nil {
				t.Fatalf("round %d 成员 %d: %v", round, i, err)
			}
		}
		if !server.HandleFEC(g2[0]) {
			t.Fatalf("round %d 校验包应被登记", round)
		}
		if rec := server.Recover(); rec == nil || !bytes.Equal(rec, w2[0]) {
			t.Fatalf("round %d 必须照常补回", round)
		}
	}
	if v := server.Stats().View(); v.FECGiveUp == 0 {
		t.Fatalf("补不齐的组必须被淘汰并计数: %+v", v)
	}
}

// 冗余副本：小包发两份，第二份靠重放窗口免费去重；大包与限频窗口内不触发。
func TestTailDuplicationSmallPackets(t *testing.T) {
	client, server := sessionPair(t, FeatTailDup)

	small := bytes.Repeat([]byte{0x45}, 64)
	wire, extra := client.SealDataFEC(sealBuf(), small)
	if extra == nil {
		t.Fatal("小包应触发冗余副本")
	}
	if !bytes.Equal(wire, extra) {
		t.Fatal("副本必须是同一密文盒（接收侧靠重放窗口去重）")
	}
	dup := append([]byte(nil), extra...)
	if _, err := server.OpenData(sealBuf(), wire); err != nil {
		t.Fatalf("首份必须可解: %v", err)
	}
	if _, err := server.OpenData(sealBuf(), dup); !errors.Is(err, ErrReplay) {
		t.Fatalf("副本必须被重放窗口拒绝，得到 %v", err)
	}

	// 限频窗口内不再发副本。
	if _, extra2 := client.SealDataFEC(sealBuf(), small); extra2 != nil {
		t.Fatal("限频窗口内不应再发副本")
	}
	// 大包不触发（副本只保护组尾小包）。
	time.Sleep(dupMinInterval + 5*time.Millisecond)
	if _, extra3 := client.SealDataFEC(sealBuf(), bytes.Repeat([]byte{0x45}, dupMaxSize+1)); extra3 != nil {
		t.Fatal("超过 dupMaxSize 的包不应发副本")
	}
	if v := client.Stats().View(); v.DupSent != 1 {
		t.Fatalf("DupSent = %d，期望 1", v.DupSent)
	}
}

// 未启用任何特性时，SealDataFEC 必须与 SealData 行为一致（无 extra）。
func TestSealDataFECWithoutFeatures(t *testing.T) {
	client, server := sessionPair(t, 0)
	want := bytes.Repeat([]byte{0x45}, 100)
	wire, extra := client.SealDataFEC(sealBuf(), want)
	if extra != nil {
		t.Fatal("未启用特性时不应产出额外包")
	}
	plain, err := server.OpenData(sealBuf(), wire)
	if err != nil || !bytes.Equal(plain, want) {
		t.Fatalf("往返失败: %v", err)
	}
}

// FEC 让出的 MTU 必须够装下最坏情况的校验包，否则校验包自己会被 IP 分片，
// 而分片丢失是整包全损——正是 FEC 想解决的问题。
//
// 不变量：开启 FEC 后隧道 MTU 降到 MaxTunMTU-FECOverhead，此时最坏校验包的
// 线上长度必须仍然不超过「未开 FEC 时最大数据包」的线上长度（那个尺寸已经
// 被验证过不分片：1400+25+28 = 1453 < 1500）。
func TestFECOverheadCoversWorstCaseGroup(t *testing.T) {
	client, _ := sessionPair(t, FeatFEC)
	mtu := MaxTunMTU - FECOverhead
	payloads := make([][]byte, fecGroup)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{0x45}, mtu)
	}
	_, groups := fecSend(t, client, payloads)
	if len(groups) != 1 {
		t.Fatalf("应产出 1 个校验包，得到 %d", len(groups))
	}
	wireBudget := MaxTunMTU + SealOverhead
	if len(groups[0]) > wireBudget {
		t.Fatalf("校验包 %d 字节 > 线上预算 %d 字节：FECOverhead(%d) 不足",
			len(groups[0]), wireBudget, FECOverhead)
	}
	if len(groups[0]) > MaxPacket {
		t.Fatalf("校验包 %d 字节超出 MaxPacket %d", len(groups[0]), MaxPacket)
	}
	// 同时确认 FECOverhead 没有虚高：再多让 8 字节就该装不下了（换句话说
	// 当前值是紧的，不是随手写的富余量）。
	if len(groups[0]) < wireBudget-8 {
		t.Fatalf("校验包只有 %d 字节而预算 %d：FECOverhead(%d) 让出得过多，白损失吞吐",
			len(groups[0]), wireBudget, FECOverhead)
	}
}

func BenchmarkFECGroupXOR1400(b *testing.B) {
	s := mustSession(b, FeatFEC)
	plain := bytes.Repeat([]byte{0x42}, MaxTunMTU-FECOverhead)
	dst := sealBuf()
	b.SetBytes(int64(len(plain)) * fecGroup)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < fecGroup; j++ {
			s.SealDataFEC(dst[:0], plain)
		}
	}
}
