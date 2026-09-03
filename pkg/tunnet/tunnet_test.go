package tunnet

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeTun 是可注入的 tun.Device：按脚本返回批读结果，并记录写入内容。
type fakeTun struct {
	batch    int
	reads    [][][]byte // 每次 Read 交付的包组
	readIdx  int
	written  [][]byte
	wrOff    int
	writes   int // Write 被调用的次数（批量写的验证锚点）
	wrErr    error
	wrGroups []int // 每次 Write 收到的包数
	// discard 让 Write 不记录内容：基准要测的是批量路径本身，替身的逐包拷贝
	// 会把自己的分配算到被测代码头上。
	discard bool
	closes  int // Close 被调用的次数（幂等性验证锚点）
}

func (f *fakeTun) File() *os.File { return nil }

func (f *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if f.readIdx >= len(f.reads) {
		return 0, os.ErrClosed
	}
	group := f.reads[f.readIdx]
	f.readIdx++
	if len(group) > len(bufs) {
		return 0, errors.New("fakeTun: group larger than bufs")
	}
	for i, pkt := range group {
		if offset+len(pkt) > len(bufs[i]) {
			return 0, errors.New("fakeTun: packet overflows caller buffer")
		}
		copy(bufs[i][offset:], pkt)
		sizes[i] = len(pkt)
	}
	return len(group), nil
}

func (f *fakeTun) Write(bufs [][]byte, offset int) (int, error) {
	f.wrOff = offset
	f.writes++
	f.wrGroups = append(f.wrGroups, len(bufs))
	if f.wrErr != nil {
		return 0, f.wrErr
	}
	if f.discard {
		return len(bufs), nil
	}
	for _, b := range bufs {
		f.written = append(f.written, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}

func (f *fakeTun) MTU() (int, error)        { return 1400, nil }
func (f *fakeTun) Name() (string, error)    { return "fake", nil }
func (f *fakeTun) Events() <-chan tun.Event { return nil }
func (f *fakeTun) Close() error {
	f.closes++
	return nil
}
func (f *fakeTun) BatchSize() int { return f.batch }

// ipPacket 造一个长度为 n 的可辨识 IPv4 包（首字节 0x45，尾字节为标记）。
func ipPacket(n int, tag byte) []byte {
	p := make([]byte, n)
	p[0] = 0x45
	p[n-1] = tag
	return p
}

// Offset 必须留够 Linux 侧 virtio_net_hdr（10 字节），否则 tun.Write 会以
// "invalid offset" 整批失败——该常量是数据面能否工作的硬约束。
func TestOffsetCoversVirtioNetHeader(t *testing.T) {
	if Offset < 10 {
		t.Fatalf("Offset = %d，必须 ≥ 10 以容纳 virtio_net_hdr", Offset)
	}
}

func TestReadPacketReturnsFullPacket(t *testing.T) {
	want := ipPacket(64, 0xAB)
	f := &fakeTun{batch: 1, reads: [][][]byte{{want}}}
	d := newDevice(f, 1400)

	buf := make([]byte, 1500)
	n, err := d.ReadPacket(buf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if n != len(want) {
		t.Fatalf("长度 = %d, 期望 %d（读侧不得截断 offset 字节）", n, len(want))
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("内容不符：得到 %x…%x", buf[:4], buf[n-1:n])
	}
}

// Linux 开启 GSO 后单次 Read 可返回多个包，逐个交付不得丢包。
func TestReadPacketDrainsBatch(t *testing.T) {
	pkts := [][]byte{ipPacket(40, 1), ipPacket(50, 2), ipPacket(60, 3)}
	f := &fakeTun{batch: 4, reads: [][][]byte{pkts}}
	d := newDevice(f, 1400)

	buf := make([]byte, 1500)
	for i, want := range pkts {
		n, err := d.ReadPacket(buf)
		if err != nil {
			t.Fatalf("第 %d 个包 ReadPacket: %v", i, err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("第 %d 个包内容不符", i)
		}
	}
	if _, err := d.ReadPacket(buf); err == nil {
		t.Fatal("批读耗尽后应继续向底层 Read（此处返回 ErrClosed）")
	}
}

func TestWritePacketPlacesPacketAtOffset(t *testing.T) {
	f := &fakeTun{batch: 1}
	d := newDevice(f, 1400)

	pkt := ipPacket(48, 0xCD)
	if err := d.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if f.wrOff != Offset {
		t.Fatalf("写入 offset = %d, 期望 %d", f.wrOff, Offset)
	}
	if len(f.written) != 1 || !bytes.Equal(f.written[0], pkt) {
		t.Fatalf("buf[Offset:] 应恰为原始 IP 包，得到 %x", f.written)
	}
}

// 超出调用方缓冲的包只能丢弃并计数，不能截断成半个包送进隧道。
func TestReadPacketDropsOversizePacket(t *testing.T) {
	big, small := ipPacket(900, 1), ipPacket(100, 2)
	f := &fakeTun{batch: 2, reads: [][][]byte{{big, small}}}
	d := newDevice(f, 1400)

	buf := make([]byte, 200)
	n, err := d.ReadPacket(buf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if !bytes.Equal(buf[:n], small) {
		t.Fatal("超长包应被跳过，返回下一个可容纳的包")
	}
	if d.Dropped() != 1 {
		t.Fatalf("Dropped = %d, 期望 1", d.Dropped())
	}
}

// 按 ReadBufSize 分配的缓冲必须能容纳设备可能交出的任意包：调用方此前硬编码
// 1500，MTU 一提高就变成静默丢包。
func TestReadBufSizeCoversDeviceBuffers(t *testing.T) {
	for _, batch := range []int{1, 4} {
		f := &fakeTun{batch: batch}
		d := newDevice(f, 1400)
		if d.ReadBufSize() < d.MTU() {
			t.Fatalf("batch=%d: ReadBufSize %d 小于 MTU %d", batch, d.ReadBufSize(), d.MTU())
		}
		pkt := ipPacket(d.ReadBufSize(), 0x7F)
		f.reads = [][][]byte{{pkt}}
		buf := make([]byte, d.ReadBufSize())
		n, err := d.ReadPacket(buf)
		if err != nil {
			t.Fatalf("batch=%d: ReadPacket: %v", batch, err)
		}
		if n != len(pkt) || d.Dropped() != 0 {
			t.Fatalf("batch=%d: n=%d dropped=%d，按 ReadBufSize 分配不该丢包", batch, n, d.Dropped())
		}
	}
}

// SetMTU 只允许在读缓冲能容纳的范围内调整：协商只往下调，越界值必须被忽略
// 而不是把 MTU 设成一个读缓冲装不下的数（那会让每个满长包静默丢弃）。
func TestSetMTURespectsBufferCapacity(t *testing.T) {
	d := newDevice(&fakeTun{batch: 4}, 1400)
	d.SetMTU(1300)
	if d.MTU() != 1300 {
		t.Fatalf("下调 MTU 失败: %d", d.MTU())
	}
	d.SetMTU(60000)
	if d.MTU() != 1300 {
		t.Fatalf("超出读缓冲容量的 MTU 必须被忽略，得到 %d", d.MTU())
	}
	d.SetMTU(0)
	if d.MTU() != 1300 {
		t.Fatalf("非法 MTU 必须被忽略，得到 %d", d.MTU())
	}
}

// 批量写：N 个包必须只产生一次底层 Write，且每个包都落在 Offset 之后、内容
// 逐字节保真、顺序保持。这三条任何一条错都是数据面故障。
func TestBatchWriteCoalescesIntoOneCall(t *testing.T) {
	f := &fakeTun{batch: 8}
	d := newDevice(f, 1400)
	b := d.NewBatch(0)
	if b.Cap() != 8 {
		t.Fatalf("批容量 = %d，期望跟随设备 BatchSize", b.Cap())
	}

	pkts := [][]byte{ipPacket(40, 1), ipPacket(1400, 2), ipPacket(64, 3)}
	for _, p := range pkts {
		if !b.Add(p) {
			t.Fatal("批未满时 Add 不应失败")
		}
	}
	if b.Len() != len(pkts) {
		t.Fatalf("Len = %d, 期望 %d", b.Len(), len(pkts))
	}
	if f.writes != 0 {
		t.Fatal("Flush 之前不得触发底层写")
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if f.writes != 1 {
		t.Fatalf("底层 Write 调用次数 = %d，期望 1（批量化的全部意义）", f.writes)
	}
	if f.wrOff != Offset {
		t.Fatalf("写入 offset = %d, 期望 %d", f.wrOff, Offset)
	}
	if len(f.written) != len(pkts) {
		t.Fatalf("写出包数 = %d, 期望 %d", len(f.written), len(pkts))
	}
	for i, want := range pkts {
		if !bytes.Equal(f.written[i], want) {
			t.Fatalf("第 %d 个包内容不符（顺序或暂存复用出错）", i)
		}
	}
	if b.Len() != 0 {
		t.Fatal("Flush 后批必须清空")
	}
	// 空批 Flush 不得产生 syscall。
	if err := b.Flush(); err != nil || f.writes != 1 {
		t.Fatalf("空批 Flush 应是空操作: err=%v writes=%d", err, f.writes)
	}
}

// Next/Commit 是零拷贝入口：调用方把明文直接解进槽位再提交，写出的内容必须
// 与它写入的逐字节一致。
func TestBatchNextCommitWritesInPlace(t *testing.T) {
	f := &fakeTun{batch: 4}
	d := newDevice(f, 1400)
	b := d.NewBatch(2)

	want := ipPacket(120, 0xAA)
	dst := b.Next()
	if dst == nil || len(dst) != 0 {
		t.Fatalf("Next 应返回长度 0 的可写切片，得到 %v", dst)
	}
	dst = append(dst, want...)
	b.Commit(len(dst))

	// 未 Commit 的槽位必须被放弃，不进入写出序列。
	if second := b.Next(); second == nil {
		t.Fatal("第二个槽位应可用")
	}
	if b.Len() != 1 {
		t.Fatalf("Len = %d，未 Commit 的槽位不该计入", b.Len())
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(f.written) != 1 || !bytes.Equal(f.written[0], want) {
		t.Fatalf("写出内容不符: %x", f.written)
	}
}

// 批满必须能被调用方感知（Next 返回 nil / Add 返回 false），否则包会被静默
// 丢掉——那正是「链路通但业务不通」的经典形态。
func TestBatchReportsFull(t *testing.T) {
	d := newDevice(&fakeTun{batch: 1}, 1400)
	b := d.NewBatch(2)
	if !b.Add(ipPacket(40, 1)) || !b.Add(ipPacket(40, 2)) {
		t.Fatal("前两个包应成功入批")
	}
	if b.Next() != nil {
		t.Fatal("批满时 Next 必须返回 nil")
	}
	if b.Add(ipPacket(40, 3)) {
		t.Fatal("批满时 Add 必须返回 false 让调用方 Flush")
	}
}

// 超出单槽容量的包丢弃并计数，但不得卡住整批。
func TestBatchDropsOversizePacket(t *testing.T) {
	f := &fakeTun{batch: 4}
	d := newDevice(f, 1400)
	b := d.NewBatch(2)

	huge := make([]byte, writeSegment+1)
	if !b.Add(huge) {
		t.Fatal("超规格包应被丢弃并视为已处理，不能卡住整批")
	}
	if d.Dropped() != 1 {
		t.Fatalf("Dropped = %d，期望 1", d.Dropped())
	}
	ok := ipPacket(50, 9)
	if !b.Add(ok) {
		t.Fatal("超规格包不应占用槽位")
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(f.written) != 1 || !bytes.Equal(f.written[0], ok) {
		t.Fatalf("只应写出合规包: %d 个", len(f.written))
	}
}

// 整批写失败必须把错误上抛：静默丢弃写错误曾让「服务端每个包都写失败」的
// 故障在日志里一个字都没有。
func TestBatchFlushPropagatesError(t *testing.T) {
	f := &fakeTun{batch: 4, wrErr: errors.New("boom")}
	d := newDevice(f, 1400)
	b := d.NewBatch(2)
	b.Add(ipPacket(40, 1))
	if err := b.Flush(); err == nil {
		t.Fatal("底层写失败必须上抛")
	}
	if b.Len() != 0 {
		t.Fatal("失败后批也要清空，否则下一轮会重复写同一批")
	}
}

// 暂存复用的经典风险是串包：连续多批写入，每批内容必须互不污染。
func TestBatchReuseDoesNotLeakAcrossFlushes(t *testing.T) {
	f := &fakeTun{batch: 4}
	d := newDevice(f, 1400)
	b := d.NewBatch(3)

	for round := 0; round < 5; round++ {
		var want [][]byte
		for i := 0; i < 3; i++ {
			// 长度递减：若暂存切片长度没被正确重置，上一轮的尾部会漏出来。
			p := ipPacket(300-round*40-i*7, byte(round*10+i))
			want = append(want, p)
			if !b.Add(p) {
				t.Fatalf("round %d: Add 失败", round)
			}
		}
		if err := b.Flush(); err != nil {
			t.Fatalf("round %d: Flush: %v", round, err)
		}
		got := f.written[len(f.written)-3:]
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("round %d 第 %d 个包被污染: len %d vs %d",
					round, i, len(got[i]), len(want[i]))
			}
		}
	}
	if f.writes != 5 {
		t.Fatalf("底层 Write 次数 = %d，期望 5", f.writes)
	}
}

// 批量写 vs 逐包写：前者每批一次 syscall、零分配，后者每包一次 make + 一次
// [][]byte 切片头分配 + 一次 syscall。两条都用 discard 替身，测的是本包代码。
func BenchmarkBatchWrite64(b *testing.B) {
	f := &fakeTun{batch: 64, discard: true}
	d := newDevice(f, 1400)
	batch := d.NewBatch(64)
	pkt := ipPacket(1400, 7)
	b.SetBytes(int64(len(pkt)) * 64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 64; j++ {
			batch.Add(pkt)
		}
		if err := batch.Flush(); err != nil {
			b.Fatal(err)
		}
	}
}

// Next/Commit 是零拷贝入口：调用方直接把数据写进槽位，连一次 copy 都省掉。
func BenchmarkBatchNextCommit64(b *testing.B) {
	f := &fakeTun{batch: 64, discard: true}
	d := newDevice(f, 1400)
	batch := d.NewBatch(64)
	pkt := ipPacket(1400, 7)
	b.SetBytes(int64(len(pkt)) * 64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 64; j++ {
			dst := batch.Next()
			batch.Commit(copy(dst[:cap(dst)], pkt))
		}
		if err := batch.Flush(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWritePacket64(b *testing.B) {
	f := &fakeTun{batch: 1, discard: true}
	d := newDevice(f, 1400)
	pkt := ipPacket(1400, 7)
	b.SetBytes(int64(len(pkt)) * 64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 64; j++ {
			if err := d.WritePacket(pkt); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// Device.Close 必须幂等：Engine.Stop 会提前关它以解除阻塞读（铁律 3），
// run 的 defer 还会再关一次——底层被关两次轻则多余错误、重则驱动异常。
func TestDeviceCloseIsIdempotent(t *testing.T) {
	f := &fakeTun{batch: 1}
	d := newDevice(f, 1400)
	if err := d.Close(); err != nil {
		t.Fatalf("第一次 Close: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("第二次 Close: %v", err)
	}
	if f.closes != 1 {
		t.Fatalf("底层 Close 次数 = %d，期望恰好 1", f.closes)
	}
}
