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
	batch   int
	reads   [][][]byte // 每次 Read 交付的包组
	readIdx int
	written [][]byte
	wrOff   int
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
	for _, b := range bufs {
		f.written = append(f.written, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}

func (f *fakeTun) MTU() (int, error)          { return 1400, nil }
func (f *fakeTun) Name() (string, error)      { return "fake", nil }
func (f *fakeTun) Events() <-chan tun.Event   { return nil }
func (f *fakeTun) Close() error               { return nil }
func (f *fakeTun) BatchSize() int             { return f.batch }

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
