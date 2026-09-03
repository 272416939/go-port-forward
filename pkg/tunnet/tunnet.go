// Package tunnet 封装 wireguard/tun 的包级读写。
//
// wireguard/tun 的 Read/Write 是批量 API，且要求调用方在缓冲区前部预留
// offset 字节：Linux 侧 CreateTUN 固定带 IFF_VNET_HDR，写入时 offset 之前
// 必须容纳 10 字节 virtio_net_hdr（offset 小于该长度会被判为 invalid offset
// 而整批写入失败）；Windows wintun 无头，但同样只取 buf[offset:]。
// 这里沿用 wireguard-go 自身使用的 16 字节，读写共用。
package tunnet

import (
	"fmt"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

// Offset 是读写缓冲区中 IP 包的起始偏移。必须 ≥ virtio_net_hdr 的 10 字节。
const Offset = 16

const (
	// readHeadroom 是读缓冲相对 MTU 的余量。设备正常只会交出 ≤ MTU 的包
	// （内核按接口 MTU 分片），余量是给驱动层的边界情况留的——一旦真的超出，
	// 就是需要被看见的异常而不是可以静默吞掉的常态。
	readHeadroom = 512
	// writeSegment 是批量写单槽容量。写进 TUN 的包来自隧道对端，其上限由
	// 协议的 MaxPacket 约束（2000），2048 覆盖它且是页对齐的整数。
	writeSegment = 2048
)

// Device 是一个已打开的 TUN 设备。
//
// ReadPacket 内部维护批读队列（Linux 开启 GSO 后一次 Read 可能返回多个包），
// 因此不可并发调用；WritePacket 可并发（底层自带写锁）。
// 批量写用 Batch，每个写者各持一个，Batch 本身不可并发。
type Device struct {
	dev       tun.Device
	mtu       atomic.Int64
	batch     int
	bufSize   int
	bufs      [][]byte
	sizes     []int
	nRead     int // 上次批读返回的包数
	next      int // 下一个待取用的包索引
	drop      atomic.Int64
	closeOnce sync.Once
}

// Open 打开名为 name 的 TUN 设备（Windows 走 wintun，Linux 走 /dev/net/tun）。
func Open(name string, mtu int) (*Device, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("tunnet: create tun %q (需要管理员/root 权限): %w", name, err)
	}
	return newDevice(dev, mtu), nil
}

// newDevice 按设备的批量大小准备读缓冲（测试可注入伪设备）。
func newDevice(dev tun.Device, mtu int) *Device {
	batch := dev.BatchSize()
	if batch < 1 {
		batch = 1
	}
	// 批读 > 1 说明底层会把 GSO 巨包拆成不超过 MTU 的分片，每个缓冲按 MTU
	// 备量即可；批读 == 1（wintun）时单个缓冲必须能容纳网卡交出的任意包。
	bufSize := Offset + mtu + readHeadroom
	if batch == 1 {
		bufSize = Offset + 65535
	}
	d := &Device{
		dev:     dev,
		batch:   batch,
		bufSize: bufSize,
		bufs:    make([][]byte, batch),
		sizes:   make([]int, batch),
	}
	d.mtu.Store(int64(mtu))
	for i := range d.bufs {
		d.bufs[i] = make([]byte, bufSize)
	}
	return d
}

// MTU 返回设备 MTU（协商后的值）。
func (d *Device) MTU() int { return int(d.mtu.Load()) }

// SetMTU 更新本地记录的 MTU。协商只会把 MTU 往下调，因此读缓冲无需重建。
// 改系统网卡 MTU 由调用方另做（Linux 用 ip link、Windows 用 netsh）。
func (d *Device) SetMTU(mtu int) {
	if mtu > 0 && Offset+mtu+readHeadroom <= d.bufSize {
		d.mtu.Store(int64(mtu))
	}
}

// BatchSize 返回底层设备偏好的批量大小（Linux GSO 下通常 128，wintun 恒 1）。
func (d *Device) BatchSize() int { return d.batch }

// Buffered 返回上一次批读中尚未交付的包数。
//
// 出向泵用它决定「什么时候把攒起来的 UDP 发送批冲刷出去」：读队列刚好排空的
// 那一刻就是当前可处理的流量已全部消费完的时刻。批的边界由此完全由系统调用
// 返回多少包决定——不定时、不等待，绝不引入凑批延迟。
func (d *Device) Buffered() int {
	if d.nRead <= d.next {
		return 0
	}
	return d.nRead - d.next
}

// ReadBufSize 返回调用方读缓冲应有的最小长度。
//
// 按它分配，ReadPacket 里「包比调用方缓冲大」这条丢弃路径就只会在设备真的
// 交出超规格包时命中——那是需要被看见的异常。此前调用方硬编码 1500，一旦
// MTU 提高就变成静默丢包。
func (d *Device) ReadBufSize() int { return d.bufSize - Offset }

// Dropped 返回因超出缓冲容量而丢弃的包数（正常情况下恒为 0）。
//
// 必须被上层透出到指标里：这一层的丢弃对应用完全不可见，不透出就是黑盒丢包。
func (d *Device) Dropped() int64 { return d.drop.Load() }

// ReadPacket 取出一个 IP 包写入 p，返回包长度。p 应按 ReadBufSize 分配；
// 超出它的包无法交付，计入 Dropped 后跳过。
func (d *Device) ReadPacket(p []byte) (int, error) {
	for {
		for d.next >= d.nRead {
			n, err := d.dev.Read(d.bufs, d.sizes, Offset)
			if err != nil {
				return 0, err
			}
			d.nRead, d.next = n, 0
		}
		i := d.next
		d.next++
		size := d.sizes[i]
		if size <= 0 {
			continue
		}
		if size > len(p) || Offset+size > len(d.bufs[i]) {
			d.drop.Add(1)
			continue
		}
		return copy(p, d.bufs[i][Offset:Offset+size]), nil
	}
}

// WritePacket 写出一个 IP 包（p 为裸 IP 包，前置 offset 空间由本函数准备）。
//
// 低频路径专用（客户端安装器代写、单包场景）。热路径请用 Batch：这里每包
// 一次分配 + 一次拷贝 + 一次 syscall。
func (d *Device) WritePacket(p []byte) error {
	buf := make([]byte, Offset+len(p))
	copy(buf[Offset:], p)
	_, err := d.dev.Write([][]byte{buf}, Offset)
	return err
}

// Close 关闭设备。幂等：Engine.Stop 会提前关它以解除阻塞读，run 的 defer
// 还会再关一次——第二次必须是无操作，否则会把 wintun 的关闭错误翻出来。
func (d *Device) Close() error {
	var err error
	d.closeOnce.Do(func() { err = d.dev.Close() })
	return err
}

// Batch 是一批待写入 TUN 的包。
//
// 存在的理由：底层 tun.Device.Write 本来就是批量 API（Linux 读侧早已吃到
// 批量红利，写侧一直没用上）。逐包写的代价是每包一次 make+copy+syscall；
// 攒批之后每批一次 syscall，且调用方可以**把解密后的明文直接写进 Next()
// 返回的缓冲**，连明文分配都一起消失。
//
// wintun（BatchSize()==1）下底层 Write 内部退化为逐包发送，但 make+copy
// 已经消失，客户端仍有净收益。
//
// 不可并发使用：每个写 goroutine 各持一个 Batch。
type Batch struct {
	dev   *Device
	store [][]byte // 各槽位的完整缓冲（含 Offset 前缀）
	slots [][]byte // 提交后的切片视图，交给 dev.Write
	n     int
}

// NewBatch 建一个批量写句柄。size ≤ 0 时按设备偏好的批量大小。
func (d *Device) NewBatch(size int) *Batch {
	if size <= 0 {
		size = d.batch
	}
	b := &Batch{
		dev:   d,
		store: make([][]byte, size),
		slots: make([][]byte, size),
	}
	for i := range b.store {
		b.store[i] = make([]byte, Offset+writeSegment)
	}
	return b
}

// Cap 返回批量容量。
func (b *Batch) Cap() int { return len(b.store) }

// Len 返回当前已提交的包数。
func (b *Batch) Len() int { return b.n }

// Next 返回下一个槽位的可写区域（不含 Offset 前缀），供调用方直接写入 IP 包
// （典型用法：把它作为解密输出缓冲）。批已满时返回 nil，调用方应先 Flush。
//
// 返回的切片长度为 0、容量为单槽上限：按 append 语义写入，随后用实际写入的
// 长度调用 Commit。不 Commit 即视为放弃该槽位（缓冲留待复用）。
func (b *Batch) Next() []byte {
	if b.n >= len(b.store) {
		return nil
	}
	return b.store[b.n][Offset:Offset]
}

// Commit 确认当前槽位写入了 size 字节。size ≤ 0 视为放弃。
func (b *Batch) Commit(size int) {
	if size <= 0 || b.n >= len(b.store) {
		return
	}
	if Offset+size > len(b.store[b.n]) {
		b.dev.drop.Add(1)
		return
	}
	b.slots[b.n] = b.store[b.n][:Offset+size]
	b.n++
}

// Add 拷贝一个包进批（供已有明文缓冲的调用方使用）。
// 返回 false 表示批已满，调用方应 Flush 后重试。
func (b *Batch) Add(p []byte) bool {
	dst := b.Next()
	if dst == nil {
		return false
	}
	if len(p) > cap(dst) {
		// 超规格包：丢弃并计数。返回 true 表示「已处理」——让它卡住整批
		// 会把一个畸形包变成一次全体停摆。
		b.dev.drop.Add(1)
		return true
	}
	b.Commit(copy(dst[:cap(dst)], p))
	return true
}

// Flush 把已提交的包一次写入设备并清空批。
//
// 内核拷贝语义：dev.Write 返回时数据已被取走，暂存可立即复用（与
// wireguard-go 自身用法一致）。整批失败时错误上抛，绝不静默——数据面写失败
// 静默丢弃过一次，代价是整轮排查都被那行丢掉的错误误导。
func (b *Batch) Flush() error {
	if b.n == 0 {
		return nil
	}
	n := b.n
	b.n = 0
	_, err := b.dev.dev.Write(b.slots[:n], Offset)
	return err
}
