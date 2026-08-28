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
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

// Offset 是读写缓冲区中 IP 包的起始偏移。必须 ≥ virtio_net_hdr 的 10 字节。
const Offset = 16

// Device 是一个已打开的 TUN 设备。
//
// ReadPacket 内部维护批读队列（Linux 开启 GSO 后一次 Read 可能返回多个包），
// 因此不可并发调用；WritePacket 可并发（底层自带写锁）。
type Device struct {
	dev   tun.Device
	mtu   int
	bufs  [][]byte
	sizes []int
	nRead int // 上次批读返回的包数
	next  int // 下一个待取用的包索引
	drop  atomic.Int64
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
	bufSize := Offset + mtu + 512
	if batch == 1 {
		bufSize = Offset + 65535
	}
	d := &Device{
		dev:   dev,
		mtu:   mtu,
		bufs:  make([][]byte, batch),
		sizes: make([]int, batch),
	}
	for i := range d.bufs {
		d.bufs[i] = make([]byte, bufSize)
	}
	return d
}

// MTU 返回设备 MTU。
func (d *Device) MTU() int { return d.mtu }

// Dropped 返回因超出调用方缓冲而丢弃的包数（正常情况下恒为 0）。
func (d *Device) Dropped() int64 { return d.drop.Load() }

// ReadPacket 取出一个 IP 包写入 p，返回包长度。p 需至少能容纳一个 MTU 包；
// 超长包无法经隧道转发，计入 Dropped 后跳过。
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
func (d *Device) WritePacket(p []byte) error {
	buf := make([]byte, Offset+len(p))
	copy(buf[Offset:], p)
	_, err := d.dev.Write([][]byte{buf}, Offset)
	return err
}

// Close 关闭设备。
func (d *Device) Close() error { return d.dev.Close() }
