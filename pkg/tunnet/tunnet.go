// Package tunnet 封装 wireguard/tun 的包级读写。
//
// wireguard/tun 的 Read/Write 为批量 API 且带 offset（Linux 的 tun 包前有
// 4 字节 [flags][proto] 头，Windows wintun 无头但同样遵守 offset 约定）。
// 这里统一 offset=4，并在写入时按平台填充地址族前缀。
package tunnet

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

// Offset 是读写缓冲区中 IP 包的起始偏移。
const Offset = 4

// Device 是一个已打开的 TUN 设备。
type Device struct {
	dev tun.Device
	mtu int
}

// Open 打开名为 name 的 TUN 设备（Windows 走 wintun，Linux 走 /dev/net/tun）。
func Open(name string, mtu int) (*Device, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("tunnet: create tun %q (需要管理员/root 权限): %w", name, err)
	}
	return &Device{dev: dev, mtu: mtu}, nil
}

// MTU 返回设备 MTU。
func (d *Device) MTU() int { return d.mtu }

// ReadPacket 读取一个 IP 包（不含 4 字节前缀，返回长度为包长）。
func (d *Device) ReadPacket(buf []byte) (int, error) {
	if len(buf) < d.mtu+Offset {
		return 0, fmt.Errorf("tunnet: buffer too small")
	}
	sizes := make([]int, 1)
	n, err := d.dev.Read([][]byte{buf}, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 || sizes[0] < Offset {
		return 0, nil
	}
	return sizes[0] - Offset, nil
}

// WritePacket 写出一个 IP 包。IP 包必须位于 buf[Offset:]（wireguard/tun
// 约定：offset 前的空间由实现自动填充链路层头——Linux 按 IP 版本补
// flags+proto；Windows wintun 无头但同样跳过 offset）。
func (d *Device) WritePacket(p []byte) error {
	buf := make([]byte, Offset+len(p))
	copy(buf[Offset:], p)
	_, err := d.dev.Write([][]byte{buf}, Offset)
	return err
}

// Close 关闭设备。
func (d *Device) Close() error { return d.dev.Close() }
