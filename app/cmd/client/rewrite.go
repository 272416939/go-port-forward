package main

// 回包源地址改写（NAT 的用户态等价物）。
//
// 透明模式下 go-port-forward 以玩家真实 IP:端口 为源经隧道送达 Windows；
// BDS 的回包源地址是隧道虚拟 IP（10.66.0.2），若不改写直接发回玩家，
// 源地址与服务端公网地址不符会被丢弃。pf-client 在写入 TUN 前把
// src=10.66.0.2 的包改写为服务器公网 IP，并按协议处理校验和：
//   - UDP（IPv4）：校验和置 0 即表示“不校验”，合法且免重算
//   - TCP/ICMP：需要重算——透明模式仅支持 UDP，此处不处理
//
// 反方向（玩家 → BDS）源地址本就是玩家真实 IP，无需改写。

import (
	"bytes"
	"net"
)

// oldTunnelIP 是隧道虚拟网段中客户端的地址（回包的源地址）。
var oldTunnelIP = net.IPv4(10, 66, 0, 2)

// rewriteSource 对 IPv4 包做源地址改写（仅当源 = 隧道虚拟 IP）。
func rewriteSource(pkt []byte) {
	if serverIP == nil || len(pkt) < 20 || pkt[0]>>4 != 4 {
		return
	}
	if !bytes.Equal(pkt[12:16], oldTunnelIP) {
		return
	}
	copy(pkt[12:16], serverIP.To4())
	fixIPv4Checksum(pkt)
	fixL4ChecksumForAddr(pkt)
}

// fixIPv4Checksum 重算 IPv4 头校验和（IHL 假定无选项，20 字节）。
func fixIPv4Checksum(pkt []byte) {
	pkt[10], pkt[11] = 0, 0
	sum := onesComplementSum(pkt[:20])
	pkt[10] = byte(sum >> 8)
	pkt[11] = byte(sum)
}

// fixL4ChecksumForAddr 在传输层校验和上应用“旧地址→新地址”的增量修正
//（RFC 1624 增量技巧，无需完整重算伪头）。
func fixL4ChecksumForAddr(pkt []byte) {
	ihl := int(pkt[0]&0x0F) * 4
	if ihl+8 > len(pkt) {
		return
	}
	switch pkt[9] {
	case 17: // UDP：IPv4 下校验和 0 表示不校验，直接置 0
		if ihl+8 <= len(pkt) {
			pkt[ihl+6] = 0
			pkt[ihl+7] = 0
		}
	case 6: // TCP：增量修正
		applyAddrDelta(pkt[ihl:], oldTunnelIP, serverIP)
	}
}

// applyAddrDelta 对 TCP 校验和做源地址增量修正（old → new）。
func applyAddrDelta(tcpHdr []byte, oldIP, newIP []byte) {
	if len(tcpHdr) < 18 || len(oldIP) != 4 || len(newIP) != 4 {
		return
	}
	const off = 16 // TCP 头校验和在 16-17
	sum := uint32(tcpHdr[off])<<8 | uint32(tcpHdr[off+1])
	for i := 0; i < 4; i += 2 {
		sum += 0xFFFF - (uint32(oldIP[i])<<8 | uint32(oldIP[i+1])) // 减旧值（反码减法）
		sum += uint32(newIP[i])<<8 | uint32(newIP[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	tcpHdr[off] = byte(sum >> 8)
	tcpHdr[off+1] = byte(sum)
}

// onesComplementSum 标准 16 位反码求和。
func onesComplementSum(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return sum
}
