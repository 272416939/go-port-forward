//go:build windows

package syssetup

// AddStaticNeighbor 为 wintun 接口添加静态邻居（ARP）表项。
//
// Windows 把 wintun 当以太网适配器，发往网关的回包前会做邻居解析，
// 而 wintun 是三层设备没有 ARP 应答——解析永远失败，回包全部滞留
// （症状：TUN 读不到任何出站包）。静态表项（MAC 任意）直接绕过解析，
// wintun 发送侧只取 IP 包、忽略二层，是社区验证过的标准做法。
func AddStaticNeighbor(ifaceName, ip, mac string) error {
	_, err := run("netsh", "interface", "ipv4", "add", "neighbors",
		ifaceName, ip, mac)
	return err
}

// RemoveStaticNeighbor 移除静态邻居表项（不存在不报错）。
func RemoveStaticNeighbor(ifaceName, ip string) {
	_, _ = run("netsh", "interface", "ipv4", "delete", "neighbors",
		ifaceName, ip)
}
