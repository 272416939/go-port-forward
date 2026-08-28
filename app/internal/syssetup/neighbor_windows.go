//go:build windows

package syssetup

// AddStaticNeighbor 为 wintun 接口添加静态邻居（ARP）表项。
//
// wintun 是三层设备，Windows 对它不做 ARP，因此这一项不是回程能否通的
// 前提；保留它是为了在 Windows 把接口当以太网处理的边缘场景下省掉一次
// 解析。失败仅告警，不影响隧道建立。
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
