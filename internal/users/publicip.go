package users

// 中转机公网地址探测。
//
// 接入码里的地址必须能让客户端的 UDP 直达本机。面板域名可能挂在 CDN/反代
// 后面，按请求 Host 推导得到的是 CDN 地址——所以这里的兜底只认 IP：
// 先看本机网卡上有没有公网 IPv4（直连公网的主机直接命中），没有再问公网
// 回显服务（NAT 云主机本机网卡是内网 IP，只能这样拿真实出口）。
//
// 成功结果缓存到进程退出：公网 IP 变更极罕见，而每次生成接入码都外呼不可
// 接受；失败退避一分钟，避免探测服务不可达时面板被外呼拖慢。

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"go-port-forward/internal/logger"
)

const (
	publicIPProbeTimeout = 3 * time.Second
	publicIPRetryBackoff = time.Minute
)

// 只挑固定返回 IPv4 的端点；顺序即尝试顺序。
var publicIPServices = []string{
	"https://api-4.ipify.org",
	"https://ifconfig.me/ip",
	"https://icanhazip.com",
}

// publicIPDetector 持有探测结果的进程级缓存。
type publicIPDetector struct {
	mu       sync.Mutex
	cached   string
	lastFail time.Time
}

// Detect 返回本机公网 IPv4，拿不到返回空串（并发安全）。
func (d *publicIPDetector) Detect() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cached != "" {
		return d.cached
	}
	if time.Since(d.lastFail) < publicIPRetryBackoff {
		return ""
	}
	ip := publicIPFromInterfaces()
	if ip == "" {
		ip = publicIPFromEchoServices()
	}
	if ip == "" {
		d.lastFail = time.Now()
		return ""
	}
	d.cached = ip
	logger.S.Infow("已自动探测中转机公网地址 | auto-detected relay public address", "addr", ip)
	return ip
}

// publicIPFromInterfaces 找本机网卡上的公网 IPv4。排除回环/私网/CGNAT/
// 链路本地后剩下的全局单播地址即视为公网。
func publicIPFromInterfaces() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP.To4()
		if ip != nil && isPublicIPv4(ip) {
			return ip.String()
		}
	}
	return ""
}

// publicIPFromEchoServices 依次请求公网回显服务拿出口 IP。
func publicIPFromEchoServices() string {
	client := &http.Client{Timeout: publicIPProbeTimeout}
	for _, svc := range publicIPServices {
		resp, err := client.Get(svc)
		if err != nil {
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if rerr != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(string(body))).To4()
		if ip != nil && isPublicIPv4(ip) {
			return ip.String()
		}
	}
	return ""
}

func isPublicIPv4(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	// CGNAT 100.64.0.0/10：运营商级 NAT，不是公网可达地址。
	if ip[0] == 100 && ip[1] >= 64 && ip[1] < 128 {
		return false
	}
	return ip.IsGlobalUnicast()
}
