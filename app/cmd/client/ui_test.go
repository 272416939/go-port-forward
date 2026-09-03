//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// testAddressing 模拟服务端下发的隧道地址（多用户版不再有编译期常量）。
var testAddressing = tunnelAddressing{ClientIP: "10.66.0.7", Mask: "255.255.255.0", Gateway: "10.66.0.1"}

// startUI 必须能真正提供页面与接口，并且写操作要拒绝错误的 token——
// 这是这个本地控制面唯一的访问控制，不能回归。
func TestUIServerServesAndGuards(t *testing.T) {
	eng := NewEngine()
	url, _, err := startUI(eng)
	if err != nil {
		t.Fatalf("startUI: %v", err)
	}
	base, token, ok := strings.Cut(url, "/?t=")
	if !ok {
		t.Fatalf("入口 URL 缺少 token：%s", url)
	}

	t.Run("嵌入页面可访问", func(t *testing.T) {
		for _, path := range []string{"/", "/app.css", "/app.js"} {
			res, err := http.Get(base + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Errorf("GET %s = %d, 期望 200（embed 资源是否漏打包？）", path, res.StatusCode)
			}
		}
	})

	t.Run("带 token 可读状态", func(t *testing.T) {
		res, err := http.Get(base + "/api/status?t=" + token)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, 期望 200", res.StatusCode)
		}
		var snap Snapshot
		if err := json.NewDecoder(res.Body).Decode(&snap); err != nil {
			t.Fatalf("解析响应: %v", err)
		}
		if snap.State != StateIdle {
			t.Errorf("初始状态 = %q, 期望 %q", snap.State, StateIdle)
		}
		// 未连接时隧道地址是空的：多用户版由服务端在握手应答里下发，
		// 客户端不再有编译期常量可以先填。
		if snap.TunIP != "" {
			t.Errorf("未连接时 tun_ip = %q, 期望空（地址由服务端下发）", snap.TunIP)
		}
		// 未连接时 routes 必须是 []，不能是 null——前端直接 for..of 遍历。
		if snap.Routes == nil {
			t.Error("routes = null，期望空数组")
		}
	})

	t.Run("错误 token 被拒绝", func(t *testing.T) {
		for _, path := range []string{"/api/status?t=wrong", "/api/status"} {
			res, err := http.Get(base + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			res.Body.Close()
			if res.StatusCode != http.StatusForbidden {
				t.Errorf("GET %s = %d, 期望 403", path, res.StatusCode)
			}
		}
	})

	t.Run("连接接口拒绝缺凭据的请求", func(t *testing.T) {
		// 空请求、只有地址没有凭据、损坏的接入码：都必须 400 而不是
		// 带着空凭据去握手（那样服务端只会静默丢包，用户看到的是「无应答」）。
		for _, body := range []string{
			`{}`,
			`{"addr":""}`,
			`{"addr":"1.2.3.4:7947"}`,
			`{"code":"pf1.!!!broken"}`,
			`{"code":"not-an-access-code"}`,
		} {
			res, err := http.Post(base+"/api/connect?t="+token, "application/json",
				strings.NewReader(body))
			if err != nil {
				t.Fatalf("connect %s: %v", body, err)
			}
			res.Body.Close()
			if res.StatusCode != http.StatusBadRequest {
				t.Errorf("%s = %d, 期望 400", body, res.StatusCode)
			}
		}
	})

	t.Run("GET 不能触发连接", func(t *testing.T) {
		res, err := http.Get(base + "/api/connect?t=" + token)
		if err != nil {
			t.Fatalf("connect via GET: %v", err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("GET /api/connect = %d, 期望 403（写操作必须是 POST）", res.StatusCode)
		}
	})
}

// eligible 是防止把隧道自身流量或本机流量导进 TUN 的唯一守卫。
func TestRouteEligibility(t *testing.T) {
	relay := "203.0.113.9"
	m := newRouteManager(relay, testAddressing, nil, func(string, ...any) {})

	rejected := []string{
		relay,                    // 中转机自己：会形成隧道环路
		testAddressing.Gateway,   // 隧道网关（服务端下发）
		testAddressing.ClientIP,  // 本机隧道地址
		"127.0.0.1",
		"10.1.2.3",
		"192.168.1.1",
		"172.16.0.1",
		"224.0.0.1",
		"169.254.1.1",
		"0.0.0.0",
		"255.255.255.255",
		"2001:db8::1", // 仅支持 IPv4
		"",
		"不是地址",
	}
	for _, ip := range rejected {
		if m.eligibleStr(ip) {
			t.Errorf("eligible(%q) = true, 期望被拒绝", ip)
		}
	}

	for _, ip := range []string{"111.29.236.135", "8.8.8.8", "203.0.113.10"} {
		if !m.eligibleStr(ip) {
			t.Errorf("eligible(%q) = false, 期望允许（公网单播）", ip)
		}
	}
}

// ipv4 造一个源/目的可控的 IPv4 包，总长度 total 字节。
func ipv4(src, dst [4]byte, total int) []byte {
	p := make([]byte, total)
	p[0] = 0x45
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	return p
}

// 字节必须按方向归到正确的 IP 上：入站看源地址，回程看目的地址。方向搞反
// 会让两列数字互换，而界面上看起来一切正常。
func TestPerIPByteAttribution(t *testing.T) {
	m := newRouteManager("203.0.113.9", testAddressing, nil, func(string, ...any) {})

	// 预置两条状态，避免 ensure() 真的去跑 route.exe 改动系统路由表。
	// installing 默认为 false，所以 deliverInbound 走快路径、不进缓冲。
	alice, bob := "111.29.236.135", "8.8.8.8"
	m.mu.Lock()
	m.states[ra(alice)] = newRouteState(time.Now())
	m.states[ra(bob)] = newRouteState(time.Now())
	m.publish()
	m.mu.Unlock()

	aliceIP := [4]byte{111, 29, 236, 135}
	bobIP := [4]byte{8, 8, 8, 8}
	tunIP := [4]byte{10, 66, 0, 2}

	// 玩家 alice 的入站包：源 = alice，计入 alice 的 down。
	m.deliverInbound(ipv4(aliceIP, tunIP, 100))
	m.deliverInbound(ipv4(aliceIP, tunIP, 200))
	// 后端发给 alice 的回程包：目的 = alice，计入 alice 的 up。
	m.countOutbound(ipv4(tunIP, aliceIP, 50))
	// bob 只有入站。
	m.deliverInbound(ipv4(bobIP, tunIP, 70))

	got := m.view()
	if len(got) != 2 {
		t.Fatalf("view() 返回 %d 条, 期望 2", len(got))
	}
	// view() 必须按 IP 排序，否则 1Hz 刷新时表格行会乱跳。
	if got[0].IP != "111.29.236.135" || got[1].IP != "8.8.8.8" {
		t.Errorf("排序错误：%s, %s", got[0].IP, got[1].IP)
	}

	byIP := map[string]RouteEntry{got[0].IP: got[0], got[1].IP: got[1]}
	if e := byIP[alice]; e.BytesDown != 300 || e.BytesUp != 50 {
		t.Errorf("%s: down=%d up=%d, 期望 down=300 up=50", alice, e.BytesDown, e.BytesUp)
	}
	if e := byIP[bob]; e.BytesDown != 70 || e.BytesUp != 0 {
		t.Errorf("%s: down=%d up=%d, 期望 down=70 up=0", bob, e.BytesDown, e.BytesUp)
	}
}

// countOutbound 绝不能安装路由：它在 TUN 读循环里逐包调用，而安装要起
// route.exe 子进程（几十毫秒），会拖垮吞吐。
func TestCountOutboundNeverInstallsRoute(t *testing.T) {
	m := newRouteManager("203.0.113.9", testAddressing, nil, func(string, ...any) {})
	m.countOutbound(ipv4([4]byte{10, 66, 0, 2}, [4]byte{8, 8, 8, 8}, 100))
	if n := stateCount(m); n != 0 {
		t.Fatalf("countOutbound 新建了 %d 条状态，期望 0（不得触发 route.exe）", n)
	}
}

// 非 IPv4 或过短的包不能让计数逻辑 panic（隧道里出现畸形包不该拖垮客户端）。
func TestCountIgnoresMalformedPackets(t *testing.T) {
	m := newRouteManager("203.0.113.9", testAddressing, nil, func(string, ...any) {})
	for _, pkt := range [][]byte{
		nil,
		{},
		{0x45},
		make([]byte, 19),               // 短于 IPv4 头
		append([]byte{0x60}, make([]byte, 39)...), // IPv6
	} {
		m.deliverInbound(pkt)
		m.countOutbound(pkt)
	}
	if n := stateCount(m); n != 0 {
		t.Errorf("畸形包产生了 %d 条状态，期望 0", n)
	}
}

// 嵌入的图标必须是多尺寸未压缩 DIB：CreateIconFromResourceEx 不认 PNG 压缩的
// ICO 条目，而 PIL/在线转换工具默认就会输出 PNG 条目——换图标时极易踩到，
// 表现是窗口和托盘静默地没有图标。
func TestEmbeddedIconIsUncompressedDIB(t *testing.T) {
	ico, err := assetFS.ReadFile("assets/icon.ico")
	if err != nil {
		t.Fatalf("读取嵌入图标: %v", err)
	}
	if got := binary.LittleEndian.Uint16(ico[2:4]); got != 1 {
		t.Fatalf("ICO type = %d, 期望 1（图标）", got)
	}
	count := int(binary.LittleEndian.Uint16(ico[4:6]))
	if count < 2 {
		t.Fatalf("只有 %d 个尺寸，期望至少 16/32 两档", count)
	}

	sizes := map[int]bool{}
	for i := 0; i < count; i++ {
		e := ico[icoDirHeader+icoDirEntry*i:]
		w := int(e[0])
		if w == 0 {
			w = 256
		}
		sizes[w] = true

		off := binary.LittleEndian.Uint32(e[12:])
		if head := ico[off : off+4]; !bytes.Equal(head, []byte{0x28, 0, 0, 0}) {
			t.Errorf("%dx%d 条目不是未压缩 DIB（头 %x），CreateIconFromResourceEx 会失败", w, w, head)
		}
	}
	for _, want := range []int{16, 32} {
		if !sizes[want] {
			t.Errorf("缺少 %dx%d 尺寸（标题栏用 32、托盘用 16）", want, want)
		}
	}
}

// iconFromICO 必须挑最贴合目标尺寸的条目，否则把 16 放大到 32 会明显发虚。
func TestIconPicksClosestSize(t *testing.T) {
	ico, err := assetFS.ReadFile("assets/icon.ico")
	if err != nil {
		t.Fatalf("读取嵌入图标: %v", err)
	}
	for _, size := range []int{16, 32, 48} {
		h, err := iconFromICO(ico, size)
		if err != nil {
			t.Errorf("iconFromICO(%d): %v", size, err)
			continue
		}
		if h == 0 {
			t.Errorf("iconFromICO(%d) 返回空句柄", size)
		}
	}
	if _, err := iconFromICO([]byte{0, 0, 1, 0}, 16); err == nil {
		t.Error("截断数据应报错而不是崩溃")
	}
}
