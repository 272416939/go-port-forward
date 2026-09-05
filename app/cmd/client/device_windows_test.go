//go:build windows

package main

import (
	"testing"

	"go-port-forward/pkg/tunnel"
)

// smbStruct 按 SMBIOS 结构编码：[type][length][handle2] + 格式化区 + 字符串区
// （每串一个 0x00 结尾，列表以第二个 0x00 结束）。
func smbStruct(stype byte, handle uint16, formatted []byte, strs ...string) []byte {
	out := []byte{stype, byte(4 + len(formatted)), byte(handle), byte(handle >> 8)}
	out = append(out, formatted...)
	for _, s := range strs {
		out = append(out, []byte(s)...)
		out = append(out, 0x00)
	}
	return append(out, 0x00)
}

// TestParseSmbiosSystemUUID 锁解析器：多结构寻走、Type 1 UUID 提取、字符串区
// 跳步、占位 UUID 与损坏数据的 fail-closed。
func TestParseSmbiosSystemUUID(t *testing.T) {
	uuid := [16]byte{0x2C, 0x4B, 0x11, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// 头 4 字节 + BIOS 结构（带字符串，练字符串区跳步）+ Type 1 + 处理器结构
	blob := []byte{0x00, 0x06, 0x03, 0xFF}
	blob = append(blob, smbStruct(0, 0x0001, make([]byte, 0x12), "ACME BIOS", "1/1/2026")...)
	// SMBIOS 规范：Type 1 的 UUID 在结构偏移 0x08（头 4 字节 + 4 字节厂商/型号索引）
	fmt1 := make([]byte, 21)
	copy(fmt1[4:], uuid[:])
	typ1 := smbStruct(1, 0x0002, fmt1, "VM-NAME")
	blob = append(blob, typ1...)
	blob = append(blob, smbStruct(4, 0x0003, make([]byte, 0x2A), "CPU0")...)

	got, ok, stopOff, stopType := parseSmbiosSystemUUID(blob)
	if !ok {
		t.Fatalf("应能从多结构 blob 中取到 Type 1 UUID（止于 off=%d type=%#x）", stopOff, stopType)
	}
	if got != uuid {
		t.Fatalf("UUID = %v, want %v", got, uuid)
	}
}

// TestNormalizeUUIDString 锁 CIM 回退的 GUID 串规范化（用户实测
// 73A79996-D127-4BE3-90E2-A9E1C8CA5F05 形态）。
func TestNormalizeUUIDString(t *testing.T) {
	crlf := string(rune(13)) + string(rune(10))
	got, ok := normalizeUUIDString("73A79996-D127-4BE3-90E2-A9E1C8CA5F05" + crlf)
	if !ok || got != "73A79996D1274BE390E2A9E1C8CA5F05" {
		t.Fatalf("normalize = %q ok=%v", got, ok)
	}
	if _, ok := normalizeUUIDString("not-a-guid"); ok {
		t.Fatal("非 GUID 串必须拒绝")
	}
	if _, ok := normalizeUUIDString("73A79996"); ok {
		t.Fatal("长度不足必须拒绝")
	}

	// 全 0x00 / 全 0xFF 占位（规范位置 0x08）：视为不存在（fail-closed）
	for _, fill := range []byte{0x00, 0xFF} {
		fmt1 := make([]byte, 21)
		for i := 4; i < 20; i++ {
			fmt1[i] = fill
		}
		blob2 := []byte{0x00, 0x06, 0x03, 0xFF}
		blob2 = append(blob2, smbStruct(1, 0x0002, fmt1)...)
		if _, ok, _, _ := parseSmbiosSystemUUID(blob2); ok {
			t.Fatalf("占位 UUID（%#x…）不得作为指纹来源", fill)
		}
	}

	// 损坏数据（length 字段越界）：宁缺毋滥。
	if _, ok, _, _ := parseSmbiosSystemUUID([]byte{0, 6, 3, 0xFF, 0x01, 0x7F, 0x00}); ok {
		t.Fatal("损坏数据不得返回 UUID")
	}
}

// TestDeviceFingerprintV2From 锁指纹 v2 派生：确定性、UUID 缺失降级到主指纹、
// 不同 UUID 派生不同指纹（克隆去重的根基）。
func TestDeviceFingerprintV2From(t *testing.T) {
	if _, err := deviceFingerprint(); err != nil {
		t.Skipf("本机 machineid 不可读，跳过：%v", err)
	}
	src := fingerprintSource{machineGUID: "some-guid", hasUUID: true,
		smbiosUUID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}
	a := deviceFingerprintV2From(src)
	b := deviceFingerprintV2From(src)
	if a != b || len(a) != tunnel.FingerprintSize*2 {
		t.Fatalf("指纹 v2 应确定且为 64 hex：%q vs %q", a, b)
	}
	primary, _ := deviceFingerprint()
	if a == primary {
		t.Fatal("掺入 UUID 后指纹 v2 不应等于主指纹")
	}

	// 换 UUID（克隆机被宿主机重生成）：指纹不同。
	clone := src
	clone.smbiosUUID[0] ^= 0xFF
	if deviceFingerprintV2From(clone) == a {
		t.Fatal("不同 UUID 必须派生不同指纹")
	}

	// UUID 缺失：降级主指纹（旧行为）。
	noUUID := fingerprintSource{machineGUID: "some-guid"}
	if deviceFingerprintV2From(noUUID) != primary {
		t.Fatal("UUID 缺失应降级为主指纹")
	}
}

// TestDeviceFingerprintV2RealSmoke：真机冒烟——指纹 v2 必须可得且确定
// （SMBIOS 取不到的机器会等于主指纹，属合法降级）。
func TestDeviceFingerprintV2RealSmoke(t *testing.T) {
	v := deviceFingerprintV2()
	if len(v) != tunnel.FingerprintSize*2 {
		t.Fatalf("指纹 v2 长度 = %d, want 64 hex", len(v))
	}
	if v != deviceFingerprintV2() {
		t.Fatal("指纹 v2 应确定")
	}
	t.Logf("本机指纹 v2 摘要：%s", v[:4]+"…"+v[len(v)-4:])
}
