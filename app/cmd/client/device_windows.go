//go:build windows

package main

// 设备指纹：把本机的 machineid 派生成一个稳定的 32 字节标识，供服务端把访问码
// 绑定到这台机器。
//
// 强度要如实说明：Windows 上它派生自注册表 MachineGuid，该值由 OS 安装时生成，
// 换硬件、系统更新都不变，但**本地管理员可以改写它**，而且用同一镜像克隆出来的
// 机器（云上批量开的 Windows 没跑 sysprep）指纹相同。所以它防的是「把接入码
// 转发给朋友」这类随手滥用，不是防有动机的攻击者。
//
// 指纹 v2（2026-09-04 克隆去重）：MachineGuid 掺入 **SMBIOS 系统UUID** 再派生。
// UUID 由宿主机注入，Hyper-V/VMware 在克隆/复制虚拟机时会主动更换（这正是
// 「虚拟机生成 ID」的设计用途），因此两台克隆机的指纹 v2 天然不同。取不到
// UUID（部分物理机/老虚拟化平台）时指纹 v2 回落为主指纹，行为与旧版一致。

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"unsafe"

	"go-port-forward/pkg/machineid"
	"go-port-forward/pkg/tunnel"

	"golang.org/x/sys/windows/registry"
)

// fingerprintAppID 是派生指纹时的应用标识。
//
// 带版本后缀：万一将来要让全部客户端重新绑定（比如发现派生方式有问题），改这个
// 字符串就能让所有指纹一次性变化，而不必去动服务端的数据。**主指纹的 appID
// 不能随意改**：它是存量绑定的迁移锚点（服务端按它识别旧设备）。
const (
	fingerprintAppID   = "pf-client-device-v1"
	fingerprintAppIDV2 = "pf-client-device-v2"
)

var (
	fpOnce sync.Once
	fpHex  string
	fpErr  error

	fp2Once sync.Once
	fp2Hex  string
)

// deviceFingerprint 返回本机主指纹（64 位小写 hex）。结果缓存，失败也缓存——
// 取不到 machineid 是环境问题，重试不会变好，反复调外部接口只是浪费。
func deviceFingerprint() (string, error) {
	fpOnce.Do(func() {
		fpHex, fpErr = machineid.ProtectedID(fingerprintAppID)
		if fpErr != nil {
			fpErr = fmt.Errorf("无法读取本机标识（设备绑定需要它）：%w", fpErr)
			return
		}
		if len(fpHex) != tunnel.FingerprintSize*2 {
			fpErr = fmt.Errorf("本机标识长度异常：%d", len(fpHex))
		}
	})
	return fpHex, fpErr
}

// deviceFingerprintV2 返回指纹 v2（64 位小写 hex）：MachineGuid 掺 SMBIOS
// 系统UUID 派生。任何一步取不到都回落主指纹——降级到旧行为，绝不因此拒绝连接。
func deviceFingerprintV2() string {
	fp2Once.Do(func() {
		src := fingerprintSource{}
		if guid, err := machineid.ID(); err == nil {
			src.machineGUID = guid
			src.smbiosUUID, src.hasUUID = smbiosSystemUUID()
		}
		fp2Hex = deviceFingerprintV2From(src)
	})
	return fp2Hex
}

// fingerprintSource 是指纹 v2 的两路输入，拆出来便于单测注入。
type fingerprintSource struct {
	machineGUID string
	smbiosUUID  [16]byte
	hasUUID     bool
}

// deviceFingerprintV2From 从给定输入派生指纹 v2（纯函数，可测）。
// MachineGuid 或 UUID 缺失、UUID 是占位值时返回主指纹（降级到旧行为）。
func deviceFingerprintV2From(src fingerprintSource) string {
	primary, err := deviceFingerprint()
	if err != nil || src.machineGUID == "" || !src.hasUUID || isSmbiosPlaceholderUUID(src.smbiosUUID) {
		return primary
	}
	mac := hmac.New(sha256.New, []byte(src.machineGUID))
	mac.Write([]byte(fingerprintAppIDV2))
	mac.Write(src.smbiosUUID[:])
	return hex.EncodeToString(mac.Sum(nil))
}

// isSmbiosPlaceholderUUID：全 0x00 = 不存在；全 0xFF = 未设置。两者都不是
// 可用的指纹来源。
func isSmbiosPlaceholderUUID(u [16]byte) bool {
	same := true
	for _, b := range u[1:] {
		if b != u[0] {
			same = false
			break
		}
	}
	return same
}

// deviceFingerprintBytes 返回握手包要用的 32 字节主指纹。
func deviceFingerprintBytes() ([tunnel.FingerprintSize]byte, error) {
	var out [tunnel.FingerprintSize]byte
	s, err := deviceFingerprint()
	if err != nil {
		return out, err
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("本机标识格式异常：%w", err)
	}
	copy(out[:], raw)
	return out, nil
}

// deviceFingerprintV2Bytes 返回握手包要用的 32 字节指纹 v2（取不到时等于主指纹）。
func deviceFingerprintV2Bytes() [tunnel.FingerprintSize]byte {
	var out [tunnel.FingerprintSize]byte
	s := deviceFingerprintV2()
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != tunnel.FingerprintSize {
		p, _ := deviceFingerprintBytes()
		return p
	}
	copy(out[:], raw)
	return out
}

// deviceLabel 返回指纹摘要（供界面展示与报障时和面板对照）。
//
// 展示**指纹 v2**：服务端迁移后绑定的是它，客户端与面板显示的必须一致；
// 无第二指纹来源的机器它与主指纹相同。只展示摘要：完整指纹不该出现在
// 界面、截图或日志里。
func deviceLabel() string {
	s := deviceFingerprintV2()
	if len(s) < 12 {
		return ""
	}
	return s[:4] + "…" + s[len(s)-4:]
}

// ---- SMBIOS 系统UUID 读取 ----
//
// kernel32!GetSystemFirmwareTable 不在 golang.org/x/sys/windows 的封装列表里，
// 手工声明（范式同 tray_windows.go）。'RSMB' provider 返回 raw SMBIOS 数据：
// 4 字节头（UsedCalling/ major/ minor/ length）+ SMBIOS 结构表。注册表
// mssmbios\Data\SMBIOSData 是同一份内容的另一个视图，作兜底。

var (
	// kernel32 已在 tray_windows.go 声明（x/sys 未封装固件表 API，手工取 proc）。
	procGetSystemFirmwareTable = kernel32.NewProc("GetSystemFirmwareTable")
)

// smbiosSystemUUID 读取 SMBIOS Type 1（System Information）的 UUID。
// 两路来源都失败或 UUID 是占位值时 ok=false。
func smbiosSystemUUID() ([16]byte, bool) {
	if raw, ok := rawSmbiosViaFirmwareTable(); ok {
		if u, ok := parseSmbiosSystemUUID(raw); ok {
			return u, true
		}
	}
	if raw, ok := rawSmbiosViaRegistry(); ok {
		if u, ok := parseSmbiosSystemUUID(raw); ok {
			return u, true
		}
	}
	return [16]byte{}, false
}

func rawSmbiosViaFirmwareTable() ([]byte, bool) {
	const providerRSMB = 'R'<<24 | 'S'<<16 | 'M'<<8 | 'B'
	n, _, _ := procGetSystemFirmwareTable.Call(uintptr(providerRSMB), 0, 0, 0)
	if n == 0 {
		return nil, false
	}
	buf := make([]byte, n)
	n, _, _ = procGetSystemFirmwareTable.Call(uintptr(providerRSMB), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || int(n) < 8 || int(n) > len(buf) {
		return nil, false
	}
	return buf[:n], true
}

func rawSmbiosViaRegistry() ([]byte, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\mssmbios\Data`, registry.QUERY_VALUE)
	if err != nil {
		return nil, false
	}
	defer k.Close()
	v, _, err := k.GetBinaryValue("SMBIOSData")
	if err != nil || len(v) < 8 {
		return nil, false
	}
	return v, true
}

// parseSmbiosSystemUUID 从 raw SMBIOS 数据（含 4 字节 RawSMBIOSData 头）里取
// Type 1（System Information）结构的 UUID（结构头后偏移 0x08，16 字节）。
// 结构遍历与 SMBIOS 版本无关（按每结构的 length 与字符串区双 0 结尾步进）。
func parseSmbiosSystemUUID(raw []byte) ([16]byte, bool) {
	var out [16]byte
	if len(raw) < 8 {
		return out, false
	}
	table := raw[4:] // 跳过 RawSMBIOSData 头（UsedCalling/major/minor/length 各 1 字节）
	off := 0
	for off+4 <= len(table) {
		stype := table[off]
		slen := int(table[off+1])
		if slen < 4 || off+slen > len(table) {
			return out, false // 结构表损坏，宁缺毋滥
		}
		if stype == 1 && slen >= 0x19 {
			uuid := [16]byte{}
			copy(uuid[:], table[off+8:off+24])
			if !isSmbiosPlaceholderUUID(uuid) {
				return uuid, true
			}
			// 占位 UUID：Type 1 只出现一次，不必再走。
			break
		}
		// 跳过格式化区 + 字符串区（字符串区以连续两个 0x00 结束）。
		next := off + slen
		for next+1 < len(table) && !(table[next] == 0 && table[next+1] == 0) {
			next++
		}
		off = next + 2
	}
	return out, false
}
