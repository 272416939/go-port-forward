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
// UUID（部分虚拟化平台）时指纹 v2 回落主指纹，行为与旧版一致。
//
// UUID 的读取有三路，逐级兜底，失败时把每一步的结局写进诊断字符串（握手日志
// 可见，2026-09-06 QEMU 实机：CIM 能读到 UUID 而固件表路径读不到，靠诊断定位）：
//  1. kernel32!GetSystemFirmwareTable('RSMB') —— x/sys 未封装，手工声明；
//  2. 注册表 mssmbios\Data\SMBIOSData —— 同一份内容的另一视图；
//  3. PowerShell CIM 查询 Win32_ComputerSystemProduct.UUID —— 最重但最稳。

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"go-port-forward/pkg/machineid"
	"go-port-forward/pkg/tunnel"

	"golang.org/x/sys/windows/registry"
)

// sysProcAttrHidden：GUI 进程派生控制台命令必须隐藏窗口，否则每次指纹回退
// 都会闪一个 PowerShell 黑框。
var sysProcAttrHidden = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}

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

	fp2Once    sync.Once
	fp2Hex     string
	fp2HasUUID bool
	fp2Diag    string
	fp2Source  string // "smbios" | "cim" | ""（回落主指纹）
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
			var uuid [16]byte
			var ok bool
			if uuid, ok, fp2Diag = smbiosSystemUUIDDiag(); ok {
				src.smbiosUUID, src.hasUUID = uuid, true
				fp2Source = "smbios"
			} else if u, cerr := uuidViaCIM(); cerr {
				if raw, derr := hex.DecodeString(u); derr == nil {
					copy(src.smbiosUUID[:], raw)
					src.hasUUID = true
					fp2Source = "cim"
					fp2Diag = "SMBIOS 两路不可用（" + fp2Diag + "），已用 CIM 回退"
				} else {
					fp2Diag = "SMBIOS 两路不可用（" + fp2Diag + "）；CIM 返回值无法解析"
				}
			}
		} else {
			fp2Diag = fmt.Sprintf("MachineGuid 读取失败(%v)", err)
		}
		fp2Hex = deviceFingerprintV2From(src)
		fp2HasUUID = src.machineGUID != "" && src.hasUUID && !isSmbiosPlaceholderUUID(src.smbiosUUID)
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

// deviceFingerprintHasUUID 报告指纹 v2 是否真的掺入了 SMBIOS/CIM UUID（false =
// 已回落主指纹，克隆机无法区分）。
func deviceFingerprintHasUUID() bool {
	deviceFingerprintV2()
	return fp2HasUUID
}

// fingerprintV2Source 返回指纹 v2 的实际来源（"smbios"/"cim"/""=回落主指纹）。
func fingerprintV2Source() string {
	deviceFingerprintV2()
	return fp2Source
}

// fingerprintV2Diag 返回来源获取过程的诊断串（成功时为空或含回退说明）。
func fingerprintV2Diag() string {
	deviceFingerprintV2()
	return fp2Diag
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

// smbiosSystemUUIDDiag 读取 SMBIOS Type 1（System Information）的 UUID，
// 带逐级诊断。两路都失败时 ok=false 且 diag 说明每步结局。
func smbiosSystemUUIDDiag() (uuid [16]byte, ok bool, diag string) {
	raw, err := rawSmbiosViaFirmwareTable()
	if err == nil {
		uuid, ok, off, stype := parseSmbiosSystemUUID(raw)
		if ok {
			return uuid, true, ""
		}
		diag = fmt.Sprintf("固件表(%d 字节)解析止于 offset=%d type=%#x", len(raw), off, stype)
	} else {
		diag = fmt.Sprintf("固件表读取失败(%v)", err)
	}
	raw2, err2 := rawSmbiosViaRegistry()
	if err2 != nil {
		diag += fmt.Sprintf("；注册表读取失败(%v)", err2)
		return uuid, false, diag
	}
	uuid2, ok2, off2, stype2 := parseSmbiosSystemUUID(raw2)
	if ok2 {
		return uuid2, true, ""
	}
	diag += fmt.Sprintf("；注册表(%d 字节)解析止于 offset=%d type=%#x", len(raw2), off2, stype2)
	return uuid, false, diag
}

func rawSmbiosViaFirmwareTable() ([]byte, error) {
	const providerRSMB = 'R'<<24 | 'S'<<16 | 'M'<<8 | 'B'
	n, _, callErr := procGetSystemFirmwareTable.Call(uintptr(providerRSMB), 0, 0, 0)
	if n == 0 {
		return nil, fmt.Errorf("GetSystemFirmwareTable 返回长度 0（%v）", callErr)
	}
	buf := make([]byte, n)
	n, _, callErr = procGetSystemFirmwareTable.Call(uintptr(providerRSMB), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || int(n) < 8 || int(n) > len(buf) {
		return nil, fmt.Errorf("GetSystemFirmwareTable 返回长度异常 %d（%v）", n, callErr)
	}
	return buf[:n], nil
}

func rawSmbiosViaRegistry() ([]byte, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\mssmbios\Data`, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	v, _, err := k.GetBinaryValue("SMBIOSData")
	if err != nil {
		return nil, err
	}
	if len(v) < 8 {
		return nil, fmt.Errorf("SMBIOSData 过短（%d 字节）", len(v))
	}
	return v, nil
}

// parseSmbiosSystemUUID 从 raw SMBIOS 数据（含 4 字节 RawSMBIOSData 头）里取
// Type 1（System Information）结构的 UUID（结构头后偏移 0x08，16 字节）。
// 结构遍历与 SMBIOS 版本无关（按每结构的 length 与字符串区双 0 结尾步进）。
// 失败时返回止步位置与结构类型（诊断用）。
func parseSmbiosSystemUUID(raw []byte) (uuid [16]byte, ok bool, stopOff int, stopType byte) {
	if len(raw) < 8 {
		return uuid, false, 0, 0
	}
	table := raw[4:] // 跳过 RawSMBIOSData 头（UsedCalling/major/minor/length 各 1 字节）
	off := 0
	for off+4 <= len(table) {
		stype := table[off]
		slen := int(table[off+1])
		if slen < 4 || off+slen > len(table) {
			return uuid, false, off, stype // 结构表损坏，宁缺毋滥
		}
		if stype == 1 && slen >= 0x19 {
			u := [16]byte{}
			copy(u[:], table[off+8:off+24])
			if isSmbiosPlaceholderUUID(u) {
				return uuid, false, off, stype // 占位 UUID：Type 1 只出现一次
			}
			return u, true, off, stype
		}
		// 跳过格式化区 + 字符串区（字符串区以连续两个 0x00 结束）。
		next := off + slen
		for next+1 < len(table) && !(table[next] == 0 && table[next+1] == 0) {
			next++
		}
		off = next + 2
	}
	return uuid, false, off, 0 // 走完没找到 Type 1
}

// ---- CIM 兜底 ----
//
// SMBIOS 两路都不可用时的第三路：直接问 Windows（用户环境实测 QEMU VM 上
// CIM 可读而固件表路径不可读）。每次进程只跑一次（指纹缓存），1~3 秒可接受。

// uuidViaCIM 查询 Win32_ComputerSystemProduct.UUID，返回规范化后的 32 hex
// （大写去连字符），供指纹 v2 掺入。
func uuidViaCIM() (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive",
		"-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID")
	cmd.SysProcAttr = sysProcAttrHidden
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return normalizeUUIDString(string(out))
}

// normalizeUUIDString 把「73A79996-D127-4BE3-90E2-A9E1C8CA5F05」形态的 GUID
// 串规范化为 32 位大写 hex（去连字符/大括号/空白）。
func normalizeUUIDString(s string) (string, bool) {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			b.WriteRune(upperHex(r))
		case r == '-' || r == '{' || r == '}' || r == ' ':
			// 分隔符，跳过
		default:
			return "", false
		}
	}
	if b.Len() != 32 {
		return "", false
	}
	return b.String(), true
}

func upperHex(r rune) rune {
	if r >= 'a' && r <= 'f' {
		return r - ('a' - 'A')
	}
	return r
}
