//go:build windows

package main

// 设备指纹：把本机的 machineid 派生成一个稳定的 32 字节标识，供服务端把访问码
// 绑定到这台机器。
//
// 强度要如实说明：Windows 上它派生自注册表 MachineGuid，该值由 OS 安装时生成，
// 换硬件、系统更新都不变，但**本地管理员可以改写它**，而且用同一镜像克隆出来的
// 机器（云上批量开的 Windows 没跑 sysprep）指纹相同。所以它防的是「把接入码
// 转发给朋友」这类随手滥用，不是防有动机的攻击者。

import (
	"encoding/hex"
	"fmt"
	"sync"

	"go-port-forward/pkg/machineid"
	"go-port-forward/pkg/tunnel"
)

// fingerprintAppID 是派生指纹时的应用标识。
//
// 带版本后缀：万一将来要让全部客户端重新绑定（比如发现派生方式有问题），改这个
// 字符串就能让所有指纹一次性变化，而不必去动服务端的数据。
const fingerprintAppID = "pf-client-device-v1"

var (
	fpOnce sync.Once
	fpHex  string
	fpErr  error
)

// deviceFingerprint 返回本机指纹（64 位小写 hex）。结果缓存，失败也缓存——
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

// deviceFingerprintBytes 返回握手包要用的 32 字节指纹。
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

// deviceLabel 返回指纹摘要（供界面展示与报障时和面板对照）。
//
// 只展示摘要：完整指纹不该出现在界面、截图或日志里。
func deviceLabel() string {
	s, err := deviceFingerprint()
	if err != nil || len(s) < 12 {
		return ""
	}
	return s[:4] + "…" + s[len(s)-4:]
}
