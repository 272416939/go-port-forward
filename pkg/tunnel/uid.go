package tunnel

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// UID 是隧道用户 ID 的线上表示（uuid 的 16 字节二进制形式）。
//
// 握手包里带的是二进制 uuid 而不是用户名：用户名会随重命名变化，而且明文
// 出现在网络上等于泄漏身份语义。这里刻意不引入 uuid 库——pkg/tunnel 同时被
// 主模块和独立的客户端 module 依赖，少一个依赖就少一处版本漂移。
type UID [UIDSize]byte

// ParseUID 解析 uuid 文本（接受带连字符与不带连字符两种写法）。
func ParseUID(s string) (UID, error) {
	var u UID
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(clean) != UIDSize*2 {
		return u, fmt.Errorf("tunnel: 无效的用户 ID %q | invalid user id", s)
	}
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return u, fmt.Errorf("tunnel: 无效的用户 ID %q | invalid user id", s)
	}
	copy(u[:], raw)
	return u, nil
}

// String 返回标准 uuid 文本（8-4-4-4-12）。
func (u UID) String() string {
	h := hex.EncodeToString(u[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// IsZero 报告是否为全零 ID（未填充）。
func (u UID) IsZero() bool {
	for _, b := range u {
		if b != 0 {
			return false
		}
	}
	return true
}
