//go:build windows

package main

// 服务端拒绝握手时的原因翻译。
//
// 协议只传一个数值，文案在客户端本地生成——这样服务端不必为了改一句提示而
// 发版，也不会把中文文案硬编码进网络协议。

import (
	"fmt"

	"go-port-forward/pkg/tunnel"
)

// rejectedError 表示服务端明确拒绝了握手（区别于「无应答」）。
type rejectedError struct {
	reason tunnel.RejectReason
}

func (e *rejectedError) Error() string {
	return rejectMessage(e.reason)
}

// rejectMessage 把拒绝原因翻成面向用户的中文提示，并给出下一步动作。
//
// 每条都要能回答「我现在该做什么」：只说"被拒绝了"等于把用户推去猜。
func rejectMessage(r tunnel.RejectReason) string {
	switch r {
	case tunnel.RejectDeviceMismatch:
		return "这个访问码已经绑定到另一台设备。请在面板的「我的访问码」里点「解绑」后重连，" +
			"或改用一个未绑定的访问码。"
	case tunnel.RejectCodeDisabled:
		return "这个访问码已被停用，请联系管理员或在面板里重新启用。"
	case tunnel.RejectUserDisabled:
		return "你的账号已被停用，请联系管理员。"
	case tunnel.RejectTunnelLimit:
		return "同时在线的隧道数已达上限。请先在别的机器上断开一条隧道，或联系管理员提高上限。"
	case tunnel.RejectAddrInvalid:
		return "这个访问码的隧道地址已失效（可能是管理员改小了隧道网段），请联系管理员重新分配。"
	default:
		return fmt.Sprintf("服务端拒绝了连接（原因代码 %d），请联系管理员。", uint8(r))
	}
}
