// Package emailtest 提供确定性的验证码实现，供 users/web 层测试注入。
//
// 独立成 _test 包之外的正常包，是因为 web 与 users 两个包的测试都要用；
// 放在 _test.go 里无法跨包引用。实现刻意简单：任何签发的验证码都是同一个
// 固定值，Verify 只认它且一次性消费。真实现的限频/过期/防爆破语义由
// internal/email 自己的测试覆盖。
package emailtest

import "errors"

// FixedCode 是本实现签发的固定验证码。
const FixedCode = "654321"

// Fixed 是确定性的 CodeIssuer（users.CodeIssuer 接口的测试替身）。
type Fixed struct {
	used map[string]bool
}

// NewFixed 创建一个固定验证码服务。
func NewFixed() *Fixed { return &Fixed{used: map[string]bool{}} }

// Issue 签发验证码（值恒为 FixedCode）。
func (f *Fixed) Issue(email, purpose string) error {
	if f.used == nil {
		f.used = map[string]bool{}
	}
	f.used[purpose+"|"+email] = false
	return nil
}

// Verify 校验验证码，一次性消费。
func (f *Fixed) Verify(email, purpose, code string) error {
	key := purpose + "|" + email
	if _, ok := f.used[key]; !ok || code != FixedCode {
		return errors.New("invalid code")
	}
	if f.used[key] {
		return errors.New("already used")
	}
	f.used[key] = true
	return nil
}
