package tunnelapp

import "testing"

// 集合指纹必须与顺序无关：会话 IP 来自 map 遍历，顺序天然不稳定。
// 若指纹随顺序变化，每次推送都会被误判为「变更」并打一条 info——正是
// 这次要消掉的刷屏。
func TestSessionIPsSignatureIgnoresOrder(t *testing.T) {
	a := sessionIPsSignature([]string{"1.1.1.1", "2.2.2.2", "3.3.3.3"})
	b := sessionIPsSignature([]string{"3.3.3.3", "1.1.1.1", "2.2.2.2"})
	if a != b {
		t.Errorf("同一集合不同顺序指纹不同：\n  %q\n  %q", a, b)
	}
}

func TestSessionIPsSignatureDetectsChange(t *testing.T) {
	base := sessionIPsSignature([]string{"1.1.1.1", "2.2.2.2"})

	cases := map[string][]string{
		"新增":     {"1.1.1.1", "2.2.2.2", "3.3.3.3"},
		"移除":     {"1.1.1.1"},
		"替换":     {"1.1.1.1", "9.9.9.9"},
		"清空":     {},
	}
	for name, ips := range cases {
		if got := sessionIPsSignature(ips); got == base {
			t.Errorf("%s 后指纹未变化（%q），变更会被漏报", name, got)
		}
	}
}

// 不得就地修改入参：调用方传的是活跃会话快照，排序会打乱其它使用者看到的顺序。
func TestSessionIPsSignatureDoesNotMutateInput(t *testing.T) {
	ips := []string{"3.3.3.3", "1.1.1.1", "2.2.2.2"}
	sessionIPsSignature(ips)
	if ips[0] != "3.3.3.3" {
		t.Errorf("入参被就地排序了：%v", ips)
	}
}
