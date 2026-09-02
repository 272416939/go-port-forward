package tunnelapp

import (
	"fmt"
	"strings"
	"testing"
)

// fakeShell 以最小语义模拟 iptables/ip/sysctl，锁住守护协程的核心语义：
// 在位不重装（防规则堆积）、缺失才补装、修复后收敛（防 -C/-A spec 漂移）。
type fakeShell struct {
	sysctl map[string]string
	rules  map[string]bool
	ipRule bool
	routes map[string]string
	// mutates 记录全部变更类命令（-A/-I/-D/add/replace/-w），查询不计。
	mutates []string
}

func newFakeShell() *fakeShell {
	return &fakeShell{
		// 从"全缺"的常见出厂值出发：ip_forward=0、rp_filter=1（Ubuntu 默认）
		sysctl: map[string]string{
			"net.ipv4.ip_forward":                       "0",
			"net.ipv4.conf.all.rp_filter":               "1",
			"net.ipv4.conf.default.rp_filter":           "1",
			"net.ipv4.conf." + tunName + ".rp_filter":   "1",
		},
		rules:  map[string]bool{},
		routes: map[string]string{},
	}
}

const tunName = "pftun0"

func ruleKey(table, chain string, spec []string) string {
	return table + "|" + chain + "|" + strings.Join(spec, " ")
}

func (f *fakeShell) run(name string, args ...string) (string, error) {
	switch name {
	case "iptables":
		return f.iptables(args...)
	case "ip":
		return f.ip(args...)
	case "sysctl":
		return f.sysctlCmd(args...)
	}
	return "", fmt.Errorf("fakeShell: 未知命令 %s", name)
}

func (f *fakeShell) iptables(args ...string) (string, error) {
	if len(args) < 4 || args[0] != "-t" {
		return "", fmt.Errorf("fakeShell: iptables 参数异常 %v", args)
	}
	table, op, chain := args[1], args[2], args[3]
	specArgs := args[4:]
	// -I INPUT 1 <spec> 与 -I <spec> 等价（都插链首），key 必须一致
	if op == "-I" && len(specArgs) > 0 && isAllDigits(specArgs[0]) {
		specArgs = specArgs[1:]
	}
	key := ruleKey(table, chain, specArgs)
	switch op {
	case "-C":
		if f.rules[key] {
			return "", nil
		}
		return "", fmt.Errorf("iptables: 规则不存在 %s", key)
	case "-A", "-I":
		f.rules[key] = true
		f.mutates = append(f.mutates, op+" "+key)
		return "", nil
	case "-D":
		delete(f.rules, key)
		f.mutates = append(f.mutates, op+" "+key)
		return "", nil
	}
	return "", fmt.Errorf("fakeShell: iptables 未知操作 %s", op)
}

func (f *fakeShell) ip(args ...string) (string, error) {
	switch {
	case len(args) == 2 && args[0] == "rule" && args[1] == "show":
		if f.ipRule {
			return "0:      from all lookup local\n32765:  from all fwmark 0x7947 lookup 7947\n", nil
		}
		return "0:      from all lookup local\n", nil
	case len(args) >= 2 && args[0] == "rule" && args[1] == "add":
		f.ipRule = true
		f.mutates = append(f.mutates, "ip rule add")
		return "", nil
	case len(args) == 4 && args[0] == "route" && args[1] == "show" && args[2] == "table":
		return f.routes[args[3]], nil
	case len(args) >= 2 && args[0] == "route" && args[1] == "replace":
		for i, a := range args {
			if a == "table" && i+1 < len(args) {
				f.routes[args[i+1]] = "local default dev lo"
			}
		}
		f.mutates = append(f.mutates, "ip route replace")
		return "", nil
	}
	return "", fmt.Errorf("fakeShell: ip 参数异常 %v", args)
}

func (f *fakeShell) sysctlCmd(args ...string) (string, error) {
	switch args[0] {
	case "-n":
		v, ok := f.sysctl[args[1]]
		if !ok {
			return "", fmt.Errorf("sysctl: 未知键 %s", args[1])
		}
		return v, nil
	case "-w":
		kv := strings.SplitN(args[1], "=", 2)
		if len(kv) != 2 {
			return "", fmt.Errorf("sysctl: 参数异常 %q", args[1])
		}
		f.sysctl[kv[0]] = kv[1]
		f.mutates = append(f.mutates, "sysctl -w "+args[1])
		return "", nil
	}
	return "", fmt.Errorf("fakeShell: sysctl 参数异常 %v", args)
}

// seedAllInstalled 把回程路径的全部内核状态置为"已装配"（模拟正常运行的机器）。
func (f *fakeShell) seedAllInstalled(tunName string) {
	mark := markRuleSpec(tunName)
	f.rules[ruleKey("mangle", mark[0], mark[1:])] = true
	est, drop := inputRuleSpecs(tunName)
	f.rules[ruleKey("filter", "INPUT", est)] = true
	f.rules[ruleKey("filter", "INPUT", drop)] = true
	hp := hairpinRuleSpec(tunName)
	f.rules[ruleKey("filter", hp[0], hp[1:])] = true
	fi := forwardInSpec(tunName)
	f.rules[ruleKey("filter", fi[0], fi[1:])] = true
	fo := forwardOutSpec(tunName)
	f.rules[ruleKey("filter", fo[0], fo[1:])] = true
	f.ipRule = true
	f.routes[returnTable] = "local default dev lo"
	f.sysctl["net.ipv4.ip_forward"] = "1"
	for _, k := range []string{
		"net.ipv4.conf.all.rp_filter",
		"net.ipv4.conf.default.rp_filter",
		"net.ipv4.conf." + tunName + ".rp_filter",
	} {
		f.sysctl[k] = "2"
	}
}

func (f *fakeShell) count(prefix string) int {
	n := 0
	for _, m := range f.mutates {
		if strings.HasPrefix(m, prefix) {
			n++
		}
	}
	return n
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// 全部在位：不得报告修复，更不得发出任何变更命令——这是防规则堆积的锁。
// spec 与检查漂移时，此测试以「每轮都插一条」的形式失败。
func TestVerifyReturnPathAllInPlace_NoMutation(t *testing.T) {
	f := newFakeShell()
	f.seedAllInstalled(tunName)
	repaired, err := verifyReturnPathWith(f.run, tunName)
	if err != nil {
		t.Fatalf("全部在位却报错: %v", err)
	}
	if repaired {
		t.Fatal("全部在位却报告修复")
	}
	if len(f.mutates) != 0 {
		t.Fatalf("在位时不应有任何变更命令，得到 %v", f.mutates)
	}
}

// 全缺（ufw 整表 flush 的现场）：逐项补装各一次，再次校验必须收敛为零变更。
func TestVerifyReturnPathMissingAll_RepairsAndConverges(t *testing.T) {
	f := newFakeShell()
	repaired, err := verifyReturnPathWith(f.run, tunName)
	if err != nil {
		t.Fatalf("补装失败: %v", err)
	}
	if !repaired {
		t.Fatal("全缺却报告未修复")
	}
	checks := []struct {
		prefix string
		want   int
		what   string
	}{
		{"-A mangle|", 1, "mangle MARK"},
		{"ip rule add", 1, "策略路由"},
		{"ip route replace", 1, "本机投递路由"},
		{"-I filter|INPUT|", 2, "INPUT 先删后插"},
		{"-I filter|FORWARD|", 1, "hairpin DROP 插链首"},
		{"-A filter|FORWARD|", 2, "FORWARD 两条放行"},
		{"sysctl -w", 4, "sysctl 四项"},
	}
	for _, c := range checks {
		if got := f.count(c.prefix); got != c.want {
			t.Fatalf("%s 补装次数 = %d，期望 %d（全部命令: %v）", c.what, got, c.want, f.mutates)
		}
	}
	// 收敛：补装后 -C 与 -A/-I 必须命中同一规则，否则守护协程会每轮重装
	n := len(f.mutates)
	repaired2, err := verifyReturnPathWith(f.run, tunName)
	if err != nil || repaired2 {
		t.Fatalf("修复后未收敛: repaired=%v err=%v", repaired2, err)
	}
	if len(f.mutates) != n {
		t.Fatalf("收敛后仍发出变更命令: %v", f.mutates[n:])
	}
}

// 只缺 mangle 一条：只补 mangle，INPUT 不得重排、FORWARD 不得追加、sysctl 不动。
func TestVerifyReturnPathPartial_OnlyRepairsMissing(t *testing.T) {
	f := newFakeShell()
	f.seedAllInstalled(tunName)
	mark := markRuleSpec(tunName)
	delete(f.rules, ruleKey("mangle", mark[0], mark[1:]))

	f.mutates = nil
	repaired, err := verifyReturnPathWith(f.run, tunName)
	if err != nil || !repaired {
		t.Fatalf("repaired=%v err=%v", repaired, err)
	}
	if len(f.mutates) != 1 || !strings.HasPrefix(f.mutates[0], "-A mangle|") {
		t.Fatalf("应只补装 mangle 一条，得到 %v", f.mutates)
	}
}

// INPUT 只缺一条（DROP）：必须走先删后插恢复链首顺序，且不碰其它装配项。
func TestVerifyReturnPathInputHalfMissing_Resequences(t *testing.T) {
	f := newFakeShell()
	f.seedAllInstalled(tunName)
	_, drop := inputRuleSpecs(tunName)
	delete(f.rules, ruleKey("filter", "INPUT", drop))

	repaired, err := verifyReturnPathWith(f.run, tunName)
	if err != nil || !repaired {
		t.Fatalf("repaired=%v err=%v", repaired, err)
	}
	if got := f.count("-I filter|INPUT|"); got != 2 {
		t.Fatalf("INPUT 重排应插入两条，得到 %d（%v）", got, f.mutates)
	}
	if f.count("-A mangle|") != 0 || f.count("-I filter|FORWARD|") != 0 || f.count("sysctl -w") != 0 {
		t.Fatalf("其余装配项不应被触碰: %v", f.mutates)
	}
}
