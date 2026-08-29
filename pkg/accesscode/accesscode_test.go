package accesscode

import (
	"strings"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := Code{Addr: "124.221.181.159:7947", UserID: "3f2b1c4d-5e6f-4071-8293-a4b5c6d7e8f9", Secret: "c2VjcmV0LWtleS1iYXNlNjQ="}
	s, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, Prefix) || !Looks(s) {
		t.Fatalf("code = %q", s)
	}
	out, err := Decode(s)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip = %+v, want %+v", out, in)
	}
}

// 用户从网页复制接入码时经常带上换行或首尾空格，拒绝它们只会制造无谓的支持工单。
func TestDecodeToleratesWhitespace(t *testing.T) {
	s, err := Encode(Code{Addr: "1.2.3.4", UserID: "u", Secret: "k"})
	if err != nil {
		t.Fatal(err)
	}
	messy := "  " + s[:10] + "\r\n" + s[10:] + "\n"
	out, err := Decode(messy)
	if err != nil {
		t.Fatalf("whitespace-laden code must decode: %v", err)
	}
	if out.Addr != "1.2.3.4" {
		t.Fatalf("out = %+v", out)
	}
}

func TestDecodeRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"空":     "",
		"无前缀":   "aGVsbG8",
		"损坏载荷":  Prefix + "!!!not-base64!!!",
		"非 JSON": Prefix + "aGVsbG8",
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Fatalf("%s: 必须报错", name)
		}
	}
}

func TestDecodeRejectsIncompletePayload(t *testing.T) {
	// 手工构造缺少密钥的载荷。
	s, err := Encode(Code{Addr: "1.2.3.4", UserID: "u", Secret: "k"})
	if err != nil {
		t.Fatal(err)
	}
	// 换成只含地址的 JSON。
	partial := Prefix + "eyJoIjoiMS4yLjMuNCJ9" // {"h":"1.2.3.4"}
	if _, err := Decode(partial); err == nil {
		t.Fatal("缺字段的接入码必须报错")
	}
	if _, err := Decode(s); err != nil {
		t.Fatalf("完整接入码应可解析: %v", err)
	}
}

func TestEncodeRejectsEmptyFields(t *testing.T) {
	if _, err := Encode(Code{Addr: "1.2.3.4", UserID: "u"}); err == nil {
		t.Fatal("缺密钥必须报错")
	}
}

func TestLooks(t *testing.T) {
	if Looks("124.221.181.159:7947") {
		t.Fatal("裸地址不应被当作接入码")
	}
	if !Looks("  pf1.abc") {
		t.Fatal("带空格的接入码应被识别")
	}
}
