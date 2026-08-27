package raksniff

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"io"
)

// Login 包里的身份信息藏在微软签发的 JWT 链中：链上每个 token 是
// base64url(header).(base64url(claims)).signature 形态。claims 的 JSON 中含
// DisplayName/XUID 等字段；不同登录模式字段名略有差异，这里做宽容挖掘。
//
// The login JWT chain travels as base64url segments; we decode the payload
// segment of every plausible token and mine the well-known claim names.

const (
	maxDecodedStream = 256 * 1024 // 解压输出上限，防解压炸弹 | decompression output cap
	maxTokenAttempts = 256        // 每个候选流的 JWT 解码尝试次数上限
)

// identityClaims mirrors the Bedrock auth chain claim names we care about.
type identityClaims struct {
	DisplayName  string `json:"DisplayName"`
	IdentityName string `json:"IdentityName"`
	XUID         string `json:"XUID"`
}

// extractIdentity mines accumulated payloads for a player identity. It tries
// raw and decompressed interpretations; any single success wins.
func extractIdentity(pieces [][]byte) (Identity, bool) {	var id Identity
	found := false
	for _, p := range pieces {
		candidates := candidateStreams(p)
		for _, c := range candidates {
			id2, ok := scanCandidate(c)
			if !ok {
				continue
			}
			// 后出现的字段以先到者优先，这里取第一个命中的完整身份
			if !found {
				id = id2
				found = true
			} else {
				if id.Gamertag == "" {
					id.Gamertag = id2.Gamertag
				}
				if id.XUID == "" {
					id.XUID = id2.XUID
				}
			}
			if id.Gamertag != "" && id.XUID != "" {
				return id, true
			}
		}
	}
	return id, found
}

// candidateStreams yields the raw payload plus bounded decompression variants.
// [id][alg][compressed] 包装形态导致压缩起点可能是 offset 1 或 2。
func candidateStreams(p []byte) [][]byte {
	out := make([][]byte, 0, 7)
	out = append(out, p)
	for off := 1; off <= 2; off++ {
		if len(p) <= off {
			break
		}
		if d := decompressBounded(p[off:], algoZlib); d != nil {
			out = append(out, d)
		}
		if d := decompressBounded(p[off:], algoFlate); d != nil {
			out = append(out, d)
		}
	}
	return out
}

const (
	algoZlib = iota
	algoFlate
)

func decompressBounded(data []byte, algo int) []byte {
	var r io.ReadCloser
	var err error
	br := bytes.NewReader(data)
	switch algo {
	case algoZlib:
		r, err = zlib.NewReader(br)
	default:
		r = flate.NewReader(br)
	}
	if err != nil {
		return nil
	}
	defer r.Close()

	out := make([]byte, 0, 4096)
	buf := make([]byte, 8192)
	total := 0
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			total += n
			if total > maxDecodedStream {
				return nil
			}
			out = append(out, buf[:n]...)
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break // 提前截断也算成功：我们要的 JSON 在头部通常已完整
		}
		if rerr != nil {
			return nil
		}
	}
	if total < 32 {
		return nil
	}
	return out
}

func isBase64URLChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
		c >= '0' && c <= '9' || c == '-' || c == '_' || c == '='
}

// scanCandidate searches one candidate stream for identity-bearing JWT tokens,
// falling back to a loose plaintext JSON scan for non-standard login formats.
// 注意：JWT 的三段由 '.' 分隔，逐段独立解码 —— claims 段自身就是一个完整 run。
func scanCandidate(b []byte) (Identity, bool) {
	// 1) 明文 JSON 直接挖（覆盖部分离线/自定义认证实现）
	if id, ok := mineClaimsJSON(b); ok {
		return id, true
	}

	// 2) JWT base64url 段扫描
	attempts := 0
	start := -1
	for i := 0; i <= len(b); i++ {
		inAlpha := i < len(b) && isBase64URLChar(b[i])
		if inAlpha {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			run := b[start:i]
			start = -1
			if id, ok := decodeClaimsSegment(run, &attempts); ok {
				return id, true
			}
		}
	}
	return Identity{}, false
}

// decodeClaimsSegment 把单个 base64url 段当作 JWT claims 解码并挖掘身份字段。
func decodeClaimsSegment(seg []byte, attempts *int) (Identity, bool) {
	if *attempts >= maxTokenAttempts {
		return Identity{}, false
	}
	*attempts++
	if len(seg) < 8 || len(seg) > 8192 {
		return Identity{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(string(seg))
	if err != nil {
		payload, err = base64.StdEncoding.DecodeString(string(seg))
		if err != nil {
			return Identity{}, false
		}
	}
	j := bytes.IndexByte(payload, '{')
	if j < 0 {
		return Identity{}, false
	}
	e := bytes.LastIndexByte(payload, '}')
	if e <= j {
		return Identity{}, false
	}
	var cl identityClaims
	if err := json.Unmarshal(payload[j:e+1], &cl); err != nil {
		return Identity{}, false
	}
	name := cl.DisplayName
	if name == "" {
		name = cl.IdentityName
	}
	if name == "" && cl.XUID == "" {
		return Identity{}, false // 既没名字也没 XUID，视为无关 token
	}
	return Identity{Gamertag: name, XUID: cl.XUID}, true
}

// mineClaimsJSON loosely digs quoted fields straight out of a plaintext stream.
func mineClaimsJSON(b []byte) (Identity, bool) {
	name := mineJSONString(b, "DisplayName")
	if name == "" {
		name = mineJSONString(b, "IdentityName")
	}
	xuid := mineJSONString(b, "XUID")
	if name == "" && xuid == "" {
		return Identity{}, false
	}
	return Identity{Gamertag: name, XUID: xuid}, true
}

func mineJSONString(b []byte, key string) string {
	pattern := []byte(`"` + key + `"`)
	idx := bytes.Index(b, pattern)
	if idx < 0 {
		return ""
	}
	rest := b[idx+len(pattern):]
	colon := bytes.IndexByte(rest, ':')
	if colon < 0 {
		return ""
	}
	rest = rest[colon+1:]
	rest = bytes.TrimLeft(rest, " \t\r\n")
	if len(rest) == 0 {
		return ""
	}
	if rest[0] == '"' {
		end := bytes.IndexByte(rest[1:], '"')
		if end < 0 {
			return ""
		}
		v := rest[1 : 1+end]
		if len(v) > 128 {
			return ""
		}
		return string(v)
	}
	// 数值型 XUID
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 || end > 32 {
		return ""
	}
	return string(rest[:end])
}

// ExtractForTest 暴露单载荷提取逻辑给本地集成测试（生产代码勿用）。
func ExtractForTest(payload []byte) (Identity, bool) {
	return extractIdentity([][]byte{payload})
}
