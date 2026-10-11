package certmanager

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"go-port-forward/internal/models"
	"go-port-forward/pkg/serializer/json"
)

// DNSProvider 抽象 ACME DNS-01 验证所需的 TXT 记录写入与清理。
type DNSProvider interface {
	Present(ctx context.Context, fqdn, value string) (cleanup func(), err error)
}

func newDNSProvider(provider models.ACMEProvider, creds map[string]string, httpClient *http.Client) (DNSProvider, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	// provider 可能是复合值（如 litessl_cloudflare），归一化到 DNS 服务商本身。
	provider = provider.DNSProvider()
	switch provider {
	case models.ACMEProviderCloudflare:
		token := strings.TrimSpace(creds["api_token"])
		if token == "" {
			return nil, fmt.Errorf("Cloudflare API Token 不能为空 | Cloudflare API Token is required")
		}
		baseURL := strings.TrimSpace(creds["base_url"])
		if baseURL == "" {
			baseURL = "https://api.cloudflare.com/client/v4"
		}
		return &cloudflareProvider{apiToken: token, baseURL: strings.TrimRight(baseURL, "/"), client: httpClient}, nil
	case models.ACMEProviderAliyun:
		ak := strings.TrimSpace(creds["access_key_id"])
		sk := strings.TrimSpace(creds["access_key_secret"])
		if ak == "" || sk == "" {
			return nil, fmt.Errorf("阿里云 AccessKey ID 与 Secret 不能为空 | Aliyun credentials are required")
		}
		endpoint := strings.TrimSpace(creds["endpoint"])
		if endpoint == "" {
			endpoint = "https://alidns.aliyuncs.com/"
		}
		return &aliyunProvider{accessKeyID: ak, accessKeySecret: sk, endpoint: endpoint, client: httpClient}, nil
	case models.ACMEProviderDNSPod:
		sid := strings.TrimSpace(creds["secret_id"])
		skey := strings.TrimSpace(creds["secret_key"])
		if sid == "" || skey == "" {
			return nil, fmt.Errorf("腾讯云 SecretId 与 SecretKey 不能为空 | Tencent Cloud credentials are required")
		}
		endpoint := strings.TrimSpace(creds["endpoint"])
		if endpoint == "" {
			endpoint = "https://dnspod.tencentcloudapi.com"
		}
		return &dnspodProvider{secretID: sid, secretKey: skey, endpoint: endpoint, client: httpClient}, nil
	default:
		return nil, fmt.Errorf("不支持的 DNS 验证服务商: %s | unsupported DNS provider: %s", provider, provider)
	}
}

// splitDomainAndRR 将完整主机名（如 _acme-challenge.play.example.com）按根域名切分为
// (rootDomain="example.com", rr="_acme-challenge.play")。
func splitDomainAndRR(fqdn string) (rootDomain, rr string, err error) {
	fqdn = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	parts := strings.Split(fqdn, ".")
	if len(parts) < 3 {
		return "", "", fmt.Errorf("无效的挑战域名 %q | invalid challenge fqdn %q", fqdn, fqdn)
	}
	// 处理常见二级后缀（如 .com.cn / .net.cn / .org.cn / .gov.cn / .co.uk）
	twoPartTLD := false
	if len(parts) >= 4 {
		lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
		switch lastTwo {
		case "com.cn", "net.cn", "org.cn", "gov.cn", "ac.cn", "co.uk", "org.uk", "com.hk", "com.tw":
			twoPartTLD = true
		}
	}
	rootParts := 2
	if twoPartTLD {
		rootParts = 3
	}
	rootDomain = strings.Join(parts[len(parts)-rootParts:], ".")
	rr = strings.Join(parts[:len(parts)-rootParts], ".")
	return rootDomain, rr, nil
}

// --- 1. Cloudflare DNS-01 Provider ---

type cloudflareProvider struct {
	apiToken string
	baseURL  string
	client   *http.Client
}

func (p *cloudflareProvider) Present(ctx context.Context, fqdn, value string) (func(), error) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zoneID, err := p.findZoneID(ctx, fqdn)
	if err != nil {
		return nil, err
	}

	body, _ := json.Marshal(map[string]interface{}{
		"type":    "TXT",
		"name":    fqdn,
		"content": value,
		"ttl":     120,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/zones/"+zoneID+"/dns_records", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Cloudflare 创建 TXT 记录请求失败: %w", err)
	}
	defer resp.Body.Close()

	var cfResp struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		return nil, fmt.Errorf("解析 Cloudflare 响应失败: %w", err)
	}
	if !cfResp.Success || cfResp.Result.ID == "" {
		msg := "unknown error"
		if len(cfResp.Errors) > 0 {
			msg = cfResp.Errors[0].Message
		}
		return nil, fmt.Errorf("Cloudflare 添加 TXT 记录失败: %s", msg)
	}

	recordID := cfResp.Result.ID
	cleanup := func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		delReq, err := http.NewRequestWithContext(cctx, http.MethodDelete, p.baseURL+"/zones/"+zoneID+"/dns_records/"+recordID, nil)
		if err != nil {
			return
		}
		delReq.Header.Set("Authorization", "Bearer "+p.apiToken)
		if r, err := p.client.Do(delReq); err == nil {
			_ = r.Body.Close()
		}
	}
	return cleanup, nil
}

func (p *cloudflareProvider) findZoneID(ctx context.Context, fqdn string) (string, error) {
	parts := strings.Split(fqdn, ".")
	// 从右往左逐层探测匹配的 zone
	for i := 1; i < len(parts)-1; i++ {
		zoneName := strings.Join(parts[i:], ".")
		u := p.baseURL + "/zones?name=" + url.QueryEscape(zoneName) + "&status=active"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+p.apiToken)
		resp, err := p.client.Do(req)
		if err != nil {
			continue
		}
		var r struct {
			Success bool `json:"success"`
			Result  []struct {
				ID string `json:"id"`
			} `json:"result"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&r)
		_ = resp.Body.Close()
		if r.Success && len(r.Result) > 0 && r.Result[0].ID != "" {
			return r.Result[0].ID, nil
		}
	}
	return "", fmt.Errorf("未能通过 Cloudflare API 找到包含 %s 的有效托管区域 (Zone) | no active Cloudflare zone found for %s", fqdn, fqdn)
}

// --- 2. 阿里云 DNS-01 Provider ---

type aliyunProvider struct {
	accessKeyID     string
	accessKeySecret string
	endpoint        string
	client          *http.Client
}

func (p *aliyunProvider) Present(ctx context.Context, fqdn, value string) (func(), error) {
	rootDomain, rr, err := splitDomainAndRR(fqdn)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Set("Action", "AddDomainRecord")
	params.Set("DomainName", rootDomain)
	params.Set("RR", rr)
	params.Set("Type", "TXT")
	params.Set("Value", value)
	params.Set("TTL", "600")

	res, err := p.doRequest(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("阿里云添加 TXT 记录失败: %w", err)
	}
	recordID, _ := res["RecordId"].(string)
	if recordID == "" {
		return nil, fmt.Errorf("阿里云响应中未返回 RecordId: %+v", res)
	}

	cleanup := func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		delParams := url.Values{}
		delParams.Set("Action", "DeleteDomainRecord")
		delParams.Set("RecordId", recordID)
		_, _ = p.doRequest(cctx, delParams)
	}
	return cleanup, nil
}

func (p *aliyunProvider) doRequest(ctx context.Context, params url.Values) (map[string]interface{}, error) {
	params.Set("Format", "JSON")
	params.Set("Version", "2015-01-09")
	params.Set("AccessKeyId", p.accessKeyID)
	params.Set("SignatureMethod", "HMAC-SHA1")
	params.Set("Timestamp", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	params.Set("SignatureVersion", "1.0")
	params.Set("SignatureNonce", strconv.FormatInt(time.Now().UnixNano(), 10))

	// CanonicalizedQueryString
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonicalQuery []string
	for _, k := range keys {
		canonicalQuery = append(canonicalQuery, url.QueryEscape(k)+"="+url.QueryEscape(params.Get(k)))
	}
	canonicalStr := strings.Join(canonicalQuery, "&")
	stringToSign := "POST&%2F&" + url.QueryEscape(canonicalStr)

	mac := hmac.New(sha1.New, []byte(p.accessKeySecret+"&"))
	mac.Write([]byte(stringToSign))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	params.Set("Signature", sig)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, fmt.Errorf("解析阿里云 JSON 失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("阿里云 API 错误 (status=%d): %s", resp.StatusCode, string(bodyBytes))
	}
	return result, nil
}

// --- 3. 腾讯云 DNSPod DNS-01 Provider ---

type dnspodProvider struct {
	secretID  string
	secretKey string
	endpoint  string
	client    *http.Client
}

func (p *dnspodProvider) Present(ctx context.Context, fqdn, value string) (func(), error) {
	rootDomain, rr, err := splitDomainAndRR(fqdn)
	if err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"Domain":     rootDomain,
		"SubDomain":  rr,
		"RecordType": "TXT",
		"RecordLine": "默认",
		"Value":      value,
		"TTL":        600,
	})

	res, err := p.doRequest(ctx, "CreateRecord", payload)
	if err != nil {
		return nil, fmt.Errorf("腾讯云添加 TXT 记录失败: %w", err)
	}
	respObj, _ := res["Response"].(map[string]interface{})
	var recordID uint64
	if idVal, ok := respObj["RecordId"]; ok {
		switch v := idVal.(type) {
		case float64:
			recordID = uint64(v)
		case int64:
			recordID = uint64(v)
		}
	}
	if recordID == 0 {
		return nil, fmt.Errorf("腾讯云响应中未返回有效 RecordId: %+v", res)
	}

	cleanup := func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		delPayload, _ := json.Marshal(map[string]interface{}{
			"Domain":   rootDomain,
			"RecordId": recordID,
		})
		_, _ = p.doRequest(cctx, "DeleteRecord", delPayload)
	}
	return cleanup, nil
}

func (p *dnspodProvider) doRequest(ctx context.Context, action string, payload []byte) (map[string]interface{}, error) {
	host := strings.TrimPrefix(strings.TrimPrefix(p.endpoint, "https://"), "http://")
	host = strings.TrimRight(host, "/")

	now := time.Now().UTC()
	date := now.Format("2006-01-02")
	timestamp := now.Unix()

	service := "dnspod"
	canonicalHeaders := fmt.Sprintf("content-type:application/json; charset=utf-8\nhost:%s\nx-tc-action:%s\n", host, strings.ToLower(action))
	signedHeaders := "content-type;host;x-tc-action"

	hPayload := sha256.Sum256(payload)
	canonicalRequest := fmt.Sprintf("POST\n/\n\n%s\n%s\n%s", canonicalHeaders, signedHeaders, hex.EncodeToString(hPayload[:]))

	credentialScope := fmt.Sprintf("%s/%s/tc3_request", date, service)
	hReq := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := fmt.Sprintf("TC3-HMAC-SHA256\n%d\n%s\n%s", timestamp, credentialScope, hex.EncodeToString(hReq[:]))

	kDate := hmacSHA256([]byte("TC3"+p.secretKey), date)
	kService := hmacSHA256(kDate, service)
	kSigning := hmacSHA256(kService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	authorization := fmt.Sprintf("TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		p.secretID, credentialScope, signedHeaders, signature)

	urlStr := p.endpoint
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", host)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Version", "2021-03-23")
	req.Header.Set("X-TC-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("Authorization", authorization)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var res map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return nil, fmt.Errorf("解析腾讯云响应失败: %w", err)
	}
	if respObj, ok := res["Response"].(map[string]interface{}); ok {
		if errObj, ok := respObj["Error"].(map[string]interface{}); ok {
			return nil, fmt.Errorf("腾讯云 API 错误: %v - %v", errObj["Code"], errObj["Message"])
		}
	}
	return res, nil
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
