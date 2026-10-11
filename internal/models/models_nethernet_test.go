package models

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// testKeyPair 生成一张自签名证书与配套私钥，用来验证「粘贴 PEM 内容」这条路
// 真的能配成 keypair（这是用户在面板里唯一会遇到的形态）。
func testKeyPair(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mc.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"mc.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// NetherNet 规则的前置条件（透明模式 + UDP）必须在创建与更新两条路径上都被拒绝。
// 这些条件由 UI 的开关保证，但 API 直调可以绕过 UI——服务端必须自己站住。
func TestValidateNetherNetRequiresTransparentUDP(t *testing.T) {
	certPEM, keyPEM := testKeyPair(t)

	cases := []struct {
		name    string
		req     CreateRuleRequest
		wantErr bool
	}{
		{
			name: "nethernet without transparent",
			req: CreateRuleRequest{
				Name: "nn", ListenPort: 19130, TargetAddr: "10.66.0.3", TargetPort: 19132,
				Protocol: ProtocolUDP, NetherNet: true,
			},
			wantErr: true,
		},
		{
			name: "nethernet with transparent but TCP",
			req: CreateRuleRequest{
				Name: "nn", ListenPort: 19130, TargetAddr: "10.66.0.3", TargetPort: 19132,
				Protocol: ProtocolTCP, Transparent: true, NetherNet: true,
			},
			wantErr: true,
		},
		{
			name: "nethernet valid without TLS",
			req: CreateRuleRequest{
				Name: "nn", ListenPort: 19130, TargetAddr: "10.66.0.3", TargetPort: 19132,
				Protocol: ProtocolUDP, Transparent: true, NetherNet: true,
			},
			wantErr: false,
		},
		{
			name: "nethernet TLS enabled but no cert",
			req: CreateRuleRequest{
				Name: "nn", ListenPort: 19130, TargetAddr: "10.66.0.3", TargetPort: 19132,
				Protocol: ProtocolUDP, Transparent: true, NetherNet: true,
				NetherNetTLS: &NetherNetTLS{Enabled: true},
			},
			wantErr: true,
		},
		{
			name: "nethernet TLS with mismatched pair",
			req: CreateRuleRequest{
				Name: "nn", ListenPort: 19130, TargetAddr: "10.66.0.3", TargetPort: 19132,
				Protocol: ProtocolUDP, Transparent: true, NetherNet: true,
				NetherNetTLS: &NetherNetTLS{Enabled: true, Dual: true, CertPEM: certPEM, KeyPEM: certPEM},
			},
			wantErr: true,
		},
		{
			name: "nethernet TLS valid pasted pair",
			req: CreateRuleRequest{
				Name: "nn", ListenPort: 19130, TargetAddr: "10.66.0.3", TargetPort: 19132,
				Protocol: ProtocolUDP, Transparent: true, NetherNet: true,
				NetherNetTLS: &NetherNetTLS{Enabled: true, Dual: true, CertPEM: certPEM, KeyPEM: keyPEM},
			},
			wantErr: false,
		},
		{
			name: "nethernet data port out of range",
			req: CreateRuleRequest{
				Name: "nn", ListenPort: 19130, TargetAddr: "10.66.0.3", TargetPort: 19132,
				Protocol: ProtocolUDP, Transparent: true, NetherNet: true,
				NetherNetTLS: &NetherNetTLS{DataPort: 70000},
			},
			wantErr: true,
		},
		{
			name: "plain transparent rule unaffected",
			req: CreateRuleRequest{
				Name: "tp", ListenPort: 19132, TargetAddr: "10.66.0.3", TargetPort: 19132,
				Protocol: ProtocolUDP, Transparent: true,
			},
			wantErr: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := c.req
			err := ValidateCreateRuleRequest(&req)
			if (err != nil) != c.wantErr {
				t.Fatalf("ValidateCreateRuleRequest() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}


// ValidateForwardRule 是更新合并路径的校验入口：更新请求可以只改
// transparent/protocol，合并后才暴露 NetherNet 的前置条件违规。
func TestValidateForwardRuleNetherNet(t *testing.T) {
	certPEM, keyPEM := testKeyPair(t)

	rule := ForwardRule{
		Name: "nn", ListenAddr: "0.0.0.0", ListenPort: 19130,
		Protocol: ProtocolUDP, TargetAddr: "10.66.0.3", TargetPort: 19132,
		Transparent: true, NetherNet: true,
		NetherNetTLS: &NetherNetTLS{Enabled: true, Dual: true, CertPEM: certPEM, KeyPEM: keyPEM},
	}
	if err := ValidateForwardRule(&rule); err != nil {
		t.Fatalf("valid NetherNet rule rejected: %v", err)
	}

	// 关掉透明模式后应被拒（模拟更新请求只改了 transparent）
	rule.Transparent = false
	if err := ValidateForwardRule(&rule); err == nil {
		t.Fatal("NetherNet without transparent mode must be rejected")
	}

	// 证书被清空
	rule.Transparent = true
	rule.NetherNetTLS = &NetherNetTLS{Enabled: true}
	if err := ValidateForwardRule(&rule); err == nil {
		t.Fatal("NetherNet TLS without cert/key must be rejected")
	}
}

// Normalize 必须 trim 粘贴内容：从终端/面板复制的 PEM 常带首尾空白与 CRLF。
// 不 trim 会让「只改空白」也被判定为证书变更，从而无谓重启数据面。
func TestNetherNetTLSNormalize(t *testing.T) {
	in := &NetherNetTLS{Enabled: true, CertPEM: "  -----BEGIN----  ", KeyPEM: "\t-----KEY----\n"}
	out := in.Normalize()
	if out.CertPEM != "-----BEGIN----" || out.KeyPEM != "-----KEY----" {
		t.Fatalf("Normalize() = %+v, want trimmed content", out)
	}
	if in.CertPEM != "  -----BEGIN----  " {
		t.Fatal("Normalize must not mutate the receiver")
	}
	if (*NetherNetTLS)(nil).Normalize() != nil {
		t.Fatal("nil receiver must normalize to nil")
	}
}

// TestNetherNetPortValidation 校验 NetherNet 端口计算与冲突约束：
// 1. 数据端口超出 65535（如默认 listen_port=65535 且未显式指定 data_port 时计算出 65536）必须被拒；
// 2. 信令端口与数据端口相同时必须被拒；
// 3. 正常情况 NetherNetPorts 正确返回端口。
func TestNetherNetPortValidation(t *testing.T) {
	sig, dat := NetherNetPorts(39042, nil)
	if sig != 39042 || dat != 39043 {
		t.Fatalf("NetherNetPorts(39042, nil) = (%d, %d), want (39042, 39043)", sig, dat)
	}

	sig2, dat2 := NetherNetPorts(39042, &NetherNetTLS{SignalPort: 39044, DataPort: 39045})
	if sig2 != 39044 || dat2 != 39045 {
		t.Fatalf("NetherNetPorts custom = (%d, %d), want (39044, 39045)", sig2, dat2)
	}

	// 端口溢出拦截：65535 默认 +1 变成 65536
	req := CreateRuleRequest{
		Name: "overflow", ListenPort: 65535, TargetAddr: "10.66.0.3", TargetPort: 19132,
		Protocol: ProtocolUDP, Transparent: true, NetherNet: true,
	}
	if err := ValidateCreateRuleRequest(&req); err == nil {
		t.Fatal("listen_port=65535 without data_port must be rejected")
	}

	// 信令端口与数据端口相同拦截
	reqSame := CreateRuleRequest{
		Name: "same-port", ListenPort: 39042, TargetAddr: "10.66.0.3", TargetPort: 19132,
		Protocol: ProtocolUDP, Transparent: true, NetherNet: true,
		NetherNetTLS: &NetherNetTLS{SignalPort: 39042, DataPort: 39042},
	}
	if err := ValidateCreateRuleRequest(&reqSame); err == nil {
		t.Fatal("signal_port == data_port must be rejected")
	}
}

