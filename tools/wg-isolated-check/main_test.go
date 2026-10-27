package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func testProfile() string {
	// Synthetic parser-only keys are constructed, never used for a network test.
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return "[Interface]\nPrivateKey = " + key + "\nAddress = 10.70.0.4/32\nDNS = 1.1.1.1\nMTU = 1280\n\n[Peer]\nPublicKey = " + key + "\nPresharedKey = " + key + "\nEndpoint = 217.18.60.102:51820\nAllowedIPs = 0.0.0.0/0\n"
}

func TestParseProfile(t *testing.T) {
	p, err := parseProfile(testProfile())
	if err != nil {
		t.Fatal(err)
	}
	if p.local.String() != "10.70.0.4" || p.mtu != 1280 || !strings.Contains(p.ipc, "allowed_ip=0.0.0.0/0") {
		t.Fatal("unexpected isolated configuration")
	}
}

func TestRejectUnsafeOrInvalidInput(t *testing.T) {
	cases := []string{
		"invalid",
		testProfile() + "\n[Peer]\n",
		strings.Replace(testProfile(), "217.18.60.102:51820", "hostname.example:51820", 1),
		strings.Replace(testProfile(), "MTU = 1280", "MTU = 9000", 1),
		strings.Replace(testProfile(), "DNS = 1.1.1.1", "DNS = invalid", 1),
	}
	for i, text := range cases {
		if _, err := parseProfile(text); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestKeyErrorsDoNotDiscloseInput(t *testing.T) {
	secret := "sensitive-invalid-value"
	_, err := keyHex(secret)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("key validation must fail without disclosing the value")
	}
}
