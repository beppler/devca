package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

func newTestCA(t *testing.T, domains []string, networks []*net.IPNet) (*x509.Certificate, crypto.PrivateKey) {
	t.Helper()
	cert, key, err := NewCertificateAuthority("Test CA", domains, networks)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func verifyServer(caCert, serverCert *x509.Certificate, dnsName string) error {
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	_, err := serverCert.Verify(x509.VerifyOptions{
		DNSName:   dnsName,
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

func TestIssueServer(t *testing.T) {
	caCert, caKey := newTestCA(t, nil, nil)
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	cert, key, err := IssueServer(caCert, caKey, []string{"Example.com", "*.bücher.example"}, ips)
	if err != nil {
		t.Fatal(err)
	}

	wantDNSNames := []string{"example.com", "*.xn--bcher-kva.example"}
	if !slices.Equal(cert.DNSNames, wantDNSNames) {
		t.Errorf("DNSNames = %v, want %v", cert.DNSNames, wantDNSNames)
	}
	if cert.Subject.CommonName != wantDNSNames[0] {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, wantDNSNames[0])
	}
	if len(cert.IPAddresses) != len(ips) {
		t.Fatalf("IPAddresses = %v, want %v", cert.IPAddresses, ips)
	}
	for i, ip := range cert.IPAddresses {
		if !ip.Equal(ips[i]) {
			t.Errorf("IPAddresses[%d] = %v, want %v", i, ip, ips[i])
		}
	}

	if cert.IsCA {
		t.Error("server certificate is a CA")
	}
	if want := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature; cert.KeyUsage != want {
		t.Errorf("KeyUsage = %v, want %v", cert.KeyUsage, want)
	}
	if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("ExtKeyUsage = %v, want [ServerAuth]", cert.ExtKeyUsage)
	}
	if got, want := cert.NotAfter.Sub(cert.NotBefore), 2*365*24*time.Hour; got != want {
		t.Errorf("validity = %v, want %v", got, want)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key type = %T, want *ecdsa.PrivateKey", key)
	}
	if !ecKey.PublicKey.Equal(cert.PublicKey) {
		t.Error("private key does not match certificate public key")
	}

	for _, name := range []string{"example.com", "www.xn--bcher-kva.example", "127.0.0.1", "::1"} {
		if err := verifyServer(caCert, cert, name); err != nil {
			t.Errorf("verify %q: %v", name, err)
		}
	}
	if err := verifyServer(caCert, cert, "other.com"); err == nil {
		t.Error("verify other.com: want error")
	}
}

func TestIssueServerIPsOnly(t *testing.T) {
	caCert, caKey := newTestCA(t, nil, nil)
	ips := []net.IP{net.ParseIP("192.168.1.10")}

	cert, _, err := IssueServer(caCert, caKey, nil, ips)
	if err != nil {
		t.Fatal(err)
	}

	if len(cert.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want none", cert.DNSNames)
	}
	if cert.Subject.CommonName != "192.168.1.10" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "192.168.1.10")
	}
	if err := verifyServer(caCert, cert, "192.168.1.10"); err != nil {
		t.Errorf("verify: %v", err)
	}
}

func TestIssueServerNoNames(t *testing.T) {
	caCert, caKey := newTestCA(t, nil, nil)

	_, _, err := IssueServer(caCert, caKey, nil, nil)
	if err == nil {
		t.Fatal("want error")
	}
}

func TestIssueServerInvalidHostName(t *testing.T) {
	caCert, caKey := newTestCA(t, nil, nil)

	_, _, err := IssueServer(caCert, caKey, []string{"example.com", "bad..name"}, nil)
	if err == nil || !strings.Contains(err.Error(), `"bad..name"`) {
		t.Fatalf("error = %v, want invalid host name error", err)
	}
}

func TestIssueServerCAExpiresFirst(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Short-lived CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = IssueServer(caCert, caKey, []string{"example.com"}, nil)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error = %v, want CA expiration error", err)
	}
}

func TestIssueServerRespectsCANameConstraints(t *testing.T) {
	caCert, caKey := newTestCA(t, []string{"example.com"}, nil)

	allowed, _, err := IssueServer(caCert, caKey, []string{"www.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyServer(caCert, allowed, "www.example.com"); err != nil {
		t.Errorf("verify permitted name: %v", err)
	}

	outside, _, err := IssueServer(caCert, caKey, []string{"other.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyServer(caCert, outside, "other.com"); err == nil {
		t.Error("verify name outside constraints: want error")
	}

	// A CA restricted to domains only must not vouch for any IP address.
	withIP, _, err := IssueServer(caCert, caKey, []string{"www.example.com"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyServer(caCert, withIP, "www.example.com"); err == nil {
		t.Error("verify certificate with excluded IP: want error")
	}
}
