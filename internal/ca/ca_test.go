package ca

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func mustParseCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return network
}

func TestNewCertificateAuthority(t *testing.T) {
	before := time.Now().Truncate(time.Second)
	cert, key, err := NewCertificateAuthority("Test CA", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if cert.Subject.CommonName != "Test CA" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "Test CA")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		t.Error("certificate is not a CA")
	}
	if cert.MaxPathLen != 1 {
		t.Errorf("MaxPathLen = %d, want 1", cert.MaxPathLen)
	}
	if want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign; cert.KeyUsage != want {
		t.Errorf("KeyUsage = %v, want %v", cert.KeyUsage, want)
	}
	if cert.NotBefore.Before(before) {
		t.Errorf("NotBefore = %v, want not before %v", cert.NotBefore, before)
	}
	if got, want := cert.NotAfter.Sub(cert.NotBefore), 10*365*24*time.Hour; got != want {
		t.Errorf("validity = %v, want %v", got, want)
	}

	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("certificate is not self-signed: %v", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key type = %T, want *ecdsa.PrivateKey", key)
	}
	if !ecKey.PublicKey.Equal(cert.PublicKey) {
		t.Error("private key does not match certificate public key")
	}

	if cert.PermittedDNSDomainsCritical {
		t.Error("PermittedDNSDomainsCritical = true, want false")
	}
	if len(cert.PermittedDNSDomains)+len(cert.PermittedIPRanges)+len(cert.ExcludedIPRanges) != 0 {
		t.Error("unconstrained CA has name constraints")
	}
}

func TestNewCertificateAuthorityDomainsOnlyExcludesAllIPs(t *testing.T) {
	cert, _, err := NewCertificateAuthority("Test CA", []string{"example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !cert.PermittedDNSDomainsCritical {
		t.Error("PermittedDNSDomainsCritical = false, want true")
	}
	if len(cert.PermittedDNSDomains) != 1 || cert.PermittedDNSDomains[0] != "example.com" {
		t.Errorf("PermittedDNSDomains = %v, want [example.com]", cert.PermittedDNSDomains)
	}
	if len(cert.PermittedIPRanges) != 0 {
		t.Errorf("PermittedIPRanges = %v, want none", cert.PermittedIPRanges)
	}

	want := []string{"0.0.0.0/0", "::/0"}
	if len(cert.ExcludedIPRanges) != len(want) {
		t.Fatalf("ExcludedIPRanges = %v, want %v", cert.ExcludedIPRanges, want)
	}
	for i, network := range cert.ExcludedIPRanges {
		if network.String() != want[i] {
			t.Errorf("ExcludedIPRanges[%d] = %v, want %v", i, network, want[i])
		}
	}
}

func TestNewCertificateAuthorityDomainsAndNetworks(t *testing.T) {
	networks := []*net.IPNet{mustParseCIDR(t, "192.168.0.0/16"), mustParseCIDR(t, "fd00::/8")}
	cert, _, err := NewCertificateAuthority("Test CA", []string{"example.com", "test"}, networks)
	if err != nil {
		t.Fatal(err)
	}

	if len(cert.PermittedDNSDomains) != 2 {
		t.Errorf("PermittedDNSDomains = %v, want [example.com test]", cert.PermittedDNSDomains)
	}
	if len(cert.PermittedIPRanges) != len(networks) {
		t.Fatalf("PermittedIPRanges = %v, want %v", cert.PermittedIPRanges, networks)
	}
	for i, network := range cert.PermittedIPRanges {
		if network.String() != networks[i].String() {
			t.Errorf("PermittedIPRanges[%d] = %v, want %v", i, network, networks[i])
		}
	}
	if len(cert.ExcludedIPRanges) != 0 {
		t.Errorf("ExcludedIPRanges = %v, want none", cert.ExcludedIPRanges)
	}
}

func TestNewCertificateAuthorityNetworksOnly(t *testing.T) {
	cert, _, err := NewCertificateAuthority("Test CA", nil, []*net.IPNet{mustParseCIDR(t, "10.0.0.0/8")})
	if err != nil {
		t.Fatal(err)
	}

	if cert.PermittedDNSDomainsCritical {
		t.Error("PermittedDNSDomainsCritical = true, want false")
	}
	if len(cert.PermittedIPRanges) != 1 || cert.PermittedIPRanges[0].String() != "10.0.0.0/8" {
		t.Errorf("PermittedIPRanges = %v, want [10.0.0.0/8]", cert.PermittedIPRanges)
	}
	if len(cert.ExcludedIPRanges) != 0 {
		t.Errorf("ExcludedIPRanges = %v, want none", cert.ExcludedIPRanges)
	}
}
