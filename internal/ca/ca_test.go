package ca

import (
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
	cert, key, err := NewCertificateAuthority("Test CA", elliptic.P384(), nil, nil)
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
	cert, _, err := NewCertificateAuthority("Test CA", elliptic.P384(), []string{"example.com"}, nil)
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
	cert, _, err := NewCertificateAuthority("Test CA", elliptic.P384(), []string{"example.com", "test"}, networks)
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
	cert, _, err := NewCertificateAuthority("Test CA", elliptic.P384(), nil, []*net.IPNet{mustParseCIDR(t, "10.0.0.0/8")})
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

func TestNewCertificateAuthorityUsesCurve(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			cert, _, err := NewCertificateAuthority("Test CA", curve, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("public key type = %T, want *ecdsa.PublicKey", cert.PublicKey)
			}
			if publicKey.Curve != curve {
				t.Errorf("curve = %s, want %s", publicKey.Curve.Params().Name, curve.Params().Name)
			}
		})
	}
}

func TestParseCurve(t *testing.T) {
	tests := []struct {
		name string
		want elliptic.Curve
	}{
		{"p256", elliptic.P256()},
		{"p384", elliptic.P384()},
		{"P384", elliptic.P384()},
		{"p521", elliptic.P521()},
	}
	for _, tt := range tests {
		got, err := ParseCurve(tt.name)
		if err != nil {
			t.Errorf("ParseCurve(%q) error = %v", tt.name, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseCurve(%q) = %s, want %s", tt.name, got.Params().Name, tt.want.Params().Name)
		}
	}
}

func TestParseCurveRejectsUnknown(t *testing.T) {
	for _, name := range []string{"", "p224", "ed25519"} {
		if _, err := ParseCurve(name); err == nil {
			t.Errorf("ParseCurve(%q) error = nil, want error", name)
		}
	}
}

func verifyIntermediate(root, intermediate, cert *x509.Certificate, dnsName string) error {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	_, err := cert.Verify(x509.VerifyOptions{
		DNSName:       dnsName,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

func TestIssueCertificateAuthority(t *testing.T) {
	caCert, caKey := newTestCA(t, nil, nil)

	cert, key, err := IssueCertificateAuthority(caCert, caKey, " Team CA ", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if cert.Subject.CommonName != "Team CA" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "Team CA")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		t.Error("certificate is not a CA")
	}
	if cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Errorf("MaxPathLen = %d (zero %v), want 0", cert.MaxPathLen, cert.MaxPathLenZero)
	}
	if want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign; cert.KeyUsage != want {
		t.Errorf("KeyUsage = %v, want %v", cert.KeyUsage, want)
	}
	if got, want := cert.NotAfter.Sub(cert.NotBefore), 5*365*24*time.Hour; got != want {
		t.Errorf("validity = %v, want %v", got, want)
	}
	if len(cert.PermittedDNSDomains)+len(cert.PermittedIPRanges)+len(cert.ExcludedIPRanges) != 0 {
		t.Error("unconstrained authority has name constraints")
	}

	if err := cert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("certificate is not signed by the authority: %v", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key type = %T, want *ecdsa.PrivateKey", key)
	}
	if !ecKey.PublicKey.Equal(cert.PublicKey) {
		t.Error("private key does not match certificate public key")
	}
	caPublicKey, ok := caCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("authority public key type = %T, want *ecdsa.PublicKey", caCert.PublicKey)
	}
	if ecKey.Curve != caPublicKey.Curve {
		t.Errorf("curve = %s, want %s", ecKey.Curve.Params().Name, caPublicKey.Curve.Params().Name)
	}

	serverCert, _, err := IssueServer(cert, key, []string{"www.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyIntermediate(caCert, cert, serverCert, "www.example.com"); err != nil {
		t.Errorf("verify server certificate issued by the subordinate authority: %v", err)
	}
}

func TestIssueCertificateAuthorityWithConstraints(t *testing.T) {
	caCert, caKey := newTestCA(t, []string{"example.com"}, []*net.IPNet{mustParseCIDR(t, "10.0.0.0/8"), mustParseCIDR(t, "fd00::/8")})

	networks := []*net.IPNet{mustParseCIDR(t, "10.1.0.0/16")}
	cert, key, err := IssueCertificateAuthority(caCert, caKey, "Team Example CA", []string{"team.example.com"}, networks)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(cert.PermittedDNSDomains, []string{"team.example.com"}) {
		t.Errorf("PermittedDNSDomains = %v, want [team.example.com]", cert.PermittedDNSDomains)
	}
	if !cert.PermittedDNSDomainsCritical {
		t.Error("PermittedDNSDomainsCritical = false, want true")
	}
	if len(cert.PermittedIPRanges) != len(networks) || cert.PermittedIPRanges[0].String() != networks[0].String() {
		t.Errorf("PermittedIPRanges = %v, want %v", cert.PermittedIPRanges, networks)
	}
	if len(cert.ExcludedIPRanges) != 0 {
		t.Errorf("ExcludedIPRanges = %v, want none", cert.ExcludedIPRanges)
	}

	ips := []net.IP{net.ParseIP("10.1.2.3")}
	serverCert, _, err := IssueServer(cert, key, []string{"www.team.example.com"}, ips)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"www.team.example.com", "10.1.2.3"} {
		if err := verifyIntermediate(caCert, cert, serverCert, name); err != nil {
			t.Errorf("verify permitted name %q: %v", name, err)
		}
	}

	outside, _, err := IssueServer(cert, key, []string{"other.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyIntermediate(caCert, cert, outside, "other.com"); err == nil {
		t.Error("verify name outside constraints: want error")
	}
}

func TestIssueCertificateAuthorityDomainsOnlyExcludesIPs(t *testing.T) {
	caCert, caKey := newTestCA(t, nil, nil)

	cert, _, err := IssueCertificateAuthority(caCert, caKey, "Team CA", []string{"team.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !cert.PermittedDNSDomainsCritical {
		t.Error("PermittedDNSDomainsCritical = false, want true")
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

func TestIssueCertificateAuthorityOutsideParentConstraints(t *testing.T) {
	caCert, caKey := newTestCA(t, []string{"example.com"}, []*net.IPNet{mustParseCIDR(t, "10.0.0.0/8")})

	domainsOutside := []string{"other.com"}
	_, _, err := IssueCertificateAuthority(caCert, caKey, "Team CA", domainsOutside, nil)
	if err == nil || !strings.Contains(err.Error(), `"other.com"`) {
		t.Errorf("domain outside constraints: error = %v, want not permitted error", err)
	}

	networksOutside := []*net.IPNet{mustParseCIDR(t, "192.168.0.0/16")}
	_, _, err = IssueCertificateAuthority(caCert, caKey, "Team CA", nil, networksOutside)
	if err == nil || !strings.Contains(err.Error(), "192.168.0.0/16") {
		t.Errorf("network outside constraints: error = %v, want not permitted error", err)
	}

	domainsOnlyCert, domainsOnlyKey := newTestCA(t, []string{"example.com"}, nil)
	network := []*net.IPNet{mustParseCIDR(t, "10.1.0.0/16")}
	_, _, err = IssueCertificateAuthority(domainsOnlyCert, domainsOnlyKey, "Team CA", nil, network)
	if err == nil || !strings.Contains(err.Error(), "excluded") {
		t.Errorf("network excluded by the authority: error = %v, want excluded error", err)
	}
}

func TestIssueCertificateAuthorityMissingName(t *testing.T) {
	caCert, caKey := newTestCA(t, nil, nil)

	for _, name := range []string{"", "   "} {
		if _, _, err := IssueCertificateAuthority(caCert, caKey, name, nil, nil); err == nil {
			t.Errorf("name %q: want error", name)
		}
	}
}

func TestIssueCertificateAuthorityNonCAParent(t *testing.T) {
	caCert, caKey := newTestCA(t, nil, nil)

	serverCert, serverKey, err := IssueServer(caCert, caKey, []string{"example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = IssueCertificateAuthority(serverCert, serverKey, "Team CA", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "not a certificate authority") {
		t.Errorf("error = %v, want not a certificate authority error", err)
	}
}

func TestIssueCertificateAuthorityFromSubordinate(t *testing.T) {
	caCert, caKey := newTestCA(t, nil, nil)

	subCert, subKey, err := IssueCertificateAuthority(caCert, caKey, "Team CA", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = IssueCertificateAuthority(subCert, subKey, "Other CA", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot issue other certificate authorities") {
		t.Errorf("error = %v, want cannot issue other certificate authorities error", err)
	}
}

func TestIssueCertificateAuthorityCAExpiresFirst(t *testing.T) {
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

	_, _, err = IssueCertificateAuthority(caCert, caKey, "Team CA", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error = %v, want CA expiration error", err)
	}
}
