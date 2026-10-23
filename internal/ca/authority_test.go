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
