package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
)

func verifyUsage(caCert, cert *x509.Certificate, usage x509.ExtKeyUsage) error {
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{usage},
	})
	return err
}

func TestIssueCodeSigning(t *testing.T) {
	caCert, caKey := newTestCA(t, nil, nil)

	cert, key, err := IssueCodeSigning(caCert, caKey, " ACME Dev ", "br", "ACME Corp")
	if err != nil {
		t.Fatal(err)
	}

	if cert.Subject.CommonName != "ACME Dev" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "ACME Dev")
	}
	if !slices.Equal(cert.Subject.Country, []string{"BR"}) {
		t.Errorf("Country = %v, want [BR]", cert.Subject.Country)
	}
	if !slices.Equal(cert.Subject.Organization, []string{"ACME Corp"}) {
		t.Errorf("Organization = %v, want [ACME Corp]", cert.Subject.Organization)
	}

	if cert.IsCA {
		t.Error("code signing certificate is a CA")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want %v", cert.KeyUsage, x509.KeyUsageDigitalSignature)
	}
	if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}) {
		t.Errorf("ExtKeyUsage = %v, want [CodeSigning]", cert.ExtKeyUsage)
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

	if err := verifyUsage(caCert, cert, x509.ExtKeyUsageCodeSigning); err != nil {
		t.Errorf("verify code signing: %v", err)
	}
	if err := verifyUsage(caCert, cert, x509.ExtKeyUsageServerAuth); err == nil {
		t.Error("verify server auth: want error")
	}
}

func TestIssueCodeSigningNameOnly(t *testing.T) {
	caCert, caKey := newTestCA(t, nil, nil)

	cert, _, err := IssueCodeSigning(caCert, caKey, "Developer", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if len(cert.Subject.Country) != 0 {
		t.Errorf("Country = %v, want none", cert.Subject.Country)
	}
	if len(cert.Subject.Organization) != 0 {
		t.Errorf("Organization = %v, want none", cert.Subject.Organization)
	}
}

func TestIssueCodeSigningMissingName(t *testing.T) {
	caCert, caKey := newTestCA(t, nil, nil)

	for _, name := range []string{"", "   "} {
		if _, _, err := IssueCodeSigning(caCert, caKey, name, "", ""); err == nil {
			t.Errorf("name %q: want error", name)
		}
	}
}

func TestIssueCodeSigningInvalidCountry(t *testing.T) {
	caCert, caKey := newTestCA(t, nil, nil)

	for _, country := range []string{"BRA", "B", "1A", "ü"} {
		_, _, err := IssueCodeSigning(caCert, caKey, "Developer", country, "")
		if err == nil || !strings.Contains(err.Error(), "country") {
			t.Errorf("country %q: error = %v, want invalid country error", country, err)
		}
	}
}

func TestIssueCodeSigningCAExpiresFirst(t *testing.T) {
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

	_, _, err = IssueCodeSigning(caCert, caKey, "Developer", "", "")
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error = %v, want CA expiration error", err)
	}
}
