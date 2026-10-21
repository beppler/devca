package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func newTestCAWithKey(t *testing.T, caKey crypto.Signer) *x509.Certificate {
	t.Helper()
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return caCert
}

func TestIssueUsesCACurve(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			caKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			caCert := newTestCAWithKey(t, caKey)

			_, key, err := issue(caCert, caKey, &x509.Certificate{}, 24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}

			ecKey, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("private key type = %T, want *ecdsa.PrivateKey", key)
			}
			if ecKey.Curve != curve {
				t.Errorf("curve = %s, want %s", ecKey.Curve.Params().Name, curve.Params().Name)
			}
		})
	}
}

func TestIssueNonECDSACA(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caCert := newTestCAWithKey(t, caKey)

	_, _, err = issue(caCert, caKey, &x509.Certificate{}, 24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "ECDSA") {
		t.Fatalf("error = %v, want unsupported CA key error", err)
	}
}
