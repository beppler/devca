// Package ca creates development certificate authorities and issues
// certificates signed by them.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// ParseCurve returns the elliptic curve with the given name (p256, p384 or
// p521, case insensitive).
func ParseCurve(name string) (elliptic.Curve, error) {
	switch strings.ToLower(name) {
	case "p256":
		return elliptic.P256(), nil
	case "p384":
		return elliptic.P384(), nil
	case "p521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
}

func NewCertificateAuthority(authorityName string, curve elliptic.Curve, domains []string, networks []*net.IPNet) (*x509.Certificate, crypto.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: authorityName,
		},
		NotBefore:                   time.Now(),
		NotAfter:                    time.Now().Add(time.Hour * 24 * 365 * 10),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                        true,
		MaxPathLen:                  1,
		BasicConstraintsValid:       true,
		PermittedDNSDomainsCritical: len(domains) > 0,
		PermittedDNSDomains:         domains,
		PermittedIPRanges:           networks,
		ExcludedIPRanges:            excludedNetworks(domains, networks),
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	return cert, privateKey, nil
}
