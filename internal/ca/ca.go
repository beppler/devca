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

// rootAuthorityValidity is how long the root certificate authority is valid:
// longer than subordinate authorities and leaf certificates (10 years).
const rootAuthorityValidity = time.Hour * 24 * 365 * 10

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
		NotAfter:                    time.Now().Add(rootAuthorityValidity),
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

// authorityValidity is how long subordinate certificate authorities are valid:
// longer than leaf certificates, shorter than the root authority (5 years).
const authorityValidity = time.Hour * 24 * 365 * 5

// IssueCertificateAuthority issues a subordinate certificate authority with
// the given name and name constraints, signed by the given certificate
// authority. The subordinate authority can issue certificates but not other
// authorities, and its constraints must be within the ones of the signing
// authority.
func IssueCertificateAuthority(caCertificate *x509.Certificate, caPrivateKey crypto.PrivateKey, authorityName string, domains []string, networks []*net.IPNet) (*x509.Certificate, crypto.PrivateKey, error) {
	authorityName = strings.TrimSpace(authorityName)
	if authorityName == "" {
		return nil, nil, fmt.Errorf("authority name should be provided")
	}

	if !caCertificate.IsCA {
		return nil, nil, fmt.Errorf("signer certificate is not a certificate authority")
	}

	if caCertificate.MaxPathLen == 0 && caCertificate.MaxPathLenZero {
		return nil, nil, fmt.Errorf("certificate authority cannot issue other certificate authorities")
	}

	if err := validateConstraints(caCertificate, domains, networks); err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: authorityName,
		},
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: len(domains) > 0,
		PermittedDNSDomains:         domains,
		PermittedIPRanges:           networks,
		ExcludedIPRanges:            excludedNetworks(domains, networks),
	}

	return sign(caCertificate, caPrivateKey, &template, authorityValidity)
}
