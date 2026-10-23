package ca

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
	"time"
)

// authorityValidity is how long subordinate certificate authorities are valid:
// longer than leaf certificates, shorter than the root authority.
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
