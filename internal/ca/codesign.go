package ca

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"time"
)

// codeSigningValidity is how long code signing certificates are valid (2 years).
const codeSigningValidity = time.Hour * 24 * 365 * 2

// IssueCodeSigning issues a code signing certificate for the given subject,
// signed by the given certificate authority. Country and organization are
// optional.
func IssueCodeSigning(caCertificate *x509.Certificate, caPrivateKey crypto.PrivateKey, commonName, country, organization string) (*x509.Certificate, crypto.PrivateKey, error) {
	commonName = strings.TrimSpace(commonName)
	if commonName == "" {
		return nil, nil, fmt.Errorf("common name should be provided")
	}

	subject := pkix.Name{
		CommonName: commonName,
	}

	if country != "" {
		if !isCountryCode(country) {
			return nil, nil, fmt.Errorf("invalid country code %q: should be two letters", country)
		}
		subject.Country = []string{strings.ToUpper(country)}
	}

	if organization != "" {
		subject.Organization = []string{organization}
	}

	template := x509.Certificate{
		Subject:     subject,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	return issue(caCertificate, caPrivateKey, &template, codeSigningValidity)
}

// isCountryCode reports whether s has the shape of an ISO 3166-1 alpha-2 code.
func isCountryCode(s string) bool {
	if len(s) != 2 {
		return false
	}
	for _, c := range s {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}
