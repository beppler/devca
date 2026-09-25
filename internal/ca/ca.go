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
	"time"
)

func NewCertificateAuthority(authorityName string, domains []string, networks []*net.IPNet) (*x509.Certificate, crypto.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA private key: %w", err)
	}

	var excludedNetworks []*net.IPNet
	if len(domains) > 0 && len(networks) == 0 {
		excludedNetworks = []*net.IPNet{{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, {IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}}
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
	}

	if len(excludedNetworks) > 0 {
		template.ExcludedIPRanges = excludedNetworks
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
