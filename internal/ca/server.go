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

// IssueServer issues a server certificate for the given host names and IP
// addresses, signed by the given certificate authority.
func IssueServer(caCertificate *x509.Certificate, caPrivateKey crypto.PrivateKey, hostNames []string, ips []net.IP) (*x509.Certificate, crypto.PrivateKey, error) {
	if len(hostNames) < 1 && len(ips) < 1 {
		return nil, nil, fmt.Errorf("at least one host name or IP should be provided")
	}

	dnsNames := make([]string, 0, len(hostNames))
	for _, hostName := range hostNames {
		dnsName, err := normalizeHostName(hostName)
		if err != nil {
			return nil, nil, err
		}
		dnsNames = append(dnsNames, dnsName)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 365 * 2)

	if notBefore.After(caCertificate.NotAfter) || notAfter.After(caCertificate.NotAfter) {
		return nil, nil, fmt.Errorf("ca certificate will be expired before host certificate")
	}

	serialNumber := big.NewInt(notBefore.Unix())

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("create server private key: %w", err)
	}

	template := x509.Certificate{
		IsCA:                  false,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			CommonName: dnsNames[0],
		},
		DNSNames:    dnsNames,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
	}

	if len(ips) > 0 {
		template.IPAddresses = ips
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCertificate, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create server certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse server certificate: %w", err)
	}

	return cert, privateKey, nil
}
