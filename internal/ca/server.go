package ca

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"time"
)

// serverValidity is how long server certificates are valid (2 years).
const serverValidity = time.Hour * 24 * 365 * 2

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

	var commonName string
	if len(dnsNames) > 0 {
		commonName = dnsNames[0]
	} else {
		commonName = ips[0].String()
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:    dnsNames,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if len(ips) > 0 {
		template.IPAddresses = ips
	}

	return issue(caCertificate, caPrivateKey, &template, serverValidity)
}
