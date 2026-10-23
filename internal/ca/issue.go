package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

// issue completes the leaf certificate template with validity, serial number
// and a new private key on the same curve as the certificate authority, and
// signs it with the given certificate authority.
func issue(caCertificate *x509.Certificate, caPrivateKey crypto.PrivateKey, template *x509.Certificate, validity time.Duration) (*x509.Certificate, crypto.PrivateKey, error) {
	template.IsCA = false
	template.BasicConstraintsValid = true
	return sign(caCertificate, caPrivateKey, template, validity)
}

// sign completes the given certificate template with validity, serial number
// and a new private key on the same curve as the certificate authority, and
// signs it with the given certificate authority. The template must carry the
// basic constraints and key usage appropriate to the certificate kind.
func sign(caCertificate *x509.Certificate, caPrivateKey crypto.PrivateKey, template *x509.Certificate, validity time.Duration) (*x509.Certificate, crypto.PrivateKey, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	if notBefore.After(caCertificate.NotAfter) || notAfter.After(caCertificate.NotAfter) {
		return nil, nil, fmt.Errorf("ca certificate will be expired before the issued certificate")
	}

	caPublicKey, ok := caCertificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("unsupported CA key type %T: only ECDSA is supported", caCertificate.PublicKey)
	}

	privateKey, err := ecdsa.GenerateKey(caPublicKey.Curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("create private key: %w", err)
	}

	template.SerialNumber = big.NewInt(notBefore.Unix())
	template.NotBefore = notBefore
	template.NotAfter = notAfter

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCertificate, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	return cert, privateKey, nil
}
