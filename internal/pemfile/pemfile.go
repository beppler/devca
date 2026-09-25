// Package pemfile reads and writes certificates and private keys as PEM files.
package pemfile

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Load reads a certificate and its private key from PEM files.
func Load(certificateFileName, keyFileName string) (*x509.Certificate, crypto.PrivateKey, error) {
	pemBytes, err := os.ReadFile(certificateFileName)
	if err != nil {
		return nil, nil, fmt.Errorf("load certificate: %w", err)
	}

	certPemBlock, _ := pem.Decode(pemBytes)
	if certPemBlock == nil {
		return nil, nil, fmt.Errorf("decode certificate")
	}

	certificate, err := x509.ParseCertificate(certPemBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	pemBytes, err = os.ReadFile(keyFileName)
	if err != nil {
		return nil, nil, fmt.Errorf("load private key: %w", err)
	}

	keyPemBlock, _ := pem.Decode(pemBytes)
	if keyPemBlock == nil {
		return nil, nil, fmt.Errorf("decode private key")
	}

	privateKey, err := parsePrivateKey(keyPemBlock)
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}

	return certificate, privateKey, nil
}

func parsePrivateKey(pemBlock *pem.Block) (privateKey crypto.PrivateKey, err error) {
	switch pemBlock.Type {
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(pemBlock.Bytes)
	default:
		privateKey = nil
		err = fmt.Errorf("unsupported private key type: %s", pemBlock.Type)
	}
	return
}

// Save writes a certificate and its private key to PEM files.
func Save(certificate *x509.Certificate, certificateFileName string, privateKey crypto.PrivateKey, keyFileName string) error {
	certificateBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if certificateBytes == nil {
		return fmt.Errorf("encode certificate")
	}

	privateKeyPEM, err := marshalPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)
	if privateKeyBytes == nil {
		return fmt.Errorf("encode private key")
	}

	err = os.WriteFile(certificateFileName, certificateBytes, 0640)
	if err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	err = os.WriteFile(keyFileName, privateKeyBytes, 0600)
	if err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	// WriteFile keeps the mode of an existing file (e.g. init --force).
	err = os.Chmod(keyFileName, 0600)
	if err != nil {
		return fmt.Errorf("set private key permissions: %w", err)
	}

	return nil
}

func marshalPrivateKey(privateKey crypto.PrivateKey) (*pem.Block, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}, nil
}
