package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/user"
	"regexp"
	"time"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Println("command must be specified.")
		os.Exit(2)
	}

	command := os.Args[1]

	switch command {
	case "init":
		handleInit()
	case "server":
		handleServer()
	default:
		fmt.Printf("invalid command %s.\n", command)
		os.Exit(2)
	}
}

func handleInit() {
	if _, err := os.Stat("ca.crt"); err == nil {
		fmt.Println("certificate authority already exist")
		os.Exit(1)
	}

	caName := "Local Development CA"
	if len(os.Args) >= 3 {
		caName = os.Args[2]
	} else {
		user, err := user.Current()
		if err == nil && user.Username != "" {
			caName = user.Username + " " + caName
		}
	}

	caCert, caKey, err := createCertificateAuthority(caName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = saveCertificateAndPrivateKey(caCert, "ca.crt", caKey, "ca.key")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func handleServer() {
	if len(os.Args) < 3 {
		fmt.Println("host name must be specified.")
		os.Exit(2)
	}

	caCert, caKey, err := loadCertificateAndPrivateKey("ca.crt", "ca.key")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	hostNames := os.Args[2:]

	hostCert, hostKey, err := signHostCertificate(caCert, caKey, hostNames)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	baseFileName := hostNames[0] + "-" + fmt.Sprintf("%x", hostCert.SerialNumber)
	err = saveCertificateAndPrivateKey(hostCert, baseFileName+".crt", hostKey, baseFileName+".key")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func createCertificateAuthority(authorityName string) (*x509.Certificate, crypto.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   authorityName,
			Organization: []string{authorityName},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 10),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
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

func signHostCertificate(caCertificate *x509.Certificate, caPrivateKey crypto.PrivateKey, hostNames []string) (*x509.Certificate, crypto.PrivateKey, error) {
	if len(hostNames) < 1 {
		return nil, nil, fmt.Errorf("at least on host name should be provided")
	}

	validHostNameRegexp, _ := regexp.Compile(`^((\*|[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)

	for _, hostName := range hostNames {
		if !validHostNameRegexp.MatchString(hostName) {
			return nil, nil, fmt.Errorf("invalid host name: %s", hostName)
		}
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 365 * 2)

	if notBefore.After(caCertificate.NotAfter) || notAfter.After(caCertificate.NotAfter) {
		return nil, nil, fmt.Errorf("signer certificate will be expired before host certificate")
	}

	serialNumber := big.NewInt(time.Now().Unix())

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("create host private key: %w", err)
	}

	template := x509.Certificate{
		IsCA:                  false,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			CommonName: hostNames[0],
		},
		DNSNames:    hostNames,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCertificate, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create host certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse host certificate: %w", err)
	}

	return cert, privateKey, nil
}

func loadCertificateAndPrivateKey(certificateName, keyName string) (*x509.Certificate, crypto.PrivateKey, error) {
	pemBytes, err := ioutil.ReadFile(certificateName)
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

	pemBytes, err = ioutil.ReadFile(keyName)
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
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(pemBlock.Bytes)
	default:
		privateKey = nil
		err = fmt.Errorf("unsupported private key type")
	}
	return
}

func saveCertificateAndPrivateKey(certificate *x509.Certificate, certificateName string, privateKey crypto.PrivateKey, keyName string) error {
	certificatePEM := &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}
	certificateBuffer := &bytes.Buffer{}
	pem.Encode(certificateBuffer, certificatePEM)

	privateKeyPEM, err := marshalPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	privateKeyBuffer := &bytes.Buffer{}
	pem.Encode(privateKeyBuffer, privateKeyPEM)

	err = ioutil.WriteFile(certificateName, certificateBuffer.Bytes(), 0640)
	if err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	err = ioutil.WriteFile(keyName, privateKeyBuffer.Bytes(), 0640)
	if err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	return nil
}

func marshalPrivateKey(privateKey interface{}) (*pem.Block, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}, nil
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("marshal ECDSA private key: %w", err)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}, nil
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}
