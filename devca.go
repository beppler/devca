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
	"math/big"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/alexflint/go-arg"
)

func main() {
	var command rootCommand

	parser := arg.MustParse(&command)

	if parser.Subcommand() == nil {
		parser.WriteHelp(os.Stdout)
		os.Exit(-1)
	}

	err := command.Handle()

	if err != nil {
		parser.FailSubcommand(err.Error(), parser.SubcommandNames()...)
	}
}

type rootCommand struct {
	Init   *initCommand   `arg:"subcommand:init" help:"Initialize Certificate Authority"`
	Server *serverCommand `arg:"subcommand:server" help:"Sign Server Certificate"`
}

func (cmd *rootCommand) Description() string {
	return "Manages Certificate Authorities and Certificates for development."
}

func (cmd *rootCommand) Handle() error {
	switch {
	case cmd.Init != nil:
		return cmd.Init.Handle()
	case cmd.Server != nil:
		return cmd.Server.Handle()
	default:
		return nil
	}
}

type initCommand struct {
	Name  string `arg:"positional" help:"certificate authority name"`
	Force bool   `arg:"-f,--force" help:"allow overwrite of the authority certificate"`
}

func (cmd *initCommand) Handle() error {
	if !cmd.Force {
		if _, err := os.Stat("ca.crt"); err == nil {
			return fmt.Errorf("certificate authority already exist")
		}
	}

	caName := "Local Development CA"
	if cmd.Name != "" {
		caName = cmd.Name
	} else {
		hostname, err := os.Hostname()
		if err == nil && hostname != "" {
			caName = strings.ToUpper(hostname) + " Development CA"
		}
	}

	caCert, caKey, err := createCertificateAuthority(caName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = saveCertificateAndPrivateKey(caCert, "ca.crt", caKey, "ca.key")
	if err != nil {
		return fmt.Errorf("could not save CA certificate: %w", err)
	}

	return nil
}

type serverCommand struct {
	HostName []string `arg:"positional,required" help:"server host names"`
}

func (cmd *serverCommand) Handle() error {
	caCert, caKey, err := loadCertificateAndPrivateKey("ca.crt", "ca.key")
	if err != nil {
		return fmt.Errorf("could not load signer certificate: %w", err)
	}

	hostNames := cmd.HostName

	hostCert, hostKey, err := signHostCertificate(caCert, caKey, hostNames)
	if err != nil {
		return fmt.Errorf("could not sign server certificate: %w", err)
	}

	baseFileName := hostNames[0] + "-" + fmt.Sprintf("%x", hostCert.SerialNumber)
	err = saveCertificateAndPrivateKey(hostCert, baseFileName+".crt", hostKey, baseFileName+".key")
	if err != nil {
		return fmt.Errorf("could not save server certificate: %w", err)
	}

	return nil
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

	serialNumber := big.NewInt(notBefore.Unix())

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

func loadCertificateAndPrivateKey(certificateFileName, keyFileName string) (*x509.Certificate, crypto.PrivateKey, error) {
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

func saveCertificateAndPrivateKey(certificate *x509.Certificate, certificateFileName string, privateKey crypto.PrivateKey, keyFileName string) error {
	certificatePEM := &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}
	certificateBuffer := &bytes.Buffer{}
	pem.Encode(certificateBuffer, certificatePEM)

	privateKeyPEM, err := marshalPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	privateKeyBuffer := &bytes.Buffer{}
	pem.Encode(privateKeyBuffer, privateKeyPEM)

	err = os.WriteFile(certificateFileName, certificateBuffer.Bytes(), 0640)
	if err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	err = os.WriteFile(keyFileName, privateKeyBuffer.Bytes(), 0640)
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
