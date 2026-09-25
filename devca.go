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
	"net"
	"os"
	"strings"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/earthboundkid/versioninfo/v2"
	"golang.org/x/net/idna"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func main() {
	var command rootCommand

	parser := arg.MustParse(&command)

	switch parser.Subcommand().(type) {
	case nil, *issueCommand:
		parser.WriteHelpForSubcommand(os.Stdout, parser.SubcommandNames()...)
		os.Exit(-1)
	}

	err := command.Handle()

	if err != nil {
		parser.FailSubcommand(err.Error(), parser.SubcommandNames()...)
	}
}

type rootCommand struct {
	Init  *initCommand  `arg:"subcommand:init" help:"Initialize Certificate Authority"`
	Issue *issueCommand `arg:"subcommand:issue" help:"Issue Certificates"`
}

func (cmd *rootCommand) Description() string {
	return "Manages Certificate Authorities and Certificates for development."
}

func (cmd *rootCommand) Epilogue() string {
	return "For more information visit https://github.com/beppler/devca"
}

func (cmd *rootCommand) Version() string {
	return versioninfo.Short()
}

func (cmd *rootCommand) Handle() error {
	switch {
	case cmd.Init != nil:
		return cmd.Init.Handle()
	case cmd.Issue != nil:
		return cmd.Issue.Handle()
	default:
		return nil
	}
}

type initCommand struct {
	Name     string   `arg:"positional" help:"Certificate authority name"`
	Force    bool     `arg:"-f,--force" help:"Allow overwrite of the authority certificate"`
	Domains  []string `arg:"-d,--domain,separate" help:"Allowed domains for the authority"`
	Networks []string `arg:"-n,--network,separate" help:"Allowed networks for the authority"`
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
			caName = cases.Title(language.Und, cases.NoLower).String(hostname) + " Development CA"
		}
	}

	var networks []*net.IPNet
	for _, network := range cmd.Networks {
		_, ipNet, err := net.ParseCIDR(network)
		if err != nil {
			return fmt.Errorf("invalid network constraint: %s", network)
		}
		networks = append(networks, ipNet)
	}

	caCert, caKey, err := createCertificateAuthority(caName, cmd.Domains, networks)
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

type issueCommand struct {
	Server *serverCommand `arg:"subcommand:server" help:"Issue Server Certificate"`
}

func (cmd *issueCommand) Handle() error {
	switch {
	case cmd.Server != nil:
		return cmd.Server.Handle()
	default:
		return fmt.Errorf("missing subcommand")
	}
}

type serverCommand struct {
	HostName  []string `arg:"positional,required" help:"Server host names"`
	IPAddress []string `arg:"-i,--ip,separate" help:"Server IP addresses"`
}

func (cmd *serverCommand) Handle() error {
	caCert, caKey, err := loadCertificateAndPrivateKey("ca.crt", "ca.key")
	if err != nil {
		return fmt.Errorf("could not load signer certificate: %w", err)
	}

	hostNames := cmd.HostName

	var ipAddresses []net.IP
	for _, ipAddress := range cmd.IPAddress {
		parsed := net.ParseIP(ipAddress)
		if parsed == nil {
			return fmt.Errorf("invalid IP address: %s", ipAddress)
		}
		ipAddresses = append(ipAddresses, parsed)
	}

	hostCert, hostKey, err := signServerCertificate(caCert, caKey, hostNames, ipAddresses)
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

func createCertificateAuthority(authorityName string, domains []string, networks []*net.IPNet) (*x509.Certificate, crypto.PrivateKey, error) {
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

func signServerCertificate(caCertificate *x509.Certificate, caPrivateKey crypto.PrivateKey, hostNames []string, ips []net.IP) (*x509.Certificate, crypto.PrivateKey, error) {
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
		return nil, nil, fmt.Errorf("create host certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse host certificate: %w", err)
	}

	return cert, privateKey, nil
}

var hostNameProfile = idna.New(
	idna.MapForLookup(),
	idna.VerifyDNSLength(true),
	idna.BidiRule(),
)

// normalizeHostName validates a host name and converts it to its lowercase
// ASCII form. A leading "*." wildcard label is allowed and preserved.
func normalizeHostName(name string) (string, error) {
	prefix, rest := "", name
	if after, ok := strings.CutPrefix(name, "*."); ok {
		prefix, rest = "*.", after
	}

	ascii, err := hostNameProfile.ToASCII(rest)
	if err != nil {
		return "", fmt.Errorf("invalid host name %q: %w", name, err)
	}

	return prefix + ascii, nil
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
