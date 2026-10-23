package main

import (
	"fmt"
	"net"
	"os"

	"github.com/alexflint/go-arg"
	"github.com/earthboundkid/versioninfo/v2"
	"go.beppler.dev.br/devca/internal/ca"
	"go.beppler.dev.br/devca/internal/pemfile"
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
	Init   *initCommand   `arg:"subcommand:init" help:"Initialize Certificate Authority"`
	Issue  *issueCommand  `arg:"subcommand:issue" help:"Issue Certificates"`
	Server *serverCommand `arg:"subcommand:server" help:"Issue Server Certificate (backward compatibility, use 'issue server' instead)"`
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
	Curve    string   `arg:"-c,--curve" default:"p384" help:"Elliptic curve for the authority key (p256, p384 or p521)"`
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

	curve, err := ca.ParseCurve(cmd.Curve)
	if err != nil {
		return err
	}

	networks, err := parseNetworks(cmd.Networks)
	if err != nil {
		return err
	}

	caCert, caKey, err := ca.NewCertificateAuthority(caName, curve, cmd.Domains, networks)
	if err != nil {
		return fmt.Errorf("could not create CA certificate: %w", err)
	}

	err = pemfile.Save(caCert, "ca.crt", caKey, "ca.key")
	if err != nil {
		return fmt.Errorf("could not save CA certificate: %w", err)
	}

	return nil
}

// parseNetworks parses the network constraints given on the command line as
// CIDR blocks.
func parseNetworks(networks []string) ([]*net.IPNet, error) {
	var parsed []*net.IPNet
	for _, network := range networks {
		_, ipNet, err := net.ParseCIDR(network)
		if err != nil {
			return nil, fmt.Errorf("invalid network constraint: %s", network)
		}
		parsed = append(parsed, ipNet)
	}
	return parsed, nil
}

type issueCommand struct {
	Server   *serverCommand   `arg:"subcommand:server" help:"Issue Server Certificate"`
	CodeSign *codeSignCommand `arg:"subcommand:codesign" help:"Issue Code Signing Certificate"`
	CA       *caCommand       `arg:"subcommand:ca" help:"Issue Subordinate Certificate Authority"`
}

func (cmd *issueCommand) Handle() error {
	switch {
	case cmd.Server != nil:
		return cmd.Server.Handle()
	case cmd.CodeSign != nil:
		return cmd.CodeSign.Handle()
	case cmd.CA != nil:
		return cmd.CA.Handle()
	default:
		return fmt.Errorf("missing subcommand")
	}
}

type serverCommand struct {
	HostName  []string `arg:"positional,required" help:"Server host names"`
	IPAddress []string `arg:"-i,--ip,separate" help:"Server IP addresses"`
}

func (cmd *serverCommand) Handle() error {
	caCert, caKey, err := pemfile.Load("ca.crt", "ca.key")
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

	hostCert, hostKey, err := ca.IssueServer(caCert, caKey, hostNames, ipAddresses)
	if err != nil {
		return fmt.Errorf("could not sign server certificate: %w", err)
	}

	baseFileName := ca.FileSafeName(hostNames[0], "server") + "-" + fmt.Sprintf("%x", hostCert.SerialNumber)
	err = pemfile.Save(hostCert, baseFileName+".crt", hostKey, baseFileName+".key")
	if err != nil {
		return fmt.Errorf("could not save server certificate: %w", err)
	}

	return nil
}

type codeSignCommand struct {
	Name         string `arg:"positional,required" help:"Common name of the certificate subject"`
	Country      string `arg:"-c,--country" help:"Two-letter country code"`
	Organization string `arg:"-o,--organization" help:"Organization name"`
}

func (cmd *codeSignCommand) Handle() error {
	caCert, caKey, err := pemfile.Load("ca.crt", "ca.key")
	if err != nil {
		return fmt.Errorf("could not load signer certificate: %w", err)
	}

	cert, key, err := ca.IssueCodeSigning(caCert, caKey, cmd.Name, cmd.Country, cmd.Organization)
	if err != nil {
		return fmt.Errorf("could not sign code signing certificate: %w", err)
	}

	baseFileName := ca.FileSafeName(cert.Subject.CommonName, "codesign") + "-" + fmt.Sprintf("%x", cert.SerialNumber)
	err = pemfile.Save(cert, baseFileName+".crt", key, baseFileName+".key")
	if err != nil {
		return fmt.Errorf("could not save code signing certificate: %w", err)
	}

	return nil
}

type caCommand struct {
	Name     string   `arg:"positional,required" help:"Subordinate certificate authority name"`
	Domains  []string `arg:"-d,--domain,separate" help:"Allowed domains for the authority"`
	Networks []string `arg:"-n,--network,separate" help:"Allowed networks for the authority"`
}

func (cmd *caCommand) Handle() error {
	caCert, caKey, err := pemfile.Load("ca.crt", "ca.key")
	if err != nil {
		return fmt.Errorf("could not load signer certificate: %w", err)
	}

	networks, err := parseNetworks(cmd.Networks)
	if err != nil {
		return err
	}

	cert, key, err := ca.IssueCertificateAuthority(caCert, caKey, cmd.Name, cmd.Domains, networks)
	if err != nil {
		return fmt.Errorf("could not sign certificate authority: %w", err)
	}

	baseFileName := ca.FileSafeName(cert.Subject.CommonName, "ca") + "-" + fmt.Sprintf("%x", cert.SerialNumber)
	err = pemfile.Save(cert, baseFileName+".crt", key, baseFileName+".key")
	if err != nil {
		return fmt.Errorf("could not save certificate authority certificate: %w", err)
	}

	return nil
}
