package main

import (
	"fmt"
	"net"
	"os"

	"github.com/alexflint/go-arg"
	"github.com/beppler/devca/internal/ca"
	"github.com/beppler/devca/internal/pemfile"
	"github.com/earthboundkid/versioninfo/v2"
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

	caCert, caKey, err := ca.NewCertificateAuthority(caName, cmd.Domains, networks)
	if err != nil {
		return fmt.Errorf("could not create CA certificate: %w", err)
	}

	err = pemfile.Save(caCert, "ca.crt", caKey, "ca.key")
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

	baseFileName := hostNames[0] + "-" + fmt.Sprintf("%x", hostCert.SerialNumber)
	err = pemfile.Save(hostCert, baseFileName+".crt", hostKey, baseFileName+".key")
	if err != nil {
		return fmt.Errorf("could not save server certificate: %w", err)
	}

	return nil
}
