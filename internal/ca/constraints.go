package ca

import (
	"crypto/x509"
	"fmt"
	"net"
	"strings"
)

// excludedNetworks returns every IPv4 and IPv6 range when domains are
// constrained but networks are not, so that a domains-only authority cannot
// vouch for any IP address.
func excludedNetworks(domains []string, networks []*net.IPNet) []*net.IPNet {
	if len(domains) > 0 && len(networks) == 0 {
		return []*net.IPNet{
			{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}
	}
	return nil
}

// validateConstraints reports whether the given name constraints can be issued
// by the given certificate authority: RFC 5280 requires that the permitted
// subtrees of a subordinate authority are within the permitted subtrees of its
// parent and outside its excluded subtrees. An authority without constraints
// accepts anything.
func validateConstraints(caCertificate *x509.Certificate, domains []string, networks []*net.IPNet) error {
	for _, domain := range domains {
		if len(caCertificate.PermittedDNSDomains) > 0 && !withinAnyDomain(caCertificate.PermittedDNSDomains, domain) {
			return fmt.Errorf("domain %q is not permitted by the certificate authority", domain)
		}
	}

	for _, network := range networks {
		if len(caCertificate.PermittedIPRanges) > 0 && !withinAnyNetwork(caCertificate.PermittedIPRanges, network) {
			return fmt.Errorf("network %s is not permitted by the certificate authority", network)
		}
		for _, excluded := range caCertificate.ExcludedIPRanges {
			if networksOverlap(network, excluded) {
				return fmt.Errorf("network %s is excluded by the certificate authority", network)
			}
		}
	}

	return nil
}

// withinAnyDomain reports whether domain is within one of the permitted
// domains. A permitted domain of "example.com" matches itself and any
// subdomain; one of ".example.com" matches subdomains only.
func withinAnyDomain(permitted []string, domain string) bool {
	for _, constraint := range permitted {
		if strings.HasPrefix(constraint, ".") {
			if strings.HasSuffix(domain, constraint) {
				return true
			}
			continue
		}
		if domain == constraint || strings.HasSuffix(domain, "."+constraint) {
			return true
		}
	}
	return false
}

// withinAnyNetwork reports whether network is a subnet of one of the permitted
// networks.
func withinAnyNetwork(permitted []*net.IPNet, network *net.IPNet) bool {
	for _, constraint := range permitted {
		if subnetWithin(network, constraint) {
			return true
		}
	}
	return false
}

// subnetWithin reports whether subnet is within network.
func subnetWithin(subnet, network *net.IPNet) bool {
	if !network.Contains(subnet.IP) {
		return false
	}

	subnetBits, subnetTotal := subnet.Mask.Size()
	networkBits, networkTotal := network.Mask.Size()
	return subnetTotal == networkTotal && subnetBits >= networkBits
}

// networksOverlap reports whether the two networks share any address. CIDR
// networks nest or are disjoint, so it is enough to check that one contains
// the network address of the other.
func networksOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}
