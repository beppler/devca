package ca

import (
	"net"
	"testing"
)

func TestExcludedNetworks(t *testing.T) {
	tests := []struct {
		name     string
		domains  []string
		networks []*net.IPNet
		want     []string
	}{
		{"unconstrained", nil, nil, nil},
		{"domains only", []string{"example.com"}, nil, []string{"0.0.0.0/0", "::/0"}},
		{"domains and networks", []string{"example.com"}, []*net.IPNet{mustParseCIDR(t, "10.0.0.0/8")}, nil},
		{"networks only", nil, []*net.IPNet{mustParseCIDR(t, "10.0.0.0/8")}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := excludedNetworks(tt.domains, tt.networks)
			if len(got) != len(tt.want) {
				t.Fatalf("excludedNetworks() = %v, want %v", got, tt.want)
			}
			for i, network := range got {
				if network.String() != tt.want[i] {
					t.Errorf("excludedNetworks()[%d] = %v, want %v", i, network, tt.want[i])
				}
			}
		})
	}
}

func TestWithinAnyDomain(t *testing.T) {
	permitted := []string{"example.com", ".internal.dev"}
	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"wwwexample.com", false},
		{"internal.dev", false},
		{"www.internal.dev", true},
		{"example.org", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := withinAnyDomain(permitted, tt.domain); got != tt.want {
			t.Errorf("withinAnyDomain(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestSubnetWithin(t *testing.T) {
	tests := []struct {
		name    string
		subnet  string
		network string
		want    bool
	}{
		{"same", "10.0.0.0/8", "10.0.0.0/8", true},
		{"subnetwork", "10.1.0.0/16", "10.0.0.0/8", true},
		{"outside", "192.168.0.0/16", "10.0.0.0/8", false},
		{"smaller network", "10.0.0.0/16", "10.0.0.0/8", true},
		{"larger network", "10.0.0.0/8", "10.1.0.0/16", false},
		{"partial overlap", "10.0.0.0/15", "10.0.0.0/16", false},
		{"families differ", "10.0.0.0/8", "::/0", false},
		{"ipv6 subnetwork", "fd00::/16", "fd00::/8", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subnet := mustParseCIDR(t, tt.subnet)
			network := mustParseCIDR(t, tt.network)
			if got := subnetWithin(subnet, network); got != tt.want {
				t.Errorf("subnetWithin(%s, %s) = %v, want %v", tt.subnet, tt.network, got, tt.want)
			}
		})
	}
}

func TestNetworksOverlap(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"disjoint", "10.0.0.0/8", "192.168.0.0/16", false},
		{"nested", "10.1.0.0/16", "10.0.0.0/8", true},
		{"reverse nested", "10.0.0.0/8", "10.1.0.0/16", true},
		{"equal", "10.0.0.0/8", "10.0.0.0/8", true},
		{"families differ", "10.0.0.0/8", "fd00::/8", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := mustParseCIDR(t, tt.a)
			b := mustParseCIDR(t, tt.b)
			if got := networksOverlap(a, b); got != tt.want {
				t.Errorf("networksOverlap(%s, %s) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestValidateConstraintsUnconstrainedParent(t *testing.T) {
	caCert, _ := newTestCA(t, nil, nil)

	networks := []*net.IPNet{mustParseCIDR(t, "192.168.0.0/16")}
	if err := validateConstraints(caCert, []string{"other.com"}, networks); err != nil {
		t.Errorf("unconstrained parent: error = %v, want nil", err)
	}
}
