package ca

import (
	"strings"
	"testing"
)

func TestNormalizeHostName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.Com", "example.com"},
		{"localhost", "localhost"},
		{"*.example.com", "*.example.com"},
		{"bücher.example", "xn--bcher-kva.example"},
		{"*.bücher.example", "*.xn--bcher-kva.example"},
		{"xn--bcher-kva.example", "xn--bcher-kva.example"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeHostName(tt.name)
			if err != nil {
				t.Fatalf("normalizeHostName(%q) error: %v", tt.name, err)
			}
			if got != tt.want {
				t.Errorf("normalizeHostName(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestNormalizeHostNameInvalid(t *testing.T) {
	tests := []string{
		"",
		"*.",
		"example..com",
		strings.Repeat("a", 64) + ".example.com",
		"under_score.example.com",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := normalizeHostName(name)
			if err == nil {
				t.Fatalf("normalizeHostName(%q) = %q, want error", name, got)
			}
			if !strings.Contains(err.Error(), "invalid host name") {
				t.Errorf("error %q does not mention invalid host name", err)
			}
		})
	}
}
