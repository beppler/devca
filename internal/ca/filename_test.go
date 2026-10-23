package ca

import "testing"

func TestFileSafeName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"Developer", "developer"},
		{"ACME Corp / Dev", "acme-corp-dev"},
		{"Bücher", "b-cher"},
		{"my_cert.v1", "my_cert.v1"},
		{"///", "codesign"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FileSafeName(tt.name); got != tt.want {
				t.Errorf("FileSafeName(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}
