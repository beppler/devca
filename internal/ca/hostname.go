package ca

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

var hostNameProfile = idna.New(
	idna.MapForLookup(),
	idna.VerifyDNSLength(true),
	idna.BidiRule(),
)

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
