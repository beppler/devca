package ca

import (
	"regexp"
	"strings"
)

var fileUnsafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// FileSafeName turns name into something usable as a file name prefix by
// replacing each run of unsafe characters with "-".
func FileSafeName(name string) string {
	safe := strings.ToLower(strings.Trim(fileUnsafeChars.ReplaceAllString(name, "-"), "-"))
	if safe == "" {
		return "codesign"
	}
	return safe
}
