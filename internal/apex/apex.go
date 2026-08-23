// Package apex canonicalizes DNS names (IDNA, wildcards, case) and
// derives the registrable eTLD+1 they belong to using the embedded
// Public Suffix List.
package apex

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var lookupProfile = idna.Lookup

var specialUseSuffixes = []string{
	".local", ".test", ".invalid", ".localhost", ".home.arpa",
}

func Normalize(input string) (string, error) {
	s := strings.TrimSpace(input)
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("empty name")
	}
	if strings.ContainsAny(s, "/\\?#@ ") {
		return "", fmt.Errorf("invalid characters")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return "", fmt.Errorf("invalid characters")
		}
	}
	ascii, err := lookupProfile.ToASCII(s)
	if err != nil {
		return "", err
	}
	s = ascii
	for _, suf := range specialUseSuffixes {
		if s == strings.TrimPrefix(suf, ".") || strings.HasSuffix(s, suf) {
			return "", fmt.Errorf("special-use name")
		}
	}
	return s, nil
}

var ingestProfile = idna.New(idna.MapForLookup())

// Canonical prepares an ingest-side hostname for storage: unicode names are
// mapped to punycode (with case folding) so stored records match what search
// clients ask for. Names the IDNA lookup profile rejects but that are plain
// ASCII with common service characters (e.g. DKIM-style underscores) are
// kept, since they are useful recon data.
func Canonical(host string) (string, bool) {
	s := strings.TrimPrefix(host, "*.")
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return "", false
	}
	if ascii, err := ingestProfile.ToASCII(s); err == nil {
		s = ascii
	} else {
		for i := 0; i < len(s); i++ {
			c := s[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			case c == '.' || c == '-' || c == '_':
			default:
				return "", false
			}
		}
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", false
		}
	}
	return s, true
}

func ValidateApex(normalized string) (string, error) {
	etld1, err := publicsuffix.EffectiveTLDPlusOne(normalized)
	if err != nil {
		return "", fmt.Errorf("not an eTLD+1")
	}
	if etld1 != normalized {
		return "", fmt.Errorf("not an eTLD+1")
	}
	return etld1, nil
}

func ApexOf(host string) (string, bool) {
	a, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return "", false
	}
	return a, true
}
