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
	s := strings.ToLower(strings.TrimSpace(input))
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
