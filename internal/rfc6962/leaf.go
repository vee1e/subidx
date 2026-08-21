package rfc6962

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	OIDExtensionSCT     = "1.3.6.1.4.1.11129.2.4.2"
	OIDExtensionSubject = "2.5.29.17"
)

type LeafEntry struct {
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

type TimestampedEntry struct {
	Timestamp  int64
	EntryType  uint16
	CertDER    []byte
	TBSCertDER []byte
	IssuerHash []byte
}

type DecodedLeaf struct {
	Timestamp int64
	SCTStamps []int64
	Names     []string
}

func DecodeLeafEntry(e LeafEntry) (*DecodedLeaf, error) {
	b := e.LeafInput
	if len(b) < 2 || b[0] != 0 {
		return nil, fmt.Errorf("unsupported leaf version")
	}
	if b[1] != 0 {
		return nil, fmt.Errorf("not a timestamped entry")
	}
	te, err := decodeTimestampedEntry(b[2:])
	if err != nil {
		return nil, err
	}
	out := &DecodedLeaf{Timestamp: te.Timestamp}
	switch te.EntryType {
	case 0:
		names, scts, err := namesFromCert(te.CertDER)
		if err != nil {
			return nil, err
		}
		out.Names = names
		out.SCTStamps = scts
	case 1:
		names, scts, err := namesFromTBS(te.TBSCertDER)
		if err != nil {
			return nil, err
		}
		out.Names = names
		out.SCTStamps = scts
	default:
		return nil, fmt.Errorf("unknown entry type %d", te.EntryType)
	}
	return out, nil
}

func decodeTimestampedEntry(b []byte) (*TimestampedEntry, error) {
	if len(b) < 10 {
		return nil, fmt.Errorf("truncated timestamped entry")
	}
	ts := int64(binary.BigEndian.Uint64(b[:8]))
	et := binary.BigEndian.Uint16(b[8:10])
	te := &TimestampedEntry{Timestamp: ts, EntryType: et}
	rest := b[10:]
	switch et {
	case 0:
		der, rest2, err := readUint24Labeled(rest)
		if err != nil {
			return nil, err
		}
		te.CertDER = der
		rest = rest2
	case 1:
		if len(rest) < 32 {
			return nil, fmt.Errorf("truncated issuer key hash")
		}
		te.IssuerHash = rest[:32]
		rest = rest[32:]
		der, rest2, err := readUint24Labeled(rest)
		if err != nil {
			return nil, err
		}
		te.TBSCertDER = der
		rest = rest2
	default:
		return nil, fmt.Errorf("unknown signed_entry type %d", et)
	}
	if len(rest) < 2 {
		return nil, fmt.Errorf("truncated extensions length")
	}
	return te, nil
}

func readUint24Labeled(b []byte) ([]byte, []byte, error) {
	if len(b) < 3 {
		return nil, nil, fmt.Errorf("truncated uint24 length")
	}
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	b = b[3:]
	if len(b) < n {
		return nil, nil, fmt.Errorf("truncated labeled data")
	}
	return b[:n], b[n:], nil
}

func namesFromCert(der []byte) ([]string, []int64, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	var scts []int64
	for _, ext := range cert.Extensions {
		if ext.Id.String() == OIDExtensionSCT {
			scts = parseSCTList(ext.Value)
		}
	}
	return dedupeLower(cert.DNSNames), scts, nil
}

func dedupeLower(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = lowerASCII(s)
		s = trimTrailingDot(s)
		s = strings.TrimPrefix(s, "*.")
		if s == "" || hasControlByte(s) {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// hasControlByte rejects control characters early. Hostnames must never
// contain them, and the store uses 0x00 as its key separator, so a NUL byte
// from a hostile certificate would corrupt keys. Full charset validation
// happens in apex.Canonical.
func hasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
