package rfc6962

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"strings"
)

type derTLV struct {
	tag   byte
	clazz int
	body  []byte
	full  []byte
}

func iterDER(b []byte) ([]derTLV, bool) {
	var out []derTLV
	for len(b) > 0 {
		tlv, rest, ok := readTLV(b)
		if !ok {
			return nil, false
		}
		out = append(out, tlv)
		b = rest
	}
	return out, true
}

func readTLV(b []byte) (derTLV, []byte, bool) {
	if len(b) < 2 {
		return derTLV{}, nil, false
	}
	tag := b[0]
	clazz := int(tag >> 6)
	l := int(b[1])
	hdr := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			return derTLV{}, nil, false
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[2+i])
		}
		hdr = 2 + n
	}
	if len(b) < hdr+l {
		return derTLV{}, nil, false
	}
	return derTLV{tag: tag, clazz: clazz, body: b[hdr : hdr+l], full: b[:hdr+l]}, b[hdr+l:], true
}

var (
	oidSCTList    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	oidSubjectAlt = asn1.ObjectIdentifier{2, 5, 29, 17}
)

func namesFromTBS(tbs []byte) ([]string, []int64, error) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(tbs, &outer); err != nil {
		return nil, nil, err
	}
	children, ok := iterDER(outer.Bytes)
	if !ok {
		return nil, nil, fmt.Errorf("truncated DER")
	}
	var extRaw []byte
	for _, c := range children {
		if c.clazz == 2 && c.tag&0x1f == 3 && c.tag&0x20 != 0 {
			extRaw = c.body
			break
		}
	}
	if extRaw == nil {
		return nil, nil, nil
	}
	var extSeq asn1.RawValue
	if _, err := asn1.Unmarshal(extRaw, &extSeq); err != nil {
		return nil, nil, err
	}
	exts, ok := iterDER(extSeq.Bytes)
	if !ok {
		return nil, nil, fmt.Errorf("truncated DER")
	}
	var names []string
	var scts []int64
	for _, e := range exts {
		fields, ok := iterDER(e.body)
		if !ok || len(fields) < 2 {
			continue
		}
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(fields[0].full, &oid); err != nil {
			continue
		}
		valField := fields[len(fields)-1]
		switch {
		case oid.Equal(oidSubjectAlt):
			names = parseSAN(valField.body)
		case oid.Equal(oidSCTList):
			scts = parseSCTList(valField.body)
		}
	}
	return names, scts, nil
}

func parseSAN(octets []byte) []string {
	var inner asn1.RawValue
	if _, err := asn1.Unmarshal(octets, &inner); err != nil {
		return nil
	}
	kids, ok := iterDER(inner.Bytes)
	if !ok {
		return nil
	}
	var out []string
	for _, k := range kids {
		if k.clazz == 2 && k.tag&0x20 == 0 && k.tag&0x1f == 2 {
			out = append(out, string(k.body))
		}
	}
	return out
}

func parseSCTList(octets []byte) []int64 {
	// Per RFC 6962 section 3.3, the extension value is already the
	// TLS-encoded SCT list: uint16 total length followed by
	// length-prefixed SCTs. Callers pass the OCTET STRING contents.
	list := octets
	if len(list) < 2 {
		return nil
	}
	total := int(binary.BigEndian.Uint16(list))
	if len(list) < 2+total {
		return nil
	}
	b := list[2 : 2+total]
	var out []int64
	for len(b) >= 2 {
		n := int(binary.BigEndian.Uint16(b))
		b = b[2:]
		if len(b) < n {
			break
		}
		if ts := parseSingleSCT(b[:n]); ts > 0 {
			out = append(out, ts)
		}
		b = b[n:]
	}
	return out
}

func parseSingleSCT(b []byte) int64 {
	if len(b) < 1+32+8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(b[33:41]))
}

func lowerASCII(s string) string {
	return strings.ToLower(s)
}

func trimTrailingDot(s string) string {
	return strings.TrimSuffix(s, ".")
}
