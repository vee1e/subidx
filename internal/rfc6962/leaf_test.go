package rfc6962

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

var asn1OIDSCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

func asn1MarshalOctetString(b []byte) ([]byte, error) {
	return asn1.Marshal(b)
}

func makeCert(t *testing.T, dns []string) *x509.Certificate {
	return makeCertWithExtra(t, dns, pkix.Extension{})
}

func makeCertWithExtra(t *testing.T, dns []string, extra pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var extras []pkix.Extension
	if extra.Id.String() != "" {
		extras = append(extras, extra)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "test"},
		DNSNames:        dns,
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: extras,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func uint24(n int) []byte {
	return []byte{byte(n >> 16), byte(n >> 8), byte(n)}
}

func buildLeaf(entryType uint16, signedEntry []byte, ts int64) []byte {
	b := []byte{0, 0}
	b = binary.BigEndian.AppendUint64(b, uint64(ts))
	b = binary.BigEndian.AppendUint16(b, entryType)
	b = append(b, signedEntry...)
	b = append(b, 0, 0)
	return b
}

func TestDecodeX509Entry(t *testing.T) {
	cert := makeCert(t, []string{"WWW.Example.com", "mail.example.com"})
	signed := append(uint24(len(cert.Raw)), cert.Raw...)
	leaf, err := DecodeLeafEntry(LeafEntry{LeafInput: buildLeaf(0, signed, 1234567890123)})
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Timestamp != 1234567890123 {
		t.Errorf("timestamp = %d", leaf.Timestamp)
	}
	want := map[string]bool{"www.example.com": true, "mail.example.com": true}
	if len(leaf.Names) != len(want) {
		t.Fatalf("names = %v", leaf.Names)
	}
	for _, n := range leaf.Names {
		if !want[n] {
			t.Errorf("unexpected name %q", n)
		}
	}
}

func TestWildcardCollapsed(t *testing.T) {
	cert := makeCert(t, []string{"*.wild.example.com"})
	signed := append(uint24(len(cert.Raw)), cert.Raw...)
	leaf, err := DecodeLeafEntry(LeafEntry{LeafInput: buildLeaf(0, signed, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Names) != 1 || leaf.Names[0] != "wild.example.com" {
		t.Errorf("names = %v, want [wild.example.com]", leaf.Names)
	}
}

func TestDecodePrecertEntry(t *testing.T) {
	cert := makeCert(t, []string{"prec.example.com"})
	hash := make([]byte, 32)
	signed := append(append(hash, uint24(len(cert.RawTBSCertificate))...), cert.RawTBSCertificate...)
	leaf, err := DecodeLeafEntry(LeafEntry{LeafInput: buildLeaf(1, signed, 42)})
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Names) != 1 || leaf.Names[0] != "prec.example.com" {
		t.Errorf("names = %v", leaf.Names)
	}
}

func buildSCTListDER(t *testing.T, stamps ...int64) []byte {
	t.Helper()
	var list []byte
	list = binary.BigEndian.AppendUint16(list, 0)
	base := len(list)
	for _, ts := range stamps {
		var sct []byte
		sct = append(sct, 0)
		sct = append(sct, make([]byte, 32)...)
		sct = binary.BigEndian.AppendUint64(sct, uint64(ts))
		sct = binary.BigEndian.AppendUint16(sct, 0)
		sig := make([]byte, 8)
		sct = binary.BigEndian.AppendUint16(sct, uint16(len(sig)))
		sct = append(sct, sig...)
		list = binary.BigEndian.AppendUint16(list, uint16(len(sct)))
		list = append(list, sct...)
	}
	binary.BigEndian.PutUint16(list[base-2:], uint16(len(list)-base))
	der, err := asn1MarshalOctetString(list)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestEmbeddedSCTTimestamps(t *testing.T) {
	stamps := []int64{111111111, 222222222}
	extBytes := buildSCTListDER(t, stamps...)
	cert := makeCertWithExtra(t, []string{"sct.example.com"}, pkix.Extension{
		Id:    asn1OIDSCT,
		Value: extBytes,
	})
	names, got, err := namesFromCert(cert.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "sct.example.com" {
		t.Errorf("names = %v", names)
	}
	if len(got) != len(stamps) {
		t.Fatalf("scts = %v", got)
	}
	for i, s := range stamps {
		if got[i] != s {
			t.Errorf("sct[%d] = %d, want %d", i, got[i], s)
		}
	}
}

func TestDecodeGarbage(t *testing.T) {
	if _, err := DecodeLeafEntry(LeafEntry{LeafInput: []byte{1}}); err == nil {
		t.Error("garbage accepted")
	}
	if _, err := DecodeLeafEntry(LeafEntry{LeafInput: []byte{0, 5}}); err == nil {
		t.Error("wrong leaf type accepted")
	}
}

func TestControlBytesRejected(t *testing.T) {
	cert := makeCert(t, []string{"ab\x00cd.example.com", "ok.example.com"})
	signed := append(uint24(len(cert.Raw)), cert.Raw...)
	leaf, err := DecodeLeafEntry(LeafEntry{LeafInput: buildLeaf(0, signed, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Names) != 1 || leaf.Names[0] != "ok.example.com" {
		t.Errorf("names = %q, want [ok.example.com]", leaf.Names)
	}
}
