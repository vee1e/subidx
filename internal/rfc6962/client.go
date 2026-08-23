// Package rfc6962 implements the RFC 6962 pieces subidx needs: a CT
// log client with pinned-key signed tree head verification, entry
// decoding, and Merkle inclusion proof checking.
package rfc6962

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type STH struct {
	TreeSize          int64  `json:"tree_size"`
	Timestamp         int64  `json:"timestamp"`
	SHA256RootHash    []byte `json:"sha256_root_hash"`
	TreeHeadSignature []byte `json:"tree_head_signature"`
}

type getEntriesResp struct {
	Entries []LeafEntry `json:"entries"`
}

type Client struct {
	BaseURL string
	HTTP    *http.Client
	pubKey  crypto.PublicKey
	logID   []byte
}

func NewClient(baseURL, keyB64 string) (*Client, error) {
	if keyB64 == "" {
		return nil, fmt.Errorf("missing log key")
	}
	// Log list URLs are joined with "/ct/v1/..." paths below; a trailing
	// slash would produce "//ct/v1/..." and every request would 404.
	baseURL = strings.TrimRight(baseURL, "/")
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("bad log url: %w", err)
	}
	// Endpoints come from externally fetched log lists, so treat them as
	// untrusted input: plain http is only tolerated on loopback (local
	// test servers), and redirects are never followed — a hijacked list
	// source must not be able to aim the tailer at internal hosts.
	if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("log url must be https, got %q", u.Scheme)
	}
	c := &Client{
		BaseURL: baseURL,
		HTTP: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	der, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("bad log key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("bad log key: %w", err)
	}
	c.pubKey = pub
	sum := sha256.Sum256(der)
	c.logID = sum[:]
	return c, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Client) LogID() string {
	return base64.StdEncoding.EncodeToString(c.logID)
}

func (c *Client) ShortID() string {
	if len(c.logID) == 0 {
		return "unknown"
	}
	return fmt.Sprintf("%x", c.logID[:8])
}

func (c *Client) STH(ctx context.Context) (*STH, error) {
	var out STH
	if err := c.getJSON(ctx, "/ct/v1/get-sth", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Entries(ctx context.Context, start, end int64) ([]LeafEntry, error) {
	var out getEntriesResp
	url := fmt.Sprintf("/ct/v1/get-entries?start=%d&end=%d", start, end)
	if err := c.getJSON(ctx, url, &out); err != nil {
		return nil, err
	}
	return out.Entries, nil
}

type InclusionProof struct {
	LeafIndex int64    `json:"leaf_index"`
	AuditPath [][]byte `json:"audit_path"`
}

// ProofByHash fetches get-proof-by-hash for leafHash at the given tree
// size. Verify the result with VerifyInclusion against a signed root.
func (c *Client) ProofByHash(ctx context.Context, leafHash []byte, treeSize int64) (*InclusionProof, error) {
	q := url.Values{}
	q.Set("hash", base64.StdEncoding.EncodeToString(leafHash))
	q.Set("tree_size", strconv.FormatInt(treeSize, 10))
	var out InclusionProof
	if err := c.getJSON(ctx, "/ct/v1/get-proof-by-hash?"+q.Encode(), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) getJSON(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		n := len(body)
		if n > 512 {
			n = 512
		}
		return &HTTPError{Status: resp.StatusCode, Body: body[:n]}
	}
	return json.Unmarshal(body, v)
}

type HTTPError struct {
	Status int
	Body   []byte
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("log http %d: %s", e.Status, e.Body)
}

func (c *Client) VerifySTH(sth *STH) error {
	if c.pubKey == nil {
		return fmt.Errorf("no log key pinned")
	}
	if len(sth.TreeHeadSignature) == 0 {
		return fmt.Errorf("sth has no signature")
	}
	if len(sth.SHA256RootHash) != 32 {
		return fmt.Errorf("sth root hash has %d bytes; want 32", len(sth.SHA256RootHash))
	}
	if sth.TreeSize < 0 {
		return fmt.Errorf("sth tree size %d is negative", sth.TreeSize)
	}
	ds, err := decodeDigitallySigned(sth.TreeHeadSignature)
	if err != nil {
		return err
	}
	input := make([]byte, 0, 2+8+8+32)
	input = append(input, 0, 1)
	input = binary.BigEndian.AppendUint64(input, uint64(sth.Timestamp))
	input = binary.BigEndian.AppendUint64(input, uint64(sth.TreeSize))
	input = append(input, sth.SHA256RootHash...)
	digest := sha256.Sum256(input)
	switch key := c.pubKey.(type) {
	case *ecdsa.PublicKey:
		// RFC 6962 DigitallySigned must be ecdsa_secp256r1_sha256 (4,3).
		if ds.HashAlg != 4 || ds.SigAlg != 3 {
			return fmt.Errorf("sth signature algorithm (%d,%d); want ecdsa+sha256 (4,3)", ds.HashAlg, ds.SigAlg)
		}
		if !ecdsa.VerifyASN1(key, digest[:], ds.Sig) {
			return fmt.Errorf("sth signature verify failed")
		}
		return nil
	case *rsa.PublicKey:
		// rsa_pkcs1_sha256 is (4,1).
		if ds.HashAlg != 4 || ds.SigAlg != 1 {
			return fmt.Errorf("sth signature algorithm (%d,%d); want rsa+sha256 (4,1)", ds.HashAlg, ds.SigAlg)
		}
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], ds.Sig)
	default:
		return fmt.Errorf("unsupported log key type %T", c.pubKey)
	}
}

type digitallySigned struct {
	HashAlg byte
	SigAlg  byte
	Sig     []byte
}

func decodeDigitallySigned(b []byte) (*digitallySigned, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("truncated signature")
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if len(b) < 4+n {
		return nil, fmt.Errorf("truncated signature body")
	}
	return &digitallySigned{HashAlg: b[0], SigAlg: b[1], Sig: b[4 : 4+n]}, nil
}
