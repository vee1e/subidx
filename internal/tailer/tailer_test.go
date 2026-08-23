package tailer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"subidx/internal/loglist"
	"subidx/internal/rfc6962"
	"subidx/internal/store"
)

type fakeLog struct {
	entries   [][]byte
	sthHits   int
	shortRead bool
	tamper    bool
	key       *ecdsa.PrivateKey
}

// Test-side reference RFC 6962 Merkle tree, so the fake log can serve
// roots and audit paths that VerifyInclusion must accept.
func nodeHashT(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

func rootOfT(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		h := sha256.Sum256(nil)
		return h[:]
	}
	if len(leaves) == 1 {
		return rfc6962.LeafHash(leaves[0])
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	return nodeHashT(rootOfT(leaves[:k]), rootOfT(leaves[k:]))
}

func pathOfT(leaves [][]byte, idx int) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	if idx < k {
		return append(pathOfT(leaves[:k], idx), rootOfT(leaves[k:]))
	}
	return append(pathOfT(leaves[k:], idx-k), rootOfT(leaves[:k]))
}

func newFakeLog(t *testing.T) *fakeLog {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeLog{key: key}
}

// keyB64 returns the log's public key in the log list format, and logID its
// RFC 6962 log id (base64 of SHA-256 of the public key DER).
func (f *fakeLog) keyB64(t *testing.T) (keyB64, logID string) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(der), base64.StdEncoding.EncodeToString(sum[:])
}

func (f *fakeLog) signSTH(t *testing.T, ts int64, size int64, root []byte) []byte {
	t.Helper()
	input := make([]byte, 0, 2+8+8+32)
	input = append(input, 0, 1)
	input = binary.BigEndian.AppendUint64(input, uint64(ts))
	input = binary.BigEndian.AppendUint64(input, uint64(size))
	input = append(input, root...)
	digest := sha256.Sum256(input)
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out := []byte{4, 3}
	out = binary.BigEndian.AppendUint16(out, uint16(len(sig)))
	return append(out, sig...)
}

func (f *fakeLog) leafInput(der []byte, ts int64) []byte {
	b := []byte{0, 0}
	b = binary.BigEndian.AppendUint64(b, uint64(ts))
	b = binary.BigEndian.AppendUint16(b, 0)
	n := len(der)
	b = append(b, byte(n>>16), byte(n>>8), byte(n))
	b = append(b, der...)
	return append(b, 0, 0)
}

func (f *fakeLog) serve(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ct/v1/get-sth":
			f.sthHits++
			root := rootOfT(f.entries)
			json.NewEncoder(w).Encode(map[string]any{
				"tree_size":           len(f.entries),
				"timestamp":           time.Now().UnixMilli(),
				"sha256_root_hash":    base64.StdEncoding.EncodeToString(root),
				"tree_head_signature": base64.StdEncoding.EncodeToString(f.signSTH(t, time.Now().UnixMilli(), int64(len(f.entries)), root)),
			})
		case "/ct/v1/get-proof-by-hash":
			hb, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("hash"))
			if err != nil {
				http.Error(w, "bad hash", http.StatusBadRequest)
				return
			}
			ts, _ := strconv.ParseInt(r.URL.Query().Get("tree_size"), 10, 64)
			idx := -1
			for i := 0; i < len(f.entries) && int64(i) < ts; i++ {
				if bytes.Equal(rfc6962.LeafHash(f.entries[i]), hb) {
					idx = i
					break
				}
			}
			if idx < 0 {
				http.Error(w, "hash not found", http.StatusNotFound)
				return
			}
			limited := f.entries
			if int(ts) < len(limited) {
				limited = limited[:ts]
			}
			path := pathOfT(limited, idx)
			enc := make([]string, len(path))
			for i, p := range path {
				enc[i] = base64.StdEncoding.EncodeToString(p)
			}
			json.NewEncoder(w).Encode(map[string]any{"leaf_index": idx, "audit_path": enc})
		case "/ct/v1/get-entries":
			var start, end int64
			fmt.Sscanf(r.URL.RawQuery, "start=%d&end=%d", &start, &end)
			if start < 0 {
				start = 0
			}
			if end >= int64(len(f.entries)) {
				end = int64(len(f.entries)) - 1
			}
			out := []map[string]string{}
			limit := end
			if f.shortRead && start == 0 && end-start > 0 {
				limit = start + (end-start)/2
			}
			for i := start; i <= limit; i++ {
				leaf := f.entries[i]
				if f.tamper {
					// Serve bytes that are not committed by the signed
					// root; every served entry is foreign.
					leaf = append(bytes.Clone(leaf), 0xFF)
				}
				out = append(out, map[string]string{
					"leaf_input": base64.StdEncoding.EncodeToString(leaf),
					"extra_data": "",
				})
			}
			json.NewEncoder(w).Encode(map[string]any{"entries": out})
		default:
			http.NotFound(w, r)
		}
	}))
}

func makeLeafCert(t *testing.T, dns []string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		DNSNames:     dns,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestTailToSearchRoundTrip(t *testing.T) {
	for _, short := range []bool{false, true} {
		name := fmt.Sprintf("shortread=%v", short)
		t.Run(name, func(t *testing.T) {
			fl := newFakeLog(t)
			fl.shortRead = short
			keyB64, logID := fl.keyB64(t)
			ts1 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
			ts2 := time.Date(2021, 6, 15, 12, 0, 0, 0, time.UTC).UnixMilli()
			c1 := makeLeafCert(t, []string{"roundtrip.example.com", "www.roundtrip.example.com"})
			c2 := makeLeafCert(t, []string{"mail.roundtrip.example.com"})
			fl.entries = [][]byte{fl.leafInput(c1, ts1), fl.leafInput(c2, ts2)}
			srv := fl.serve(t)
			defer srv.Close()

			st, err := store.Open(filepath.Join(t.TempDir(), "db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()

			tr := &Tailer{Store: st, Interval: time.Millisecond, Window: 1}
			logs := []loglist.Log{{
				LogID: logID,
				Key:   keyB64,
				URL:   srv.URL,
				State: map[string]loglist.StateDetail{"usable": {}},
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tr.Sync(ctx, logs)

			deadline := time.Now().Add(10 * time.Second)
			for {
				res, err := st.Scan("example.com", 0)
				if err == nil && len(res) == 3 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("index never filled: %d results, err %v", len(res), err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			res, _ := st.Scan("example.com", 0)
			want := map[string]int64{
				"roundtrip.example.com":      ts1,
				"www.roundtrip.example.com":  ts1,
				"mail.roundtrip.example.com": ts2,
			}
			for _, r := range res {
				if want[r.Sub] != r.FirstSeen {
					t.Errorf("%s first_seen = %d, want %d", r.Sub, r.FirstSeen, want[r.Sub])
				}
			}
			if res[0].Sub != "roundtrip.example.com" || res[2].Sub != "mail.roundtrip.example.com" {
				t.Errorf("insertion order wrong: %+v", res)
			}
			wm, err := st.Watermark(logID)
			if err != nil || wm != 2 {
				t.Errorf("watermark = %d, %v", wm, err)
			}
		})
	}
}

func TestSTHRegressionIgnored(t *testing.T) {
	fl := newFakeLog(t)
	keyB64, logID := fl.keyB64(t)
	der := makeLeafCert(t, []string{"reg.example.com"})
	fl.entries = [][]byte{fl.leafInput(der, 1000)}
	srv := fl.serve(t)
	defer srv.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetWatermarkSync(logID, 5); err != nil {
		t.Fatal(err)
	}
	tr := &Tailer{Store: st, Interval: time.Millisecond}
	tr.Sync(context.Background(), []loglist.Log{{
		LogID: logID,
		Key:   keyB64,
		URL:   srv.URL,
		State: map[string]loglist.StateDetail{"usable": {}},
	}})
	time.Sleep(50 * time.Millisecond)
	wm, _ := st.Watermark(logID)
	if wm < 5 {
		t.Errorf("watermark rewound to %d", wm)
	}
}

func TestWatermarkErrorSkipsLog(t *testing.T) {
	fl := newFakeLog(t)
	keyB64, logID := fl.keyB64(t)
	der := makeLeafCert(t, []string{"wmfail.example.com"})
	fl.entries = [][]byte{fl.leafInput(der, 1000)}
	srv := fl.serve(t)
	defer srv.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	// A closed store makes Watermark fail, as it would on IO trouble or
	// corruption. The tailer must skip the log, not assume watermark 0
	// and re-drain it from the beginning.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	tr := &Tailer{Store: st, Interval: time.Millisecond}
	tr.Sync(context.Background(), []loglist.Log{{
		LogID: logID,
		Key:   keyB64,
		URL:   srv.URL,
		State: map[string]loglist.StateDetail{"usable": {}},
	}})
	tr.Wait()
	if fl.sthHits != 0 {
		t.Fatalf("tailer contacted log %d times despite watermark read failure", fl.sthHits)
	}
}

func TestTamperedEntriesRejected(t *testing.T) {
	fl := newFakeLog(t)
	fl.tamper = true
	keyB64, logID := fl.keyB64(t)
	der := makeLeafCert(t, []string{"evil.example.com"})
	fl.entries = [][]byte{fl.leafInput(der, 1000)}
	srv := fl.serve(t)
	defer srv.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx, cancel := context.WithCancel(context.Background())
	tr := &Tailer{Store: st, Interval: time.Millisecond, Window: 1}
	tr.Sync(ctx, []loglist.Log{{
		LogID: logID,
		Key:   keyB64,
		URL:   srv.URL,
		State: map[string]loglist.StateDetail{"usable": {}},
	}})
	// Several poll cycles with every served entry outside the signed
	// tree: nothing may be ingested and the watermark must not move.
	time.Sleep(300 * time.Millisecond)
	cancel()
	tr.Wait()

	res, err := st.Scan("example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 {
		t.Fatalf("tampered entries ingested: %d records", len(res))
	}
	wm, err := st.Watermark(logID)
	if err != nil || wm != 0 {
		t.Fatalf("watermark = %d, %v; want 0 — tampered batches must not advance it", wm, err)
	}
}
