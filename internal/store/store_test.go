package store

import (
	"github.com/cockroachdb/pebble/v2"
	"path/filepath"
	"testing"
	"time"
)

func TestWatermarkAtomicWithRecords(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Ingest(Record{Apex: "example.com", Sub: "a.example.com", FirstSeen: 1000, Source: 1}); err != nil {
		t.Fatal(err)
	}
	if err := st.AdvanceWatermark("log1", 42); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	wm, err := st2.Watermark("log1")
	if err != nil || wm != 42 {
		t.Fatalf("watermark = %d, %v; want 42", wm, err)
	}
	total, err := st2.Total()
	if err != nil || total != 1 {
		t.Fatalf("total = %d, %v; want 1", total, err)
	}

	if err := st2.AdvanceWatermark("log1", 100); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		wm, err = st2.Watermark("log1")
		if err == nil && wm == 100 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("watermark never advanced: %d, %v", wm, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := st2.AdvanceWatermark("log1", 50); err != nil {
		t.Fatal(err)
	}
	st2.Close()
	st3, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st3.Close()
	if wm, _ := st3.Watermark("log1"); wm != 100 {
		t.Fatalf("watermark rewound: %d, want 100", wm)
	}
}

func TestRecount(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, r := range []Record{
		{Apex: "example.com", Sub: "a.example.com", FirstSeen: 1, Source: 1},
		{Apex: "example.com", Sub: "b.example.com", FirstSeen: 2, Source: 1},
		{Apex: "other.com", Sub: "x.other.com", FirstSeen: 3, Source: 1},
	} {
		if err := st.Ingest(r); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	total, err := st.Recount()
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("recount total = %d, want 3", total)
	}
	if n, _ := st.Count("example.com"); n != 2 {
		t.Errorf("count(example.com) = %d, want 2", n)
	}
	// Ingestion must keep working with correct counters after a recount.
	if err := st.Ingest(Record{Apex: "example.com", Sub: "c.example.com", FirstSeen: 4, Source: 1}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if got, _ := st.Total(); got != 4 {
		t.Errorf("total after recount+ingest = %d, want 4", got)
	}
}

func TestCorruptValuesDoNotPanic(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Ingest(Record{Apex: "example.com", Sub: "a.example.com", FirstSeen: 1, Source: 1}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	st.db.Set([]byte("example.com\x00junk"), []byte{1, 2, 3}, nil)
	st.db.Set(metaKey("total"), []byte{9}, pebble.Sync)
	res, err := st.Scan("example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("scan = %d results, want 1", len(res))
	}
	if _, err := st.Total(); err == nil {
		t.Error("corrupt meta accepted")
	}
	st.Close()
}
