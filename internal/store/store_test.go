package store

import (
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
