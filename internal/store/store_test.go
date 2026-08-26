package store

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/pebble/v2"
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

func TestOnNewHookAndScanAfter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var mu sync.Mutex
	var hooked []Record
	st.OnNew = func(r Record) {
		mu.Lock()
		defer mu.Unlock()
		hooked = append(hooked, r)
	}

	for _, sub := range []string{"s1.x.com", "s2.x.com", "s3.x.com"} {
		if err := st.Ingest(Record{Apex: "x.com", Sub: sub, FirstSeen: 1000, Source: 1}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	if len(hooked) != 3 {
		t.Fatalf("hook fired %d times; want 3", len(hooked))
	}
	for i, r := range hooked {
		if r.Seq == 0 {
			t.Fatalf("hooked[%d].Seq = 0", i)
		}
		if i > 0 && r.Seq <= hooked[i-1].Seq {
			t.Fatalf("seq not monotonic: %d then %d", hooked[i-1].Seq, r.Seq)
		}
	}
	mu.Unlock()

	// Duplicate ingest must not fire the hook (only new names count).
	if err := st.Ingest(Record{Apex: "x.com", Sub: "s1.x.com", FirstSeen: 1000, Source: 1}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	if len(hooked) != 3 {
		t.Fatalf("dup ingest fired hook; %d events", len(hooked))
	}
	mu.Unlock()

	rows0, max0, trunc, err := st.ScanAfter("x.com", 0, 100)
	if err != nil || trunc || len(rows0) != 3 {
		t.Fatalf("ScanAfter base: rows=%d trunc=%v err=%v", len(rows0), trunc, err)
	}
	bySub := map[string]uint64{}
	for _, r := range rows0 {
		bySub[r.Sub] = r.Seq
	}
	if uint64(len(rows0)) > 0 && max0 == 0 {
		t.Fatal("maxSeq = 0 with rows present")
	}

	// Delta after the second-smallest seq leaves exactly the largest.
	cut := bySub["s2.x.com"]
	rows1, max1, _, err := st.ScanAfter("x.com", cut, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows1) != 1 || rows1[0].Sub != "s3.x.com" {
		t.Fatalf("delta rows = %+v", rows1)
	}
	if max1 != max0 {
		t.Fatalf("maxSeq drifted: %d vs %d", max1, max0)
	}

	_, _, truncated, err := st.ScanAfter("x.com", 0, 2)
	if err != nil || !truncated {
		t.Fatalf("limit=2: truncated=%v err=%v", truncated, err)
	}

	empty, emptyMax, _, err := st.ScanAfter("nothere.example", 0, 10)
	if err != nil || len(empty) != 0 || emptyMax != 0 {
		t.Fatalf("unknown apex: rows=%d max=%d err=%v", len(empty), emptyMax, err)
	}
}

func TestTopApproxBounds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, apexName := range []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"} {
		if err := st.Ingest(Record{Apex: apexName, Sub: "s." + apexName, FirstSeen: 1000, Source: 1}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(150 * time.Millisecond)

	exact, err := st.TopApprox(3, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(exact) != 3 {
		t.Fatalf("TopApprox(3, 100) = %d entries; want 3", len(exact))
	}
	bounded, err := st.TopApprox(3, 2)
	if err != nil {
		t.Fatal(err)
	}
	// Only the first two apexes in key order are inspected, so the result
	// must be a subset of them.
	if len(bounded) > 2 {
		t.Fatalf("TopApprox(3, 2) = %d entries; want <= 2", len(bounded))
	}
	for _, ac := range bounded {
		if ac.Apex != "a.example.com" && ac.Apex != "b.example.com" {
			t.Fatalf("bounded result includes %s from outside the scan cap", ac.Apex)
		}
	}
}

func TestTopOrdersByCount(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	counts := map[string]int{
		"a.example.com": 3,
		"b.example.com": 7,
		"c.example.com": 1,
		"d.example.com": 5,
	}
	for apexName, n := range counts {
		for i := int64(0); i < int64(n); i++ {
			if err := st.Ingest(Record{Apex: apexName, Sub: fmt.Sprintf("s%d.%s", i, apexName), FirstSeen: 1000, Source: 1}); err != nil {
				t.Fatal(err)
			}
		}
	}
	time.Sleep(150 * time.Millisecond) // let the async ingest loop settle
	top, err := st.Top(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(top) != 3 {
		t.Fatalf("len(top) = %d; want 3", len(top))
	}
	want := []string{"b.example.com", "d.example.com", "a.example.com"}
	for i, ac := range top {
		if ac.Apex != want[i] {
			t.Fatalf("top[%d] = %s (%d); want %s (%d)", i, ac.Apex, ac.Count, want[i], counts[want[i]])
		}
		if ac.Count != uint64(counts[want[i]]) {
			t.Fatalf("top[%d].Count = %d; want %d", i, ac.Count, counts[want[i]])
		}
	}
}
