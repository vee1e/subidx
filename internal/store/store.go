package store

import (
	"container/heap"
	"encoding/binary"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/cockroachdb/pebble/v2"
)

type Record struct {
	Apex      string
	Sub       string
	FirstSeen int64
	Source    byte
}

type Result struct {
	Sub       string
	FirstSeen int64
	Seq       uint64
}

type ApexCount struct {
	Apex  string
	Count uint64
}

const (
	pfxMeta  byte = 0xff
	pfxCount byte = 0xfe
)

var errStoreClosed = fmt.Errorf("store closed")

type Store struct {
	db     *pebble.DB
	ch     chan ingestOp
	done   chan struct{}
	seq    uint64
	mu     sync.Mutex
	closed bool

	pendingRecords map[string]*recState
	pendingCounts  map[string]uint64
	pendingWM      map[string]int64
	wmHigh         map[string]int64
	pendingTotal   uint64
	totalBase      uint64
}

type ingestOp struct {
	rec     *Record
	logID   string
	wm      int64
	recount chan recountResult
}

type recountResult struct {
	total uint64
	err   error
}

func Open(dir string) (*Store, error) {
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		return nil, err
	}
	s := &Store{
		db:             db,
		ch:             make(chan ingestOp, 4096),
		done:           make(chan struct{}),
		pendingRecords: make(map[string]*recState),
		pendingCounts:  make(map[string]uint64),
		pendingWM:      make(map[string]int64),
		wmHigh:         make(map[string]int64),
	}
	if v, err := s.getMeta("seq"); err == nil {
		s.seq = v
	}
	if v, err := s.getMeta("total"); err == nil {
		s.totalBase = v
	}
	go s.ingestLoop()
	return s, nil
}

func (s *Store) ingestLoop() {
	defer close(s.done)
	batch := s.db.NewBatch()
	pending := 0
	defer batch.Close()
	flush := func() error {
		if batch.Count() == 0 && len(s.pendingWM) == 0 {
			return nil
		}
		var seqBuf [8]byte
		binary.BigEndian.PutUint64(seqBuf[:], s.seq)
		if err := batch.Set(metaKey("seq"), seqBuf[:], nil); err != nil {
			return err
		}
		var wmBuf [8]byte
		for id, n := range s.pendingWM {
			binary.BigEndian.PutUint64(wmBuf[:], uint64(n))
			if err := batch.Set(metaKey("wm/"+id), wmBuf[:], nil); err != nil {
				return err
			}
		}
		if err := batch.Commit(pebble.Sync); err != nil {
			return err
		}
		s.pendingRecords = make(map[string]*recState)
		s.pendingCounts = make(map[string]uint64)
		s.pendingWM = make(map[string]int64)
		s.pendingTotal = 0
		pending = 0
		batch.Reset()
		return nil
	}
	for {
		select {
		case op, ok := <-s.ch:
			if !ok {
				if err := flush(); err != nil {
					log.Printf("store final flush: %v", err)
				}
				return
			}
			if op.rec == nil && op.recount == nil {
				if cur, ok := s.wmHigh[op.logID]; !ok || op.wm > cur {
					s.wmHigh[op.logID] = op.wm
					s.pendingWM[op.logID] = op.wm
				}
				continue
			}
			if op.recount != nil {
				total, err := s.recountInLoop(flush, batch)
				op.recount <- recountResult{total: total, err: err}
				continue
			}
			if err := s.apply(batch, *op.rec); err != nil {
				log.Printf("store apply %s/%s: %v", op.rec.Apex, op.rec.Sub, err)
				continue
			}
			s.seq++
			pending++
			if pending >= 512 {
				if err := flush(); err != nil {
					log.Printf("store flush: %v", err)
				}
				pending = 0
			}
		case <-time.After(20 * time.Millisecond):
			if pending > 0 || len(s.pendingWM) > 0 {
				if err := flush(); err != nil {
					log.Printf("store flush: %v", err)
				}
				pending = 0
			}
		}
	}
}

type recState struct {
	firstSeen int64
	source    byte
	seq       uint64
}

func (s *Store) apply(batch *pebble.Batch, r Record) error {
	rkBytes := recordKey(r.Apex, r.Sub)
	rk := string(rkBytes)
	st, known := s.pendingRecords[rk]
	if !known {
		existing, closer, err := s.db.Get(rkBytes)
		if err != nil && err != pebble.ErrNotFound {
			return err
		}
		if err == pebble.ErrNotFound {
			st = nil
		} else {
			if len(existing) < 17 {
				closer.Close()
				st = nil
			} else {
				st = &recState{
					firstSeen: int64(binary.BigEndian.Uint64(existing[:8])),
					source:    existing[8],
					seq:       binary.BigEndian.Uint64(existing[9:17]),
				}
				closer.Close()
			}
		}
	}
	if st == nil {
		ns := &recState{firstSeen: r.FirstSeen, source: r.Source, seq: s.seq + 1}
		s.pendingRecords[rk] = ns
		if err := batch.Set(rkBytes, encodeValue(ns.firstSeen, ns.source, ns.seq), nil); err != nil {
			return err
		}
		cn := s.pendingCount(r.Apex)
		var cntBuf [8]byte
		binary.BigEndian.PutUint64(cntBuf[:], cn+1)
		s.pendingCounts[r.Apex] = cn + 1
		if err := batch.Set(countKey(r.Apex), cntBuf[:], nil); err != nil {
			return err
		}
		s.pendingTotal++
		var totBuf [8]byte
		binary.BigEndian.PutUint64(totBuf[:], s.totalBase+s.pendingTotal)
		if err := batch.Set(totalKey(), totBuf[:], nil); err != nil {
			return err
		}
		return nil
	}
	s.pendingRecords[rk] = st
	if st.firstSeen <= r.FirstSeen {
		return nil
	}
	val := encodeValue(r.FirstSeen, st.source, st.seq)
	return batch.Set(rkBytes, val, nil)
}

func (s *Store) pendingCount(apex string) uint64 {
	if n, ok := s.pendingCounts[apex]; ok {
		return n
	}
	v, err := s.getRaw(countKey(apex))
	if err != nil || v == nil {
		s.pendingCounts[apex] = 0
		return 0
	}
	n, ok := beUint64(v)
	if !ok {
		s.pendingCounts[apex] = 0
		return 0
	}
	s.pendingCounts[apex] = n
	return n
}

func (s *Store) Ingest(r Record) error {
	return s.sendOp(ingestOp{rec: &r})
}

// AdvanceWatermark records a new high-water mark for a log. It is persisted in
// the same atomic batch as the records ingested before it, so a crash can
// never persist the marker without the data it covers (or vice versa).
func (s *Store) AdvanceWatermark(logID string, n int64) error {
	return s.sendOp(ingestOp{logID: logID, wm: n})
}

// DefaultScanLimit caps how many results Scan will buffer for a single
// query. Popular apexes can have millions of records; without a cap one
// request can exhaust memory.
const DefaultScanLimit = 100000

type resultHeap []Result

func (h resultHeap) Len() int           { return len(h) }
func (h resultHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h resultHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *resultHeap) Push(x any)        { *h = append(*h, x.(Result)) }
func (h *resultHeap) Pop() any          { old := *h; n := len(old); x := old[n-1]; *h = old[:n-1]; return x }

func (s *Store) Scan(apex string, limit int) ([]Result, error) {
	if limit <= 0 {
		limit = DefaultScanLimit
	}
	lo := []byte(recordKey(apex, ""))
	hi := make([]byte, len(apex)+1)
	copy(hi, apex)
	hi[len(apex)] = 0x01
	it, err := s.db.NewIter(&pebble.IterOptions{LowerBound: lo, UpperBound: hi})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	h := &resultHeap{}
	for ok := it.First(); ok; ok = it.Next() {
		v := it.Value()
		if len(v) < 17 {
			continue
		}
		r := Result{
			Sub:       string(it.Key()[len(lo):]),
			FirstSeen: int64(binary.BigEndian.Uint64(v[:8])),
			Seq:       binary.BigEndian.Uint64(v[9:17]),
		}
		if h.Len() < limit {
			heap.Push(h, r)
		} else if r.Seq > (*h)[0].Seq {
			(*h)[0] = r
			heap.Fix(h, 0)
		}
	}
	out := make([]Result, h.Len())
	for i := range out {
		out[i] = heap.Pop(h).(Result)
	}
	return out, it.Error()
}

func (s *Store) Count(apex string) (uint64, error) {
	v, err := s.getRaw(countKey(apex))
	if err != nil {
		return 0, err
	}
	if v == nil {
		return 0, nil
	}
	n, ok := beUint64(v)
	if !ok {
		return 0, fmt.Errorf("corrupt count value for %s", apex)
	}
	return n, nil
}

func (s *Store) Total() (uint64, error) {
	return s.getMeta("total")
}

func (s *Store) Top(n int) ([]ApexCount, error) {
	lo := []byte{pfxCount}
	hi := []byte{pfxCount + 1}
	it, err := s.db.NewIter(&pebble.IterOptions{LowerBound: lo, UpperBound: hi})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	all := make([]ApexCount, 0, 1024)
	for ok := it.First(); ok; ok = it.Next() {
		n, ok := beUint64(it.Value())
		if !ok {
			continue
		}
		all = append(all, ApexCount{Apex: string(it.Key()[1:]), Count: n})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Count > all[j].Count })
	if len(all) > n {
		all = all[:n]
	}
	return all, it.Error()
}

func (s *Store) Watermark(logID string) (int64, error) {
	v, err := s.getMeta("wm/" + logID)
	return int64(v), err
}

func (s *Store) SetWatermarkSync(logID string, n int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errStoreClosed
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(n))
	return s.db.Set(metaKey("wm/"+logID), buf[:], pebble.Sync)
}

func (s *Store) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	close(s.ch)
	<-s.done
	return s.db.Close()
}

// Recount rebuilds per-apex counters and the total from a full record scan.
// It runs inside the ingest loop so counter state is never touched from two
// goroutines; the pebble file lock keeps other processes out meanwhile.
func (s *Store) Recount() (uint64, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, errStoreClosed
	}
	s.mu.Unlock()
	ch := make(chan recountResult, 1)
	if err := s.sendOp(ingestOp{recount: ch}); err != nil {
		return 0, err
	}
	r := <-ch
	return r.total, r.err
}

func (s *Store) sendOp(op ingestOp) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errStoreClosed
	}
	s.ch <- op
	return nil
}

func (s *Store) recountInLoop(flush func() error, batch *pebble.Batch) (uint64, error) {
	if err := flush(); err != nil {
		return 0, err
	}
	lo := []byte{0x00}
	hi := []byte{pfxCount}
	it, err := s.db.NewIter(&pebble.IterOptions{LowerBound: lo, UpperBound: hi})
	if err != nil {
		return 0, err
	}
	counts := make(map[string]uint64)
	var total uint64
	for ok := it.First(); ok; ok = it.Next() {
		k := it.Key()
		sep := -1
		for i, b := range k {
			if b == 0x00 {
				sep = i
				break
			}
		}
		if sep < 0 {
			continue
		}
		counts[string(k[:sep])]++
		total++
	}
	if err := it.Close(); err != nil {
		return 0, err
	}
	rcBatch := s.db.NewBatch()
	defer rcBatch.Close()
	for apex, n := range counts {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], n)
		if err := rcBatch.Set(countKey(apex), buf[:], nil); err != nil {
			return 0, err
		}
		if rcBatch.Count() >= 4096 {
			if err := rcBatch.Commit(pebble.Sync); err != nil {
				return 0, err
			}
			rcBatch.Reset()
		}
	}
	var totBuf [8]byte
	binary.BigEndian.PutUint64(totBuf[:], total)
	if err := rcBatch.Set(totalKey(), totBuf[:], nil); err != nil {
		return 0, err
	}
	if err := rcBatch.Commit(pebble.Sync); err != nil {
		return 0, err
	}
	s.totalBase = total
	s.pendingTotal = 0
	s.pendingCounts = make(map[string]uint64)
	s.pendingRecords = make(map[string]*recState)
	batch.Reset()
	return total, nil
}

func (s *Store) getRaw(k []byte) ([]byte, error) {
	// Hold mu across the read: Close marks the store closed under mu before
	// closing pebble, so a read that starts before Close finishes safely,
	// and one that starts after returns an error instead of panicking
	// inside pebble ("pebble: closed").
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errStoreClosed
	}
	v, closer, err := s.db.Get(k)
	if err == pebble.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, closer.Close()
}

func (s *Store) getMeta(name string) (uint64, error) {
	v, err := s.getRaw(metaKey(name))
	if err != nil || v == nil {
		return 0, err
	}
	n, ok := beUint64(v)
	if !ok {
		return 0, fmt.Errorf("corrupt meta value for %s", name)
	}
	return n, nil
}

func recordKey(apex, sub string) []byte {
	k := make([]byte, 0, len(apex)+1+len(sub))
	k = append(k, apex...)
	k = append(k, 0x00)
	k = append(k, sub...)
	return k
}

func countKey(apex string) []byte {
	k := make([]byte, 0, 1+len(apex))
	k = append(k, pfxCount)
	k = append(k, apex...)
	return k
}

func metaKey(name string) []byte {
	k := make([]byte, 0, 2+len(name))
	k = append(k, pfxMeta, 0x00)
	k = append(k, name...)
	return k
}

func totalKey() []byte { return metaKey("total") }

func beUint64(b []byte) (uint64, bool) {
	if len(b) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(b), true
}

func encodeValue(firstSeen int64, source byte, seq uint64) []byte {
	v := make([]byte, 17)
	binary.BigEndian.PutUint64(v[:8], uint64(firstSeen))
	v[8] = source
	binary.BigEndian.PutUint64(v[9:17], seq)
	return v
}
