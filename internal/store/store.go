package store

import (
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
	ch     chan Record
	done   chan struct{}
	seq    uint64
	mu     sync.Mutex
	closed bool

	pendingRecords map[string]*recState
	pendingCounts  map[string]uint64
	pendingTotal   uint64
	totalBase      uint64
}

func Open(dir string) (*Store, error) {
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		return nil, err
	}
	s := &Store{
		db:             db,
		ch:             make(chan Record, 4096),
		done:           make(chan struct{}),
		pendingRecords: make(map[string]*recState),
		pendingCounts:  make(map[string]uint64),
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
		if batch.Count() == 0 {
			return nil
		}
		var seqBuf [8]byte
		binary.BigEndian.PutUint64(seqBuf[:], s.seq)
		if err := batch.Set(metaKey("seq"), seqBuf[:], nil); err != nil {
			return err
		}
		if err := batch.Commit(pebble.Sync); err != nil {
			return err
		}
		s.pendingRecords = make(map[string]*recState)
		s.pendingCounts = make(map[string]uint64)
		s.pendingTotal = 0
		pending = 0
		batch.Reset()
		return nil
	}
	for {
		select {
		case r, ok := <-s.ch:
			if !ok {
				if err := flush(); err != nil {
					log.Printf("store final flush: %v", err)
				}
				return
			}
			if err := s.apply(batch, r); err != nil {
				log.Printf("store apply %s/%s: %v", r.Apex, r.Sub, err)
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
			if pending > 0 {
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
			st = &recState{
				firstSeen: int64(binary.BigEndian.Uint64(existing[:8])),
				source:    existing[8],
				seq:       binary.BigEndian.Uint64(existing[9:17]),
			}
			closer.Close()
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
	n := binary.BigEndian.Uint64(v)
	s.pendingCounts[apex] = n
	return n
}

func (s *Store) Ingest(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errStoreClosed
	}
	s.ch <- r
	return nil
}

func (s *Store) Scan(apex string) ([]Result, error) {
	lo := []byte(recordKey(apex, ""))
	hi := make([]byte, len(apex)+1)
	copy(hi, apex)
	hi[len(apex)] = 0x01
	it, err := s.db.NewIter(&pebble.IterOptions{LowerBound: lo, UpperBound: hi})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []Result
	for ok := it.First(); ok; ok = it.Next() {
		v := it.Value()
		if len(v) < 17 {
			continue
		}
		sub := string(it.Key()[len(lo):])
		out = append(out, Result{
			Sub:       sub,
			FirstSeen: int64(binary.BigEndian.Uint64(v[:8])),
			Seq:       binary.BigEndian.Uint64(v[9:17]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
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
	return binary.BigEndian.Uint64(v), nil
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
		all = append(all, ApexCount{Apex: string(it.Key()[1:]), Count: binary.BigEndian.Uint64(it.Value())})
	}
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].Count > all[i].Count {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
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

func (s *Store) Recount() (uint64, error) {
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
		apex := string(k[:sep])
		counts[apex]++
		total++
	}
	if err := it.Close(); err != nil {
		return 0, err
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	for apex, n := range counts {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], n)
		if err := batch.Set(countKey(apex), buf[:], nil); err != nil {
			return 0, err
		}
		if batch.Count() >= 4096 {
			if err := batch.Commit(pebble.Sync); err != nil {
				return 0, err
			}
			batch.Reset()
		}
	}
	var totBuf [8]byte
	binary.BigEndian.PutUint64(totBuf[:], total)
	if err := batch.Set(totalKey(), totBuf[:], nil); err != nil {
		return 0, err
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.totalBase = total
	s.pendingTotal = 0
	s.mu.Unlock()
	return total, nil
}

func (s *Store) getRaw(k []byte) ([]byte, error) {
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
	return binary.BigEndian.Uint64(v), nil
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

func encodeValue(firstSeen int64, source byte, seq uint64) []byte {
	v := make([]byte, 17)
	binary.BigEndian.PutUint64(v[:8], uint64(firstSeen))
	v[8] = source
	binary.BigEndian.PutUint64(v[9:17], seq)
	return v
}
