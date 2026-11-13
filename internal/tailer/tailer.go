// Package tailer watches Certificate Transparency logs: it verifies
// signed tree heads, binds fetched entries to them via inclusion
// proofs, and feeds decoded names into the store.
package tailer

import (
	"context"
	crand "crypto/rand"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"subidx/internal/apex"
	"subidx/internal/loglist"
	"subidx/internal/rfc6962"
	"subidx/internal/store"
)

const sourceCT byte = 1

type Tailer struct {
	Store     *store.Store
	Interval  time.Duration
	Window    int64
	Drain     bool
	HeadStart int64
	// BatchDelay pauses after each fetched window. Catch-up is CPU-bound:
	// every window is downloaded, gunzipped, JSON-parsed, X.509-parsed and
	// then written to the store, and a tailer that runs `for pos < to`
	// without a pause pins the process at its CPU quota for as long as the
	// backlog lasts (it also does two HTTP requests per window). 0 keeps
	// the old flat-out behaviour.
	BatchDelay time.Duration

	mu      sync.Mutex
	runners map[string]*logRunner
	wg      sync.WaitGroup
}

type logRunner struct {
	cancel      context.CancelFunc
	mu          sync.Mutex
	state       string
	drainTarget int64 // -1 means live (no drain cap)
}

func (t *Tailer) Sync(ctx context.Context, logs []loglist.Log) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.runners == nil {
		t.runners = make(map[string]*logRunner)
	}
	seen := make(map[string]bool)
	for _, lg := range logs {
		if lg.Kind() != "rfc6962" || lg.CurrentState() == "" {
			continue
		}
		state := lg.CurrentState()
		if !t.Drain && (state == "readonly" || state == "frozen" || state == "retired" || state == "rejected") {
			if r, ok := t.runners[lg.LogID]; ok {
				r.cancel()
				delete(t.runners, lg.LogID)
			}
			continue
		}
		seen[lg.LogID] = true
		drainTarget := drainTargetFor(lg, state)
		if r, ok := t.runners[lg.LogID]; ok {
			r.mu.Lock()
			r.state = state
			if drainTarget >= 0 {
				r.drainTarget = drainTarget
			}
			r.mu.Unlock()
			continue
		}
		rctx, cancel := context.WithCancel(ctx)
		r := &logRunner{cancel: cancel, state: state, drainTarget: drainTarget}
		t.runners[lg.LogID] = r
		t.wg.Add(1)
		go func(lg loglist.Log, r *logRunner) {
			defer t.wg.Done()
			defer func() {
				t.mu.Lock()
				if t.runners[lg.LogID] == r {
					delete(t.runners, lg.LogID)
				}
				t.mu.Unlock()
			}()
			t.tailOne(rctx, lg, r)
		}(lg, r)
	}
	for id, r := range t.runners {
		if !seen[id] {
			r.cancel()
			delete(t.runners, id)
		}
	}
}

func drainTargetFor(lg loglist.Log, state string) int64 {
	switch state {
	case "readonly", "frozen":
		if d := lg.State[state]; d.FinalTreeHead != nil {
			return d.FinalTreeHead.TreeSize
		}
	}
	return -1
}

func (t *Tailer) Wait() {
	t.wg.Wait()
}

func (t *Tailer) tailOne(ctx context.Context, lg loglist.Log, r *logRunner) {
	client, err := rfc6962.NewClient(lg.Endpoint(), lg.Key)
	if err != nil {
		log.Printf("tail %s: %v", lg.LogID, err)
		return
	}
	if expected := client.LogID(); lg.LogID != "" && expected != lg.LogID {
		log.Printf("tail %s: log list key mismatch (sha256(key) = %s), skipping", lg.LogID, expected)
		return
	}
	id := lg.LogID
	wm, err := t.Store.Watermark(id)
	if err != nil {
		// A read failure is indistinguishable from corruption. Assuming
		// zero here would re-drain the entire log from index 0, so skip
		// the log instead; the watermark is retried on the next Sync.
		log.Printf("tail %s: watermark read failed: %v; skipping log to avoid full re-drain", client.ShortID(), err)
		return
	}
	if wm == 0 && t.HeadStart > 0 {
		seeded, herr := t.seedHeadStart(ctx, client, id)
		if herr != nil {
			log.Printf("tail %s: head-start seed failed: %v; skipping log to avoid a full re-drain from index 0", client.ShortID(), herr)
			return
		}
		wm = seeded
	}

	interval := t.Interval
	if interval <= 0 {
		interval = 3 * time.Second
	}
	window := t.Window
	if window <= 0 {
		window = 512
	}
	r.mu.Lock()
	state := r.state
	drainTarget := r.drainTarget
	r.mu.Unlock()
	log.Printf("tail %s (%s %s): start watermark=%d drain=%d", client.ShortID(), state, lg.Description, wm, drainTarget)
	for {
		if ctx.Err() != nil {
			return
		}
		r.mu.Lock()
		state = r.state
		drainTarget = r.drainTarget
		r.mu.Unlock()
		if (state == "retired" || state == "rejected") && drainTarget < 0 {
			if sth, serr := client.STH(ctx); serr == nil && client.VerifySTH(sth) == nil {
				drainTarget = sth.TreeSize
				r.mu.Lock()
				r.drainTarget = drainTarget
				r.mu.Unlock()
			}
		}
		sth, err := client.STH(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("tail %s: sth: %v", client.ShortID(), err)
			if !sleepCtx(ctx, jitter(interval)) {
				return
			}
			continue
		}
		if err := client.VerifySTH(sth); err != nil {
			log.Printf("tail %s: verify: %v", client.ShortID(), err)
			if !sleepCtx(ctx, jitter(interval)) {
				return
			}
			continue
		}
		target := sth.TreeSize
		if drainTarget >= 0 && drainTarget < target {
			target = drainTarget
		}
		if target > wm {
			n, err := t.fetchRange(ctx, client, id, wm, target, window, sth.SHA256RootHash, sth.TreeSize)
			if err != nil && ctx.Err() == nil {
				log.Printf("tail %s: entries: %v", client.ShortID(), err)
			}
			wm += n
			if err := t.Store.AdvanceWatermark(id, wm); err != nil {
				log.Printf("tail %s: watermark: %v", client.ShortID(), err)
			}
		}
		if drainTarget >= 0 && wm >= drainTarget {
			log.Printf("tail %s: drained to %d", client.ShortID(), wm)
			return
		}
		if !sleepCtx(ctx, jitter(interval)) {
			return
		}
	}
}

func (t *Tailer) seedHeadStart(ctx context.Context, client *rfc6962.Client, id string) (int64, error) {
	backoff := t.Interval
	if backoff <= 0 {
		backoff = time.Second
	}
	var last error
	for {
		if err := ctx.Err(); err != nil {
			if last != nil {
				return 0, fmt.Errorf("cancelled after: %w", last)
			}
			return 0, err
		}
		sth, err := client.STH(ctx)
		if err != nil {
			last = err
			log.Printf("tail %s: head-start sth: %v", client.ShortID(), err)
			if !sleepCtx(ctx, jitter(backoff)) {
				return 0, ctx.Err()
			}
			continue
		}
		if err := client.VerifySTH(sth); err != nil {
			last = err
			log.Printf("tail %s: head-start verify: %v", client.ShortID(), err)
			if !sleepCtx(ctx, jitter(backoff)) {
				return 0, ctx.Err()
			}
			continue
		}
		wm := int64(0)
		if sth.TreeSize > t.HeadStart {
			wm = sth.TreeSize - t.HeadStart
		}
		if err := t.Store.AdvanceWatermark(id, wm); err != nil {
			return 0, err
		}
		return wm, nil
	}
}

func (t *Tailer) fetchRange(ctx context.Context, client *rfc6962.Client, logID string, from, to, window int64, root []byte, treeSize int64) (int64, error) {
	var total int64
	pos := from
	for pos < to {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		end := pos + window - 1
		if end > to-1 {
			end = to - 1
		}
		entries, err := client.Entries(ctx, pos, end)
		if err != nil {
			return total, err
		}
		if len(entries) == 0 {
			return total, nil
		}
		// Only consider entries inside the requested [pos, end] window.
		limit := len(entries)
		if int64(limit) > end-pos+1 {
			limit = int(end - pos + 1)
		}
		batch := entries[:limit]
		// Bind the batch to the signed root before ingesting anything:
		// a randomly chosen entry must prove inclusion in the verified
		// tree at the index we asked for. Entries served outside the
		// signed tree — by a tampered connection or a misbehaving log —
		// fail here and are never stored. The pick is cryptographically
		// random so a tamperer cannot predict which entry will be checked.
		if err := spotCheck(ctx, client, batch, root, treeSize, pos); err != nil {
			return total, fmt.Errorf("inclusion spot-check: %w", err)
		}
		skipped := int64(0)
		for _, e := range batch {
			leaf, err := rfc6962.DecodeLeafEntry(e)
			if err != nil {
				skipped++
				continue
			}
			fs := leaf.Timestamp
			for _, s := range leaf.SCTStamps {
				if s > 0 && (fs == 0 || s < fs) {
					fs = s
				}
			}
			if fs <= 0 {
				skipped++
				continue
			}
			for _, name := range leaf.Names {
				c, ok := apex.Canonical(name)
				if !ok {
					continue
				}
				a, ok := apex.ApexOf(c)
				if !ok {
					continue
				}
				if err := t.Store.Ingest(store.Record{Apex: a, Sub: c, FirstSeen: fs, Source: sourceCT}); err != nil {
					return total, err
				}
			}
		}
		if skipped > 0 {
			log.Printf("tail %s: skipped %d undecodable entries in [%d,%d]", client.ShortID(), skipped, pos, end)
		}
		n := int64(limit)
		total += n
		pos += n
		// Persist the watermark per window, not once at the end. The
		// window's records and this watermark land in the same atomic
		// batch, so nothing can be marked fetched without being stored;
		// without this, a restart in the middle of a multi-hour catch-up
		// resumes where the call started and re-downloads every window
		// fetched since.
		if err := t.Store.AdvanceWatermark(logID, from+total); err != nil {
			return total, err
		}
		if pos < to && t.BatchDelay > 0 {
			if !sleepCtx(ctx, t.BatchDelay) {
				return total, ctx.Err()
			}
		}
	}
	return total, nil
}

// spotCheck demands an inclusion proof for one uniformly random entry
// of a fetched batch and verifies it locally against the signed root,
// requiring the proof's leaf index to be the index we requested.
func spotCheck(ctx context.Context, client *rfc6962.Client, entries []rfc6962.LeafEntry, root []byte, treeSize, pos int64) error {
	n, err := crand.Int(crand.Reader, big.NewInt(int64(len(entries))))
	if err != nil {
		return fmt.Errorf("pick entry: %w", err)
	}
	idx := n.Int64()
	want := pos + idx
	leafHash := rfc6962.LeafHash(entries[idx].LeafInput)
	proof, err := client.ProofByHash(ctx, leafHash, treeSize)
	if err != nil {
		return fmt.Errorf("fetch proof: %w", err)
	}
	if proof.LeafIndex != want {
		return fmt.Errorf("proof leaf index %d does not match requested index %d", proof.LeafIndex, want)
	}
	if err := rfc6962.VerifyInclusion(leafHash, proof.LeafIndex, treeSize, proof.AuditPath, root); err != nil {
		return fmt.Errorf("entry %d of batch (index %d) not provably in signed tree: %w", idx, want, err)
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int63n(int64(d)))
}
