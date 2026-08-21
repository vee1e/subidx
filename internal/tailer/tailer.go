package tailer

import (
	"context"
	"log"
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
	Store    *store.Store
	Interval time.Duration
	Window   int64
	Drain    bool

	mu      sync.Mutex
	started map[string]bool
	wg      sync.WaitGroup
}

func (t *Tailer) Sync(ctx context.Context, logs []loglist.Log) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started == nil {
		t.started = make(map[string]bool)
	}
	for _, lg := range logs {
		if lg.Kind() != "rfc6962" || lg.CurrentState() == "" {
			continue
		}
		state := lg.CurrentState()
		if !t.Drain && (state == "readonly" || state == "retired" || state == "rejected") {
			continue
		}
		if t.started[lg.LogID] {
			continue
		}
		t.started[lg.LogID] = true
		t.wg.Add(1)
		go func(lg loglist.Log) {
			defer t.wg.Done()
			t.tailOne(ctx, lg, state)
		}(lg)
	}
}

func (t *Tailer) Wait() {
	t.wg.Wait()
}

func (t *Tailer) tailOne(ctx context.Context, lg loglist.Log, state string) {
	client, err := rfc6962.NewClient(lg.Endpoint(), lg.Key)
	if err != nil {
		log.Printf("tail %s: %v", client.ShortID(), err)
		return
	}
	id := lg.LogID
	wm, err := t.Store.Watermark(id)
	if err != nil {
		wm = 0
	}
	drainTarget := int64(-1)
	switch state {
	case "readonly":
		if d := lg.State["readonly"]; d.FinalTreeHead != nil {
			drainTarget = d.FinalTreeHead.TreeSize
		}
	case "retired", "rejected":
		sth, err := client.STH(ctx)
		if err == nil {
			drainTarget = sth.TreeSize
		}
	}
	interval := t.Interval
	if interval <= 0 {
		interval = 3 * time.Second
	}
	window := t.Window
	if window <= 0 {
		window = 512
	}
	log.Printf("tail %s (%s %s): start watermark=%d drain=%d", client.ShortID(), state, lg.Description, wm, drainTarget)
	for {
		if ctx.Err() != nil {
			return
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
		}
		target := sth.TreeSize
		if drainTarget >= 0 && drainTarget < target {
			target = drainTarget
		}
		if target > wm {
			n, err := t.fetchRange(ctx, client, id, wm, target, window)
			if err != nil && ctx.Err() == nil {
				log.Printf("tail %s: entries: %v", client.ShortID(), err)
			}
			wm += n
			if err := t.Store.SetWatermarkSync(id, wm); err != nil {
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

func (t *Tailer) fetchRange(ctx context.Context, client *rfc6962.Client, logID string, from, to, window int64) (int64, error) {
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
		decoded := int64(0)
		for _, e := range entries {
			leaf, err := rfc6962.DecodeLeafEntry(e)
			decoded++
			if err != nil {
				continue
			}
			fs := leaf.Timestamp
			for _, s := range leaf.SCTStamps {
				if s > 0 && (fs == 0 || s < fs) {
					fs = s
				}
			}
			if fs <= 0 {
				continue
			}
			for _, name := range leaf.Names {
				a, ok := apex.ApexOf(name)
				if !ok {
					continue
				}
				if err := t.Store.Ingest(store.Record{Apex: a, Sub: name, FirstSeen: fs, Source: sourceCT}); err != nil {
					return total, err
				}
			}
		}
		total += decoded
		pos += decoded
	}
	return total, nil
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
