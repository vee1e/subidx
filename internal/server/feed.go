package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"subidx/internal/apex"
)

// maxActiveFeeds bounds memory across concurrent SSE streams.
const maxActiveFeeds = 128

// FeedEvent is one newly stored name, fanned out to live subscribers.
type FeedEvent struct {
	Apex      string
	Sub       string
	FirstSeen int64
	Seq       uint64
}

// Hub broadcasts ingest events to per-apex subscribers. Broadcast runs on
// the store's ingest loop, so it never blocks: a slow consumer's events
// are dropped and the subscriber is flagged to resync over /v1/watch.
type Hub struct {
	mu   sync.Mutex
	next int64
	subs map[int64]*FeedSub
}

// FeedSub is one subscription. Handlers read Chan and poll takeDropped.
type FeedSub struct {
	apex string
	ch   chan FeedEvent
	drop atomic.Bool
}

func NewHub() *Hub {
	return &Hub{subs: make(map[int64]*FeedSub)}
}

func (h *Hub) Subscribe(apex string) (int64, *FeedSub) {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := h.next
	h.next++
	sub := &FeedSub{apex: apex, ch: make(chan FeedEvent, 256)}
	h.subs[id] = sub
	return id, sub
}

func (h *Hub) Unsubscribe(id int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if sub, ok := h.subs[id]; ok {
		close(sub.ch)
		delete(h.subs, id)
	}
}

// Close tears every subscriber down; used at server shutdown.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, sub := range h.subs {
		close(sub.ch)
		delete(h.subs, id)
	}
}

// Broadcast fans one newly stored name out to matching subscribers.
// Safe to call from the ingest loop: it never blocks, and a full
// subscriber just gets flagged to resync over /v1/watch.
func (h *Hub) Broadcast(e FeedEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, sub := range h.subs {
		if sub.apex != e.Apex {
			continue
		}
		select {
		case sub.ch <- e:
		default:
			sub.drop.Store(true)
		}
	}
}

// Chan returns the event stream for this subscription.
func (fs *FeedSub) Chan() <-chan FeedEvent { return fs.ch }

func (fs *FeedSub) takeDropped() bool { return fs.drop.Swap(false) }

type feedLine struct {
	FirstSeen *string `json:"first_seen"`
	Sub       string  `json:"sub"`
}

// handleFeed serves GET /v1/feed?apex=X as a server-sent-event stream of
// newly collected names for that apex. Opening a stream consumes one
// unit of the caller's rate budget; heartbeats keep proxies idle.
func (s *Server) handleFeed(w http.ResponseWriter, r *http.Request) {
	if !s.gate(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w)
		return
	}
	if s.Hub == nil {
		http.Error(w, "feed unavailable", http.StatusServiceUnavailable)
		return
	}
	raw := r.URL.Query().Get("apex")
	if raw == "" {
		http.Error(w, "missing apex parameter", http.StatusBadRequest)
		return
	}
	norm, err := apex.Normalize(raw)
	if err != nil {
		http.Error(w, "invalid apex: "+err.Error(), http.StatusBadRequest)
		return
	}
	a, err := apex.ValidateApex(norm)
	if err != nil {
		http.Error(w, "invalid apex: "+err.Error(), http.StatusBadRequest)
		return
	}
	if n := s.activeFeeds.Add(1); n > maxActiveFeeds {
		s.activeFeeds.Add(-1)
		http.Error(w, "too many live feeds", http.StatusServiceUnavailable)
		return
	}
	defer s.activeFeeds.Add(-1)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")

	id, sub := s.Hub.Subscribe(a)
	defer s.Hub.Unsubscribe(id)

	ctx := r.Context()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	io.WriteString(w, "retry: 3000\n\n")
	flusher.Flush()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.Stop:
			return
		case e, ok := <-sub.Chan():
			if !ok {
				return
			}
			if sub.takeDropped() {
				io.WriteString(w, "event: resync\ndata: {}\n\n")
				flusher.Flush()
			}
			line := feedLine{Sub: e.Sub}
			if e.FirstSeen > 0 {
				ts := formatTS(e.FirstSeen)
				line.FirstSeen = &ts
			}
			payload, err := json.Marshal(line)
			if err != nil {
				continue
			}
			if _, err := io.WriteString(w, "id: "+strconv.FormatUint(e.Seq, 10)+"\ndata: "+string(payload)+"\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// handleWatch serves GET /v1/watch?apex=X&after=N as NDJSON rows newer
// than the cursor, for clients reconciling a dropped feed or polling.
func (s *Server) handleWatch(w http.ResponseWriter, r *http.Request) {
	if !s.gate(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w)
		return
	}
	raw := r.URL.Query().Get("apex")
	if raw == "" {
		http.Error(w, "missing apex parameter", http.StatusBadRequest)
		return
	}
	norm, err := apex.Normalize(raw)
	if err != nil {
		http.Error(w, "invalid apex: "+err.Error(), http.StatusBadRequest)
		return
	}
	a, err := apex.ValidateApex(norm)
	if err != nil {
		http.Error(w, "invalid apex: "+err.Error(), http.StatusBadRequest)
		return
	}
	var after uint64
	if v := r.URL.Query().Get("after"); v != "" {
		after, err = strconv.ParseUint(v, 10, 64)
		if err != nil {
			http.Error(w, "invalid after", http.StatusBadRequest)
			return
		}
	}

	rows, maxSeq, truncated, err := s.Store.ScanAfter(a, after, s.MaxResults)
	if err != nil {
		log.Printf("watch %s: %v", a, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("x-max-seq", strconv.FormatUint(maxSeq, 10))
	if truncated {
		w.Header().Set("x-truncated", "1")
	}
	s.renderNDJSON(w, rows, r.URL.Query().Get("dates") == "1")
}
