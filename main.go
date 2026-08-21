package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"subidx/internal/loglist"
	"subidx/internal/server"
	"subidx/internal/store"
	"subidx/internal/tailer"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "tail":
		err = cmdTail(os.Args[2:])
	case "stats":
		err = cmdStats(os.Args[2:])
	case "version":
		fmt.Println("subidx 0.1.0")
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: subidx <serve|tail|stats|version>")
}

func cmdStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	dir := fs.String("store", "./data", "store directory")
	recount := fs.Bool("recount", false, "rebuild counters and total from a full scan")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.Open(*dir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	if *recount {
		total, err := st.Recount()
		if err != nil {
			return err
		}
		fmt.Printf("recounted records: %d\n", total)
	}
	total, err := st.Total()
	if err != nil {
		return err
	}
	top, err := st.Top(10)
	if err != nil {
		return err
	}
	fmt.Printf("records: %d\n", total)
	for _, ac := range top {
		fmt.Printf("%8d  %s\n", ac.Count, ac.Apex)
	}
	return st.Close()
}

type commonConfig struct {
	storeDir string
	interval time.Duration
	window   int64
}

func addCommon(fs *flag.FlagSet) *commonConfig {
	c := &commonConfig{}
	fs.StringVar(&c.storeDir, "store", "./data", "store directory")
	fs.DurationVar(&c.interval, "poll-interval", 3*time.Second, "base STH poll interval")
	fs.Int64Var(&c.window, "window", 512, "get-entries window size")
	return c
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	c := addCommon(fs)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	noTail := fs.Bool("no-tail", false, "disable CT tailers")
	rateLimit := fs.Int64("rate-limit", 1000, "requests per rolling 24h per IP")
	maxResults := fs.Int("max-results", store.DefaultScanLimit, "max results buffered per search query")
	allowedHosts := fs.String("allowed-hosts", "", "comma-separated Host values to accept (default: localhost, 127.0.0.1, ::1)")
	trustedHops := fs.Int("trusted-proxy-hops", 0, "trusted proxies in front (0 = ignore X-Forwarded-For)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *trustedHops < 0 || *rateLimit <= 0 || *maxResults <= 0 {
		return fmt.Errorf("invalid config")
	}

	st, err := store.Open(c.storeDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tailerDone := make(chan struct{})
	if !*noTail {
		go func() {
			defer close(tailerDone)
			runTailers(ctx, st, c, true)
		}()
	}

	var hosts []string
	for _, h := range strings.Split(*allowedHosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}

	srv := &server.Server{
		Store:        st,
		Limiter:      server.NewLimiter(*rateLimit, 24*time.Hour),
		TrustedHops:  *trustedHops,
		RateLimit:    *rateLimit,
		MaxResults:   *maxResults,
		AllowedHosts: hosts,
		ReadyFn: func() bool {
			t, err := st.Total()
			return err == nil && t >= 0
		},
	}
	srv.Limiter.StartSweeper(ctx.Done())

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    8192,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.ListenAndServe() }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	case s := <-sig:
		log.Printf("received %s, shutting down", s)
	}
	shutdownCtx, sc := context.WithTimeout(context.Background(), 30*time.Second)
	defer sc()
	httpSrv.Shutdown(shutdownCtx)
	cancel()
	select {
	case <-tailerDone:
	case <-time.After(10 * time.Second):
		log.Printf("timed out waiting for tailers to stop")
	}
	return st.Close()
}

func cmdTail(args []string) error {
	fs := flag.NewFlagSet("tail", flag.ExitOnError)
	c := addCommon(fs)
	noDrain := fs.Bool("no-drain", false, "skip readonly/retired/rejected log drains")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.Open(c.storeDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()
	runTailers(ctx, st, c, !*noDrain)
	return st.Close()
}

func runTailers(ctx context.Context, st *store.Store, c *commonConfig, drain bool) {
	t := &tailer.Tailer{Store: st, Interval: c.interval, Window: c.window, Drain: drain}
	for {
		logs, err := loglist.FetchAll(nil)
		if err == nil {
			t.Sync(ctx, logs)
			log.Printf("loglist sync: %d logs known", len(logs))
		} else {
			log.Printf("loglist fetch failed: %v", err)
		}
		select {
		case <-ctx.Done():
			t.Wait()
			return
		case <-time.After(time.Hour):
		}
	}
}
