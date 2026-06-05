// Command netwatch scans the local network and serves a live inventory over HTTP.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jkrauska/netwatch/internal/scan"
	"github.com/jkrauska/netwatch/internal/server"
	"github.com/jkrauska/netwatch/internal/store"
)

// locationDBPath makes a database path subnet-aware by inserting the scanned
// prefix (with the slash replaced by an underscore, since "/" is a path
// separator) before the file extension. This keeps per-network inventories in
// separate files so scanning a different network doesn't overwrite the last
// one. For example, base "netwatch.db" on 192.168.7.0/24 becomes
// "netwatch-192.168.7.0_24.db". An empty base (persistence disabled) is
// returned unchanged.
func locationDBPath(base string, prefix netip.Prefix) string {
	if base == "" || !prefix.IsValid() {
		return base
	}
	loc := strings.ReplaceAll(prefix.String(), "/", "_")
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return fmt.Sprintf("%s-%s%s", stem, loc, ext)
}

// stringList is a flag.Value that accumulates repeated flags and also splits
// comma-separated values, so both "--skip-ip a --skip-ip b" and
// "--skip-ip a,b" populate the list.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

func main() {
	var (
		ifaceName = flag.String("iface", "", "network interface to scan (default: auto-detect)")
		addr      = flag.String("listen", ":8080", "HTTP listen address")
		interval  = flag.Duration("interval", 30*time.Second, "rescan interval")
		pingTO    = flag.Duration("ping-timeout", 2*time.Second, "ping sweep reply window")
		mdnsWait  = flag.Duration("mdns-wait", 2*time.Second, "mDNS listen window")
		workers   = flag.Int("workers", 128, "concurrent ping senders")
		ouiFile   = flag.String("oui", "", "path to IEEE oui.txt or Wireshark manuf file")
		dbPath    = flag.String("db", "netwatch.db", "SQLite database path for persistence (empty to disable)")
	)
	var skipIPs, skipMACs stringList
	flag.Var(&skipIPs, "skip-ip", "IP address to exclude from results (repeatable or comma-separated)")
	flag.Var(&skipMACs, "skip-mac", "MAC address to exclude from results (repeatable or comma-separated)")
	flag.Parse()

	iface, err := scan.DefaultInterface(*ifaceName)
	if err != nil {
		log.Fatalf("interface: %v", err)
	}
	log.Printf("scanning %s on %s (self %s)", iface.Prefix, iface.Name, iface.Self)

	oui := scan.NewOUI()
	if *ouiFile != "" {
		if err := oui.LoadFile(*ouiFile); err != nil {
			log.Printf("oui: %v (using built-in table)", err)
		} else {
			log.Printf("oui: loaded vendor database from %s", *ouiFile)
		}
	}

	st := store.New()

	// Make the database file location-aware so switching networks keeps a
	// separate inventory per subnet instead of overwriting the last one.
	resolvedDB := locationDBPath(*dbPath, iface.Prefix)

	var db *store.DB
	if resolvedDB != "" {
		var err error
		db, err = store.OpenDB(resolvedDB)
		if err != nil {
			log.Printf("persistence disabled: %v", err)
		} else {
			defer db.Close()
			if hosts, err := db.Load(); err != nil {
				log.Printf("db load: %v", err)
			} else if len(hosts) > 0 {
				st.Restore(hosts)
				log.Printf("restored %d hosts from %s", len(hosts), resolvedDB)
			}
			log.Printf("persisting to %s", resolvedDB)
			st.SetPersister(db)
		}
	}

	skip := scan.NewSkipSet(skipIPs, skipMACs)
	if !skip.Empty() {
		log.Printf("skipping %d IP(s) and %d MAC(s)", len(skipIPs), len(skipMACs))
	}

	sc := &scan.Scanner{
		Iface:       iface,
		Store:       st,
		OUI:         oui,
		Skip:        skip,
		PingTimeout: *pingTO,
		MDNSWait:    *mdnsWait,
		Workers:     *workers,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Allow the UI's Stop button to trigger the same graceful shutdown path as
	// an OS signal by cancelling the run context.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go sc.Run(ctx, *interval)

	handler := server.New(st, sc)
	handler.SetShutdown(func() {
		log.Printf("shutdown requested via UI")
		cancel()
	})
	srv := &http.Server{Addr: *addr, Handler: handler}
	go func() {
		<-ctx.Done()
		// Reconcile the database with the final in-memory state, pruning any
		// rows whose key was re-keyed (IP→MAC) during the session.
		if db != nil {
			if err := db.SaveAll(st.Snapshot()); err != nil {
				log.Printf("db flush: %v", err)
			}
		}
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	log.Printf("netwatch UI on http://localhost%s", *addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("http: %v", err)
	}
}
