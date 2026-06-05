package scan

import (
	"context"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jkrauska/netwatch/internal/store"
)

// Scanner runs repeated discovery passes over an interface and feeds results
// into a Store.
type Scanner struct {
	Iface *Interface
	Store *store.Store
	OUI   *OUI

	// Skip excludes matching IPs/MACs from results. nil means skip nothing.
	Skip *SkipSet

	PingTimeout time.Duration
	MDNSWait    time.Duration
	Workers     int

	// Pause/resume state. paused gates the Run loop; wake lets Resume cut a
	// pending inter-scan wait short so scanning restarts promptly.
	mu     sync.Mutex
	paused bool
	wake   chan struct{}
}

// Paused reports whether scanning is currently suspended.
func (s *Scanner) Paused() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.paused
}

// Pause suspends scanning after any in-flight pass completes.
func (s *Scanner) Pause() { s.setPaused(true) }

// Resume restarts scanning, waking the Run loop immediately if it is idling
// between passes.
func (s *Scanner) Resume() { s.setPaused(false) }

func (s *Scanner) setPaused(p bool) {
	s.mu.Lock()
	was := s.paused
	s.paused = p
	if s.wake == nil {
		s.wake = make(chan struct{}, 1)
	}
	wake := s.wake
	s.mu.Unlock()

	if was == p {
		return
	}
	if p {
		log.Print("scan: paused")
		return
	}
	// On a pause→resume transition, nudge the loop so it doesn't sit out the
	// remainder of a long inter-scan wait.
	log.Print("scan: resumed")
	select {
	case wake <- struct{}{}:
	default:
	}
}

// wakeCh returns the resume-signal channel, lazily creating it so a Scanner
// built as a struct literal still works.
func (s *Scanner) wakeCh() chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wake == nil {
		s.wake = make(chan struct{}, 1)
	}
	return s.wake
}

// bucketSize is how many target addresses each sweep bucket probes before the
// scanner re-reads the neighbor tables and upserts that bucket's hosts.
const bucketSize = 32

// Scan performs one discovery pass, streaming results into the store as they
// are found so the web view fills in progressively.
//
// Discovery proceeds in two stages:
//
//  1. ARP/NDP-first seeding — read the kernel neighbor tables and upsert every
//     already-resolved host immediately. This costs zero packets and typically
//     covers most of the subnet in milliseconds.
//
//  2. Bucketed sweep — walk the remaining target addresses in buckets of
//     bucketSize, sending ICMP echoes (to provoke ARP resolution and confirm
//     liveness) and upserting each bucket's live hosts right away.
//
//  3. Reconcile — read the neighbor tables once more after the sweep to pick up
//     the MACs that ARP resolved during it, then upsert/enrich anything new.
//
// The neighbor tables are read exactly twice per scan (seed + reconcile) rather
// than once per bucket: ARP/NDP entries are cumulative and live for minutes, so
// a single post-sweep read is the union of every per-bucket read but spawns
// far fewer `arp`/`ndp` (or `ip neigh`) subprocesses. Reverse DNS and mDNS
// enrichment runs in the background and updates rows as names resolve.
func (s *Scanner) Scan(ctx context.Context) error {
	start := time.Now()

	var enrichers sync.WaitGroup
	enrichSlots := make(chan struct{}, 4) // bound concurrent enrichment passes
	enrich := func(addrs []netip.Addr, macByIP map[string]string, ipsByMAC map[string][]netip.Addr) {
		if len(addrs) == 0 {
			return
		}
		enrichers.Add(1)
		enrichSlots <- struct{}{}
		go func() {
			defer enrichers.Done()
			defer func() { <-enrichSlots }()
			s.enrich(ctx, addrs, macByIP, ipsByMAC)
		}()
	}

	// handled tracks every address already upserted so the post-sweep
	// reconciliation only processes hosts that are genuinely new.
	handled := make(map[string]bool)

	// Stage 1: seed from kernel neighbor tables.
	macByIP, ipsByMAC := indexNeighbors(Neighbors())
	seeded := s.upsertHosts(subnetAddrs(macByIP, s.Iface.Prefix), macByIP, ipsByMAC, time.Now())
	// Make sure we always have ourselves.
	if _, ok := macByIP[s.Iface.Self.String()]; !ok {
		self := []netip.Addr{s.Iface.Self}
		s.upsertHosts(self, macByIP, ipsByMAC, time.Now())
		seeded = append(seeded, self...)
	}
	for _, ip := range seeded {
		handled[ip.String()] = true
	}
	log.Printf("scan: seeded %d hosts from neighbor tables (%s)", len(seeded), time.Since(start).Round(time.Millisecond))
	enrich(seeded, macByIP, ipsByMAC)

	// Network-wide DNS-SD/AirPlay browse runs once per pass alongside the
	// per-bucket sweep. It refines categories (Apple model=, smart-TV AirPlay,
	// printers, speakers) and learns friendly device names independent of which
	// addresses the sweep has reached yet.
	enrichers.Add(1)
	enrichSlots <- struct{}{}
	go func() {
		defer enrichers.Done()
		defer func() { <-enrichSlots }()
		s.browse(ctx)
	}()

	// Stage 2: bucketed sweep over the full target range. ICMP only provides
	// liveness here; live hosts are upserted with whatever MAC the Stage-1 index
	// already knows (usually all of them). Stragglers whose MAC resolves during
	// the sweep are picked up by the Stage-3 reconcile below.
	targets := s.Iface.Hosts()
	if !s.Skip.Empty() {
		filtered := targets[:0:0]
		for _, ip := range targets {
			if !s.Skip.SkipIP(ip) {
				filtered = append(filtered, ip)
			}
		}
		targets = filtered
	}
	swept := 0
	for offset := 0; offset < len(targets); offset += bucketSize {
		if ctx.Err() != nil {
			break
		}
		end := offset + bucketSize
		if end > len(targets) {
			end = len(targets)
		}
		bucket := targets[offset:end]

		alive, err := PingSweep(ctx, bucket, s.Iface.Prefix, s.PingTimeout, s.Workers)
		if err != nil {
			log.Printf("ping sweep: %v", err)
		}

		// PingSweep replies are only subnet-scoped (macOS delivers other hosts'
		// replies too), so dedupe against everything already handled to avoid
		// re-upserting/re-enriching a host in every bucket.
		found := make([]netip.Addr, 0, len(alive))
		for _, ip := range alive {
			if k := ip.String(); !handled[k] {
				handled[k] = true
				found = append(found, ip)
			}
		}

		if len(found) > 0 {
			s.upsertHosts(found, macByIP, ipsByMAC, time.Now())
			enrich(found, macByIP, ipsByMAC)
			swept += len(found)
		}
	}

	// Stage 3: reconcile. One more neighbor-table read catches every MAC that
	// ARP resolved during the sweep. A subnet host is reconciled if it's brand
	// new (never handled) or if its MAC now differs from the seed index — the
	// latter re-keys IP-only rows that Stage 2 upserted before ARP resolved.
	newMacByIP, newIpsByMAC := indexNeighbors(Neighbors())
	resolved := make([]netip.Addr, 0)
	for _, ip := range subnetAddrs(newMacByIP, s.Iface.Prefix) {
		ipStr := ip.String()
		if !handled[ipStr] || macByIP[ipStr] != newMacByIP[ipStr] {
			handled[ipStr] = true
			resolved = append(resolved, ip)
		}
	}
	if len(resolved) > 0 {
		s.upsertHosts(resolved, newMacByIP, newIpsByMAC, time.Now())
		enrich(resolved, newMacByIP, newIpsByMAC)
	}

	enrichers.Wait()
	log.Printf("scan: complete, %d via sweep + %d reconciled, %s elapsed",
		swept, len(resolved), time.Since(start).Round(time.Millisecond))
	return nil
}

// upsert writes an observation to the store unless it matches the skip set.
func (s *Scanner) upsert(o store.Observation) {
	if s.Skip.SkipObservation(o) {
		return
	}
	s.Store.Upsert(o)
}

// upsertHosts writes the MAC / IP / vendor facts for each address into the
// store immediately (no name enrichment). Returns the addresses upserted.
func (s *Scanner) upsertHosts(addrs []netip.Addr, macByIP map[string]string, ipsByMAC map[string][]netip.Addr, now time.Time) []netip.Addr {
	seenMAC := make(map[string]bool)
	for _, ip := range dedupeAddrs(addrs) {
		mac := macByIP[ip.String()]

		observation := store.Observation{MAC: mac, Seen: now}
		classifyIP(ip, s.Iface.Prefix, &observation)

		if mac != "" {
			observation.Vendor = s.OUI.Lookup(mac)
			observation.Category = Classify(observation.Vendor, "", "")
			// Fold in any IPv6 neighbors sharing this MAC.
			if !seenMAC[mac] {
				seenMAC[mac] = true
				for _, nip := range ipsByMAC[mac] {
					classifyIP(nip, s.Iface.Prefix, &observation)
				}
			}
		}
		s.upsert(observation)
	}
	return addrs
}

// enrich resolves mDNS and reverse-DNS names for the given addresses and
// upserts them, updating existing rows in place as names come in. The two name
// sources are written independently so the faster one (mDNS) appears in the
// web view without waiting on the slower one (reverse DNS).
func (s *Scanner) enrich(ctx context.Context, addrs []netip.Addr, macByIP map[string]string, ipsByMAC map[string][]netip.Addr) {
	netIface, _ := net.InterfaceByName(s.Iface.Name)

	// mDNS first: it returns within MDNSWait and names most consumer devices.
	mdns := MDNSNames(ctx, netIface, addrs, s.MDNSWait)
	for _, ip := range dedupeAddrs(addrs) {
		ipStr := ip.String()
		mac := macByIP[ipStr]
		name := mdns[ipStr]
		// An mDNS name may have arrived on a sibling IPv6 address of this MAC.
		if name == "" && mac != "" {
			for _, nip := range ipsByMAC[mac] {
				if n := mdns[nip.String()]; n != "" {
					name = n
					break
				}
			}
		}
		if name == "" {
			continue
		}
		name = TrimTrailingMAC(name, mac)
		observation := store.Observation{MAC: mac, MDNSName: name, Seen: time.Now()}
		observation.Category = Classify(s.OUI.Lookup(mac), "", name)
		classifyIP(ip, s.Iface.Prefix, &observation)
		s.upsert(observation)
	}

	// Reverse DNS second: bounded and context-limited, written as it resolves.
	rdns := s.reverseDNSAll(ctx, addrs)
	for _, ip := range dedupeAddrs(addrs) {
		ipStr := ip.String()
		name := rdns[ipStr]
		if name == "" {
			continue
		}
		mac := macByIP[ipStr]
		name = TrimTrailingMAC(name, mac)
		observation := store.Observation{MAC: mac, Hostname: name, Seen: time.Now()}
		observation.Category = Classify(s.OUI.Lookup(mac), name, "")
		classifyIP(ip, s.Iface.Prefix, &observation)
		s.upsert(observation)
	}
}

// browse runs a single network-wide DNS-SD/AirPlay enumeration and upserts the
// resulting friendly names and refined categories. Because the browse yields
// IPs directly, it consults the neighbor tables once to attach the MAC/vendor
// (needed to tell a smart-TV AirPlay receiver from an audio one) and to key the
// record by MAC where possible.
func (s *Scanner) browse(ctx context.Context) {
	netIface, _ := net.InterfaceByName(s.Iface.Name)
	devices := MDNSBrowse(ctx, netIface, s.MDNSWait)
	if len(devices) == 0 {
		return
	}
	macByIP, _ := indexNeighbors(Neighbors())
	for ipStr, d := range devices {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		mac := macByIP[ipStr]
		observation := store.Observation{
			MAC:          mac,
			MDNSName:     TrimTrailingMAC(d.Name, mac),
			MDNSModel:    d.Model,
			MDNSServices: d.Services,
			Seen:         time.Now(),
		}
		observation.Category = ClassifyService(s.OUI.Lookup(mac), d.Model, d.Services)
		classifyIP(ip, s.Iface.Prefix, &observation)
		s.upsert(observation)
	}
}

// indexNeighbors builds two lookup maps from a neighbor list:
// macByIP maps IP string → MAC, and ipsByMAC maps MAC → list of IPs.
func indexNeighbors(neighbors []Neighbor) (macByIP map[string]string, ipsByMAC map[string][]netip.Addr) {
	macByIP = make(map[string]string, len(neighbors))
	ipsByMAC = make(map[string][]netip.Addr)
	for _, n := range neighbors {
		macByIP[n.IP.String()] = n.MAC
		ipsByMAC[n.MAC] = append(ipsByMAC[n.MAC], n.IP)
	}
	return
}

// subnetAddrs returns all IPs from macByIP that fall within prefix.
func subnetAddrs(macByIP map[string]string, prefix netip.Prefix) []netip.Addr {
	out := make([]netip.Addr, 0, len(macByIP))
	for ipStr := range macByIP {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		if prefix.Contains(ip) && !isBroadcastIP(ip, prefix) {
			out = append(out, ip)
		}
	}
	return out
}

// Run scans once immediately, then repeatedly until ctx is cancelled, pausing
// for 2x the duration of the scan that just finished between runs (clamped to a
// minimum of interval) so back-to-back scans don't saturate the network.
func (s *Scanner) Run(ctx context.Context, interval time.Duration) {
	wake := s.wakeCh()
	for {
		// While paused, idle without scanning. A resume signal (or ctx cancel)
		// breaks out promptly; the short poll is a backstop.
		if s.Paused() {
			select {
			case <-ctx.Done():
				return
			case <-wake:
			case <-time.After(time.Second):
			}
			continue
		}

		start := time.Now()
		if err := s.Scan(ctx); err != nil {
			log.Printf("scan error: %v", err)
		}
		pause := 2 * time.Since(start)
		if pause < interval {
			pause = interval
		}
		log.Printf("scan: pausing %s before next scan", pause.Round(time.Millisecond))
		t := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-wake:
			// Resumed mid-wait — fall through to scan right away.
			t.Stop()
		case <-t.C:
		}
	}
}

func (s *Scanner) reverseDNSAll(ctx context.Context, ips []netip.Addr) map[string]string {
	out := make(map[string]string)
	var mu sync.Mutex
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for _, ip := range dedupeAddrs(ips) {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			if name := ReverseDNS(ctx, ip.String()); name != "" {
				mu.Lock()
				out[ip.String()] = name
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	return out
}

// classifyIP records an address into the right bucket of an observation.
// IPv4 addresses inside the scanned subnet are the host's primary IPs; IPv4
// outside it (e.g. 169.254/16 APIPA leftovers, or addresses on another subnet)
// are tracked separately as secondary so they never drive the primary sort.
func classifyIP(ip netip.Addr, scope netip.Prefix, observation *store.Observation) {
	ip = ip.Unmap()
	s := ip.String()
	switch {
	case ip.Is4():
		if scope.IsValid() && scope.Contains(ip) {
			observation.IPv4 = appendUnique(observation.IPv4, s)
		} else {
			observation.SecondaryIPs = appendUnique(observation.SecondaryIPs, s)
		}
	case ip.IsLinkLocalUnicast():
		observation.IPv6Local = appendUnique(observation.IPv6Local, stripZone(s))
	default:
		observation.IPv6Global = appendUnique(observation.IPv6Global, stripZone(s))
	}
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func stripZone(s string) string {
	if i := strings.IndexByte(s, '%'); i >= 0 {
		return s[:i]
	}
	return s
}

func dedupeAddrs(in []netip.Addr) []netip.Addr {
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, a := range in {
		k := a.String()
		if !seen[k] {
			seen[k] = true
			out = append(out, a)
		}
	}
	return out
}
