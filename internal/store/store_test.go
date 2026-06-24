package store

import (
	"testing"
	"time"
)

// find returns the single host whose key matches, or fails the test.
func find(t *testing.T, s *Store, key string) Host {
	t.Helper()
	for _, h := range s.Snapshot() {
		if h.Key == key {
			return h
		}
	}
	t.Fatalf("no host with key %q in store", key)
	return Host{}
}

func TestUpsertKeyedByMAC(t *testing.T) {
	s := New()
	s.Upsert(Observation{MAC: "aa:bb:cc:dd:ee:ff", IPv4: []string{"192.168.1.10"}, Vendor: "Acme"})

	hosts := s.Snapshot()
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	h := hosts[0]
	if h.Key != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("key = %q, want MAC", h.Key)
	}
	if len(h.IPv4) != 1 || h.IPv4[0] != "192.168.1.10" {
		t.Errorf("ipv4 = %v", h.IPv4)
	}
}

func TestUpsertFallsBackToIP(t *testing.T) {
	s := New()
	s.Upsert(Observation{IPv4: []string{"192.168.1.20"}})

	h := find(t, s, "192.168.1.20")
	if h.MAC != "" {
		t.Errorf("MAC = %q, want empty", h.MAC)
	}
}

func TestUpsertNoKeyIgnored(t *testing.T) {
	s := New()
	s.Upsert(Observation{Hostname: "ghost"}) // no MAC, no IPv4
	if n := len(s.Snapshot()); n != 0 {
		t.Fatalf("got %d hosts, want 0 (keyless observation must be dropped)", n)
	}
}

func TestReKeyFromIPToMAC(t *testing.T) {
	s := New()
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)

	// First seen by IP only (no MAC resolved yet).
	s.Upsert(Observation{IPv4: []string{"192.168.1.30"}, Seen: t0})
	// Later the MAC resolves for the same IP — the record should migrate.
	s.Upsert(Observation{MAC: "11:22:33:44:55:66", IPv4: []string{"192.168.1.30"}, Vendor: "Acme", Seen: t1})

	hosts := s.Snapshot()
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1 after re-key", len(hosts))
	}
	h := hosts[0]
	if h.Key != "11:22:33:44:55:66" {
		t.Errorf("key = %q, want MAC after re-key", h.Key)
	}
	if !h.FirstSeen.Equal(t0) {
		t.Errorf("FirstSeen = %v, want %v (must survive re-key)", h.FirstSeen, t0)
	}
	if h.Vendor != "Acme" {
		t.Errorf("Vendor = %q, want Acme", h.Vendor)
	}
}

// A dual-homed monitor host can create an IP-keyed orphan (an mDNS/DNS-SD reply
// observed before ARP resolves the sender) after the device's MAC record already
// exists. A later observation carrying both MAC and that IP must fold the orphan
// in rather than leaving two rows for one device.
func TestOrphanFoldedAfterMACExists(t *testing.T) {
	s := New()
	mac := "aa:bb:cc:00:11:22"
	ip := "192.168.7.109"

	// MAC record is established first (e.g. seeded from the ARP table).
	s.Upsert(Observation{MAC: mac, IPv4: []string{ip}, Vendor: "Espressif"})
	// Then a name-only mDNS observation arrives with no MAC → IP-keyed orphan.
	s.Upsert(Observation{IPv4: []string{ip}, MDNSName: "shellydimmer2-C45BBE56DE9D"})
	if n := len(s.Snapshot()); n != 2 {
		t.Fatalf("precondition: got %d hosts, want 2 (MAC record + orphan)", n)
	}

	// A subsequent scan sees both MAC and IP again: the orphan must be absorbed.
	s.Upsert(Observation{MAC: mac, IPv4: []string{ip}})

	hosts := s.Snapshot()
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1 after orphan folded in", len(hosts))
	}
	h := hosts[0]
	if h.Key != mac {
		t.Errorf("key = %q, want MAC", h.Key)
	}
	if h.MDNSName != "shellydimmer2-C45BBE56DE9D" {
		t.Errorf("MDNSName = %q, want the name learned while orphaned", h.MDNSName)
	}
	if len(h.IPv4) != 1 || h.IPv4[0] != ip {
		t.Errorf("IPv4 = %v, want [%s]", h.IPv4, ip)
	}
}

func TestReconcileOrphans(t *testing.T) {
	s := New()
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)

	// Simulate a DB persisted by an older version: a MAC-keyed host and a
	// separate IP-keyed orphan for one of its IPs, plus a genuinely unresolved
	// host that must be left alone.
	s.Restore([]Host{
		{Key: "aa:bb:cc:dd:ee:01", MAC: "aa:bb:cc:dd:ee:01", IPv4: []string{"192.168.7.197"}, FirstSeen: t0, LastSeen: t0},
		{Key: "192.168.7.197", IPv4: []string{"192.168.7.197"}, MDNSName: "Garage Door 4AE53A", Comment: "note", FirstSeen: t0.Add(-time.Hour), LastSeen: t0.Add(time.Hour)},
		{Key: "192.168.7.250", IPv4: []string{"192.168.7.250"}}, // no MAC owner anywhere
	})

	if n := s.ReconcileOrphans(); n != 1 {
		t.Fatalf("ReconcileOrphans folded %d, want 1", n)
	}

	hosts := s.Snapshot()
	if len(hosts) != 2 {
		t.Fatalf("got %d hosts, want 2 (MAC host + untouched orphan)", len(hosts))
	}

	merged := find(t, s, "aa:bb:cc:dd:ee:01")
	if merged.MDNSName != "Garage Door 4AE53A" {
		t.Errorf("MDNSName = %q, want the orphan's name folded in", merged.MDNSName)
	}
	if merged.Comment != "note" {
		t.Errorf("Comment = %q, want the orphan's comment preserved", merged.Comment)
	}
	if !merged.FirstSeen.Equal(t0.Add(-time.Hour)) {
		t.Errorf("FirstSeen = %v, want the earlier orphan time", merged.FirstSeen)
	}
	if !merged.LastSeen.Equal(t0.Add(time.Hour)) {
		t.Errorf("LastSeen = %v, want the later orphan time", merged.LastSeen)
	}

	// The unowned orphan is genuinely unresolved and must survive.
	find(t, s, "192.168.7.250")
}

func TestFirstLastSeenMonotonic(t *testing.T) {
	s := New()
	t1 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	t0 := t1.Add(-time.Hour)
	t2 := t1.Add(time.Hour)

	s.Upsert(Observation{MAC: "aa:aa:aa:aa:aa:aa", Seen: t1})
	s.Upsert(Observation{MAC: "aa:aa:aa:aa:aa:aa", Seen: t2}) // later
	s.Upsert(Observation{MAC: "aa:aa:aa:aa:aa:aa", Seen: t0}) // earlier

	h := find(t, s, "aa:aa:aa:aa:aa:aa")
	if !h.FirstSeen.Equal(t0) {
		t.Errorf("FirstSeen = %v, want earliest %v", h.FirstSeen, t0)
	}
	if !h.LastSeen.Equal(t2) {
		t.Errorf("LastSeen = %v, want latest %v", h.LastSeen, t2)
	}
}

func TestMergeDoesNotClobber(t *testing.T) {
	s := New()
	mac := "de:ad:be:ef:00:01"
	// Learn vendor first, then a name in a later partial observation.
	s.Upsert(Observation{MAC: mac, Vendor: "Acme", IPv4: []string{"10.0.0.5"}})
	s.Upsert(Observation{MAC: mac, Hostname: "printer.local", Category: "printer"})
	// A neighbor-table refresh replaces stale IPv4 with the current address.
	s.Upsert(Observation{MAC: mac, IPv4: []string{"10.0.0.6"}, RefreshIPs: true})

	h := find(t, s, mac)
	if h.Vendor != "Acme" {
		t.Errorf("Vendor = %q, want Acme (must not be clobbered)", h.Vendor)
	}
	if h.Hostname != "printer.local" {
		t.Errorf("Hostname = %q, want printer.local", h.Hostname)
	}
	if h.Category != "printer" {
		t.Errorf("Category = %q, want printer", h.Category)
	}
	if len(h.IPv4) != 1 || h.IPv4[0] != "10.0.0.6" {
		t.Errorf("IPv4 = %v, want only the refreshed address", h.IPv4)
	}
}

func TestRefreshIPsKeepsDualHomed(t *testing.T) {
	s := New()
	mac := "de:ad:be:ef:00:03"
	s.Upsert(Observation{
		MAC: mac, Vendor: "Acme",
		IPv4: []string{"10.0.0.5", "10.0.0.6"},
		RefreshIPs: true,
	})

	h := find(t, s, mac)
	if len(h.IPv4) != 2 {
		t.Fatalf("IPv4 = %v, want both concurrent addresses", h.IPv4)
	}
}

func TestRefreshIPsClearsStaleIPv4(t *testing.T) {
	s := New()
	mac := "de:ad:be:ef:00:04"
	s.Upsert(Observation{MAC: mac, IPv4: []string{"10.0.0.5", "10.0.0.6"}})
	s.Upsert(Observation{MAC: mac, IPv4: []string{"10.0.0.6"}, RefreshIPs: true})

	h := find(t, s, mac)
	if len(h.IPv4) != 1 || h.IPv4[0] != "10.0.0.6" {
		t.Errorf("IPv4 = %v, want only the current address", h.IPv4)
	}
}

func TestSetComment(t *testing.T) {
	s := New()
	mac := "aa:bb:cc:dd:ee:ff"
	s.Upsert(Observation{MAC: mac, IPv4: []string{"192.168.1.10"}})

	h, ok := s.SetComment(mac, "front-door camera")
	if !ok {
		t.Fatal("SetComment returned false for a known host")
	}
	if h.Comment != "front-door camera" {
		t.Errorf("returned Comment = %q, want %q", h.Comment, "front-door camera")
	}
	if got := find(t, s, mac); got.Comment != "front-door camera" {
		t.Errorf("stored Comment = %q, want %q", got.Comment, "front-door camera")
	}

	if _, ok := s.SetComment("99:99:99:99:99:99", "ghost"); ok {
		t.Error("SetComment returned true for an unknown key")
	}
}

func TestCommentSurvivesObservationMerge(t *testing.T) {
	s := New()
	mac := "de:ad:be:ef:00:02"
	s.Upsert(Observation{MAC: mac, IPv4: []string{"10.0.0.5"}})
	s.SetComment(mac, "lab raspberry pi")

	// A later scan (no comment field on observations) must not blank the note.
	s.Upsert(Observation{MAC: mac, IPv4: []string{"10.0.0.6"}, Hostname: "pi.local", RefreshIPs: true})

	if got := find(t, s, mac).Comment; got != "lab raspberry pi" {
		t.Errorf("Comment = %q, want it preserved across upsert", got)
	}
}

func TestCommentFollowsMACAcrossReKey(t *testing.T) {
	s := New()
	ip := "192.168.1.40"
	mac := "11:22:33:44:55:77"

	// Host first seen by IP only; user adds a note while it's IP-keyed.
	s.Upsert(Observation{IPv4: []string{ip}})
	if _, ok := s.SetComment(ip, "unknown box on the shelf"); !ok {
		t.Fatal("SetComment on IP-keyed host failed")
	}

	// The MAC later resolves: the record re-keys and the note must follow.
	s.Upsert(Observation{MAC: mac, IPv4: []string{ip}})

	hosts := s.Snapshot()
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1 after re-key", len(hosts))
	}
	if hosts[0].Key != mac {
		t.Errorf("key = %q, want MAC after re-key", hosts[0].Key)
	}
	if hosts[0].Comment != "unknown box on the shelf" {
		t.Errorf("Comment = %q, want it to follow the MAC", hosts[0].Comment)
	}
}

func TestSnapshotIsSortedByIP(t *testing.T) {
	s := New()
	s.Upsert(Observation{MAC: "aa:00:00:00:00:01", IPv4: []string{"192.168.1.10"}})
	s.Upsert(Observation{MAC: "aa:00:00:00:00:02", IPv4: []string{"192.168.1.2"}})
	s.Upsert(Observation{MAC: "aa:00:00:00:00:03", IPv4: []string{"192.168.1.100"}})

	hosts := s.Snapshot()
	got := []string{hosts[0].IPv4[0], hosts[1].IPv4[0], hosts[2].IPv4[0]}
	want := []string{"192.168.1.2", "192.168.1.10", "192.168.1.100"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("snapshot order = %v, want numeric IP order %v", got, want)
		}
	}
}
