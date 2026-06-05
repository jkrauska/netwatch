package store

import (
	"path/filepath"
	"testing"
	"time"
)

func openTempDB(t *testing.T) *DB {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func sampleHost() Host {
	return Host{
		Key:          "aa:bb:cc:dd:ee:ff",
		MAC:          "aa:bb:cc:dd:ee:ff",
		Vendor:       "Acme, Inc.",
		IPv4:         []string{"192.168.1.10", "192.168.1.11"},
		SecondaryIPs: []string{"169.254.1.1"},
		IPv6Local:    []string{"fe80::1"},
		IPv6Global:   []string{"fd00::1"},
		Hostname:     "host.local",
		MDNSName:     "Acme-Device",
		Category:     "iot",
		Comment:      "kitchen sensor — do not unplug",
		FirstSeen:    time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		LastSeen:     time.Date(2026, 1, 2, 9, 8, 7, 0, time.UTC),
	}
}

func TestPersistRoundTrip(t *testing.T) {
	db := openTempDB(t)
	want := sampleHost()
	if err := db.SaveHost(want); err != nil {
		t.Fatalf("SaveHost: %v", err)
	}

	loaded, err := db.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("Load returned %d hosts, want 1", len(loaded))
	}
	got := loaded[0]

	if got.Key != want.Key || got.MAC != want.MAC || got.Vendor != want.Vendor ||
		got.Hostname != want.Hostname || got.MDNSName != want.MDNSName || got.Category != want.Category ||
		got.Comment != want.Comment {
		t.Errorf("scalar mismatch:\n got %+v\nwant %+v", got, want)
	}
	if !got.FirstSeen.Equal(want.FirstSeen) || !got.LastSeen.Equal(want.LastSeen) {
		t.Errorf("times: got first=%v last=%v, want first=%v last=%v",
			got.FirstSeen, got.LastSeen, want.FirstSeen, want.LastSeen)
	}
	assertSlice(t, "IPv4", got.IPv4, want.IPv4)
	assertSlice(t, "SecondaryIPs", got.SecondaryIPs, want.SecondaryIPs)
	assertSlice(t, "IPv6Local", got.IPv6Local, want.IPv6Local)
	assertSlice(t, "IPv6Global", got.IPv6Global, want.IPv6Global)
}

func TestSaveHostUpserts(t *testing.T) {
	db := openTempDB(t)
	h := sampleHost()
	if err := db.SaveHost(h); err != nil {
		t.Fatalf("SaveHost: %v", err)
	}
	h.Vendor = "Updated Vendor"
	h.LastSeen = h.LastSeen.Add(time.Hour)
	if err := db.SaveHost(h); err != nil {
		t.Fatalf("SaveHost update: %v", err)
	}

	loaded, _ := db.Load()
	if len(loaded) != 1 {
		t.Fatalf("got %d rows, want 1 after upsert", len(loaded))
	}
	if loaded[0].Vendor != "Updated Vendor" {
		t.Errorf("Vendor = %q, want updated", loaded[0].Vendor)
	}
}

func TestDeleteHost(t *testing.T) {
	db := openTempDB(t)
	h := sampleHost()
	_ = db.SaveHost(h)
	if err := db.DeleteHost(h.Key); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}
	loaded, _ := db.Load()
	if len(loaded) != 0 {
		t.Fatalf("got %d rows after delete, want 0", len(loaded))
	}
}

func TestSaveAllPrunes(t *testing.T) {
	db := openTempDB(t)
	a := sampleHost()
	b := sampleHost()
	b.Key, b.MAC = "11:11:11:11:11:11", "11:11:11:11:11:11"
	c := sampleHost()
	c.Key, c.MAC = "22:22:22:22:22:22", "22:22:22:22:22:22"

	_ = db.SaveHost(a)
	_ = db.SaveHost(b)
	_ = db.SaveHost(c)

	// Reconcile with only a and c present: b must be pruned.
	if err := db.SaveAll([]Host{a, c}); err != nil {
		t.Fatalf("SaveAll: %v", err)
	}

	loaded, _ := db.Load()
	if len(loaded) != 2 {
		t.Fatalf("got %d rows, want 2 after prune", len(loaded))
	}
	for _, h := range loaded {
		if h.Key == b.Key {
			t.Errorf("key %q should have been pruned", b.Key)
		}
	}
}

func assertSlice(t *testing.T, field string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s len = %d, want %d (%v vs %v)", field, len(got), len(want), got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %q, want %q", field, i, got[i], want[i])
		}
	}
}
