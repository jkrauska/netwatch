package scan

import (
	"net/netip"
	"testing"

	"github.com/jkrauska/netwatch/internal/store"
)

func TestSkipSetEmpty(t *testing.T) {
	if !NewSkipSet(nil, nil).Empty() {
		t.Fatal("expected empty set")
	}
	if NewSkipSet([]string{"192.168.7.60"}, nil).Empty() {
		t.Fatal("set with an IP should not be empty")
	}
	// Unparseable inputs are dropped, leaving the set empty.
	if !NewSkipSet([]string{"not-an-ip"}, []string{"zz:zz"}).Empty() {
		t.Fatal("expected unparseable entries to be dropped")
	}
}

func TestSkipIP(t *testing.T) {
	s := NewSkipSet([]string{"192.168.7.60"}, nil)
	if !s.SkipIP(netip.MustParseAddr("192.168.7.60")) {
		t.Fatal("expected 192.168.7.60 to be skipped")
	}
	if s.SkipIP(netip.MustParseAddr("192.168.7.61")) {
		t.Fatal("did not expect 192.168.7.61 to be skipped")
	}
}

func TestSkipMACNormalizes(t *testing.T) {
	// Input MAC uses upper case and a non-padded octet; matching must still
	// succeed against the normalized form from the neighbor table.
	s := NewSkipSet(nil, []string{"B8:E9:37:50:29:88"})
	if !s.SkipMAC("b8:e9:37:50:29:88") {
		t.Fatal("expected MAC to match regardless of case")
	}
	if !NewSkipSet(nil, []string{"8:0:20:0:0:0"}).SkipMAC("08:00:20:00:00:00") {
		t.Fatal("expected zero-padded MAC to match")
	}
	if s.SkipMAC("") {
		t.Fatal("empty MAC must never match")
	}
}

func TestSkipObservation(t *testing.T) {
	s := NewSkipSet([]string{"192.168.7.60"}, []string{"b8:e9:37:50:29:88"})

	if !s.SkipObservation(store.Observation{MAC: "b8:e9:37:50:29:88"}) {
		t.Fatal("expected skip by MAC")
	}
	if !s.SkipObservation(store.Observation{IPv4: []string{"192.168.7.60"}}) {
		t.Fatal("expected skip by IPv4")
	}
	if !s.SkipObservation(store.Observation{SecondaryIPs: []string{"192.168.7.60"}}) {
		t.Fatal("expected skip by secondary IP")
	}
	if s.SkipObservation(store.Observation{MAC: "aa:bb:cc:dd:ee:ff", IPv4: []string{"192.168.7.61"}}) {
		t.Fatal("did not expect a non-matching observation to be skipped")
	}

	// A nil/empty set skips nothing.
	if NewSkipSet(nil, nil).SkipObservation(store.Observation{IPv4: []string{"192.168.7.60"}}) {
		t.Fatal("empty set must not skip")
	}
}
