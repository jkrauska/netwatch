package scan

import (
	"net/netip"
	"strings"

	"github.com/jkrauska/netwatch/internal/store"
)

// SkipSet holds IP and MAC addresses to exclude from scan results entirely.
// Matching hosts are never pinged, enriched, or written to the store.
type SkipSet struct {
	ips  map[string]struct{}
	macs map[string]struct{}
}

// NewSkipSet builds a SkipSet from raw IP and MAC strings. Unparseable entries
// are ignored. IPs are normalized via netip and MACs via normalizeMAC so the
// matching is independent of the input's exact formatting.
func NewSkipSet(ips, macs []string) *SkipSet {
	s := &SkipSet{ips: make(map[string]struct{}), macs: make(map[string]struct{})}
	for _, raw := range ips {
		if a, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil {
			s.ips[a.Unmap().String()] = struct{}{}
		}
	}
	for _, raw := range macs {
		if mac := normalizeMAC(strings.TrimSpace(raw)); mac != "" {
			s.macs[mac] = struct{}{}
		}
	}
	return s
}

// Empty reports whether the set excludes nothing.
func (s *SkipSet) Empty() bool {
	return s == nil || (len(s.ips) == 0 && len(s.macs) == 0)
}

// SkipIP reports whether ip is excluded.
func (s *SkipSet) SkipIP(ip netip.Addr) bool {
	if s == nil {
		return false
	}
	_, ok := s.ips[ip.Unmap().String()]
	return ok
}

// SkipMAC reports whether mac is excluded.
func (s *SkipSet) SkipMAC(mac string) bool {
	if s == nil || mac == "" {
		return false
	}
	_, ok := s.macs[normalizeMAC(mac)]
	return ok
}

// SkipObservation reports whether an observation matches the skip set by MAC or
// by any of its IPv4 / secondary / IPv6 addresses.
func (s *SkipSet) SkipObservation(o store.Observation) bool {
	if s.Empty() {
		return false
	}
	if s.SkipMAC(o.MAC) {
		return true
	}
	for _, group := range [][]string{o.IPv4, o.SecondaryIPs, o.IPv6Local, o.IPv6Global} {
		for _, ip := range group {
			if a, err := netip.ParseAddr(ip); err == nil && s.SkipIP(a) {
				return true
			}
		}
	}
	return false
}
