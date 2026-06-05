// Package store holds the in-memory inventory of discovered hosts.
package store

import (
	"sort"
	"sync"
	"time"
)

// Host is a single device discovered on the network. It is keyed in the store
// by MAC address when one is known, otherwise by its first-seen IPv4 address.
type Host struct {
	Key          string    `json:"key"`
	MAC          string    `json:"mac"`
	Vendor       string    `json:"vendor"`
	IPv4         []string  `json:"ipv4"`
	SecondaryIPs []string  `json:"secondary_ips"` // IPv4 outside the scanned subnet (e.g. 169.254/16 APIPA)
	IPv6Local    []string  `json:"ipv6_local"`    // link-local fe80::/10
	IPv6Global   []string  `json:"ipv6_global"`   // routable / ULA
	Hostname     string    `json:"hostname"`      // reverse DNS (PTR)
	MDNSName     string    `json:"mdns_name"`     // mDNS / DNS-SD instance name
	MDNSModel    string    `json:"mdns_model"`    // DNS-SD model= TXT value (e.g. "AppleTV6,2", "J617")
	MDNSServices []string  `json:"mdns_services"` // DNS-SD service types advertised (e.g. "_airplay._tcp")
	Category     string    `json:"category"`      // derived device class (e.g. "wifi", "music")
	Comment      string    `json:"comment"`       // user-editable note; keyed by MAC so it follows the device across IP changes
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// Observation is the set of facts a scan learned about one host. Empty fields
// are ignored on merge so partial enrichment never clobbers known data.
type Observation struct {
	MAC          string
	Vendor       string
	IPv4         []string
	SecondaryIPs []string
	IPv6Local    []string
	IPv6Global   []string
	Hostname     string
	MDNSName     string
	MDNSModel    string
	MDNSServices []string
	Category     string
	Seen         time.Time
}

// Persister is an optional write-through backend (e.g. SQLite). The store
// calls SaveHost whenever a host changes and DeleteHost when a record is
// re-keyed away from a stale key.
type Persister interface {
	SaveHost(Host) error
	DeleteHost(key string) error
}

// Store is a concurrency-safe collection of hosts.
type Store struct {
	mu        sync.RWMutex
	hosts     map[string]*Host
	persister Persister
}

func New() *Store {
	return &Store{hosts: make(map[string]*Host)}
}

// SetPersister installs a write-through backend. Call before scanning starts.
func (s *Store) SetPersister(p Persister) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persister = p
}

// Restore loads previously persisted hosts into the store. Existing in-memory
// hosts with the same key are overwritten.
func (s *Store) Restore(hosts []Host) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range hosts {
		hostCopy := h
		s.hosts[h.Key] = &hostCopy
	}
}

// Upsert merges an observation into the store, creating or updating a host.
// The dedupe key is the MAC if present, else the first IPv4. If a host was
// previously keyed by IP and we later learn its MAC, the record is re-keyed.
func (s *Store) Upsert(o Observation) {
	if o.Seen.IsZero() {
		o.Seen = time.Now()
	}

	saved, deletedKey, persister := s.upsertLocked(o)

	// Persist outside the lock so DB IO never blocks other readers/writers.
	if persister != nil && saved != nil {
		if deletedKey != "" {
			_ = persister.DeleteHost(deletedKey)
		}
		_ = persister.SaveHost(*saved)
	}
}

// upsertLocked performs the in-memory merge under the write lock and returns a
// deep copy of the affected host (for persistence), any key that was vacated by
// a re-key migration, and the active persister.
func (s *Store) upsertLocked(o Observation) (saved *Host, deletedKey string, persister Persister) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := o.MAC
	if key == "" && len(o.IPv4) > 0 {
		key = o.IPv4[0]
	}
	if key == "" {
		return nil, "", nil
	}

	// If this MAC was first seen via an IP-keyed record, migrate it.
	if o.MAC != "" {
		if _, ok := s.hosts[o.MAC]; !ok {
			for _, ip := range o.IPv4 {
				if h, ok := s.hosts[ip]; ok && h.MAC == "" {
					delete(s.hosts, ip)
					h.Key = o.MAC
					s.hosts[o.MAC] = h
					deletedKey = ip
					break
				}
			}
		}
	}

	h := s.hosts[key]
	if h == nil {
		h = &Host{Key: key, FirstSeen: o.Seen}
		s.hosts[key] = h
	}

	if o.MAC != "" {
		h.MAC = o.MAC
	}
	if o.Vendor != "" {
		h.Vendor = o.Vendor
	}
	if o.Hostname != "" {
		h.Hostname = o.Hostname
	}
	if o.MDNSName != "" {
		h.MDNSName = o.MDNSName
	}
	if o.MDNSModel != "" {
		h.MDNSModel = o.MDNSModel
	}
	if o.Category != "" {
		h.Category = o.Category
	}
	h.MDNSServices = mergeStrings(h.MDNSServices, o.MDNSServices)
	h.IPv4 = mergeStrings(h.IPv4, o.IPv4)
	h.SecondaryIPs = mergeStrings(h.SecondaryIPs, o.SecondaryIPs)
	h.IPv6Local = mergeStrings(h.IPv6Local, o.IPv6Local)
	h.IPv6Global = mergeStrings(h.IPv6Global, o.IPv6Global)

	if o.Seen.After(h.LastSeen) {
		h.LastSeen = o.Seen
	}
	if h.FirstSeen.IsZero() || o.Seen.Before(h.FirstSeen) {
		h.FirstSeen = o.Seen
	}

	clone := cloneHost(h)
	return &clone, deletedKey, s.persister
}

// SetComment sets the user-editable note on the host identified by key and
// write-through persists it. Because hosts are keyed by MAC when one is known,
// the note follows the device even as its IP addresses change. It returns the
// updated host and true if a matching host exists, or false if key is unknown.
func (s *Store) SetComment(key, comment string) (Host, bool) {
	saved, persister := s.setCommentLocked(key, comment)
	if saved == nil {
		return Host{}, false
	}
	if persister != nil {
		_ = persister.SaveHost(*saved)
	}
	return *saved, true
}

func (s *Store) setCommentLocked(key, comment string) (*Host, Persister) {
	s.mu.Lock()
	defer s.mu.Unlock()

	h := s.hosts[key]
	if h == nil {
		return nil, nil
	}
	h.Comment = comment
	clone := cloneHost(h)
	return &clone, s.persister
}

// cloneHost returns a deep copy safe to use outside the store lock.
func cloneHost(h *Host) Host {
	c := *h
	c.IPv4 = append([]string(nil), h.IPv4...)
	c.SecondaryIPs = append([]string(nil), h.SecondaryIPs...)
	c.IPv6Local = append([]string(nil), h.IPv6Local...)
	c.IPv6Global = append([]string(nil), h.IPv6Global...)
	c.MDNSServices = append([]string(nil), h.MDNSServices...)
	return c
}

// Snapshot returns a copy of all hosts sorted by IPv4 then key.
func (s *Store) Snapshot() []Host {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Host, 0, len(s.hosts))
	for _, h := range s.hosts {
		out = append(out, cloneHost(h))
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := primaryIP(out[i]), primaryIP(out[j])
		if a != b {
			return ipLess(a, b)
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func primaryIP(h Host) string {
	if len(h.IPv4) > 0 {
		return h.IPv4[0]
	}
	return ""
}

func mergeStrings(existing, incoming []string) []string {
	seen := make(map[string]bool, len(existing))
	out := existing
	for _, v := range existing {
		seen[v] = true
	}
	for _, v := range incoming {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
