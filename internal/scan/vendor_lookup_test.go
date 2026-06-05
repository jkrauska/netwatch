package scan

import (
	"strings"
	"testing"
)

// newTestOUI builds an OUI table from an inline manuf snippet (tab-separated,
// same format as the embedded Wireshark database).
func newTestOUI(t *testing.T, lines ...string) *OUI {
	t.Helper()
	o := &OUI{table: make(map[string]string)}
	o.load(strings.NewReader(strings.Join(lines, "\n")))
	return o
}

func TestOUILookupPrefixLengths(t *testing.T) {
	o := newTestOUI(t,
		"# a comment line, ignored",
		"00:00:0C\tCisco\tCisco Systems, Inc",                         // 24-bit OUI
		"00:55:DA:A0:00:00/28\tIEEERegi\tIEEE Registration Authority", // 28-bit
		"8C:1F:64:80:00:00/36\tSpecific\tSpecific Vendor 36",          // 36-bit
	)

	cases := []struct {
		name, mac, want string
	}{
		{"24-bit OUI", "00:00:0c:11:22:33", "Cisco Systems, Inc"},
		{"28-bit prefix", "00:55:da:a5:11:22", "IEEE Registration Authority"},
		{"36-bit prefix", "8c:1f:64:80:01:23", "Specific Vendor 36"},
		{"unknown miss", "ff:ee:dd:cc:bb:aa", ""},
		{"empty mac", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := o.Lookup(c.mac); got != c.want {
				t.Fatalf("Lookup(%q) = %q, want %q", c.mac, got, c.want)
			}
		})
	}
}

func TestOUILongestPrefixWins(t *testing.T) {
	// A 36-bit sub-allocation nested inside its parent 24-bit OUI: the longer,
	// more specific prefix must win.
	o := newTestOUI(t,
		"8C:1F:64\tParent\tParent Vendor 24",
		"8C:1F:64:80:00:00/36\tChild\tChild Vendor 36",
	)
	if got := o.Lookup("8c:1f:64:80:01:23"); got != "Child Vendor 36" {
		t.Fatalf("nested lookup = %q, want Child Vendor 36", got)
	}
	// An address inside the parent but outside the child falls back to the OUI.
	if got := o.Lookup("8c:1f:64:10:00:00"); got != "Parent Vendor 24" {
		t.Fatalf("parent fallback = %q, want Parent Vendor 24", got)
	}
}

func TestParseManufLine(t *testing.T) {
	cases := []struct {
		name, line, prefix, vendor string
		ok                         bool
	}{
		{"24-bit", "00:00:0C\tCisco\tCisco Systems, Inc", "00000c", "Cisco Systems, Inc", true},
		{"short name only", "AC:DE:48\tPrivate", "acde48", "Private", true},
		{"28-bit mask", "00:55:DA:A0:00:00/28\tx\tIEEE", "0055daa", "IEEE", true},
		{"comment", "# header", "", "", false},
		{"blank", "", "", "", false},
		{"single column", "00:00:0C", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prefix, vendor, ok := parseManufLine(c.line)
			if ok != c.ok || prefix != c.prefix || vendor != c.vendor {
				t.Fatalf("parseManufLine(%q) = (%q,%q,%v), want (%q,%q,%v)",
					c.line, prefix, vendor, ok, c.prefix, c.vendor, c.ok)
			}
		})
	}
}

// TestEmbeddedOUILoads is a smoke test that the embedded manuf database parses
// into a non-trivial table.
func TestEmbeddedOUILoads(t *testing.T) {
	o := NewOUI()
	o.mu.RLock()
	n := len(o.table)
	o.mu.RUnlock()
	if n < 1000 {
		t.Fatalf("embedded manuf table only has %d entries, expected thousands", n)
	}
}
