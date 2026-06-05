package scan

import "testing"

func TestTrimTrailingMAC(t *testing.T) {
	cases := []struct {
		name string
		in   string
		mac  string
		want string
	}{
		{"shelly no separators", "shellydimmer2-C45BBE56DE9D", "c4:5b:be:56:de:9d", "shellydimmer2"},
		{"underscore join", "shelly1_C45BBE56DE9D", "c4:5b:be:56:de:9d", "shelly1"},
		{"colon-separated mac in name", "tasmota-C4:5B:BE:56:DE:9D", "c4:5b:be:56:de:9d", "tasmota"},
		{"dot-separated mac in name", "esp.c4.5b.be.56.de.9d", "c4:5b:be:56:de:9d", "esp"},
		{"lowercase suffix", "plug-c45bbe56de9d", "c4:5b:be:56:de:9d", "plug"},
		{"trailing dot domain not trimmed", "shellydimmer2-C45BBE56DE9D.local", "c4:5b:be:56:de:9d", "shellydimmer2-C45BBE56DE9D.local"},

		// Left unchanged.
		{"no mac suffix", "living-room-lamp", "c4:5b:be:56:de:9d", "living-room-lamp"},
		{"different mac", "shellydimmer2-AABBCCDDEEFF", "c4:5b:be:56:de:9d", "shellydimmer2-AABBCCDDEEFF"},
		{"partial mac suffix", "node-56DE9D", "c4:5b:be:56:de:9d", "node-56DE9D"},
		{"unknown mac", "shellydimmer2-C45BBE56DE9D", "", "shellydimmer2-C45BBE56DE9D"},
		{"name is only the mac", "C45BBE56DE9D", "c4:5b:be:56:de:9d", "C45BBE56DE9D"},
		{"name is only separated mac", "c4:5b:be:56:de:9d", "c4:5b:be:56:de:9d", "c4:5b:be:56:de:9d"},
		{"empty name", "", "c4:5b:be:56:de:9d", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := TrimTrailingMAC(c.in, c.mac); got != c.want {
				t.Errorf("TrimTrailingMAC(%q, %q) = %q, want %q", c.in, c.mac, got, c.want)
			}
		})
	}
}
