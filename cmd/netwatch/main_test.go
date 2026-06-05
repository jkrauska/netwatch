package main

import (
	"net/netip"
	"testing"
)

func TestLocationDBPath(t *testing.T) {
	tests := []struct {
		name   string
		base   string
		prefix string
		want   string
	}{
		{"default", "netwatch.db", "192.168.7.0/24", "netwatch-192.168.7.0_24.db"},
		{"no extension", "netwatch", "10.0.0.0/8", "netwatch-10.0.0.0_8"},
		{"with directory", "/var/lib/netwatch.db", "192.168.1.0/24", "/var/lib/netwatch-192.168.1.0_24.db"},
		{"empty disables", "", "192.168.7.0/24", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var prefix netip.Prefix
			if tt.prefix != "" {
				prefix = netip.MustParsePrefix(tt.prefix)
			}
			if got := locationDBPath(tt.base, prefix); got != tt.want {
				t.Errorf("locationDBPath(%q, %q) = %q, want %q", tt.base, tt.prefix, got, tt.want)
			}
		})
	}
}

func TestLocationDBPathInvalidPrefix(t *testing.T) {
	if got := locationDBPath("netwatch.db", netip.Prefix{}); got != "netwatch.db" {
		t.Errorf("invalid prefix should return base unchanged, got %q", got)
	}
}
