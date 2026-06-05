package scan

import "strings"

// TrimTrailingMAC removes a device's own MAC address when it appears as a
// suffix of name. Many appliances bake the MAC (with or without separators)
// into their host/mDNS name to make it unique — e.g. a Shelly dimmer announces
// itself as "shellydimmer2-C45BBE56DE9D" with MAC c4:5b:be:56:de:9d. The
// trailing MAC adds nothing the row's own MAC column doesn't already show, so
// we strip it back to "shellydimmer2".
//
// Matching is case-insensitive and tolerates separators (":", "-", "_", ".")
// inside the trailing MAC. name is returned unchanged when mac is unknown,
// when name doesn't end in the MAC, or when the MAC is the entire name (so we
// never blank out a row whose only label is its MAC).
func TrimTrailingMAC(name, mac string) string {
	hex := hexOnly(mac)
	if len(hex) != 12 {
		return name
	}

	// Walk backwards over name matching its trailing hex nibbles against the
	// MAC (right to left), skipping separators that may sit between nibbles.
	matched := 0
	i := len(name)
	for i > 0 && matched < 12 {
		c := name[i-1]
		switch {
		case isHexByte(c):
			if lowerHexNibble(c) != hex[11-matched] {
				return name // trailing hex run isn't this device's MAC
			}
			matched++
			i--
		case isMACSep(c):
			i--
		default:
			return name // hit a non-MAC character before the MAC completed
		}
	}
	if matched != 12 {
		return name
	}

	// Drop any separator(s) that joined the MAC to the rest of the name.
	for i > 0 && isMACSep(name[i-1]) {
		i--
	}
	if i == 0 {
		return name // the whole name was the MAC; keep it rather than blank it
	}
	return name[:i]
}

// hexOnly returns the lowercase hex digits of s with all other characters
// (separators, spaces) removed.
func hexOnly(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if isHexByte(s[i]) {
			b.WriteByte(lowerHexNibble(s[i]))
		}
	}
	return b.String()
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isMACSep(c byte) bool {
	return c == ':' || c == '-' || c == '_' || c == '.' || c == ' '
}

// lowerHexNibble lowercases a single hex digit byte.
func lowerHexNibble(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + ('a' - 'A')
	}
	return c
}
