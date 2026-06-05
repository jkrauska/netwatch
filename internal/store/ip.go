package store

import "net/netip"

// ipLess orders IPv4 strings numerically (so .2 sorts before .10). Unparseable
// or empty values sort last.
func ipLess(a, b string) bool {
	ap, aerr := netip.ParseAddr(a)
	bp, berr := netip.ParseAddr(b)
	switch {
	case aerr != nil && berr != nil:
		return a < b
	case aerr != nil:
		return false
	case berr != nil:
		return true
	default:
		return ap.Less(bp)
	}
}
