package scan

import (
	"context"
	"net"
	"strings"
	"time"
)

// reverseResolver forces Go's pure-Go resolver instead of the system (cgo)
// resolver. On macOS the cgo resolver ignores the context deadline, so a PTR
// lookup for a host with no reverse record can block for many seconds; the
// pure-Go resolver honors the context timeout, keeping scans responsive.
var reverseResolver = &net.Resolver{PreferGo: true}

// ReverseDNS does a PTR lookup for ip, returning the first name (without
// trailing dot) or "" if none. It bounds the lookup to a short timeout so a
// missing reverse record never stalls a scan.
func ReverseDNS(ctx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	names, err := reverseResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
