package scan

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	mdnsAddr = "224.0.0.251:5353"
	mdnsPort = 5353
)

// MDNSNames queries link-local multicast DNS for the names of the given IPs and
// returns a map of IP string -> ".local" name. It sends a reverse (PTR) query
// per address and collects answers for a short listen window. Devices that run
// an mDNS responder (Apple, most IoT, printers, etc.) reply with their host
// name; others are simply absent from the result.
func MDNSNames(ctx context.Context, iface *net.Interface, ips []netip.Addr, wait time.Duration) map[string]string {
	results := make(map[string]string)
	if len(ips) == 0 {
		return results
	}

	group := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: mdnsPort}
	conn, err := net.ListenMulticastUDP("udp4", iface, group)
	if err != nil {
		return results
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(1 << 20)

	dst, err := net.ResolveUDPAddr("udp4", mdnsAddr)
	if err != nil {
		return results
	}

	// Send a reverse PTR query for every target address. The whole send phase
	// shares one write deadline so a backed-up or blocked multicast socket can
	// never stall the enrichment pipeline: once the budget is spent, remaining
	// writes fail instantly and we proceed to listening.
	sendBudget := wait / 2
	if sendBudget > 500*time.Millisecond {
		sendBudget = 500 * time.Millisecond
	}
	_ = conn.SetWriteDeadline(time.Now().Add(sendBudget))
	for _, ip := range ips {
		if !ip.Is4() {
			continue
		}
		rev, err := dns.ReverseAddr(ip.String())
		if err != nil {
			continue
		}
		m := new(dns.Msg)
		m.Question = []dns.Question{{Name: rev, Qtype: dns.TypePTR, Qclass: dns.ClassINET}}
		if buf, err := m.Pack(); err == nil {
			_, _ = conn.WriteToUDP(buf, dst)
		}
	}

	// Collect answers until the window closes.
	deadline := time.Now().Add(wait)
	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, 65535)
	for {
		if ctx.Err() != nil || time.Now().After(deadline) {
			break
		}
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		for _, rr := range append(msg.Answer, msg.Extra...) {
			switch v := rr.(type) {
			case *dns.PTR:
				if ip := ptrToIP(v.Hdr.Name); ip != "" {
					results[ip] = trimLocal(v.Ptr)
				}
			case *dns.A:
				if v.Hdr.Name != "" {
					results[v.A.String()] = trimLocal(v.Hdr.Name)
				}
			}
		}
	}
	return results
}

// ptrToIP converts "100.7.168.192.in-addr.arpa." back to "192.168.7.100".
func ptrToIP(name string) string {
	name = strings.TrimSuffix(name, ".")
	suffix := ".in-addr.arpa"
	if !strings.HasSuffix(name, suffix) {
		return ""
	}
	rev := strings.Split(strings.TrimSuffix(name, suffix), ".")
	if len(rev) != 4 {
		return ""
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	if _, err := netip.ParseAddr(strings.Join(rev, ".")); err != nil {
		return ""
	}
	return strings.Join(rev, ".")
}

func trimLocal(name string) string {
	name = unescapeDNS(name)
	name = strings.TrimSuffix(name, ".")
	return strings.TrimSuffix(name, ".local")
}
