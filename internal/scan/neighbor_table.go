package scan

import (
	"net/netip"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Neighbor links an IP address to the MAC the kernel resolved for it.
type Neighbor struct {
	IP  netip.Addr
	MAC string
}

// macRe matches a colon-separated MAC, normalizing single-digit octets that
// macOS's arp/ndp print without a leading zero (e.g. "8:0:20:...").
var macRe = regexp.MustCompile(`([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}`)

// arpLineRe pulls "(192.168.7.1)" and the MAC out of an `arp -an` line:
//
//	? (192.168.7.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
var arpLineRe = regexp.MustCompile(`\(([^)]+)\)\s+at\s+([0-9a-fA-F:]+)`)

// Neighbors reads the kernel's IPv4 ARP cache and IPv6 NDP cache and returns
// the resolved IP→MAC pairs. Entries without a real MAC (incomplete/expired)
// are skipped. Errors running the tools are non-fatal; whatever resolved is
// returned.
//
// The source command is platform-specific: Linux exposes both caches through
// `ip neigh`, while macOS/BSD split them across `arp -an` (IPv4) and `ndp -an`
// (IPv6). The line parsers below are pure functions so they stay unit-testable
// regardless of the host OS.
func Neighbors() []Neighbor {
	if runtime.GOOS == "linux" {
		return parseIPNeigh(run("ip", "neigh"))
	}
	var out []Neighbor
	out = append(out, parseARP(run("arp", "-an"))...)
	out = append(out, parseNDP(run("ndp", "-an"))...)
	return out
}

func run(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func parseARP(s string) []Neighbor {
	var out []Neighbor
	for _, line := range strings.Split(s, "\n") {
		m := arpLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ip, err := netip.ParseAddr(m[1])
		if err != nil {
			continue
		}
		mac := normalizeMAC(m[2])
		if mac == "" || isGroupMAC(mac) {
			continue
		}
		out = append(out, Neighbor{IP: ip, MAC: mac})
	}
	return out
}

// parseNDP handles `ndp -an` output, whose columns are:
//
//	Neighbor                             Linklayer Address  Netif Expire    St Flgs Prbs
//	fe80::1%en0                          0:11:22:33:44:55   en0   permanent R
func parseNDP(s string) []Neighbor {
	var out []Neighbor
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ipField := fields[0]
		if i := strings.IndexByte(ipField, '%'); i >= 0 {
			ipField = ipField[:i] // strip zone
		}
		ip, err := netip.ParseAddr(ipField)
		if err != nil {
			continue
		}
		mac := normalizeMAC(fields[1])
		if mac == "" || isGroupMAC(mac) {
			continue
		}
		out = append(out, Neighbor{IP: ip, MAC: mac})
	}
	return out
}

// parseIPNeigh handles Linux `ip neigh` output, whose rows look like:
//
//	192.168.7.1 dev eth0 lladdr 50:27:a9:6b:dd:2d REACHABLE
//	192.168.7.9 dev eth0  FAILED
//	fe80::1 dev eth0 lladdr 00:11:22:33:44:55 router REACHABLE
//
// The MAC follows the "lladdr" token; rows without one (FAILED / INCOMPLETE)
// are skipped, as are group/broadcast MACs.
func parseIPNeigh(s string) []Neighbor {
	var out []Neighbor
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip, err := netip.ParseAddr(stripZone(fields[0]))
		if err != nil {
			continue
		}
		mac := ""
		for i := 1; i < len(fields)-1; i++ {
			if fields[i] == "lladdr" {
				mac = normalizeMAC(fields[i+1])
				break
			}
		}
		if mac == "" || isGroupMAC(mac) {
			continue
		}
		out = append(out, Neighbor{IP: ip, MAC: mac})
	}
	return out
}

// normalizeMAC validates and zero-pads a MAC to xx:xx:xx:xx:xx:xx lowercase.
// Returns "" for non-MAC tokens like "(incomplete)".
func normalizeMAC(s string) string {
	if !macRe.MatchString(s) {
		return ""
	}
	parts := strings.Split(strings.ToLower(s), ":")
	if len(parts) != 6 {
		return ""
	}
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}

// isGroupMAC reports whether mac is a group (broadcast or multicast) address,
// identified by the least-significant bit of the first octet being set. This
// catches the ff:ff:ff:ff:ff:ff broadcast the kernel caches for the subnet
// broadcast IP (e.g. x.x.x.255), plus IPv4/IPv6 multicast MACs such as
// 01:00:5e:… (mDNS/SSDP groups like 224.0.0.251, 239.255.255.250) and 33:33:…
// None of these are real hosts, so they must never be seeded into the store.
func isGroupMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	first, err := strconv.ParseUint(mac[:2], 16, 8)
	if err != nil {
		return false
	}
	return first&0x01 == 1
}
