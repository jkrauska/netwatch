package scan

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// dnssdServices is the set of DNS-SD service types netwatch browses for. They
// are chosen because their PTR/SRV/TXT answers reveal a device's kind and a
// friendly name far more reliably than a reverse-PTR host name:
//
//   - _airplay / _raop      → Apple TVs, HomePods, AirPlay-2 smart TVs, speakers
//   - _companion-link/_rdlink → iPhones, iPads, Macs (Continuity); human names
//   - _device-info          → carries the `model=` identifier for most Apple kit
//   - _googlecast           → Chromecast / Android TV / cast-enabled TVs
//   - _spotify-connect/_sonos → speakers and media renderers
//   - _ipp / _printer / _pdl-datastream → printers
//   - _hap                  → HomeKit accessories (IoT)
//   - _meshtastic           → Meshtastic LoRa mesh nodes (instance name is the
//     node's long name; TXT carries id=!<hex> and shortname=)
var dnssdServices = []string{
	"_airplay._tcp.local.",
	"_raop._tcp.local.",
	"_companion-link._tcp.local.",
	"_rdlink._tcp.local.",
	"_device-info._tcp.local.",
	"_googlecast._tcp.local.",
	"_spotify-connect._tcp.local.",
	"_sonos._tcp.local.",
	"_ipp._tcp.local.",
	"_printer._tcp.local.",
	"_pdl-datastream._tcp.local.",
	"_hap._tcp.local.",
	"_meshtastic._tcp.local.",
}

// MDNSDevice is the distilled DNS-SD evidence for one host: a friendly name,
// the advertised hardware `model=` (if any), and the set of service types it
// announced (e.g. "_airplay._tcp"). All fields are best-effort.
type MDNSDevice struct {
	Name     string
	Model    string
	Services []string
}

// MDNSBrowse performs a one-shot DNS-SD browse of dnssdServices on iface and
// returns a map of IPv4 string → MDNSDevice. Unlike MDNSNames (which reverse-
// resolves a known set of addresses), this is a network-wide enumeration: it
// sends a PTR query per service type and correlates the PTR → SRV → TXT → A
// answer chain to attribute a name/model/services set to each responder's IP.
//
// It is intentionally tolerant: any record we cannot correlate back to an IPv4
// address is simply dropped.
func MDNSBrowse(ctx context.Context, iface *net.Interface, wait time.Duration) map[string]MDNSDevice {
	out := make(map[string]MDNSDevice)

	group := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: mdnsPort}
	conn, err := net.ListenMulticastUDP("udp4", iface, group)
	if err != nil {
		return out
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(1 << 20)

	dst, err := net.ResolveUDPAddr("udp4", mdnsAddr)
	if err != nil {
		return out
	}

	// Send one PTR query per service type, sharing a bounded write deadline so a
	// backed-up multicast socket can never stall the pipeline (see MDNSNames).
	sendBudget := wait / 2
	if sendBudget > 500*time.Millisecond {
		sendBudget = 500 * time.Millisecond
	}
	_ = conn.SetWriteDeadline(time.Now().Add(sendBudget))
	for _, svc := range dnssdServices {
		m := new(dns.Msg)
		m.Question = []dns.Question{{Name: svc, Qtype: dns.TypePTR, Qclass: dns.ClassINET}}
		if buf, err := m.Pack(); err == nil {
			_, _ = conn.WriteToUDP(buf, dst)
		}
	}

	// Intermediate correlation tables, all keyed by the lowercased fully-
	// qualified DNS name so PTR/SRV/TXT/A answers correlate regardless of the
	// case each record happens to use. instName preserves the original-case
	// instance name for display, since lowercasing it would mangle friendly
	// names like "HP LaserJet 400 color M451dw (073022)".
	var (
		instServices = make(map[string][]string) // instance → service types
		instName     = make(map[string]string)   // instance → original-case instance name
		instTarget   = make(map[string]string)   // instance → SRV target host
		instModel    = make(map[string]string)   // instance → model= TXT
		hostIPs      = make(map[string][]string) // target host → IPv4 strings
	)

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
				svc := serviceType(v.Hdr.Name)
				inst := strings.ToLower(v.Ptr)
				instServices[inst] = appendUnique(instServices[inst], svc)
				if instName[inst] == "" {
					instName[inst] = v.Ptr
				}
			case *dns.SRV:
				instTarget[strings.ToLower(v.Hdr.Name)] = strings.ToLower(v.Target)
			case *dns.TXT:
				if model := txtModel(v.Txt); model != "" {
					inst := strings.ToLower(v.Hdr.Name)
					if instModel[inst] == "" {
						instModel[inst] = model
					}
				}
			case *dns.A:
				host := strings.ToLower(v.Hdr.Name)
				hostIPs[host] = appendUnique(hostIPs[host], v.A.String())
			}
		}
	}

	// Correlate each instance to its responder IP(s) via the SRV target's A
	// record, then fold the instance's name/model/services into that IP.
	//
	// nameScores tracks, per IP, the quality tier of the name currently stored
	// in out[ip] so a higher-quality name from another instance can replace a
	// lower-quality one (see nameScore).
	nameScores := make(map[string]int)
	for inst, services := range instServices {
		target := instTarget[inst]
		ips := hostIPs[target]
		if len(ips) == 0 {
			continue
		}
		// Derive the display name and score from the original-case instance
		// name, falling back to the lowercased key if no PTR carried it.
		orig := instName[inst]
		if orig == "" {
			orig = inst
		}
		name := instanceName(orig)
		score := nameScore(orig)
		model := instModel[inst]
		for _, ip := range ips {
			if _, err := netip.ParseAddr(ip); err != nil {
				continue
			}
			d := out[ip]
			// Prefer the most human-meaningful name seen across this host's
			// instances: first by quality tier (e.g. a Sonos's RAOP room name
			// "Bedroom" beats its bare "sonosRINCON_<hex>" id), then by length
			// within a tier (e.g. "Johns iPhone" over a bare "iPhone").
			if name != "" {
				if cur, seen := nameScores[ip]; !seen || score > cur || (score == cur && len(name) > len(d.Name)) {
					d.Name = name
					nameScores[ip] = score
				}
			}
			if d.Model == "" && model != "" {
				d.Model = model
			}
			for _, s := range services {
				d.Services = appendUnique(d.Services, s)
			}
			out[ip] = d
		}
	}
	return out
}

// serviceType reduces a full service name like "_airplay._tcp.local." to the
// "_airplay._tcp" form used by the classifier and stored on MDNSDevice.
func serviceType(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return strings.TrimSuffix(name, ".local")
}

// instanceName extracts the human-facing label from a DNS-SD instance name
// like "Johns\032iPhone._companion-link._tcp.local." → "Johns iPhone". RAOP
// instances are "<deviceid>@<name>", so anything before an "@" is dropped.
func instanceName(inst string) string {
	labels := dns.SplitDomainName(inst)
	if len(labels) == 0 {
		return ""
	}
	name := unescapeDNS(labels[0])
	if i := strings.IndexByte(name, '@'); i >= 0 {
		name = name[i+1:]
	}
	return strings.TrimSpace(name)
}

// nameScore ranks how user-friendly an instance's label is, so the most
// human-meaningful name wins when one host advertises several DNS-SD instances.
// Higher is better:
//
//	2 — a RAOP "<deviceid>@<room>" label, whose suffix is the user-assigned
//	    room/location name (e.g. Sonos advertises "C43875549E90@Bedroom._raop").
//	0 — a bare hardware identifier such as Sonos's "sonosRINCON_<hex>", which
//	    makes a poor display name and should only be used as a last resort.
//	1 — anything else (an ordinary chosen name like "Living Room").
func nameScore(inst string) int {
	labels := dns.SplitDomainName(inst)
	if len(labels) == 0 {
		return 0
	}
	label := unescapeDNS(labels[0])
	switch {
	case strings.ContainsRune(label, '@'):
		return 2
	case isDeviceID(label):
		return 0
	default:
		return 1
	}
}

// isDeviceID reports whether a label looks like a bare hardware identifier
// rather than a human-chosen name — e.g. Sonos's "sonosRINCON_C43875549E9001400"
// or other serial/MAC-derived ids. The heuristic flags Sonos's RINCON prefix
// explicitly and, more generally, any single-token (space-free) label that
// contains a long run of hex digits.
func isDeviceID(label string) bool {
	l := strings.ToLower(label)
	if strings.HasPrefix(l, "sonosrincon") {
		return true
	}
	if strings.ContainsRune(l, ' ') {
		return false
	}
	hexRun := 0
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			hexRun++
			if hexRun >= 8 {
				return true
			}
		} else {
			hexRun = 0
		}
	}
	return false
}

// txtModel returns a device's advertised hardware model from a TXT record's
// strings, or "" if absent. It reads the "model" key used by Apple/_airplay
// and _device-info records, falling back to the RAOP "am" key (AirPlay device
// model, e.g. "AppleTV3,2" or a Sonos's "Amp"). "model" wins when both are
// present. Keys are matched case-insensitively.
func txtModel(txt []string) string {
	var model, am string
	for _, kv := range txt {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(kv[:eq])
		val := strings.TrimSpace(kv[eq+1:])
		switch {
		case strings.EqualFold(key, "model"):
			if model == "" {
				model = val
			}
		case strings.EqualFold(key, "am"):
			if am == "" {
				am = val
			}
		}
	}
	if model != "" {
		return model
	}
	return am
}

// unescapeDNS decodes the wire-format escapes miekg/dns leaves in label text:
// "\DDD" decimal byte escapes (e.g. "\032" → space) and "\x" literal escapes
// (e.g. "\." → "."). Invalid sequences are passed through unchanged.
func unescapeDNS(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		next := s[i+1]
		if next >= '0' && next <= '9' && i+3 < len(s) {
			if d := decByte(s[i+1], s[i+2], s[i+3]); d >= 0 {
				b.WriteByte(byte(d))
				i += 3
				continue
			}
		}
		b.WriteByte(next)
		i++
	}
	return b.String()
}

// decByte parses three ASCII digits into a byte value, or -1 if not all digits
// or out of range.
func decByte(a, b, c byte) int {
	if a < '0' || a > '9' || b < '0' || b > '9' || c < '0' || c > '9' {
		return -1
	}
	n := int(a-'0')*100 + int(b-'0')*10 + int(c-'0')
	if n > 255 {
		return -1
	}
	return n
}
