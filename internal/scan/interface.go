// Package scan discovers hosts on the local network and enriches them with
// MAC, vendor, hostname and mDNS information.
package scan

import (
	"fmt"
	"net"
	"net/netip"
)

// Interface describes the local interface a scan will run over.
type Interface struct {
	Name   string
	Prefix netip.Prefix // the IPv4 subnet, e.g. 192.168.7.0/24
	Self   netip.Addr   // our own address on that subnet
}

// DefaultInterface picks the first non-loopback, up interface that has a
// private IPv4 address. If name is non-empty, that interface is used instead.
func DefaultInterface(name string) (*Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if name != "" && iface.Name != name {
			continue
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.Is4() || !ip.IsPrivate() {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			prefix := netip.PrefixFrom(ip, ones).Masked()
			return &Interface{Name: iface.Name, Prefix: prefix, Self: ip}, nil
		}
	}
	if name != "" {
		return nil, fmt.Errorf("interface %q has no usable private IPv4 address", name)
	}
	return nil, fmt.Errorf("no suitable network interface found")
}

// broadcastAddr returns the IPv4 directed-broadcast address of prefix (all host
// bits set), or the zero Addr for non-IPv4 prefixes.
func broadcastAddr(prefix netip.Prefix) netip.Addr {
	if !prefix.Addr().Is4() {
		return netip.Addr{}
	}
	b := prefix.Masked().Addr().As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if hostBits := 32 - prefix.Bits(); hostBits > 0 {
		v |= (uint32(1) << hostBits) - 1
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// isBroadcastIP reports whether ip is the subnet's directed broadcast or the
// limited broadcast (255.255.255.255) — neither is a real host.
func isBroadcastIP(ip netip.Addr, prefix netip.Prefix) bool {
	ip = ip.Unmap()
	if !ip.Is4() {
		return false
	}
	return ip == broadcastAddr(prefix) || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// Hosts enumerates every usable host address in the prefix (excluding the
// network and broadcast addresses for the common /24-and-larger case).
func (i *Interface) Hosts() []netip.Addr {
	prefix := i.Prefix
	if !prefix.Addr().Is4() {
		return nil
	}
	var out []netip.Addr
	network := prefix.Masked().Addr()
	bits := prefix.Bits()
	count := 1 << (32 - bits)
	addr := network
	for n := 0; n < count; n++ {
		if n != 0 && n != count-1 { // skip network + broadcast
			out = append(out, addr)
		}
		addr = addr.Next()
	}
	return out
}
