package scan

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// PingSweep sends an ICMP echo to every target and returns those that reply
// from within scope. It uses unprivileged UDP ICMP sockets, which macOS and
// Linux permit without root.
//
// macOS blocks the ICMP datagram write syscall while the kernel resolves ARP
// for an unknown host, and all writers on one socket serialize behind a single
// write lock — so a few dead addresses can starve every live one. To get real
// parallelism the sweep fans the targets across several independent sockets,
// each with its own write lock, so ARP resolutions proceed concurrently.
//
// Replies are filtered to scope: macOS delivers echo replies broadly and
// rewrites the ICMP id, so without this we'd also catch other processes' pings.
func PingSweep(ctx context.Context, targets []netip.Addr, scope netip.Prefix, timeout time.Duration, sockets int) ([]netip.Addr, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	if sockets <= 0 {
		sockets = 8
	}
	// Cap at 16: opening too many unprivileged ICMP sockets concurrently on
	// macOS causes reply routing to break and all goroutines receive nothing.
	if sockets > 16 {
		sockets = 16
	}
	if sockets > len(targets) {
		sockets = len(targets)
	}

	// Shard targets round-robin across sockets.
	shards := make([][]netip.Addr, sockets)
	for i, t := range targets {
		shards[i%sockets] = append(shards[i%sockets], t)
	}

	id := os.Getpid() & 0xffff
	var (
		mu    sync.Mutex
		alive = make(map[string]netip.Addr)
		wg    sync.WaitGroup
	)

	opened := 0
	for s := 0; s < sockets; s++ {
		conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
		if err != nil {
			if opened == 0 {
				return nil, err // can't open even one socket
			}
			break // partial fan-out is fine; remaining shards are dropped
		}
		opened++
		wg.Add(1)
		go func(conn *icmp.PacketConn, shard []netip.Addr) {
			defer wg.Done()
			defer conn.Close()

			// Reader: collect replies until the socket is closed.
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 1500)
				for {
					n, peer, err := conn.ReadFrom(buf)
					if err != nil {
						return
					}
					msg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), buf[:n])
					if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
						continue
					}
					var ipStr string
					switch a := peer.(type) {
					case *net.UDPAddr:
						ipStr = a.IP.String()
					case *net.IPAddr:
						ipStr = a.IP.String()
					default:
						continue
					}
					if addr, err := netip.ParseAddr(ipStr); err == nil && scope.Contains(addr) {
						mu.Lock()
						alive[addr.String()] = addr
						mu.Unlock()
					}
				}
			}()

			// Send this shard. Each socket serializes its own writes, but the
			// deadline is set immediately before the write (no cross-socket
			// lock wait can consume it), so live hosts always get a probe out.
			for _, addr := range shard {
				if ctx.Err() != nil {
					break
				}
				// Seq encodes the low two octets of the target so it stays
				// unique within a /16 (the single-octet form collided for /23
				// and larger). Replies are still matched by source-IP-in-scope,
				// so Seq is diagnostic rather than load-bearing.
				v4 := addr.As4()
				seq := int(v4[2])<<8 | int(v4[3])
				wm := icmp.Message{
					Type: ipv4.ICMPTypeEcho,
					Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("netwatch")},
				}
				wb, err := wm.Marshal(nil)
				if err != nil {
					continue
				}
				_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
				_, _ = conn.WriteTo(wb, &net.UDPAddr{IP: net.IP(addr.AsSlice())})
			}

			// Grace window for late replies, then close to stop the reader.
			select {
			case <-ctx.Done():
			case <-time.After(timeout):
			}
			conn.Close()
			<-done
		}(conn, shards[s])
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	out := make([]netip.Addr, 0, len(alive))
	for _, a := range alive {
		out = append(out, a)
	}
	return out, nil
}
