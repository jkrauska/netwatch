package scan

import "testing"

func TestParseARP(t *testing.T) {
	input := `
? (192.168.7.1) at 50:27:a9:6b:dd:2d on en0 ifscope [ethernet]
? (192.168.7.2) at (incomplete) on en0 ifscope [ethernet]
? (192.168.7.3) at 8:0:20:1:2:3 on en0 [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (192.168.7.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
`
	got := parseARP(input)

	// 192.168.7.2 is incomplete (skipped); 224.0.0.251 (01:00:5e:..) and the
	// broadcast row are group MACs and are filtered by isGroupMAC.
	want := map[string]string{
		"192.168.7.1": "50:27:a9:6b:dd:2d",
		"192.168.7.3": "08:00:20:01:02:03", // single-digit octets zero-padded
	}
	if len(got) != len(want) {
		t.Fatalf("parseARP returned %d entries, want %d: %+v", len(got), len(want), got)
	}
	for _, n := range got {
		w, ok := want[n.IP.String()]
		if !ok {
			t.Errorf("unexpected entry %s (group/incomplete should be filtered)", n.IP)
			continue
		}
		if n.MAC != w {
			t.Errorf("%s = %q, want %q", n.IP, n.MAC, w)
		}
	}
}

func TestParseNDP(t *testing.T) {
	input := `Neighbor                             Linklayer Address  Netif Expire    St Flgs Prbs
fe80::1%en0                          0:11:22:33:44:55   en0   permanent R
fd77:509a::1                         aa:bb:cc:dd:ee:ff  en0   23h59m58s  S
fe80::dead%en0                       (incomplete)       en0                I
`
	got := parseNDP(input)

	want := map[string]string{
		"fe80::1":      "00:11:22:33:44:55", // zone stripped, mac zero-padded
		"fd77:509a::1": "aa:bb:cc:dd:ee:ff",
	}
	if len(got) != len(want) {
		t.Fatalf("parseNDP returned %d entries, want %d: %+v", len(got), len(want), got)
	}
	for _, n := range got {
		w, ok := want[n.IP.String()]
		if !ok {
			t.Errorf("unexpected entry %s", n.IP)
			continue
		}
		if n.MAC != w {
			t.Errorf("%s = %q, want %q", n.IP, n.MAC, w)
		}
	}
}

func TestParseIPNeigh(t *testing.T) {
	input := `192.168.7.1 dev eth0 lladdr 50:27:a9:6b:dd:2d REACHABLE
192.168.7.3 dev eth0 lladdr 8:0:20:1:2:3 STALE
192.168.7.9 dev eth0  FAILED
192.168.7.10 dev eth0 INCOMPLETE
fe80::1 dev eth0 lladdr 00:11:22:33:44:55 router REACHABLE
224.0.0.251 dev eth0 lladdr 01:00:5e:00:00:fb PERMANENT
`
	got := parseIPNeigh(input)

	want := map[string]string{
		"192.168.7.1": "50:27:a9:6b:dd:2d",
		"192.168.7.3": "08:00:20:01:02:03", // zero-padded
		"fe80::1":     "00:11:22:33:44:55",
	}
	if len(got) != len(want) {
		t.Fatalf("parseIPNeigh returned %d entries, want %d: %+v", len(got), len(want), got)
	}
	for _, n := range got {
		w, ok := want[n.IP.String()]
		if !ok {
			t.Errorf("unexpected entry %s (FAILED/INCOMPLETE/group should be filtered)", n.IP)
			continue
		}
		if n.MAC != w {
			t.Errorf("%s = %q, want %q", n.IP, n.MAC, w)
		}
	}
}

func TestNormalizeMAC(t *testing.T) {
	cases := []struct{ in, want string }{
		{"50:27:a9:6b:dd:2d", "50:27:a9:6b:dd:2d"},
		{"8:0:20:1:2:3", "08:00:20:01:02:03"},
		{"AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"},
		{"(incomplete)", ""},
		{"not-a-mac", ""},
		{"00:11:22:33:44", ""}, // too few octets
	}
	for _, c := range cases {
		if got := normalizeMAC(c.in); got != c.want {
			t.Errorf("normalizeMAC(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
