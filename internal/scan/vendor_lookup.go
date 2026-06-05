package scan

import (
	"bufio"
	_ "embed"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
)

// manufData is the Wireshark "manuf" vendor database, embedded so vendor
// lookups work with no external file. Refresh it from:
//
//	https://www.wireshark.org/download/automated/data/manuf
//
//go:embed data/manuf
var manufData string

// OUI resolves a MAC address to a hardware vendor using the IEEE registry as
// distributed in Wireshark's "manuf" file. Most entries are 24-bit OUIs, but
// the file also carries longer 28- and 36-bit prefixes for sub-allocated
// blocks, so lookups try the longest matching prefix first.
type OUI struct {
	mu    sync.RWMutex
	table map[string]string // bare-hex prefix (len 6/7/9) -> vendor
}

// prefixLens are the prefix nibble-lengths present in the registry, longest
// first, so Lookup prefers a specific sub-block over its parent OUI.
var prefixLens = []int{9, 7, 6}

// NewOUI builds a lookup pre-populated from the embedded manuf database.
func NewOUI() *OUI {
	o := &OUI{table: make(map[string]string, 60000)}
	o.load(strings.NewReader(manufData))
	return o
}

// LoadFile merges entries from an additional manuf/oui file on disk.
func (o *OUI) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	o.load(f)
	return nil
}

func (o *OUI) load(r io.Reader) {
	o.mu.Lock()
	defer o.mu.Unlock()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if prefix, vendor, ok := parseManufLine(sc.Text()); ok {
			o.table[prefix] = vendor
		}
	}
}

// Lookup returns the vendor for a MAC, or "" if unknown.
func (o *OUI) Lookup(mac string) string {
	hex := normPrefix(mac)
	o.mu.RLock()
	defer o.mu.RUnlock()
	for _, n := range prefixLens {
		if len(hex) >= n {
			if v, ok := o.table[hex[:n]]; ok {
				return v
			}
		}
	}
	return ""
}

// parseManufLine handles a Wireshark manuf row:
//
//	00:00:0C            \tCisco        \tCisco Systems, Inc
//	00:55:DA:A0:00:00/28\tIEEERegi     \tIEEE Registration Authority
//
// Columns are tab-separated: prefix, short name, optional long name. The long
// name is preferred. A "/NN" mask widens the prefix beyond 24 bits.
func parseManufLine(line string) (prefix, vendor string, ok bool) {
	line = strings.TrimRight(line, "\r")
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	cols := strings.Split(line, "\t")
	if len(cols) < 2 {
		return "", "", false
	}
	prefix, ok = normManufPrefix(strings.TrimSpace(cols[0]))
	if !ok {
		return "", "", false
	}
	vendor = strings.TrimSpace(cols[len(cols)-1]) // long name if present, else short
	if vendor == "" {
		return "", "", false
	}
	return prefix, vendor, true
}

// normManufPrefix turns "00:55:DA:A0:00:00/28" into the bare-hex prefix of the
// right nibble length (here 7), or "00:00:0C" into "00000c".
func normManufPrefix(s string) (string, bool) {
	bits := 24
	if i := strings.IndexByte(s, '/'); i >= 0 {
		n, err := strconv.Atoi(s[i+1:])
		if err != nil {
			return "", false
		}
		bits = n
		s = s[:i]
	}
	hex := normPrefix(s)
	nibbles := bits / 4
	if bits%4 != 0 {
		nibbles++
	}
	if len(hex) < nibbles || nibbles < 6 {
		return "", false
	}
	return hex[:nibbles], true
}

// normPrefix strips separators and lowercases, yielding bare hex.
func normPrefix(s string) string {
	s = strings.ToLower(s)
	r := strings.NewReplacer(":", "", "-", "", ".", "", " ", "")
	return r.Replace(s)
}
