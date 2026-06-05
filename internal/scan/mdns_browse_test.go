package scan

import "testing"

func TestServiceType(t *testing.T) {
	cases := map[string]string{
		"_airplay._tcp.local.": "_airplay._tcp",
		"_RAOP._tcp.local":     "_raop._tcp",
		"_ipp._tcp.local.":     "_ipp._tcp",
	}
	for in, want := range cases {
		if got := serviceType(in); got != want {
			t.Errorf("serviceType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInstanceName(t *testing.T) {
	cases := map[string]string{
		`Johns\032iPhone._companion-link._tcp.local.`:      "Johns iPhone",
		`Living\032Room._airplay._tcp.local.`:              "Living Room",
		`B8E856001122@Office\032Speaker._raop._tcp.local.`: "Office Speaker",
		`Printer._ipp._tcp.local.`:                         "Printer",
	}
	for in, want := range cases {
		if got := instanceName(in); got != want {
			t.Errorf("instanceName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNameScore(t *testing.T) {
	cases := map[string]int{
		// RAOP room name set by the user — the best display name.
		`C43875549E90@Bedroom._raop._tcp.local.`: 2,
		`B8E856001122@Office\032Speaker._raop._tcp.local.`: 2,
		// Sonos's bare RINCON id — demoted so a room name wins.
		`sonosRINCON_C43875549E9001400._sonos._tcp.local.`: 0,
		// Generic chosen names.
		`Living\032Room._airplay._tcp.local.`: 1,
		`Printer._ipp._tcp.local.`:            1,
	}
	for in, want := range cases {
		if got := nameScore(in); got != want {
			t.Errorf("nameScore(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestIsDeviceID(t *testing.T) {
	cases := map[string]bool{
		"sonosRINCON_C43875549E9001400": true,
		"C43875549E90":                  true, // long hex run (MAC-derived)
		"Bedroom":                       false,
		"Office Speaker":                false,
		"Living Room":                   false,
		"NPI073022":                     false, // short hex run, not flagged
	}
	for in, want := range cases {
		if got := isDeviceID(in); got != want {
			t.Errorf("isDeviceID(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestTxtModel(t *testing.T) {
	cases := []struct {
		txt  []string
		want string
	}{
		{[]string{"deviceid=AA:BB", "model=AppleTV6,2", "srcvers=5.0"}, "AppleTV6,2"},
		{[]string{"MODEL=iPhone15,2"}, "iPhone15,2"},
		// RAOP records carry the model in "am" (e.g. a Sonos's "am=Amp").
		{[]string{"tp=UDP", "am=Amp", "vs=366.0"}, "Amp"},
		{[]string{"am=AppleTV2,1"}, "AppleTV2,1"},
		// "model" is preferred over "am" when both are present.
		{[]string{"am=Amp", "model=Sonos Amp"}, "Sonos Amp"},
		{[]string{"foo=bar"}, ""},
		{nil, ""},
	}
	for _, c := range cases {
		if got := txtModel(c.txt); got != c.want {
			t.Errorf("txtModel(%v) = %q, want %q", c.txt, got, c.want)
		}
	}
}

func TestUnescapeDNS(t *testing.T) {
	cases := map[string]string{
		`plain`:        "plain",
		`a\032b`:       "a b",
		`Garage\ Door`: "Garage Door",
		`dot\.name`:    "dot.name",
		`back\\slash`:  `back\slash`,
		`trailing\`:    `trailing\`,
	}
	for in, want := range cases {
		if got := unescapeDNS(in); got != want {
			t.Errorf("unescapeDNS(%q) = %q, want %q", in, got, want)
		}
	}
}
