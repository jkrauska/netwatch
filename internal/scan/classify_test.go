package scan

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		name, vendor, hostname, mdns, want string
	}{
		{"sonos vendor", "Sonos, Inc.", "", "", CategoryMusic},
		{"eero vendor", "eero inc.", "", "", CategoryWiFi},
		{"tp-link vendor", "TP-Link Systems Inc", "", "", CategoryWiFi},
		{"ring vendor", "Ring LLC", "", "", CategoryCamera},
		{"espressif vendor", "Espressif Inc.", "", "", CategoryIoT},
		{"proxmox vendor is vm/lxc", "Proxmox Server Solutions GmbH", "", "", CategoryVMLXC},
		{"apple generic vendor", "Apple, Inc.", "", "", CategoryComputer},
		{"unknown vendor", "Totally Unknown Co", "", "", ""},
		{"empty everything", "", "", "", ""},

		// Name signals are more specific than vendor and must win.
		{"apple iphone name", "Apple, Inc.", "", "Johns-iPhone", CategoryPhone},
		{"apple ipad name", "Apple, Inc.", "iPad-Pro", "", CategoryTablet},
		{"apple tv name", "Apple, Inc.", "", "Living-Room-AppleTV", CategoryTV},
		{"printer by name", "Some Vendor", "office-printer-1", "", CategoryPrinter},
		{"camera by name suffix", "Some Vendor", "front-door-cam", "", CategoryCamera},
		{"homepod name beats apple vendor", "Apple, Inc.", "", "Kitchen-HomePod", CategoryMusic},

		// New device kinds.
		{"orbit irrigation vendor", "Orbit Irrigation Products, Inc.", "", "", CategoryIrrigation},
		{"midea ac vendor", "GD Midea Air-Conditioning Equipment Co.,Ltd.", "", "", CategoryAC},
		{"reolink camera vendor", "Reolink Innovation Limited", "", "", CategoryCamera},
		{"hp printer by NPI name", "Hewlett Packard", "NPI073022", "", CategoryPrinter},
		{"skylight calendar by name", "Some Vendor", "", "Skylight-Calendar", CategoryCalendar},
		{"jphone15 is a phone", "Apple, Inc.", "", "jphone15", CategoryPhone},
		{"ps5 console by name", "Sony Interactive Entertainment Inc.", "", "PS5-8C2737", CategoryConsole},
		{"playstation vendor", "Sony Interactive Entertainment Inc.", "", "", CategoryConsole},
		{"xbox by name", "Microsoft Corporation", "XboxOne", "", CategoryConsole},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Classify(c.vendor, c.hostname, c.mdns); got != c.want {
				t.Fatalf("Classify(%q,%q,%q) = %q, want %q",
					c.vendor, c.hostname, c.mdns, got, c.want)
			}
		})
	}
}

func TestClassifyService(t *testing.T) {
	cases := []struct {
		name, vendor, model string
		services            []string
		want                string
	}{
		{"iphone model", "Apple, Inc.", "iPhone15,2", []string{"_companion-link._tcp"}, CategoryPhone},
		{"ipad model", "Apple, Inc.", "iPad13,1", []string{"_device-info._tcp"}, CategoryTablet},
		{"appletv model", "Apple, Inc.", "AppleTV6,2", []string{"_airplay._tcp", "_raop._tcp"}, CategoryTV},
		{"homepod model", "Apple, Inc.", "AudioAccessory5,1", []string{"_airplay._tcp", "_raop._tcp"}, CategoryMusic},
		{"macbook model", "Apple, Inc.", "MacBookPro18,3", []string{"_device-info._tcp"}, CategoryComputer},
		{"generic mac model", "Apple, Inc.", "Macmini9,1", []string{"_device-info._tcp"}, CategoryComputer},

		// Samsung "The Frame" advertises AirPlay video — vendor disambiguates it
		// from an audio AirPlay device, so it classifies as a TV.
		{"samsung frame tv airplay", "Samsung Electronics Co.,Ltd", "", []string{"_airplay._tcp"}, CategoryTV},
		{"lg airplay tv", "LG Electronics", "", []string{"_airplay._tcp"}, CategoryTV},

		// Service-only signals (no usable model).
		{"chromecast", "Google, Inc.", "", []string{"_googlecast._tcp"}, CategoryTV},
		{"raop speaker", "Some Speaker Co", "", []string{"_raop._tcp"}, CategoryMusic},
		{"ipp printer", "Some Vendor", "", []string{"_ipp._tcp"}, CategoryPrinter},
		{"homekit accessory", "Some Vendor", "", []string{"_hap._tcp"}, CategoryIoT},

		// Meshtastic LoRa mesh node (e.g. an ESP32-based node advertising
		// _meshtastic._tcp with id=!16cfa430 / shortname=a430 TXT records).
		{"meshtastic node", "Espressif Inc.", "", []string{"_meshtastic._tcp"}, CategoryMeshtastic},

		{"inconclusive", "Some Vendor", "", []string{"_ssh._tcp"}, ""},
		{"nothing", "", "", nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyService(c.vendor, c.model, c.services); got != c.want {
				t.Fatalf("ClassifyService(%q,%q,%v) = %q, want %q",
					c.vendor, c.model, c.services, got, c.want)
			}
		})
	}
}
