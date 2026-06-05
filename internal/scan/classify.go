package scan

import "strings"

// Device categories — a small closed set. They are plain strings so they pass
// straight through the store and JSON to the web UI, which maps each to an icon.
const (
	CategoryWiFi     = "wifi"     // access points, mesh nodes, routers
	CategoryMusic    = "music"    // speakers, media renderers
	CategoryComputer = "computer" // laptops, desktops, servers, SBCs
	CategoryPhone    = "phone"
	CategoryTablet   = "tablet"
	CategoryTV       = "tv"
	CategoryPrinter  = "printer"
	CategoryCamera   = "camera"
	CategoryNAS      = "nas"
	CategoryIoT      = "iot" // microcontrollers, smart-home gadgets
	CategoryGateway  = "gateway"

	CategoryIrrigation = "irrigation" // sprinkler / water timers (e.g. Orbit)
	CategoryAC         = "ac"         // air conditioners / HVAC (e.g. Midea)
	CategoryCalendar   = "calendar"   // wall calendars / smart displays (e.g. Skylight)
	CategoryConsole    = "console"    // game consoles (PlayStation, Xbox, Switch)
	CategoryMeshtastic = "meshtastic" // Meshtastic LoRa mesh radio nodes
	CategoryVMLXC      = "vmlxc"      // virtual machines / containers (e.g. Proxmox guests)
)

// rule maps a lowercase substring to a category. The first matching rule wins,
// so order matters: list more specific signals before more general ones.
type rule struct {
	substr   string
	category string
}

// nameRules match against the host's reverse-DNS and mDNS names. Names are a
// more specific signal than the vendor OUI (e.g. an Apple OUI could be a Mac,
// iPhone, iPad, or Apple TV — only the name disambiguates), so they are checked
// before vendorRules.
var nameRules = []rule{
	{"iphone", CategoryPhone},
	{"ipad", CategoryTablet},
	{"appletv", CategoryTV},
	{"apple-tv", CategoryTV},
	{"homepod", CategoryMusic},
	{"macbook", CategoryComputer},
	{"imac", CategoryComputer},
	{"macmini", CategoryComputer},
	{"macstudio", CategoryComputer},
	{"sonos", CategoryMusic},
	{"chromecast", CategoryTV},
	{"roku", CategoryTV},
	{"firetv", CategoryTV},
	{"shield", CategoryTV},
	// Game consoles. Sony names a PS5/PS4 "PS5-<serial>" / "PS4-<serial>".
	{"playstation", CategoryConsole},
	{"ps5", CategoryConsole},
	{"ps4", CategoryConsole},
	{"xbox", CategoryConsole},
	{"nintendo", CategoryConsole},
	{"printer", CategoryPrinter},
	// HP network printers/scanners announce themselves with an "NPI<serial>"
	// host name (e.g. "NPI073022"), a reliable printer signal.
	{"npi", CategoryPrinter},
	{"camera", CategoryCamera},
	{"-cam", CategoryCamera},
	{"doorbell", CategoryCamera},
	{"reolink", CategoryCamera},
	{"skylight", CategoryCalendar},
	{"nas", CategoryNAS},
	{"synology", CategoryNAS},
	{"router", CategoryWiFi},
	{"gateway", CategoryGateway},
	{"eero", CategoryWiFi},
	// Generic catch-all: a host whose name still contains "phone" (e.g. a
	// custom "jphone15") is almost certainly a phone. Listed last so the more
	// specific Apple/media rules above win first.
	{"phone", CategoryPhone},
}

// vendorRules match against the OUI vendor string — the strongest cheap signal,
// available the moment a MAC resolves (before any name lookup).
var vendorRules = []rule{
	{"sonos", CategoryMusic},
	{"eero", CategoryWiFi},
	{"ubiquiti", CategoryWiFi},
	{"meraki", CategoryWiFi},
	{"aruba", CategoryWiFi},
	{"netgear", CategoryWiFi},
	{"tp-link", CategoryWiFi},
	{"ruckus", CategoryWiFi},
	{"ring", CategoryCamera},
	{"wyze", CategoryCamera},
	{"axis communications", CategoryCamera},
	{"hikvision", CategoryCamera},
	{"dahua", CategoryCamera},
	{"reolink", CategoryCamera},
	{"synology", CategoryNAS},
	{"qnap", CategoryNAS},
	{"brother", CategoryPrinter},
	{"canon", CategoryPrinter},
	{"epson", CategoryPrinter},
	{"lexmark", CategoryPrinter},
	{"orbit irrigation", CategoryIrrigation},
	{"midea", CategoryAC}, // GD Midea Air-Conditioning Equipment Co.,Ltd.
	{"sony interactive", CategoryConsole}, // Sony Interactive Entertainment (PlayStation)
	{"nintendo", CategoryConsole},
	{"espressif", CategoryIoT},
	{"tuya", CategoryIoT},
	{"shelly", CategoryIoT},
	{"sonoff", CategoryIoT},
	{"raspberry", CategoryComputer},
	{"intel corporate", CategoryComputer},
	// Proxmox Server Solutions GmbH OUI is assigned to the virtual NICs Proxmox
	// hands its guests, so the device behind it is a VM or LXC container.
	{"proxmox", CategoryVMLXC},
	{"roku", CategoryTV},
	{"amazon technologies", CategoryTV},
	{"apple", CategoryComputer}, // generic Apple fallback; names refine above
}

// Classify derives a device category from the vendor and any known names,
// returning "" when nothing matches (treated as "unknown" by the UI). Name
// signals are preferred over the vendor OUI because they are more specific.
func Classify(vendor, hostname, mdnsName string) string {
	name := strings.ToLower(hostname + " " + mdnsName)
	for _, r := range nameRules {
		if strings.Contains(name, r.substr) {
			return r.category
		}
	}
	v := strings.ToLower(vendor)
	for _, r := range vendorRules {
		if strings.Contains(v, r.substr) {
			return r.category
		}
	}
	return ""
}

// modelRules map an Apple-style hardware model identifier (the `model=` TXT
// value advertised over DNS-SD, e.g. "iPhone15,2" or "AudioAccessory5,1") to a
// category. Order matters: more specific identifiers are listed before the
// broad "mac" catch-all. These are the single strongest device-kind signal
// because the device reports its own model.
var modelRules = []rule{
	{"ipad", CategoryTablet},
	{"iphone", CategoryPhone},
	{"audioaccessory", CategoryMusic}, // HomePod / HomePod mini
	{"appletv", CategoryTV},
	{"macbook", CategoryComputer},
	{"imac", CategoryComputer},
	{"macmini", CategoryComputer},
	{"macpro", CategoryComputer},
	{"macstudio", CategoryComputer},
	{"xserve", CategoryComputer},
	{"mac", CategoryComputer}, // generic Mac catch-all, after the specific ones
}

// serviceRules map a DNS-SD service type to a category. They are matched as
// substrings of the advertised service (e.g. "_googlecast._tcp"). AirPlay
// video receivers are handled separately in ClassifyService because they need
// vendor context to tell a smart TV from an audio device.
var serviceRules = []rule{
	{"_meshtastic", CategoryMeshtastic},
	{"_googlecast", CategoryTV},
	{"_spotify-connect", CategoryMusic},
	{"_sonos", CategoryMusic},
	{"_raop", CategoryMusic}, // AirPlay audio receiver (speakers, AVRs)
	{"_ipp", CategoryPrinter},
	{"_printer", CategoryPrinter},
	{"_pdl-datastream", CategoryPrinter},
	{"_scanner", CategoryPrinter},
	{"_uscan", CategoryPrinter},
	{"_hap", CategoryIoT}, // HomeKit Accessory Protocol
}

// tvVendors are makers whose AirPlay receivers are smart TVs rather than audio
// devices, so an "_airplay" service from one of these is a TV (e.g. a Samsung
// "The Frame"). Apple AirPlay video receivers are caught earlier via modelRules
// (AppleTV*), so Apple is intentionally absent here.
var tvVendors = []string{
	"samsung", "lg electronics", "sony", "vizio", "tcl", "hisense",
	"sharp", "panasonic", "roku", "amazon technologies",
}

// ClassifyService refines a category from DNS-SD evidence: the device's own
// `model=` TXT value (strongest) and the set of service types it advertises.
// vendor is consulted only to disambiguate AirPlay video receivers (TV vs.
// audio). Returns "" when the evidence is inconclusive.
func ClassifyService(vendor, model string, services []string) string {
	m := strings.ToLower(model)
	for _, r := range modelRules {
		if strings.Contains(m, r.substr) {
			return r.category
		}
	}

	// An AirPlay *video* receiver from a TV maker is a smart TV (Apple TVs are
	// already resolved above by their AppleTV* model).
	if hasService(services, "_airplay") {
		v := strings.ToLower(vendor)
		for _, tv := range tvVendors {
			if strings.Contains(v, tv) {
				return CategoryTV
			}
		}
	}

	for _, svc := range services {
		s := strings.ToLower(svc)
		for _, r := range serviceRules {
			if strings.Contains(s, r.substr) {
				return r.category
			}
		}
	}
	return ""
}

func hasService(services []string, substr string) bool {
	for _, svc := range services {
		if strings.Contains(strings.ToLower(svc), substr) {
			return true
		}
	}
	return false
}
