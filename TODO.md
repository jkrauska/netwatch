# netwatch — TODO

Open work and known limitations. (Implementation history and the original
code-review notes have been folded into the code and the README.)

## Known limitations

- **Multiple servers sharing one DB file is unsafe.** Persistence assumes a
  single writer. On shutdown `SaveAll` runs
  `DELETE FROM hosts WHERE key NOT IN (<this process's live set>)`, so a second
  instance with a different view of the network (different interface/subnet, or
  mid-sweep) will have its hosts deleted. Write-through upserts are also
  last-write-wins on every column, so a stale write can stomp a fresher
  `last_seen`. Before supporting multi-writer: enable WAL + `busy_timeout`,
  scope rows by instance/iface, and merge on write (`last_seen=max(...)`,
  `first_seen=min(...)`, `COALESCE`/`NULLIF` for enrichment columns). For now,
  run one instance per DB file.

- **IPv6 mDNS naming is out of scope.** PTR queries are sent for IPv4 only and
  `ptrToIP` only handles `in-addr.arpa`; `ip6.arpa` answers are dropped.

## Roadmap

### Web service detection (HTTP / HTTPS)

- [ ] Probe each host for a listening web server on ports 80/443 during
  enrichment (short bounded TCP connect, optional HEAD/GET ignoring TLS errors).
  Store `HTTP`/`HTTPS` booleans on `store.Host` and expose them in `/api/hosts`.
- [ ] Show port availability as green dots in new HTTP/HTTPS columns.
- [ ] Click-to-open: link the IP/HTTPS dot to `https://<ip>` (or `http://<ip>`
  when only 80 is open), preferring HTTPS.

### Device count history (time series)

- [ ] Record host counts at a regular cadence to show trends (sparkline of
  "devices online"). New `counts(bucket_start, total, online)` table bucketed by
  hour, ~2–4 week retention, `/api/history` endpoint, and a small inline
  `<svg>`/`<canvas>` chart above the host table (no CDN charting lib).

### Per-host history

- [ ] Track per-host sightings over time (table of seen events) — the
  per-device complement to the aggregate counts above.

### Classification refinements

- [ ] Grow the vendor/name rules table as new `unknown` vendors show up.
- [ ] Log hosts that fall through to `unknown` so the rules can be grown;
  optionally allow a manual per-host override.
- [ ] Full Apple identifier → friendly-name table (e.g. `iPad13,1` →
  "iPad Pro 11-inch"), surfaced in the UI. The `model=` *family* prefix is
  already mapped to a category.
- [ ] Dynamically enumerate `_services._dns-sd._udp.local` to discover all
  advertised service types, rather than the current fixed list.

### Misc

- [ ] Optionally refresh the embedded Wireshark `manuf` file on a schedule.
- [ ] Later: wrap the web UI in an Electron app (see the
  [Electron packaging plan](#electron-packaging-plan) below).

## Electron packaging plan

How to turn netwatch into a desktop app (macOS first, Linux/Windows later)
without throwing away the existing Go scanner. This is a plan, not an
implementation — it captures the recommended architecture, the work items, and
the platform gotchas that will bite us.

### Goal

Ship netwatch as a double-clickable desktop app with a native window, instead of
"run a Go binary, then open `http://localhost:8080` in a browser." Bonus native
affordances Electron unlocks: a menu-bar/tray icon, OS notifications when a new
device appears, launch-at-login, and a real app icon.

### Current architecture (what we're wrapping)

```
cmd/netwatch/main.go      CLI flags + wiring; spawns scanner goroutine + http.Server
internal/scan/            ICMP ping sweep (unprivileged UDP sockets),
                          arp/ndp/ip-neigh subprocess parsing, mDNS multicast,
                          reverse DNS, embedded ~3 MB OUI/manuf vendor DB
internal/store/           in-memory inventory + pure-Go SQLite (modernc, no cgo)
internal/server/          /api/hosts JSON (+gzip), /healthz, and an embedded,
                          fully self-contained single-page web UI (index.html)
```

Two facts make this an unusually clean Electron target:

1. **The UI is already a standalone web app.** `internal/server/web/index.html`
   is vanilla HTML/CSS/JS with no build step and no CDN deps; it just polls
   `GET /api/hosts` every 5s. Electron's renderer can load it as-is.
2. **The backend is a single static binary.** SQLite is `modernc.org/sqlite`
   (pure Go, no cgo), so `go build` yields one self-contained executable per
   platform with no shared-library baggage to bundle.

The catch: the scanner depends on **raw-ish network access** — unprivileged ICMP
sockets, mDNS multicast on UDP 5353, and shelling out to `arp`/`ndp` (macOS) or
`ip neigh` (Linux). Those are the things that fight with app sandboxing.

### Recommended architecture: Go sidecar + Electron shell

Keep the Go binary exactly as it is and run it as a **child process ("sidecar")**
that the Electron main process spawns on startup. The Electron renderer loads
the UI the binary already serves over loopback HTTP.

```
┌────────────────────────── Electron app ──────────────────────────┐
│  main process (Node)                                              │
│   • on app ready: spawn netwatch sidecar on 127.0.0.1:<port>      │
│   • health-check /healthz, then create BrowserWindow              │
│   • window loads http://127.0.0.1:<port>/  (the existing UI)      │
│   • on quit: SIGTERM the sidecar, wait for graceful DB flush      │
│                                                                   │
│  renderer (Chromium)  ── fetch ──▶  netwatch sidecar (Go)         │
│   • unchanged index.html              • scanner + store + server  │
└───────────────────────────────────────────────────────────────────┘
```

Why this approach:

- **Zero rewrite, zero behavior drift.** All the hard-won platform knowledge
  (macOS ICMP reply broadcast quirks, cgo-resolver deadline bug, mDNS
  write-deadline starvation) stays in Go where it's tested.
- **The HTTP server already exists**, with gzip and graceful shutdown. The
  renderer just points at a loopback port.
- **The Go test suite keeps protecting the core** — Electron is a thin shell.

#### Alternatives considered (and why not)

| Option | Verdict |
| --- | --- |
| Rewrite scanner in Node.js | ✗ Reimplements ICMP/ARP/mDNS/OUI from scratch; loses the tested Go core and its platform fixes. |
| Compile Go → WASM in the renderer | ✗ WASM can't open raw sockets or spawn `arp`/`ndp`; non-starter for a scanner. |
| Go ↔ Electron via native addon / cgo bridge | ✗ More complex than a sidecar for no real gain; reintroduces cgo. |
| **Go sidecar process (recommended)** | ✓ Minimal change, keeps the binary and server intact. |

(If we ever want a single binary with no Electron, the natural non-Electron
alternative is a Go-native webview like `webview/webview` or Wails — worth a
footnote, but out of scope here.)

### Proposed repo layout

Add a self-contained `desktop/` (Electron) tree; leave the Go code untouched
except for a couple of small flags (below).

```
desktop/
  package.json            electron, electron-builder, dev scripts
  main.js                 spawn sidecar, health-check, create window, lifecycle
  preload.js              minimal, contextIsolated bridge (app version, paths)
  resources/
    bin/                  per-platform netwatch binaries dropped here at build
      netwatch-darwin-arm64
      netwatch-darwin-amd64
      netwatch-linux-amd64
      netwatch.exe
    icons/                .icns / .ico / .png app icons
  build/                  electron-builder config, entitlements.plist
scripts/
  build-sidecars.sh       cross-compile Go for each target into resources/bin
```

### Small Go-side changes needed

The binary already takes everything we need via flags (`-listen`, `-db`); only
minor additions make it sidecar-friendly:

1. **Bind loopback by default / accept an ephemeral port.** Default `-listen` to
   `127.0.0.1:0` for the desktop build (OS picks a free port). Print the chosen
   `host:port` as a single parseable line on stdout (e.g. `LISTEN 127.0.0.1:53517`)
   so the Electron main process can read it instead of guessing. Today the
   server logs `http://localhost:8080`; formalize a machine-readable line.
   - This also reinforces the README security note (don't bind all interfaces by
     default).
2. **Loopback auth token (optional, recommended).** Generate a random token at
   startup, require it via header or `?token=`, and pass it to the renderer
   through preload. Stops other local processes from scraping the inventory.
3. **DB path in the OS user-data dir.** Electron passes
   `-db <app.getPath('userData')>/netwatch.db` so the database lives somewhere
   writable and per-user, not in the CWD/app bundle (bundles are read-only and
   signed).
4. **Clean shutdown on SIGTERM** already exists (`signal.NotifyContext` +
   `db.SaveAll` flush). Verify Electron's quit path gives it the ~3s it wants.

None of these change default `go run ./cmd/netwatch` behavior if we gate the new
defaults behind an env var or a `-desktop` flag.

### Electron main process responsibilities

```js
// sketch — desktop/main.js
const port = 0;                       // let Go pick; read it back from stdout
const child = spawn(sidecarPath, [
  '-listen', '127.0.0.1:0',
  '-db', path.join(app.getPath('userData'), 'netwatch.db'),
]);
// parse "LISTEN 127.0.0.1:PORT" from child.stdout → real URL
// poll GET /healthz until 200, then win.loadURL(`http://127.0.0.1:${port}/`)
// app 'before-quit' → child.kill('SIGTERM'); wait for exit (DB flush)
```

Key behaviors:

- **Resolve the sidecar path** by platform/arch under `process.resourcesPath`
  when packaged, or the dev `resources/bin` path when running unpackaged.
- **Health gate the window**: don't show the UI until `/healthz` returns 200, to
  avoid a flash of connection-refused.
- **Single instance lock** (`app.requestSingleInstanceLock()`) so we don't spawn
  two sidecars fighting over the same DB (ties into the multi-writer DB hazard
  in Known limitations above).
- **Crash supervision**: if the sidecar dies, show an error state and offer
  restart rather than a blank window.
- **Security hardening** on the BrowserWindow: `contextIsolation: true`,
  `nodeIntegration: false`, a strict CSP, and block navigation to non-loopback
  origins.

### Platform-specific concerns (the real work)

#### macOS (primary target)

- **Unprivileged ICMP** (`SOCK_DGRAM` ICMP) works for the user today and needs no
  root. Confirm it still works **inside a signed/packaged app** and outside the
  App Store. We are NOT targeting the Mac App Store (its sandbox would block the
  subprocesses and likely the raw-ish ICMP) — distribute as a notarized DMG/zip.
- **Subprocesses `arp -an` / `ndp -an`** must remain spawnable. Use absolute
  paths (`/usr/sbin/arp`, `/usr/sbin/ndp`) so a packaged app with a sanitized
  `PATH` still finds them.
- **mDNS multicast (UDP 5353)** — verify multicast join works from within the
  app. On recent macOS the app may need the **Local Network** privacy permission;
  the OS prompts on first multicast/LAN access. We must include a
  `NSLocalNetworkUsageDescription` in `Info.plist` or discovery silently returns
  nothing.
- **Signing + notarization**: Developer ID cert, `codesign` with hardened
  runtime, `notarytool` submission, staple. Entitlements:
  `com.apple.security.network.client` (and `.server` for the loopback listener).
  electron-builder handles most of this with config + `entitlements.plist`.

#### Linux (secondary)

- Discovery uses `ip neigh` (already implemented) — bundle nothing, but ensure
  `iproute2` is present (it is, on essentially all modern distros).
- Unprivileged ICMP needs `net.ipv4.ping_group_range` to include the user's GID
  (default on most distros). Document the `sysctl` fallback if pings come back
  empty.
- Package as AppImage (simplest, no install) and/or `.deb`. No notarization.

#### Windows (later / optional)

- **Not currently supported by the scanner.** `Neighbors()` only has macOS
  (`arp`/`ndp`) and Linux (`ip neigh`) paths; Windows has neither `ndp` nor the
  same `arp` output, and unprivileged ICMP differs. Treat Windows as a separate
  follow-on project: add a `arp -a` parser (different format) or use the
  `GetIpNetTable2` Win32 API via `golang.org/x/sys/windows`, and validate ICMP.
- Until that lands, scope the Electron app to macOS + Linux and say so.

### Packaging & distribution

- **Builder**: `electron-builder` (mature DMG/AppImage/NSIS targets, code-sign +
  notarize hooks) over electron-forge — fewer moving parts for our matrix.
- **Bundle the right binary per target**: a prepackage step cross-compiles Go
  (`GOOS`/`GOARCH`) into `resources/bin/`, and electron-builder's `files`/`extraResources`
  ships only the matching binary (or all of them; ~8–15 MB each incl. the 3 MB
  embedded OUI table — acceptable).
- **Universal macOS** build: ship both `darwin-arm64` and `darwin-amd64` and pick
  at runtime, or build a `lipo` universal Go binary.
- **Version stamping**: surface the Go binary version + Electron version in an
  About panel; embed via `-ldflags "-X main.version=..."`.

### Native enhancements Electron makes easy (post-MVP)

- **Tray / menu-bar app** with a live device count, "scanning / paused" state
  (the scanner already supports Pause/Resume), and quick show/hide.
- **Native notifications** when a brand-new device joins (we already track
  FirstSeen) — wire via a new SSE/long-poll endpoint or just diff `/api/hosts`
  in the renderer and call `new Notification(...)`.
- **Launch at login** (`app.setLoginItemSettings`) so it scans in the background.
- **Native menus**: rescan now, open DB location, copy inventory, preferences
  (interface, interval) that restart the sidecar with new flags.

### Risks & open questions

- **macOS Local Network permission** is the highest-risk unknown: if the prompt
  is denied or the entitlement/Info.plist string is missing, mDNS discovery
  yields zero names with no obvious error. Test early on a clean machine.
- **Packaged ICMP / subprocess access** must be validated inside a *signed,
  notarized* build, not just `electron .` in dev — sandbox/PATH differences only
  show up there.
- **Single-writer DB** assumption: the single-instance lock covers the common
  case, but document/enforce it (see Known limitations above).
- **App size**: Electron's Chromium runtime is ~100–150 MB packaged. For a LAN
  tool that's a real cost; note the Wails/webview alternative if footprint
  matters more than convenience.

### Milestones

- [ ] **M0 — Spike.** `electron .` spawns `go run ./cmd/netwatch -listen 127.0.0.1:0`,
      reads the port, loads the UI in a BrowserWindow. Confirm scanning + UI work
      unpackaged on macOS.
- [ ] **M1 — Go sidecar friendliness.** Machine-readable `LISTEN host:port`
      line, loopback default, `-db` into userData, optional auth token; verify
      graceful SIGTERM flush from Electron quit.
- [ ] **M2 — Lifecycle hardening.** Health-gated window, single-instance lock,
      sidecar crash supervision, security flags + CSP on the window.
- [ ] **M3 — macOS packaging.** electron-builder DMG, `Info.plist`
      `NSLocalNetworkUsageDescription`, entitlements, code-sign + notarize;
      validate ICMP/arp/ndp/mDNS in the *packaged* app on a clean Mac.
- [ ] **M4 — Linux packaging.** AppImage (+ optional `.deb`), document
      `ping_group_range`.
- [ ] **M5 — Native polish.** Tray, new-device notifications, launch-at-login,
      preferences that restart the sidecar.
- [ ] **M6 (optional) — Windows.** Add the Windows neighbor-table path in Go,
      validate ICMP, then NSIS installer.
