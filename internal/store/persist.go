package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DB is a SQLite-backed persistence layer for the host inventory. It uses the
// pure-Go modernc.org/sqlite driver (no cgo) so builds and cross-compilation
// stay trivial. IP-list fields are stored as JSON-encoded text columns and
// timestamps as RFC3339 strings.
type DB struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS hosts (
	key           TEXT PRIMARY KEY,
	mac           TEXT NOT NULL DEFAULT '',
	vendor        TEXT NOT NULL DEFAULT '',
	ipv4          TEXT NOT NULL DEFAULT '[]',
	secondary_ips TEXT NOT NULL DEFAULT '[]',
	ipv6_local    TEXT NOT NULL DEFAULT '[]',
	ipv6_global   TEXT NOT NULL DEFAULT '[]',
	hostname      TEXT NOT NULL DEFAULT '',
	mdns_name     TEXT NOT NULL DEFAULT '',
	mdns_model    TEXT NOT NULL DEFAULT '',
	mdns_services TEXT NOT NULL DEFAULT '[]',
	category      TEXT NOT NULL DEFAULT '',
	comment       TEXT NOT NULL DEFAULT '',
	first_seen    TEXT NOT NULL DEFAULT '',
	last_seen     TEXT NOT NULL DEFAULT ''
);`

// migrations brings an older `hosts` table up to the current schema. Each
// ALTER is additive and idempotent — a "duplicate column" error means the
// column already exists, which is fine, so those are ignored.
var migrations = []string{
	`ALTER TABLE hosts ADD COLUMN mdns_model TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE hosts ADD COLUMN mdns_services TEXT NOT NULL DEFAULT '[]'`,
	`ALTER TABLE hosts ADD COLUMN comment TEXT NOT NULL DEFAULT ''`,
}

// OpenDB opens (or creates) the SQLite database at path and ensures the schema
// exists.
func OpenDB(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, err)
	}
	// A single connection avoids "database is locked" under the write-through
	// pattern; load is short and writes are infrequent.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	// Apply additive migrations for databases created by an earlier schema.
	// A "duplicate column name" error just means the column already exists.
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			db.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}
	return &DB{db: db}, nil
}

func (d *DB) Close() error { return d.db.Close() }

// Load reads every persisted host back into memory.
func (d *DB) Load() ([]Host, error) {
	rows, err := d.db.Query(`SELECT key, mac, vendor, ipv4, secondary_ips,
		ipv6_local, ipv6_global, hostname, mdns_name, mdns_model, mdns_services,
		category, comment, first_seen, last_seen
		FROM hosts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Host
	for rows.Next() {
		var (
			h                                      Host
			ipv4, secondary, ipv6Local, ipv6Global string
			mdnsServices, firstSeen, lastSeen      string
		)
		if err := rows.Scan(&h.Key, &h.MAC, &h.Vendor, &ipv4, &secondary,
			&ipv6Local, &ipv6Global, &h.Hostname, &h.MDNSName, &h.MDNSModel,
			&mdnsServices, &h.Category, &h.Comment, &firstSeen, &lastSeen); err != nil {
			return nil, err
		}
		h.IPv4 = decodeList(ipv4)
		h.SecondaryIPs = decodeList(secondary)
		h.IPv6Local = decodeList(ipv6Local)
		h.IPv6Global = decodeList(ipv6Global)
		h.MDNSServices = decodeList(mdnsServices)
		h.FirstSeen = decodeTime(firstSeen)
		h.LastSeen = decodeTime(lastSeen)
		out = append(out, h)
	}
	return out, rows.Err()
}

// SaveHost write-through upserts a single host record.
func (d *DB) SaveHost(h Host) error {
	_, err := d.db.Exec(`
		INSERT INTO hosts (key, mac, vendor, ipv4, secondary_ips, ipv6_local,
			ipv6_global, hostname, mdns_name, mdns_model, mdns_services, category,
			comment, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			mac=excluded.mac, vendor=excluded.vendor, ipv4=excluded.ipv4,
			secondary_ips=excluded.secondary_ips, ipv6_local=excluded.ipv6_local,
			ipv6_global=excluded.ipv6_global, hostname=excluded.hostname,
			mdns_name=excluded.mdns_name, mdns_model=excluded.mdns_model,
			mdns_services=excluded.mdns_services, category=excluded.category,
			comment=excluded.comment,
			first_seen=excluded.first_seen, last_seen=excluded.last_seen`,
		h.Key, h.MAC, h.Vendor, encodeList(h.IPv4), encodeList(h.SecondaryIPs),
		encodeList(h.IPv6Local), encodeList(h.IPv6Global), h.Hostname, h.MDNSName,
		h.MDNSModel, encodeList(h.MDNSServices), h.Category, h.Comment,
		encodeTime(h.FirstSeen), encodeTime(h.LastSeen))
	return err
}

// DeleteHost removes a host by key. Used when a record is re-keyed from an IP
// to a newly-learned MAC, so the stale IP-keyed row does not linger.
func (d *DB) DeleteHost(key string) error {
	_, err := d.db.Exec(`DELETE FROM hosts WHERE key = ?`, key)
	return err
}

// SaveAll upserts every host and prunes any rows whose key is no longer present
// (a full reconciliation, useful on shutdown).
func (d *DB) SaveAll(hosts []Host) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	keys := make([]string, 0, len(hosts))
	for _, h := range hosts {
		keys = append(keys, h.Key)
		if _, err := tx.Exec(`
			INSERT INTO hosts (key, mac, vendor, ipv4, secondary_ips, ipv6_local,
				ipv6_global, hostname, mdns_name, mdns_model, mdns_services, category,
				comment, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET
				mac=excluded.mac, vendor=excluded.vendor, ipv4=excluded.ipv4,
				secondary_ips=excluded.secondary_ips, ipv6_local=excluded.ipv6_local,
				ipv6_global=excluded.ipv6_global, hostname=excluded.hostname,
				mdns_name=excluded.mdns_name, mdns_model=excluded.mdns_model,
				mdns_services=excluded.mdns_services, category=excluded.category,
				comment=excluded.comment,
				first_seen=excluded.first_seen, last_seen=excluded.last_seen`,
			h.Key, h.MAC, h.Vendor, encodeList(h.IPv4), encodeList(h.SecondaryIPs),
			encodeList(h.IPv6Local), encodeList(h.IPv6Global), h.Hostname, h.MDNSName,
			h.MDNSModel, encodeList(h.MDNSServices), h.Category, h.Comment,
			encodeTime(h.FirstSeen), encodeTime(h.LastSeen)); err != nil {
			return err
		}
	}

	// Prune rows that are no longer in the live set.
	if len(keys) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(keys)), ",")
		args := make([]any, len(keys))
		for i, k := range keys {
			args[i] = k
		}
		if _, err := tx.Exec(`DELETE FROM hosts WHERE key NOT IN (`+placeholders+`)`, args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func encodeList(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func decodeList(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

func encodeTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339Nano)
}

func decodeTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
