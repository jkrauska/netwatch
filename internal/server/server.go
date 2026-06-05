// Package server exposes the host inventory over HTTP as JSON and serves the
// single-page web UI.
package server

import (
	"compress/gzip"
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/jkrauska/netwatch/internal/store"
)

//go:embed web/*
var webFS embed.FS

// ScanController is the subset of the scanner the server can drive from the UI:
// query and toggle the paused state. It is optional — a nil controller simply
// disables the pause/resume endpoints.
type ScanController interface {
	Paused() bool
	Pause()
	Resume()
}

type Server struct {
	store    *store.Store
	ctrl     ScanController
	shutdown func()
	mux      *http.ServeMux
}

func New(s *store.Store, ctrl ScanController) *Server {
	srv := &Server{store: s, ctrl: ctrl, mux: http.NewServeMux()}

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		// The "web" directory is embedded at build time, so this can only fail
		// if the embed path is wrong — surface it loudly at startup, not later.
		panic("server: embedded web assets missing: " + err.Error())
	}
	srv.mux.Handle("/", http.FileServer(http.FS(sub)))
	srv.mux.HandleFunc("/api/hosts", srv.handleHosts)
	srv.mux.HandleFunc("/api/comment", srv.handleComment)
	srv.mux.HandleFunc("/api/scan", srv.handleScan)
	srv.mux.HandleFunc("/api/shutdown", srv.handleShutdown)
	srv.mux.HandleFunc("/healthz", srv.handleHealthz)

	return srv
}

// SetShutdown registers the callback used to gracefully stop the process when
// the UI requests it via POST /api/shutdown. A nil callback (the default)
// leaves the endpoint disabled and it responds 503.
func (s *Server) SetShutdown(fn func()) { s.shutdown = fn }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// handleHosts serves the inventory as compact JSON. Pass ?pretty=1 for an
// indented response, and the body is gzip-encoded when the client advertises
// support, which is a large win for a 65+ host list polled every few seconds.
func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hosts := s.store.Snapshot()
	resp := struct {
		GeneratedAt time.Time    `json:"generated_at"`
		Count       int          `json:"count"`
		Paused      bool         `json:"paused"`
		Hosts       []store.Host `json:"hosts"`
	}{
		GeneratedAt: time.Now(),
		Count:       len(hosts),
		Paused:      s.ctrl != nil && s.ctrl.Paused(),
		Hosts:       hosts,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	var out io.Writer = w
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		out = gz
	}

	enc := json.NewEncoder(out)
	if r.URL.Query().Get("pretty") != "" {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(resp)
}

// handleComment sets the user-editable note on a host. POST a JSON body of
// {"key": "<host key>", "comment": "<text>"}; the note is stored against the
// host's record (keyed by MAC when known) so it survives IP changes. Responds
// with the updated host as JSON, or 404 if the key is unknown.
func (s *Server) handleComment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Key     string `json:"key"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Key == "" {
		http.Error(w, "key is required", http.StatusBadRequest)
		return
	}

	host, ok := s.store.SetComment(req.Key, strings.TrimSpace(req.Comment))
	if !ok {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(host)
}

// handleScan reports and controls the scanner's run state. GET returns the
// current paused flag; POST with ?action=pause|resume|toggle changes it. The
// response is always the resulting state as JSON: {"paused": bool}.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if s.ctrl == nil {
		http.Error(w, "scan control unavailable", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		// no-op: just report state below
	case http.MethodPost:
		switch r.URL.Query().Get("action") {
		case "pause":
			s.ctrl.Pause()
		case "resume":
			s.ctrl.Resume()
		case "toggle":
			if s.ctrl.Paused() {
				s.ctrl.Resume()
			} else {
				s.ctrl.Pause()
			}
		default:
			http.Error(w, "action must be pause, resume, or toggle", http.StatusBadRequest)
			return
		}
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(struct {
		Paused bool `json:"paused"`
	}{Paused: s.ctrl.Paused()})
}

// handleShutdown triggers a graceful shutdown of the whole process. It acks the
// request first (so the UI gets a clean response) and then fires the registered
// shutdown callback from a separate goroutine, since that callback tears down
// the very server handling this request.
func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if s.shutdown == nil {
		http.Error(w, "shutdown unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(struct {
		Stopping bool `json:"stopping"`
	}{Stopping: true})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	go s.shutdown()
}

// handleHealthz is a liveness probe: always 200 once the server is up.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "ok\n")
}
