package server

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jkrauska/netwatch/internal/store"
)

// fakeController is a minimal in-memory ScanController for tests.
type fakeController struct{ paused bool }

func (f *fakeController) Paused() bool { return f.paused }
func (f *fakeController) Pause()       { f.paused = true }
func (f *fakeController) Resume()      { f.paused = false }

func newTestServer() *Server {
	st := store.New()
	st.Upsert(store.Observation{MAC: "aa:bb:cc:dd:ee:ff", IPv4: []string{"192.168.1.10"}, Vendor: "Acme"})
	return New(st, &fakeController{})
}

func TestHostsMethodNotAllowed(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api/hosts", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/hosts = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "GET") {
		t.Errorf("Allow header = %q, want it to include GET", allow)
	}
}

func TestHostsCompactByDefault(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/hosts", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "\n  ") {
		t.Errorf("default response is indented; expected compact JSON:\n%s", body)
	}
	// Sanity: it is valid JSON with our host.
	var resp struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("count = %d, want 1", resp.Count)
	}
}

func TestHostsPretty(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/hosts?pretty=1", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "\n  ") {
		t.Errorf("?pretty=1 response is not indented:\n%s", rec.Body.String())
	}
}

func TestHostsGzip(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/hosts", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if enc := rec.Header().Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", enc)
	}
	gz, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()
	decoded, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	if !strings.Contains(string(decoded), "aa:bb:cc:dd:ee:ff") {
		t.Errorf("decoded body missing host MAC:\n%s", decoded)
	}
}

func TestScanControl(t *testing.T) {
	srv := newTestServer()

	state := func() bool {
		req := httptest.NewRequest(http.MethodGet, "/api/scan", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/scan = %d, want 200", rec.Code)
		}
		var resp struct {
			Paused bool `json:"paused"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		return resp.Paused
	}
	post := func(action string) bool {
		req := httptest.NewRequest(http.MethodPost, "/api/scan?action="+action, nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST /api/scan?action=%s = %d, want 200", action, rec.Code)
		}
		var resp struct {
			Paused bool `json:"paused"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return resp.Paused
	}

	if state() {
		t.Fatal("scanner should start unpaused")
	}
	if !post("pause") {
		t.Error("after pause, want paused=true")
	}
	if !state() {
		t.Error("GET after pause should report paused=true")
	}
	if post("resume") {
		t.Error("after resume, want paused=false")
	}
	if !post("toggle") {
		t.Error("toggle from running should pause")
	}

	// Bad action is a 400.
	req := httptest.NewRequest(http.MethodPost, "/api/scan?action=bogus", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad action = %d, want 400", rec.Code)
	}
}

func TestCommentEndpoint(t *testing.T) {
	srv := newTestServer()

	// Setting a note on a known host returns the updated record.
	body := `{"key":"aa:bb:cc:dd:ee:ff","comment":"  garage door opener  "}`
	req := httptest.NewRequest(http.MethodPost, "/api/comment", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/comment = %d, want 200", rec.Code)
	}
	var host store.Host
	if err := json.Unmarshal(rec.Body.Bytes(), &host); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if host.Comment != "garage door opener" {
		t.Errorf("Comment = %q, want trimmed %q", host.Comment, "garage door opener")
	}

	// It is reflected in the inventory.
	req = httptest.NewRequest(http.MethodGet, "/api/hosts", nil)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "garage door opener") {
		t.Errorf("/api/hosts missing saved comment:\n%s", rec.Body.String())
	}

	// Unknown key -> 404.
	req = httptest.NewRequest(http.MethodPost, "/api/comment", strings.NewReader(`{"key":"00:00:00:00:00:00","comment":"x"}`))
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown key = %d, want 404", rec.Code)
	}

	// Missing key -> 400.
	req = httptest.NewRequest(http.MethodPost, "/api/comment", strings.NewReader(`{"comment":"x"}`))
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing key = %d, want 400", rec.Code)
	}

	// Wrong method -> 405.
	req = httptest.NewRequest(http.MethodGet, "/api/comment", nil)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/comment = %d, want 405", rec.Code)
	}
}

func TestShutdownDisabledWithoutCallback(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api/shutdown", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST /api/shutdown without callback = %d, want 503", rec.Code)
	}
}

func TestShutdownInvokesCallback(t *testing.T) {
	srv := newTestServer()
	called := make(chan struct{}, 1)
	srv.SetShutdown(func() { called <- struct{}{} })

	req := httptest.NewRequest(http.MethodPost, "/api/shutdown", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/shutdown = %d, want 200", rec.Code)
	}

	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("shutdown callback was not invoked")
	}

	// Non-POST methods are rejected.
	req = httptest.NewRequest(http.MethodGet, "/api/shutdown", nil)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/shutdown = %d, want 405", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Errorf("/healthz body = %q, want ok", rec.Body.String())
	}
}
