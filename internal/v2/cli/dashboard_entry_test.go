package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestDashboardEntryProxy(t *testing.T) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString(nonce[:])
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "console.example.test" || r.Header.Get("Origin") != "https://console.example.test" {
			http.Error(w, "pinned origin refused", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Laneboss-Presence", "simulated")
		_, _ = io.WriteString(w, "data: "+r.URL.Query().Get("nonce")+"\n\n")
	}))
	defer backend.Close()
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(backend.URL, "http://"))
	}}
	defer transport.CloseIdleConnections()
	proxy := httptest.NewTLSServer(dashboardProxy(transport))
	defer proxy.Close()
	request, err := http.NewRequest("GET", proxy.URL+"/api/v2/events?nonce="+want, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "console.example.test"
	request.Header.Set("Origin", "https://console.example.test")
	response, err := proxy.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(response.Body)
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || string(raw) != "data: "+want+"\n\n" || response.Header.Get("X-Laneboss-Presence") != "simulated" {
		t.Fatal("HTTPS proxy changed the actual SSE response")
	}
	request.Host = "wrong.example.test"
	response, err = proxy.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("HTTPS proxy hid the wrong Host from the installed handler")
	}
}

func TestDashboardEntryWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observed.json")
	raw := []byte("exact input bytes\n")
	if err := dashboardWrite(path, raw); err != nil {
		t.Fatal(err)
	}
	kept, err := os.ReadFile(path)
	if err != nil || string(kept) != string(raw) {
		t.Fatal("dashboard output changed exact bytes")
	}
	if err := dashboardWrite(path, []byte("replacement")); err == nil {
		t.Fatal("dashboard replaced retained evidence")
	}
}

func TestDashboardEntryInput(t *testing.T) {
	withUser := (&url.URL{Scheme: "https", Host: "entry.example.invalid", User: url.UserPassword("fixture", "unused")}).String()
	for _, origin := range []string{"http://example.test", withUser, "https://example.test/path", "https://example.test?x=1"} {
		err := dashboardHost(context.Background(), api.InstalledBinding{}, "", origin, "", "", "", "")
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeInvalid {
			t.Fatal("dashboard accepted an unpinned HTTPS origin")
		}
	}
}
