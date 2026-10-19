package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCancelledHandlers(t *testing.T) {
	for _, path := range []string{"/api/logs?lane=worker", "/api/analytics", "/api/now", "/api/ledger", "/api/judge", "/api/messages"} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		h := &handler{name: "missing-config", host: "127.0.0.1:1234", token: "recorded-token"}
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234"+path, nil).WithContext(ctx)
		r.Header.Set(tokenHeader, h.token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Body.Len() != 0 || w.Header().Get("Content-Type") != "" {
			t.Fatalf("cancelled %s loaded or replied with data", path)
		}
	}
}
