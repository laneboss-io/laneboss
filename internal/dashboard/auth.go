package dashboard

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"

	"laneboss.io/laneboss/internal/faults"
)

const tokenHeader = "X-Laneboss-Token"

func newToken() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func (h *handler) authenticated(r *http.Request) bool {
	if faults.Get("dashboard-no-token").Point != "" || r.Method == http.MethodGet && faults.Get("dashboard-get-no-token").Point != "" {
		return true
	}
	if token := r.Header.Get(tokenHeader); token != "" {
		return h.token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(h.token)) == 1
	}
	return h.cookieFaultAuth(r)
}

func (h *handler) validOrigin(r *http.Request) bool {
	return faults.Get("dashboard-no-origin").Point != "" || r.Header.Get("Origin") == "http://"+h.host
}
