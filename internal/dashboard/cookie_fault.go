//go:build laneboss_faults

package dashboard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/faults"
)

// This mutant reinstates the real signed cookie and its replay behavior.
func (h *handler) cookieSignature(expiry string) string {
	mac := hmac.New(sha256.New, []byte(h.token))
	mac.Write([]byte("dashboard-cookie:" + expiry))
	return hex.EncodeToString(mac.Sum(nil))
}
func (h *handler) cookieFaultAuth(r *http.Request) bool {
	if faults.Get("dashboard-cookie").Point == "" {
		return false
	}
	cookie, err := r.Cookie("laneboss_dashboard")
	if err != nil || len(cookie.Value) > 128 {
		return false
	}
	expiry, signature, found := strings.Cut(cookie.Value, ".")
	if !found {
		return false
	}
	seconds, err := strconv.ParseInt(expiry, 10, 64)
	now := time.Now().Unix()
	return err == nil && seconds > now && seconds <= now+900 && h.token != "" && hmac.Equal([]byte(signature), []byte(h.cookieSignature(expiry)))
}
func (h *handler) cookieFaultIssue(w http.ResponseWriter) {
	if faults.Get("dashboard-cookie").Point == "" {
		return
	}
	expiry := strconv.FormatInt(time.Now().Unix()+900, 10)
	http.SetCookie(w, &http.Cookie{Name: "laneboss_dashboard", Value: expiry + "." + h.cookieSignature(expiry), Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 900})
}
