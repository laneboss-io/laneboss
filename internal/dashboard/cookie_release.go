//go:build !laneboss_faults

package dashboard

import "net/http"

func (h *handler) cookieFaultAuth(r *http.Request) bool   { return false }
func (h *handler) cookieFaultIssue(w http.ResponseWriter) {}
