package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
)

type httpPresenceKey struct{}
type httpPresence struct {
	mu               sync.Mutex
	known, simulated bool
	paths            map[string]bool
}

func captureHTTPPresence(ctx context.Context) (context.Context, *httpPresence) {
	p := &httpPresence{}
	return context.WithValue(ctx, httpPresenceKey{}, p), p
}

// RecordHTTPPresence is server-owned response metadata for HumanTransport.
// A transport must preserve the dispatch context, or record the provenance
// from its same authorized pinned read here. No browser field selects it.
// The frozen ResourceView RPC body remains unchanged.
func RecordHTTPPresence(ctx context.Context, simulated bool) {
	if p, ok := ctx.Value(httpPresenceKey{}).(*httpPresence); ok {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.known, p.simulated = true, p.simulated || simulated
	}
}

func resourcePresencePaths(ctx context.Context, paths map[string]bool) {
	if p, ok := ctx.Value(httpPresenceKey{}).(*httpPresence); ok {
		p.mu.Lock()
		p.paths = paths
		p.mu.Unlock()
	}
}

func resourcePagePresence(ctx context.Context, page []api.Resource) {
	if p, ok := ctx.Value(httpPresenceKey{}).(*httpPresence); ok {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.known = true
		for _, resource := range page {
			p.simulated = p.simulated || p.paths[resource.Path]
		}
	}
}

func applyHTTPPresence(w http.ResponseWriter, method api.Method, p *httpPresence) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if (method == "dashboard.plugins" || method == "dashboard.resources") && !p.known {
		return api.NotImplemented("lb-v2-service", "resource response presence provenance")
	}
	presenceHeaders(w, map[string]any{"simulated_presence": p.simulated})
	return nil
}

// Presence reports audit provenance, never a claim of physical presence.
// Walking the complete result also covers nested proofs, operations, tickets,
// approvals and application receipts without dropping a newly added mark.
func simulatedPresence(value any) bool {
	switch item := value.(type) {
	case map[string]any:
		if mark, ok := item["simulated_presence"].(bool); ok && mark {
			return true
		}
		for _, child := range item {
			if simulatedPresence(child) {
				return true
			}
		}
	case []any:
		for _, child := range item {
			if simulatedPresence(child) {
				return true
			}
		}
	}
	return false
}

func presenceHeaders(w http.ResponseWriter, value any) {
	presence := "not_proven"
	raw, err := json.Marshal(value)
	if err == nil {
		var decoded any
		if json.Unmarshal(raw, &decoded) == nil && simulatedPresence(decoded) {
			presence = "simulated"
		}
	}
	// A dependent session may already have marked the response.
	if w.Header().Get("X-Laneboss-Presence") != "simulated" {
		w.Header().Set("X-Laneboss-Presence", presence)
	}
	w.Header().Set("X-Laneboss-Human-Approval", "not_proven")
}
