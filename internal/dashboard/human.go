package dashboard

import (
	"net/http"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
)

// startingHuman resolves who starts the dashboard. The page, its token and every
// write it offers belong to the human, so a lane, a supervisor, an instance or a
// process that cannot be identified is refused before a port opens.
func startingHuman(c *config.Configuration) (caller.Principal, string) {
	principal, err := caller.Resolve(c)
	if err != nil {
		return caller.Principal{}, "refused: " + err.Error()
	}
	if principal.ID != "human" {
		who := principal.ID
		if who == "" {
			who = "an unidentified process"
		}
		return caller.Principal{}, "refused: only the human may start the dashboard, and this caller resolved to " + who + ": the dashboard's token and compose box are the human's.\nInstead: report up with laneboss report."
	}
	return principal, ""
}

// humanOnly guards every write the dashboard offers. The server holds the
// principal its starter resolved to, so a handler that was not started by the
// human never writes.
func (h *handler) humanOnly(w http.ResponseWriter) bool {
	if h.principal.ID == "human" {
		return true
	}
	reply(w, http.StatusForbidden, object{"error": "only the human may write from the dashboard"})
	return false
}
