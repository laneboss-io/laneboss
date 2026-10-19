package ticket

import (
	"fmt"

	"laneboss.io/laneboss/internal/instancename"
)

// PolicyChange contains only authenticated policy/record scope, never a bearer.
// Current is nil for a removed or unreadable source. The same value travels
// over the authenticated service response so every CLI keeps the exact refusal.
type PolicyChange struct {
	Issued  Scope  `json:"issued"`
	Current *Scope `json:"current,omitempty"`
	State   string `json:"state,omitempty"`
}

func (p *PolicyChange) Valid() bool {
	valid := func(s Scope) bool {
		return namePattern.MatchString(s.Config) && s.Level >= 3 && s.Level <= 6 && instancename.Valid(s.Role)
	}
	if p == nil || !valid(p.Issued) {
		return false
	}
	if p.Current == nil {
		return p.State == "removed" || p.State == "unavailable"
	}
	return p.State == "" && valid(*p.Current) && p.Current.Config == p.Issued.Config && p.Current.Role == p.Issued.Role && p.Current.Level < p.Issued.Level
}

func (p *PolicyChange) message() string {
	if !p.Valid() {
		return (&Refusal{Reason: Unavailable}).Error()
	}
	issued := fmt.Sprintf("%s L%d %s", p.Issued.Config, p.Issued.Level, p.Issued.Role)
	current := p.State + " " + p.Issued.Config + " " + p.Issued.Role
	route := "have the administrator restore or select a current role, then have the human issue a new ticket for the current scope with laneboss ticket issue --config NAME --level LEVEL --role ROLE and register from the dedicated persistent session with --level LEVEL --role ROLE --ticket-file PATH."
	if p.Current != nil {
		s := *p.Current
		current = fmt.Sprintf("%s L%d %s", s.Config, s.Level, s.Role)
		flags := fmt.Sprintf("--config %s --level %d --role %s", s.Config, s.Level, s.Role)
		route = "have the human issue a new ticket for the current scope with laneboss ticket issue " + flags + ", then register from the dedicated persistent session with laneboss start " + flags + " --ticket-file PATH."
	}
	return "the registration policy changed: issued " + issued + "; current " + current + "\nInstead: " + route
}
