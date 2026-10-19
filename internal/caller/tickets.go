package caller

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/identityd/ticket"
)

// RequireHuman is a usability pre-check. A configured service supplies its
// authenticated human verdict without consulting caller-owned identity files;
// the issue operation repeats authorization against the accepted kernel peer.
func RequireHuman(c *config.Configuration) error {
	var principal Principal
	var err error
	_, configured, selectionError := config.IdentityService(c)
	if selectionError != nil {
		return &ticket.Refusal{Reason: ticket.HumanRequired}
	}
	if configured {
		principal, err = resolveService(c)
	} else {
		principal, err = Resolve(c)
	}
	if err != nil || principal.ID != "human" {
		return &ticket.Refusal{Reason: ticket.HumanRequired}
	}
	tty, err := ttyName()
	if err != nil || tty == "" {
		return &ticket.Refusal{Reason: ticket.HumanRequired}
	}
	return nil
}

// RegisterRoleWithTicket has no local-record fallback. Only the identity
// service may consume the ticket and record the authenticated peer. The service
// client is supplied by part 1; nil refuses before writing session state.
func RegisterRoleWithTicket(ctx context.Context, c *config.Configuration, name string, level int, raw string, service ticket.Registrar) error {
	if _, _, err := config.IdentityService(c); err != nil {
		return err
	}
	target, _, err := Role(c, name)
	if err != nil {
		return err
	}
	current, err := Resolve(c)
	if err != nil {
		var stale *ticket.Refusal
		if raw == "" || !errors.As(err, &stale) || stale.Reason != ticket.PolicyChanged {
			return err
		}
		// A fresh human-issued ticket may replace the revoked registration.
		// Ordinary commands still refuse, and the service rechecks this ticket.
	}
	if strings.HasPrefix(current.ID, "lane:") {
		return fmt.Errorf("a lane cannot register a supervisor role ticket\nInstead: report to the lane's recorded supervisor with laneboss report.")
	}
	if !RequiresTicket(c, service) {
		if raw != "" {
			return &ticket.Refusal{Reason: ticket.Unavailable}
		}
		if level != 0 && level != target.Level {
			return &ticket.Refusal{Reason: ticket.InvalidScope}
		}
		_, err := registerLegacyRole(c, name)
		return err
	}
	if raw == "" {
		return &ticket.Refusal{Reason: ticket.Required}
	}
	if service == nil {
		return &ticket.Refusal{Reason: ticket.Unavailable}
	}
	if level < 3 || level > 6 {
		return &ticket.Refusal{Reason: ticket.InvalidScope}
	}
	// The service compares scope and consumed status before its independent
	// escalation check. Do not let current policy hide WrongLevel or Used.
	scope := ticket.Scope{Config: c.Name, Level: level, Role: name}
	var registrationError error
	if selected, ok := service.(interface {
		RegisterFor(context.Context, *config.Configuration, ticket.Scope, string) error
	}); ok {
		registrationError = selected.RegisterFor(ctx, c, scope, raw)
	} else {
		registrationError = service.Register(ctx, scope, raw)
	}
	if err := registrationError; err != nil {
		var refusal *ticket.Refusal
		if errors.As(err, &refusal) {
			return refusal
		}
		return &ticket.Refusal{Reason: ticket.Unavailable}
	}
	return nil
}
