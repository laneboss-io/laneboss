package identityd

import (
	"context"
	"errors"
	"strings"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/identityd/ticket"
)

var errRoleRemoved = errors.New("the configured role was removed")
var errPolicyUnavailable = errors.New("the protected role policy is unavailable")

// Never mutate the startup snapshot: concurrent requests each read and validate
// their own current protected policy. Unreadable policy cannot retain authority.
func (s *Server) trustedRole(ctx context.Context, role string) (caller.Principal, error) {
	if s.policy == nil || ctx.Err() != nil {
		return caller.Principal{}, errPolicyUnavailable
	}
	state, _ := s.options.roots()
	current, err := config.Load(s.options.Config, config.Options{Home: s.options.ConfigHome, StateHome: state})
	if err != nil || current.Name != s.options.Config {
		return caller.Principal{}, errPolicyUnavailable
	}
	if err := protectedPolicy(current, s.process.UID); err != nil {
		return caller.Principal{}, errPolicyUnavailable
	}
	return s.readTrustedRole(ctx, current, role)
}

func policyRefusal(issued ticket.Scope, current *ticket.Scope, state string) error {
	return &ticket.Refusal{Reason: ticket.PolicyChanged, Policy: &ticket.PolicyChange{Issued: issued, Current: current, State: state}}
}

// A journal record proves provenance, not that its policy is still in force.
// This runs for each use, including whoami, before returning a live identity.
func (s *Server) validatePrincipal(ctx context.Context, principal Principal) error {
	if s.policy == nil || !validSupervisor(principal) {
		return nil
	}
	_, role, _ := strings.Cut(principal.ID, ":")
	issued := ticket.Scope{Config: s.options.Config, Level: principal.Level, Role: role}
	current, err := s.trustedRole(ctx, role)
	if errors.Is(err, errRoleRemoved) || err == nil && current.ID != principal.ID {
		return policyRefusal(issued, nil, "removed")
	}
	if err != nil {
		return policyRefusal(issued, nil, "unavailable")
	}
	if current.Level < principal.Level {
		scope := ticket.Scope{Config: issued.Config, Level: current.Level, Role: role}
		return policyRefusal(issued, &scope, "")
	}
	return nil
}
