package identityd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/identityd/ticket"
)

// Client always uses Call's kernel-authenticated Unix socket. Neither a caller
// PID nor a claimed principal is sent as authority.
type Client struct{}

func (c Client) Install() { caller.SetServiceResolver(c.Resolve) }

// Use the command's parsed selection, so an unrelated role/driver validation
// error during a second full load cannot turn an absent service into one.
func (Client) ConfiguredFor(c *config.Configuration) bool {
	_, enabled, err := config.IdentityService(c)
	return enabled || err != nil
}

func (Client) Configured(name string) bool {
	c, err := config.Load(name)
	if err != nil {
		return true
	}
	_, enabled, selectionError := config.IdentityService(c)
	return enabled || selectionError != nil
}

func clientOptions(name string) (Options, error) {
	c, err := config.Load(name)
	if err != nil {
		return Options{}, err
	}
	root, enabled, selectionError := config.IdentityService(c)
	if selectionError != nil {
		return Options{}, selectionError
	}
	if !enabled {
		return Options{}, &ticket.Refusal{Reason: ticket.Unavailable}
	}
	return Options{Config: c.Name, RuntimeRoot: root}, nil
}

func ticketError(err error) error {
	if err == nil {
		return nil
	}
	var scoped *ticket.Refusal
	if errors.As(err, &scoped) {
		return scoped
	}
	if failure, ok := err.(*failure); ok && failure.code == 2 {
		first := strings.Split(strings.TrimPrefix(failure.text, "refused: "), "\n")[0]
		for _, reason := range []ticket.Reason{ticket.HumanRequired, ticket.Required, ticket.Unknown, ticket.Expired, ticket.WrongLevel, ticket.WrongRole, ticket.WrongConfig, ticket.Used, ticket.InvalidTTL, ticket.InvalidScope, ticket.InvalidSession, ticket.Unsupported, ticket.Unavailable} {
			candidate := &ticket.Refusal{Reason: reason}
			if strings.Split(candidate.Error(), "\n")[0] == first {
				return candidate
			}
		}
	}
	return &ticket.Refusal{Reason: ticket.Unavailable}
}

func (Client) Issue(ctx context.Context, scope ticket.Scope, ttl time.Duration) (string, error) {
	options, err := clientOptions(scope.Config)
	if err != nil {
		return "", ticketError(err)
	}
	payload, err := json.Marshal(issueRequest{Level: scope.Level, Role: scope.Role, TTL: ttl.String()})
	if err != nil {
		return "", &ticket.Refusal{Reason: ticket.InvalidScope}
	}
	response, err := Call(ctx, options, Request{Op: "issue", Payload: payload})
	if err != nil {
		return "", ticketError(err)
	}
	if !ticket.Valid(response.Ticket) {
		return "", &ticket.Refusal{Reason: ticket.Unavailable}
	}
	return response.Ticket, nil
}

func (Client) Register(ctx context.Context, scope ticket.Scope, raw string) error {
	options, err := clientOptions(scope.Config)
	if err != nil {
		return ticketError(err)
	}
	return registerTicket(ctx, options, scope, raw)
}

// Start already parsed and checked service selection. Do not replace that
// view with a full client role-policy load; the service checks protected policy.
func (Client) RegisterFor(ctx context.Context, c *config.Configuration, scope ticket.Scope, raw string) error {
	root, enabled, err := config.IdentityService(c)
	if err != nil {
		return ticketError(err)
	}
	if !enabled || c.Name != scope.Config {
		return &ticket.Refusal{Reason: ticket.Unavailable}
	}
	return registerTicket(ctx, Options{Config: c.Name, RuntimeRoot: root}, scope, raw)
}

func registerTicket(ctx context.Context, options Options, scope ticket.Scope, raw string) error {
	presented, err := json.Marshal(ticket.Registration{Level: scope.Level, Role: scope.Role, Value: raw})
	if err != nil {
		return &ticket.Refusal{Reason: ticket.InvalidScope}
	}
	response, err := Call(ctx, options, Request{Op: "register", Ticket: presented})
	if err != nil {
		return ticketError(err)
	}
	if !response.Identified || response.Principal == nil || response.Record == nil || response.Record.Op != "register" {
		return &ticket.Refusal{Reason: ticket.Unavailable}
	}
	return nil
}

func (Client) Resolve(c *config.Configuration) (caller.Principal, error) {
	root, enabled, selectionError := config.IdentityService(c)
	if selectionError != nil {
		return caller.Principal{}, selectionError
	}
	if !enabled {
		return caller.Principal{}, &ticket.Refusal{Reason: ticket.Unavailable}
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	response, err := Call(ctx, Options{Config: c.Name, RuntimeRoot: root}, Request{Op: "whoami"})
	if err != nil {
		return caller.Principal{}, ticketError(err)
	}
	if response.Identified && response.Principal != nil {
		p := response.Principal
		return caller.Principal{ID: p.ID, Level: p.Level, Starter: p.Starter}, nil
	}
	if response.Human {
		return caller.Principal{ID: "human"}, nil
	}
	return caller.Principal{}, nil
}
