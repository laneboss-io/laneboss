//go:build linux

package service

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// RelayTestHost supplies only installed composition and immutable identity/mail
// ports. The actual lane listener, frames, dispatcher, blob writer and store run.
func RelayTestHost(t *testing.T, ctx context.Context, deps Dependencies, lane api.InstalledBinding, scope api.Scope, mail []api.Mail) (*Server, string) {
	t.Helper()
	host := fixtureServer(t)
	host.deps, host.options.Config = deps, lane.Config
	host.bound, host.verified = true, true
	core, err := New(deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Register(host); err != nil {
		t.Fatal(err)
	}
	if err := host.Register("identity.self", func(ctx context.Context, got api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		if err := deps.Authenticator.Authorize(ctx, got, got.Request); err != nil {
			return nil, err
		}
		return json.Marshal(api.Scope{Config: scope.Config, Actor: scope.Actor, LaunchID: scope.LaunchID,
			EndpointGeneration: scope.EndpointGeneration, PolicyGeneration: scope.PolicyGeneration})
	}); err != nil {
		t.Fatal(err)
	}
	if err := host.Register("mail.list", func(ctx context.Context, got api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		var input api.ListRequest
		if err := api.DecodeObject(raw, &input); err != nil {
			return nil, err
		}
		if input.LifeID != scope.Actor.LifeID {
			return nil, serviceError(api.CodeForbidden, "relay selected another mailbox")
		}
		return json.Marshal(api.MailPage{Messages: mail})
	}); err != nil {
		t.Fatal(err)
	}
	lane.Socket = wire.LaneSocketPath
	if err := host.startLaneEndpoint(ctx, lane); err != nil {
		t.Fatal(err)
	}
	return host, filepath.Join(filepath.Dir(deps.Binding.Socket), "lanes", string(lane.LaunchID)+".sock")
}
