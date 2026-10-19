//go:build linux

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Real native frames exercise the connection loop and its actual slot map.
// Trusted peer registration isolates admission from production enrollment.
func TestAdmissionRetry(t *testing.T) {
	for _, invalid := range []string{"wrong_config", "endpoint_class"} {
		t.Run(invalid, func(t *testing.T) {
			server := fixtureServer(t)
			auth := &admissionAuth{callers: make(map[net.Conn]admissionCaller)}
			server.deps.Authenticator = auth
			server.verified, server.bound = true, true
			closeAtEnd := func(resource io.Closer) {
				t.Cleanup(func() {
					if err := resource.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
						t.Error(err)
					}
				})
			}
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "retry.sock"), Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			closeAtEnd(listener)
			if err := wire.EnableCredentials(listener); err != nil {
				t.Fatal(err)
			}
			client, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
			if err != nil {
				t.Fatal(err)
			}
			closeAtEnd(client)
			accepted, err := listener.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			closeAtEnd(accepted)
			peer, err := wire.PeerCredentials(accepted)
			if err != nil {
				t.Fatal(err)
			}
			caller := admissionCaller{
				scope: api.Scope{Config: server.options.Config, Actor: api.Actor{Kind: "lane", ID: fixtureID(t), LifeID: fixtureID(t), Level: 3, Role: "executor"},
					LaunchID: fixtureID(t), EndpointGeneration: 1, PolicyGeneration: 1},
				facts: api.PeerFacts{HostUID: peer.UID, HostGID: peer.GID, HostPID: peer.PID,
					ProcessGeneration: "admission-fixture-lifetime", ContainmentID: fixtureID(t)},
			}
			auth.callers[accepted] = caller
			uid := "uid:" + fmt.Sprint(peer.UID)
			containment := uid + ":" + string(caller.facts.ContainmentID)
			slots := func() [3]int {
				server.mu.RLock()
				defer server.mu.RUnlock()
				return [3]int{server.admissions[uid], server.admissions[containment], len(server.admissions)}
			}
			var dispatched atomic.Int64
			observed := make(chan [3]int, 2)
			if err := server.Register("identity.self", func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
				observed <- slots()
				dispatched.Add(1)
				return identityHandler(ctx, scope, raw)
			}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			done := make(chan struct{})
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("invalid-first-frame admission worker was not collected")
				}
				server.mu.RLock()
				defer server.mu.RUnlock()
				if len(server.admissions) != 0 || len(server.connections) != 0 {
					t.Error("invalid-first-frame admission retained slots or connections")
				}
			})
			go func() { defer close(done); server.serveConnection(ctx, accepted) }()
			if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			exchange := func(request api.Request) api.Response {
				t.Helper()
				if err := wire.WriteFrame(client, publicFrame(t, request)); err != nil {
					t.Fatal("invalid-first-frame exchange write failed", err)
				}
				data, err := wire.ReadFrame(client)
				if err != nil {
					t.Fatal("invalid-first-frame exchange read failed", err)
				}
				response, err := wire.DecodeResponse(data, request)
				if err != nil {
					t.Fatal("invalid-first-frame response differs", err)
				}
				return response
			}
			request := requestFor(t, "identity.self", api.Empty{})
			if invalid == "wrong_config" {
				request.Config = "other-config"
			} else {
				request.Method = "human.session"
			}
			request.RequestSHA256, err = wire.RequestDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			if err := wire.ValidateRequest(request); err != nil {
				t.Fatal("first frame did not reach the pre-authentication dispatch gate", err)
			}
			refusal := exchange(request)
			if refusal.Error == nil || refusal.Error.Code != api.CodeForbidden || len(refusal.Result) != 0 ||
				dispatched.Load() != 0 || slots() != [3]int{1, 0, 1} {
				t.Fatal("invalid first frame changed authority or its temporary UID slot")
			}
			for index, assertion := range []string{
				"valid second frame did not move UID slot to containment",
				"admitted connection repeated its slot transfer",
			} {
				response := exchange(requestFor(t, "identity.self", api.Empty{}))
				var result api.Scope
				if response.Error != nil || wire.Decode(response.Result, &result) != nil ||
					result.Actor != caller.scope.Actor || result.LaunchID != caller.scope.LaunchID {
					t.Fatal("valid frame after refusal did not retain the registered authority", response.Error)
				}
				select {
				case actual := <-observed:
					if actual != [3]int{0, 1, 1} || slots() != actual || dispatched.Load() != int64(index+1) {
						t.Fatal(assertion)
					}
				case <-ctx.Done():
					t.Fatal("valid frame did not reach the observed admission handler")
				}
			}
		})
	}
}
