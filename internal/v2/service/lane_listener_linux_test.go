//go:build linux

package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Only peer/containment authorization is a component fixture. The listener,
// credentials on every frame, endpoint selection and response bytes are real.
func laneHostFixture(t *testing.T, host *Server) {
	t.Helper()
	directory := privateHostDirectory(t)
	uid, gid := os.Geteuid(), os.Getegid()
	if uid == 0 {
		uid = 1
	}
	if gid == 0 {
		gid = 1
	}
	if err := os.Mkdir(filepath.Join(directory, "lanes"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{directory, filepath.Join(directory, "lanes")} {
		if err := os.Chown(path, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	digest, err := wire.ArtifactDigest()
	if err != nil {
		t.Fatal(err)
	}
	host.deps.Binding = api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol,
		APISchema: api.SchemaVersion, Config: host.options.Config, Class: api.EndpointHuman, InstallationGeneration: 1, EndpointGeneration: 1,
		ServiceUID: uint32(uid), ServiceGID: uint32(gid), MappedServiceUID: uint32(uid), MappedServiceGID: uint32(gid),
		Socket: filepath.Join(directory, "control.sock"), ArtifactSHA256: digest, ServiceVersion: release.Version, Backend: "linux-bwrap-landlock"}
	t.Cleanup(func() {
		host.mu.RLock()
		entries := make([]*laneEndpoint, 0, len(host.laneEndpoints))
		for _, entry := range host.laneEndpoints {
			entries = append(entries, entry)
		}
		host.mu.RUnlock()
		for _, entry := range entries {
			entry.cancel()
		}
		done := make(chan struct{})
		go func() { host.workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("lane listener fixture did not drain its actual connections")
		}
	})
}

func laneSpecFixture(t *testing.T, host *Server) (api.LaunchSpec, api.HelperLease) {
	t.Helper()
	lease := api.HelperLease{ID: fixtureID(t), ContainmentID: fixtureID(t), UID: host.deps.Binding.ServiceUID + 1000, GID: host.deps.Binding.ServiceGID + 1000, EndpointGeneration: 1}
	spec := api.LaunchSpec{Kind: "agent", LaunchID: fixtureID(t), Target: api.LifeRef{LifeID: fixtureID(t), Run: 2}, Backend: host.deps.Binding.Backend,
		UIDLeaseID: lease.ID, EndpointGeneration: 1, Runner: &api.RunnerPlan{Driver: api.DriverCodex}}
	return spec, lease
}

func TestLaneEndpointLifetime(t *testing.T) {
	host := fixtureServer(t)
	laneHostFixture(t, host)
	first, firstLease := laneSpecFixture(t, host)
	second, secondLease := laneSpecFixture(t, host)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, item := range []struct {
		spec  api.LaunchSpec
		lease api.HelperLease
	}{{first, firstLease}, {second, secondLease}} {
		if err := host.prepareLaneEndpoint(parent, item.spec, item.lease); err != nil {
			t.Fatal("lane endpoint could not install its private listener", err)
		}
	}
	cancel()
	path := func(id api.ID) string {
		return filepath.Join(filepath.Dir(host.deps.Binding.Socket), "lanes", string(id)+".sock")
	}
	before, err := os.Lstat(path(first.LaunchID))
	if err != nil || before.Mode()&os.ModeSocket == 0 || before.Mode().Perm() != 0666 {
		t.Fatal("lane endpoint lost its actual socket inode or mode", err)
	}
	if err := host.prepareLaneEndpoint(context.Background(), first, firstLease); err != nil {
		t.Fatal("identical lane endpoint preparation did not retain its listener", err)
	}
	after, err := os.Lstat(path(first.LaunchID))
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("lane preparation replaced a live endpoint", err)
	}
	changed := first
	changed.Target.Run++
	if err := host.prepareLaneEndpoint(context.Background(), changed, firstLease); err == nil {
		t.Fatal("lane listener accepted a changed run under its original launch ID")
	}
	ctx, done := context.WithTimeout(context.Background(), 3*time.Second)
	defer done()
	if err := host.stopLaneEndpoint(ctx, first.LaunchID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path(first.LaunchID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("terminal lane endpoint retained its socket", err)
	}
	if _, err := os.Lstat(path(second.LaunchID)); err != nil {
		t.Fatal("stopping one lane removed a sibling endpoint", err)
	}
	if err := host.stopLaneEndpoint(ctx, second.LaunchID); err != nil {
		t.Fatal(err)
	}
}

type laneSocketAuth struct {
	api.Authenticator
	principal, containment api.ID
	calls                  atomic.Int32
}

func (a *laneSocketAuth) Authenticate(ctx context.Context, connection api.ConnectionContext) (api.Scope, error) {
	a.calls.Add(1)
	binding := connection.Binding()
	if binding.Class != api.EndpointLane || binding.Target == nil {
		return api.Scope{}, serviceError(api.CodeUnauthenticated, "component caller reached another endpoint class")
	}
	if connection.Peer() == nil {
		peer, err := wire.PeerCredentials(connection.Conn().(*net.UnixConn))
		if err != nil {
			return api.Scope{}, err
		}
		if err := connection.BindPeer(&peerFixture{facts: api.PeerFacts{HostUID: peer.UID, HostGID: peer.GID, HostPID: peer.PID,
			ProcessGeneration: "component-lane-socket", ContainmentID: a.containment}}); err != nil {
			return api.Scope{}, err
		}
	}
	return api.Scope{Config: binding.Config, Actor: api.Actor{Kind: "lane", ID: a.principal, LifeID: binding.Target.LifeID, Level: 3, Role: "executor"},
		LaunchID: binding.LaunchID, EndpointGeneration: binding.EndpointGeneration, PolicyGeneration: 1, Connection: connection}, connection.Peer().Alive(ctx)
}

func (a *laneSocketAuth) CurrentConnectionScope(ctx context.Context, connection api.ConnectionContext) (api.Scope, error) {
	return a.Authenticate(ctx, connection)
}

func (a *laneSocketAuth) Authorize(ctx context.Context, scope api.Scope, request api.Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if scope.Actor.Kind != "lane" || scope.Actor.ID != a.principal || scope.Config != request.Config || scope.Connection == nil ||
		scope.LaunchID != scope.Connection.Binding().LaunchID || request.Proof != nil || stringsHumanMethod(request.Method) {
		return serviceError(api.CodeForbidden, "component lane authorization differs from its socket principal")
	}
	return nil
}

func TestLaneEndpointBoundFrames(t *testing.T) {
	host := fixtureServer(t)
	laneHostFixture(t, host)
	host.verified, host.bound = true, true
	auth := &laneSocketAuth{principal: fixtureID(t), containment: fixtureID(t)}
	host.deps.Authenticator = auth
	if err := host.Register("identity.self", identityHandler); err != nil {
		t.Fatal(err)
	}
	spec, lease := laneSpecFixture(t, host)
	if err := host.prepareLaneEndpoint(context.Background(), spec, lease); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(host.deps.Binding.Socket), "lanes", string(spec.LaunchID)+".sock")
	call := func(request api.Request) api.Response {
		t.Helper()
		connection, err := net.DialTimeout("unix", path, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if err := wire.WriteFrame(connection, raw); err != nil {
			t.Fatal(err)
		}
		raw, err = wire.ReadFrame(connection)
		if err != nil {
			t.Fatal("lane endpoint did not return a complete actual frame", err)
		}
		response, err := wire.DecodeResponse(raw, request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	response := call(requestFor(t, "identity.self", api.Empty{}))
	var scope api.Scope
	if response.Error != nil || api.DecodeObject(response.Result, &scope) != nil || scope.LaunchID != spec.LaunchID || scope.Actor.ID != auth.principal || scope.Actor.Kind != "lane" || scope.Actor.LifeID != spec.Target.LifeID {
		t.Fatal("lane socket inherited the host's human binding or lost its actual caller", response.Error)
	}
	before := auth.calls.Load()
	response = call(requestFor(t, "human.challenge", api.HumanChallengeRequest{Method: "lane.start", TargetID: fixtureID(t), RequestSHA256: host.deps.Binding.ArtifactSHA256, BaseGeneration: 1}))
	if response.Error == nil || response.Error.Code != api.CodeForbidden || auth.calls.Load() != before {
		t.Fatal("lane socket reached human administration through its host binding", response.Error)
	}
}
