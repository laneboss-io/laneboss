//go:build linux

package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	datafx "laneboss.io/laneboss/internal/v2/store/matfx"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Actual native frames and retained worker state, with explicit identity
// doubles. This does not establish installed helper or kernel containment.
type workerReplyAuth struct {
	*dataAuthFixture
	calls, failAt int
}

func (a *workerReplyAuth) Authenticate(ctx context.Context, c api.ConnectionContext) (api.Scope, error) {
	facts, err := a.d.Worker.Connection.Peer().Facts(ctx)
	if err != nil {
		return api.Scope{}, err
	}
	if err := c.BindPeer(&peerFixture{facts: facts}); err != nil {
		return api.Scope{}, err
	}
	return a.dataAuthFixture.Authenticate(ctx, c)
}
func (a *workerReplyAuth) CurrentConnectionScope(ctx context.Context, c api.ConnectionContext) (api.Scope, error) {
	a.calls++
	if a.calls == a.failAt {
		return api.Scope{}, errors.Join(serviceError(api.CodeUnauthenticated, "component worker authority ended"), c.Close())
	}
	return a.dataAuthFixture.CurrentConnectionScope(ctx, c)
}

func TestWorkerFrameTurn(t *testing.T) {
	d := datafx.NewData(t)
	d.Open(t)
	s, _ := dataServer(t, d)
	auth := &workerReplyAuth{dataAuthFixture: s.deps.Authenticator.(*dataAuthFixture)}
	s.deps.Authenticator = auth
	path := filepath.Join(t.TempDir(), "worker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := wire.EnableCredentials(listener); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	socket, err := listener.AcceptUnix()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("worker frame handler did not drain")
		}
	})
	if err := client.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() { defer close(done); s.serveDataWorker(ctx, socket, d.Endpoint) }()
	for attempt := 0; attempt < 3; attempt++ {
		lease := d.Stage.Worker.ID
		if attempt == 2 {
			lease = fx.ID(t)
		}
		request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: d.F.Deps.Config,
			Method: api.Method(api.WorkerInputRead), RequestID: fx.ID(t), IdempotencyKey: fx.ID(t),
			Params: fx.JSON(t, api.WorkerInputRequest{LeaseID: lease})}
		request.RequestSHA256, err = api.RequestDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		if err := wire.WriteFrame(client, fx.JSON(t, request)); err != nil {
			t.Fatal(err)
		}
		raw, err := wire.ReadFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		var reply api.Response
		if api.DecodeObject(raw, &reply) != nil || reply.RequestID != request.RequestID {
			t.Fatal("worker frame lost its correlated reply")
		}
		if attempt == 2 {
			if reply.Error == nil || reply.Error.Code != api.CodeForbidden || len(reply.Result) != 0 {
				t.Fatal("later frame borrowed an earlier frame's job authority", reply.Error)
			}
		} else {
			var input api.WorkerJobInput
			if reply.Error != nil || api.DecodeObject(reply.Result, &input) != nil || input.LeaseID != lease {
				t.Fatal("worker frame did not read its actual retained input", reply.Error)
			}
		}
		idle, stop := context.WithTimeout(ctx, 500*time.Millisecond)
		finish, err := s.workerTurn(idle, d.Stage.Worker.ID, "archive_observe")
		stop()
		if err != nil {
			t.Fatal("idle worker socket retained the completed frame's turn", err)
		}
		finish()
	}
	if auth.calls != 6 {
		t.Fatal("worker frames omitted an entry or delivery authority recheck", auth.calls)
	}
}

func TestWorkerRefusalFlush(t *testing.T) {
	for _, phase := range []struct {
		name string
		fail int
	}{{"entry", 1}, {"delivery", 2}, {"later", 3}} {
		t.Run(phase.name, func(t *testing.T) {
			d := datafx.NewData(t)
			d.Open(t)
			s, _ := dataServer(t, d)
			auth := &workerReplyAuth{dataAuthFixture: s.deps.Authenticator.(*dataAuthFixture), failAt: phase.fail}
			s.deps.Authenticator = auth
			path := filepath.Join(t.TempDir(), "worker.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if err := wire.EnableCredentials(listener); err != nil {
				t.Fatal(err)
			}
			client, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
			if err != nil {
				t.Fatal(err)
			}
			socket, err := listener.AcceptUnix()
			if err != nil {
				client.Close()
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			done := make(chan struct{})
			t.Cleanup(func() {
				cancel()
				client.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("worker refusal handler did not drain")
				}
			})
			if err := client.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
				t.Fatal(err)
			}
			go func() { defer close(done); s.serveDataWorker(ctx, socket, d.Endpoint) }()
			for attempt := 0; ; attempt++ {
				request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: d.F.Deps.Config,
					Method: api.Method(api.WorkerInputRead), RequestID: fx.ID(t), IdempotencyKey: fx.ID(t),
					Params: fx.JSON(t, api.WorkerInputRequest{LeaseID: d.Stage.Worker.ID})}
				request.RequestSHA256, err = api.RequestDigest(request)
				if err != nil {
					t.Fatal(err)
				}
				if err := wire.WriteFrame(client, fx.JSON(t, request)); err != nil {
					t.Fatal("worker refusal request did not reach its handler", err)
				}
				raw, err := wire.ReadFrame(client)
				if err != nil {
					t.Fatal("worker recheck lost its correlated refusal", err)
				}
				var reply api.Response
				if err := json.Unmarshal(raw, &reply); err != nil || reply.RequestID != request.RequestID || reply.Protocol != api.Protocol || reply.Schema != api.SchemaVersion {
					t.Fatal("worker recheck lost its correlated refusal", err)
				}
				if phase.name == "later" && attempt == 0 {
					var input api.WorkerJobInput
					if reply.Error != nil || api.DecodeObject(reply.Result, &input) != nil || input.LeaseID != d.Stage.Worker.ID {
						t.Fatal("worker recheck control did not complete its first request", reply.Error)
					}
					continue
				}
				if reply.Error == nil || reply.Error.Code != api.CodeUnauthenticated || reply.Error.Message != "service connection refused at authentication" || len(reply.Result) != 0 {
					t.Fatal("worker recheck lost its correlated refusal", reply.Error)
				}
				break
			}
			var extra [1]byte
			if n, err := client.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatal("worker recheck refusal did not close", err)
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("worker refusal handler did not finish")
			}
			if auth.calls != phase.fail {
				t.Fatal("worker refusal did not reach its selected bound recheck", auth.calls)
			}
		})
	}
}
