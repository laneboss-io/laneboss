//go:build linux

package service

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type closingCurrentAuth struct {
	*authFixture
	calls int
	cause error
}

func (a *closingCurrentAuth) CurrentConnectionScope(_ context.Context, c api.ConnectionContext) (api.Scope, error) {
	a.calls++
	return api.Scope{}, errors.Join(a.cause, c.Close())
}

func TestCaptureAuthClose(t *testing.T) {
	f := fx.Ready(t, true)
	s := launchServer(t, f)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	// Arm the bound while both ends are open; a successful refusal closes a.
	if err := b.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	worker := f.Worker
	connection := *worker.Connection.(*fx.Connection)
	connection.Socket = a
	worker.Connection = &connection
	auth := &closingCurrentAuth{authFixture: s.deps.Authenticator.(*authFixture), cause: serviceError(api.CodeUnauthenticated, "component current authority ended")}
	s.deps.Authenticator = auth
	if _, err := s.CaptureState(context.Background(), worker, f.Plan.Capture.ID); !errors.Is(err, auth.cause) || auth.calls != 1 {
		t.Fatal("capture recheck did not reach its current authority refusal", err, auth.calls)
	}
	var one [1]byte
	if _, err := b.Read(one[:]); !errors.Is(err, io.EOF) {
		t.Fatal("failed capture authentication kept its transport open", err)
	}
}
