//go:build linux

package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func TestStreamRefusalFlush(t *testing.T) {
	s := fixtureServer(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := b.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	lifetime, err := newConnection(a, s.deps.Binding, s.deps.Clock)
	if err != nil {
		t.Fatal(err)
	}
	base := s.deps.Authenticator.(*authFixture)
	scope, err := base.Authenticate(context.Background(), lifetime)
	if err != nil {
		t.Fatal(err)
	}
	auth := &closingCurrentAuth{authFixture: base, cause: serviceError(api.CodeUnauthenticated, "component stream authority ended")}
	s.deps.Authenticator = auth
	producer := &finiteEventStream{frames: []api.StreamFrame{queueFrame([]byte("retained component output"))}, err: io.EOF, closed: make(chan struct{})}
	if err := s.RegisterStream("lane.attach", func(context.Context, api.Scope, json.RawMessage) (api.EventStream, error) { return producer, nil }); err != nil {
		t.Fatal(err)
	}
	request := requestFor(t, "lane.attach", api.AttachRequest{Target: api.LifeRef{LifeID: scope.Actor.LifeID, Run: 1}, Mode: "output"})
	initialFrame := queueFrame([]byte{})
	initialFrame.RequestID, initialFrame.Index = request.RequestID, 1
	initial, err := json.Marshal(initialFrame)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); s.serveStream(ctx, a, scope, request, initial) }()
	defer func() {
		cancel()
		a.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("stream refusal handler did not drain")
		}
	}()
	raw, err := wire.ReadFrame(b)
	if err != nil {
		t.Fatal("stream recheck lost its terminal refusal", err)
	}
	refusal, err := wire.DecodeStream(raw, request.RequestID, 1)
	if err != nil || refusal.Error == nil || refusal.Error.Code != api.CodeUnauthenticated || refusal.Cursor != initialFrame.Cursor || refusal.Chunk != nil || refusal.Event != nil || refusal.End {
		t.Fatal("stream recheck lost its terminal refusal", err)
	}
	var extra [1]byte
	if n, err := b.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal("stream recheck refusal did not close", err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("stream refusal handler did not finish")
	}
	if auth.calls != 1 {
		t.Fatal("stream refusal did not recheck its original bound connection", auth.calls)
	}
	select {
	case <-producer.closed:
	default:
		t.Fatal("stream refusal left its producer open")
	}
}
