package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func queueFrame(data []byte) api.StreamFrame {
	sum := sha256.Sum256(data)
	return api.StreamFrame{Cursor: "fixture-cursor", Chunk: &api.BlobChunk{
		ObjectID: "fixture-object", Data: data, SHA256: api.Digest(hex.EncodeToString(sum[:]))}}
}

func TestWatcherOverflow(t *testing.T) {
	t.Run("frames", func(t *testing.T) {
		queue := newStreamQueue()
		frame := queueFrame([]byte{})
		for index := 0; index < 256; index++ {
			if err := queue.push(frame); err != nil {
				t.Fatal("frame capacity control refused", err)
			}
		}
		if err := queue.push(frame); err == nil {
			t.Fatal("watcher accepted frame queue overflow")
		} else {
			codeIs(t, err, api.CodeUnavailable)
		}
		queue.release(<-queue.frames)
		if err := queue.push(frame); err != nil {
			t.Fatal("frame capacity was not released", err)
		}
	})
	t.Run("bytes", func(t *testing.T) {
		queue := newStreamQueue()
		frame := queueFrame(make([]byte, api.MaxChunkBytes))
		encoded, err := json.Marshal(frame)
		if err != nil {
			t.Fatal(err)
		}
		capacity := (4 * 1024 * 1024) / len(encoded)
		if capacity >= 256 || capacity < 1 {
			t.Fatal("byte canary does not isolate the byte bound")
		}
		for index := 0; index < capacity; index++ {
			if err := queue.push(frame); err != nil {
				t.Fatal("byte capacity control refused", err)
			}
		}
		if err := queue.push(frame); err == nil {
			t.Fatal("watcher accepted byte queue overflow")
		} else {
			codeIs(t, err, api.CodeUnavailable)
		}
		queue.release(<-queue.frames)
		if err := queue.push(frame); err != nil {
			t.Fatal("byte capacity was not released", err)
		}
	})
}

type queueErrorStream struct {
	err    error
	closed chan struct{}
}

func (s *queueErrorStream) Next(context.Context) (api.StreamFrame, error) {
	return api.StreamFrame{}, s.err
}
func (s *queueErrorStream) Close() error { close(s.closed); return nil }

func TestWatcherErrorCursor(t *testing.T) {
	queue := newStreamQueue()
	frame := queueFrame([]byte{})
	for index := 0; index < 256; index++ {
		if err := queue.push(frame); err != nil {
			t.Fatal(err)
		}
	}
	overflow := queue.push(frame)
	if overflow == nil {
		t.Fatal("error cursor control did not overflow")
	}
	producer := &queueErrorStream{err: overflow, closed: make(chan struct{})}
	server := fixtureServer(t)
	if err := server.RegisterStream("lane.attach", func(context.Context, api.Scope, json.RawMessage) (api.EventStream, error) {
		return producer, nil
	}); err != nil {
		t.Fatal(err)
	}
	request := requestFor(t, "lane.attach", api.AttachRequest{Target: api.LifeRef{
		LifeID: server.deps.Authenticator.(*authFixture).scope.Actor.LifeID, Run: 1}, Mode: "output"})
	frame.Index, frame.RequestID = 1, request.RequestID
	initial, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	inside, outside := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer outside.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer inside.Close()
		server.serveStream(ctx, inside, server.deps.Authenticator.(*authFixture).scope, request, initial)
	}()
	if err := outside.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	data, err := wire.ReadFrame(outside)
	if err != nil {
		t.Fatal(err)
	}
	var result api.StreamFrame
	if err := wire.Decode(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Cursor != frame.Cursor {
		t.Fatal("watcher overflow lost resumable cursor")
	}
	if result.End || result.Error == nil || result.Error.Code != api.CodeUnavailable || result.Index != 1 {
		t.Fatal("watcher overflow became successful or uncorrelated end")
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("overflow watcher did not quiesce")
	}
	select {
	case <-producer.closed:
	default:
		t.Fatal("overflow producer was not closed")
	}
}
