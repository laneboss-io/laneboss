package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestAttachResume(t *testing.T) {
	f, store := newIOFixture(t)
	input := bytes.Repeat([]byte{0, 255, 'x', '\n'}, 10000)
	captureCommit(t, store, "stdout-stream", input, false)
	captureCommit(t, store, "stdout-stream", []byte("tail"), false)
	captureCommit(t, store, "stdout-stream", nil, true)
	captureCommit(t, store, "stderr-stream", nil, true)
	request := api.AttachRequest{Target: f.target, Mode: "read"}
	scope := f.scope("lane.attach", request, f.parent)
	stream, err := f.service.OpenAttach(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := stream.Next(context.Background())
	if err != nil || initial.Event == nil || initial.Event.Kind != "capture.bound" || initial.Index != 1 {
		t.Fatalf("attach lost its actual initial binding: %v", err)
	}
	first, err := stream.Next(context.Background())
	if err != nil || first.Chunk == nil || first.Chunk.Offset != 0 || len(first.Chunk.Data) >= len(input) || first.End {
		t.Fatalf("attach did not expose an exact partial byte range: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	request.Cursor = first.Cursor
	scope = f.scope("lane.attach", request, f.parent)
	resumed, err := f.service.OpenAttach(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	if _, err := resumed.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := append([]byte{}, first.Chunk.Data...)
	ended := false
	for index := uint64(2); index <= 12; index++ {
		frame, err := resumed.Next(context.Background())
		if err != nil || frame.Index != index || frame.RequestID != scope.Request.RequestID || frame.Error != nil {
			t.Fatalf("attach range stream lost its correlated frame: %v", err)
		}
		if frame.End {
			ended = true
			break
		}
		if frame.Chunk == nil || frame.Chunk.SHA256 != digestOfBytes(frame.Chunk.Data) {
			t.Fatal("attach returned unverified capture bytes")
		}
		got = append(got, frame.Chunk.Data...)
	}
	if !ended || !bytes.Equal(got, append(append([]byte{}, input...), []byte("tail")...)) || f.launcher.stopped.Load() != 0 {
		t.Fatal("attach resume skipped or repeated undelivered capture bytes")
	}
}

func TestAttachCursor(t *testing.T) {
	for _, mode := range []string{"signature", "actor", "endpoint", "mode", "restart"} {
		t.Run(mode, func(t *testing.T) {
			f, store := newIOFixture(t)
			captureCommit(t, store, "stdout-stream", bytes.Repeat([]byte("x"), 20000), false)
			request := api.AttachRequest{Target: f.target, Mode: "read"}
			stream, err := f.service.OpenAttach(context.Background(), f.scope("lane.attach", request, f.parent), request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Next(context.Background()); err != nil {
				t.Fatal(err)
			}
			frame, err := stream.Next(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			request.Cursor = frame.Cursor
			if mode == "signature" {
				request.Cursor += "x"
			}
			if mode == "mode" {
				request.Mode = "interactive"
			}
			actor := f.parent
			if mode == "actor" {
				actor.ID = "another-parent-actor"
			}
			scope := f.scope("lane.attach", request, actor)
			if mode == "endpoint" {
				scope.EndpointGeneration++
			}
			service := f.service
			if mode == "restart" {
				service, err = New(f.service.deps)
				if err != nil {
					t.Fatal(err)
				}
			}
			opened, err := service.OpenAttach(context.Background(), scope, request)
			if opened != nil {
				opened.Close()
			}
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict {
				t.Fatalf("attach accepted a foreign authenticated range cursor: %s: %v", mode, err)
			}
		})
	}
}

func TestAttachEvidence(t *testing.T) {
	for _, mode := range []string{"bytes", "origin", "offset", "binding"} {
		t.Run(mode, func(t *testing.T) {
			f, store := newIOFixture(t)
			captureCommit(t, store, "stdout-stream", []byte("primary bytes"), false)
			event := &store.events[len(store.events)-1]
			record := captureRecord(t, *event)
			switch mode {
			case "bytes":
				store.blobs[record.Data.ID][0] ^= 1
			case "origin":
				metadata := store.metadata[record.Data.ID]
				metadata.Origin = "upload"
				store.metadata[record.Data.ID] = metadata
			case "offset":
				record.Offset++
				raw, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				event.Payload = raw
				store.state.Positions[0].NextOffset++
			case "binding":
				store.state.Binding.ProducerGeneration = "foreign-generation"
			}
			allowed := captureAllowed(t)
			request := api.AttachRequest{Target: f.target, Mode: "read"}
			stream, err := f.service.OpenAttach(context.Background(), f.scope("lane.attach", request, f.parent), request)
			if stream != nil {
				defer stream.Close()
			}
			if mode != "binding" {
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Close()
				if _, err := stream.Next(context.Background()); err != nil {
					t.Fatal(err)
				}
				_, err = stream.Next(context.Background())
			}
			if mode == "origin" {
				// Owner R181-R192: primary-capture provenance is allowed and logged; the intact bytes are still read.
				if err != nil || !slices.Equal(allowed(), []string{"attach_capture_provenance"}) {
					t.Fatalf("attach provenance was not allowed and logged: %v %v", err, allowed())
				}
				return
			}
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || len(allowed()) != 0 {
				t.Fatalf("attach exposed untrusted or discontinuous primary bytes: %s: %v %v", mode, err, allowed())
			}
		})
	}
}

func TestAttachPinned(t *testing.T) {
	f, store := newIOFixture(t)
	captureCommit(t, store, "stdout-stream", []byte("captured output"), false)
	request := api.AttachRequest{Target: f.target, Mode: "read"}
	scope := f.scope("lane.attach", request, f.parent)
	view := &fixtureReadView{}
	scope.ReadView = view
	initial, err := f.service.LaneAttach(context.Background(), scope, request)
	if err != nil || initial.Event == nil || initial.Event.Kind != "capture.bound" {
		t.Fatalf("attach lost its pinned response: %v", err)
	}
	stream, err := f.service.OpenAttach(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	frame, err := stream.Next(context.Background())
	if err != nil || frame.Chunk == nil || string(frame.Chunk.Data) != "captured output" || frame.Index != 1 || view.closed {
		t.Fatalf("attach repeated its pinned response or skipped capture bytes: %v", err)
	}
}

func TestAttachCancel(t *testing.T) {
	f, store := newIOFixture(t)
	request := api.AttachRequest{Target: f.target, Mode: "read"}
	stream, err := f.service.OpenAttach(context.Background(), f.scope("lane.attach", request, f.parent), request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	store.stateRead = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		frame, err := stream.Next(ctx)
		if frame.End && err == nil {
			finished <- integrity("live attach fabricated completion")
		} else {
			finished <- err
		}
	}()
	select {
	case <-store.stateRead:
	case <-time.After(time.Second):
		t.Fatal("attach never read its live capture state")
	}
	cancel()
	select {
	case err := <-finished:
		if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeCancelled || f.launcher.stopped.Load() != 0 {
			t.Fatalf("attach cancellation fabricated end or stopped its lane: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("attach watcher ignored cancellation")
	}
}

func TestAttachRevocation(t *testing.T) {
	f, store := newIOFixture(t)
	captureCommit(t, store, "stdout-stream", []byte("private capture bytes"), false)
	request := api.AttachRequest{Target: f.target, Mode: "read"}
	stream, err := f.service.OpenAttach(context.Background(), f.scope("lane.attach", request, f.parent), request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.identity.denied.Store(true)
	_, err = stream.Next(context.Background())
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeForbidden {
		t.Fatalf("attach delivered bytes after live revocation: %v", err)
	}
}
