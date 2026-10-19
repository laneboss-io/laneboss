package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func fixtureRequest(t *testing.T) api.Request {
	t.Helper()
	id, err := wire.NewID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := wire.NewID()
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(api.BlobReadRequest{ObjectID: id, Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "client-fixture",
		Method: "blob.read", RequestID: id, IdempotencyKey: key, Params: params}
	request.RequestSHA256, err = wire.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func assertCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("wanted %s, got %v", code, err)
	}
}

func TestCallFramedResult(t *testing.T) {
	request := fixtureRequest(t)
	finished := make(chan error, 1)
	c := &Client{Options: Options{Config: request.Config}}
	// Test-only transport fixture. No exported dial or bypass mode is installed.
	c.dial = func(context.Context) (net.Conn, error) {
		inside, outside := net.Pipe()
		go func() {
			var resultErr error
			defer func() { finished <- errors.Join(resultErr, outside.Close()) }()
			data, err := wire.ReadFrame(outside)
			if err != nil {
				resultErr = err
				return
			}
			actual, err := wire.DecodeRequest(data)
			if err != nil {
				resultErr = err
				return
			}
			var input api.BlobReadRequest
			if err := wire.Decode(actual.Params, &input); err != nil {
				resultErr = err
				return
			}
			bytes := []byte(actual.RequestID)[:input.Limit]
			sum := sha256.Sum256(bytes)
			result, err := json.Marshal(api.BlobChunk{ObjectID: input.ObjectID, Offset: input.Offset,
				Data: bytes, SHA256: api.Digest(hex.EncodeToString(sum[:]))})
			if err != nil {
				resultErr = err
				return
			}
			response, err := json.Marshal(api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: actual.RequestID, Result: result})
			if err != nil {
				resultErr = err
				return
			}
			resultErr = wire.WriteFrame(outside, response)
		}()
		return inside, nil
	}
	partial := request
	partial.Config, partial.Protocol, partial.Schema, partial.RequestSHA256 = "", "", 0, ""
	response, err := c.Call(context.Background(), partial)
	if err != nil {
		t.Fatal("request preparation failed", err)
	}
	var chunk api.BlobChunk
	if err := wire.Decode(response.Result, &chunk); err != nil {
		t.Fatal(err)
	}
	if chunk.ObjectID != request.RequestID || string(chunk.Data) != string(request.RequestID)[:3] {
		t.Fatal("response changed request-derived bytes")
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = c.Call(context.Background(), request)
	assertCode(t, err, api.CodeUnavailable)
}

func TestHumanStreamKeepsSessionSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sessionRequest := fixtureRequest(t)
	sessionRequest.Method, sessionRequest.Params, sessionRequest.RequestSHA256 = "human.session", json.RawMessage(`{}`), ""
	request := fixtureRequest(t)
	request.Method, request.RequestSHA256 = "event.tail", ""
	var err error
	request.Params, err = json.Marshal(api.EventTailRequest{LifeID: request.RequestID, Run: 1, Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	done := make(chan struct{})
	dials := 0
	c := &Client{Options: Options{Config: request.Config}, binding: &api.InstalledBinding{Class: api.EndpointHuman}}
	c.dial = func(context.Context) (net.Conn, error) {
		dials++
		if dials != 1 {
			return nil, &api.Error{Code: api.CodeUnavailable, Message: "fixture session belongs to its first socket"}
		}
		inside, outside := net.Pipe()
		go func() {
			var resultErr error
			defer close(done)
			defer func() { finished <- errors.Join(resultErr, outside.Close()) }()
			for index, method := range []api.Method{"human.session", "event.tail"} {
				data, err := wire.ReadFrame(outside)
				if err != nil {
					resultErr = err
					return
				}
				actual, err := wire.DecodeRequest(data)
				if err != nil || actual.Method != method {
					resultErr = errors.Join(err, wire.Invalid("fixture method sequence differs"))
					return
				}
				var result any
				if index == 0 {
					result = api.HumanSession{ID: actual.RequestID, Config: actual.Config,
						ExpiresAt:     api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)),
						IdleExpiresAt: api.Timestamp(time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano))}
				} else {
					result = api.EventPage{Events: []api.Event{}, Cursor: string(actual.IdempotencyKey), Complete: true}
				}
				payload, err := json.Marshal(result)
				if err != nil {
					resultErr = err
					return
				}
				response, err := json.Marshal(api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: actual.RequestID, LastSeq: 1, Result: payload})
				if err != nil {
					resultErr = err
					return
				}
				if err := wire.WriteFrame(outside, response); err != nil {
					resultErr = err
					return
				}
				if index == 1 {
					end, err := json.Marshal(api.StreamFrame{RequestID: actual.RequestID, Index: 1, Cursor: string(actual.IdempotencyKey), End: true})
					if err != nil {
						resultErr = err
						return
					}
					resultErr = wire.WriteFrame(outside, end)
				}
			}
		}()
		return inside, nil
	}
	t.Cleanup(func() {
		cancel()
		if err := c.Close(); err != nil {
			t.Error(err)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("session socket fixture did not collect")
		}
	})
	if _, err := c.Call(ctx, sessionRequest); err != nil {
		t.Fatal("human session socket control failed", err)
	}
	stream, err := c.Stream(ctx, request)
	if err != nil {
		t.Fatal("human stream abandoned its session socket", err)
	}
	defer stream.Close()
	frame, err := stream.Next(ctx)
	if err != nil || !frame.End || dials != 1 {
		t.Fatal("human stream abandoned its session socket", err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestCancellationClosesConnection(t *testing.T) {
	request := fixtureRequest(t)
	finished := make(chan error, 1)
	c := &Client{Options: Options{Config: request.Config}}
	c.dial = func(context.Context) (net.Conn, error) {
		inside, outside := net.Pipe()
		go func() {
			_, err := wire.ReadFrame(outside)
			if err == nil {
				_, err = wire.ReadFrame(outside)
			}
			if errors.Is(err, io.EOF) {
				err = nil
			}
			finished <- errors.Join(err, outside.Close())
		}()
		return inside, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := c.Call(ctx, request)
	assertCode(t, err, api.CodeDeadline)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNoUnboundConnection(t *testing.T) {
	request := fixtureRequest(t)
	c := &Client{Options: Options{Config: request.Config}}
	_, err := c.Call(context.Background(), request)
	assertCode(t, err, api.CodePrerequisite)
	request.Config = "different-config"
	_, err = c.Call(context.Background(), request)
	assertCode(t, err, api.CodeConflict)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamEndAndDisconnect(t *testing.T) {
	for _, mode := range []string{"end", "disconnect", "wrong-index"} {
		t.Run(mode, func(t *testing.T) {
			request := fixtureRequest(t)
			request.Method = "lane.attach"
			var err error
			request.Params, err = json.Marshal(api.AttachRequest{Target: api.LifeRef{LifeID: request.RequestID, Run: 1}, Mode: "output"})
			if err != nil {
				t.Fatal(err)
			}
			request.RequestSHA256, err = wire.RequestDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			c := &Client{Options: Options{Config: request.Config}}
			c.dial = func(context.Context) (net.Conn, error) {
				inside, outside := net.Pipe()
				go func() {
					var resultErr error
					defer func() { finished <- errors.Join(resultErr, outside.Close()) }()
					data, err := wire.ReadFrame(outside)
					if err != nil {
						resultErr = err
						return
					}
					actual, err := wire.DecodeRequest(data)
					if err != nil {
						resultErr = err
						return
					}
					bytes := []byte(actual.RequestID)
					sum := sha256.Sum256(bytes)
					initial, err := json.Marshal(api.StreamFrame{RequestID: actual.RequestID, Index: 1, Cursor: "fixture-start",
						Chunk: &api.BlobChunk{ObjectID: actual.RequestID, Data: bytes, SHA256: api.Digest(hex.EncodeToString(sum[:]))}})
					if err != nil {
						resultErr = err
						return
					}
					response, err := json.Marshal(api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: actual.RequestID, Result: initial})
					if err != nil {
						resultErr = err
						return
					}
					if err := wire.WriteFrame(outside, response); err != nil {
						resultErr = err
						return
					}
					if mode == "disconnect" {
						return
					}
					index := uint64(1)
					if mode == "wrong-index" {
						index++
					}
					end, err := json.Marshal(api.StreamFrame{RequestID: actual.RequestID, Index: index, Cursor: "fixture-end", End: true})
					if err != nil {
						resultErr = err
						return
					}
					resultErr = wire.WriteFrame(outside, end)
				}()
				return inside, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream, err := c.Stream(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			initial, ok := stream.(api.ResponseStream)
			if !ok {
				t.Fatal("attach lost initial response")
			}
			var first api.StreamFrame
			err = wire.Decode(initial.Initial().Result, &first)
			if err != nil || first.Chunk == nil || string(first.Chunk.Data) != string(request.RequestID) {
				t.Fatal("initial bytes lost", err)
			}
			frame, err := stream.Next(ctx)
			switch mode {
			case "disconnect":
				assertCode(t, err, api.CodeUnavailable)
			case "wrong-index":
				assertCode(t, err, api.CodeInvalid)
			case "end":
				if err != nil || !frame.End {
					t.Fatal("explicit end not preserved", err)
				}
				if _, err := stream.Next(ctx); !errors.Is(err, io.EOF) {
					t.Fatal("explicit end not terminal", err)
				}
			}
			if mode != "end" {
				if _, nextErr := stream.Next(ctx); nextErr == nil || errors.Is(nextErr, io.EOF) {
					t.Fatal("failed stream became successful EOF", nextErr)
				}
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStreamInitialPage(t *testing.T) {
	request := fixtureRequest(t)
	request.Method = "event.tail"
	var err error
	request.Params, err = json.Marshal(api.EventTailRequest{LifeID: request.RequestID, Run: 1, Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	request.RequestSHA256, err = wire.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	c := &Client{Options: Options{Config: request.Config}}
	c.dial = func(context.Context) (net.Conn, error) {
		inside, outside := net.Pipe()
		go func() {
			var resultErr error
			defer func() { finished <- errors.Join(resultErr, outside.Close()) }()
			data, err := wire.ReadFrame(outside)
			if err != nil {
				resultErr = err
				return
			}
			actual, err := wire.DecodeRequest(data)
			if err != nil {
				resultErr = err
				return
			}
			payload, err := json.Marshal(api.StateEvent{From: "running", To: "verifying", Generation: 2})
			if err != nil {
				resultErr = err
				return
			}
			now := api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
			actor := api.Actor{Kind: "service", ID: actual.IdempotencyKey}
			event := api.Event{Schema: api.SchemaVersion, ID: actual.IdempotencyKey, Config: actual.Config,
				Seq: api.Sequence(len(actual.RequestID)), Kind: "lane.state", Actor: actor, RequestedBy: actor,
				RequestID: actual.RequestID, OperationID: actual.IdempotencyKey, LifeID: actual.RequestID, Run: 1,
				StarterChain: []api.ID{}, RecordedAt: now, RequestedAt: now, ObservedAt: now, Origin: "service", Payload: payload}
			page, err := json.Marshal(api.EventPage{Events: []api.Event{event}, Cursor: string(actual.IdempotencyKey), Complete: true})
			if err != nil {
				resultErr = err
				return
			}
			response, err := json.Marshal(api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion,
				RequestID: actual.RequestID, LastSeq: api.Sequence(len(actual.RequestID)), Result: page})
			if err != nil {
				resultErr = err
				return
			}
			if err := wire.WriteFrame(outside, response); err != nil {
				resultErr = err
				return
			}
			end, err := json.Marshal(api.StreamFrame{RequestID: actual.RequestID, Index: 1, Cursor: string(actual.IdempotencyKey), End: true})
			if err != nil {
				resultErr = err
				return
			}
			resultErr = wire.WriteFrame(outside, end)
		}()
		return inside, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := c.Stream(ctx, request)
	if err != nil {
		t.Fatal("initial snapshot unavailable", err)
	}
	t.Cleanup(func() {
		if err := stream.Close(); err != nil {
			t.Error(err)
		}
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	responseStream, ok := stream.(api.ResponseStream)
	if !ok {
		t.Fatal("initial snapshot interface missing")
	}
	initial := responseStream.Initial()
	var page api.EventPage
	if err := wire.Decode(initial.Result, &page); err != nil || initial.RequestID != request.RequestID ||
		initial.LastSeq != api.Sequence(len(request.RequestID)) || page.Cursor != string(request.IdempotencyKey) || !page.Complete {
		t.Fatal("initial snapshot changed", err)
	}
	if len(page.Events) != 1 || page.Events[0].ID != request.IdempotencyKey || page.Events[0].LifeID != request.RequestID ||
		page.Events[0].Seq != initial.LastSeq {
		t.Fatal("initial snapshot events lost")
	}
	initial.Result[0] = '['
	if string(responseStream.Initial().Result) == string(initial.Result) {
		t.Fatal("initial snapshot shares caller storage")
	}
	frame, err := stream.Next(ctx)
	if err != nil || !frame.End || frame.Index != 1 || frame.Cursor != page.Cursor {
		t.Fatal("follow did not start after snapshot", err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}
