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

// Framed transport fixture: health closes after one request; ordinary calls
// share their socket. Native server health is exercised in service's tests.
func healthClient(t *testing.T, refuse bool) (*Client, *int) {
	t.Helper()
	c := &Client{Options: Options{Config: "client-fixture"}, binding: &api.InstalledBinding{Class: api.EndpointHuman}}
	dials := new(int)
	finished := make(chan error, 8)
	c.dial = func(context.Context) (net.Conn, error) {
		(*dials)++
		inside, outside := net.Pipe()
		go func() {
			err := serveHealthClient(outside, refuse)
			finished <- errors.Join(err, outside.Close())
		}()
		return inside, nil
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
		for i := 0; i < *dials; i++ {
			select {
			case err := <-finished:
				if err != nil {
					t.Error("health client fixture failed", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("health client fixture did not drain")
			}
		}
	})
	return c, dials
}

func serveHealthClient(connection net.Conn, refuse bool) error {
	for index := 0; ; index++ {
		data, err := wire.ReadFrame(connection)
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		request, err := wire.DecodeRequest(data)
		if err != nil {
			return err
		}
		response := api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: request.RequestID}
		var result any
		switch request.Method {
		case "health":
			var input api.HealthRequest
			if err := wire.Decode(request.Params, &input); err != nil {
				return err
			}
			if refuse || index != 0 {
				response.Error = &api.Error{Code: api.CodeForbidden, Message: "fixture health refusal"}
			} else {
				result = api.Health{Protocol: api.Protocol, Schema: api.SchemaVersion, ServiceVersion: input.ClientVersion,
					ArtifactSHA256: input.ArtifactSHA256, Capabilities: []api.Capability{}}
			}
		case "human.session":
			result = api.HumanSession{ID: request.RequestID, Config: request.Config,
				ExpiresAt:     api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)),
				IdleExpiresAt: api.Timestamp(time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano))}
		case "blob.read":
			var input api.BlobReadRequest
			if err := wire.Decode(request.Params, &input); err != nil {
				return err
			}
			body := []byte(request.RequestID)[:input.Limit]
			sum := sha256.Sum256(body)
			result = api.BlobChunk{ObjectID: input.ObjectID, Offset: input.Offset, Data: body, SHA256: api.Digest(hex.EncodeToString(sum[:]))}
		default:
			return wire.Invalid("unexpected health client fixture method")
		}
		if response.Error == nil {
			response.Result, err = json.Marshal(result)
			if err != nil {
				return err
			}
		}
		data, err = json.Marshal(response)
		if err != nil {
			return err
		}
		if err := wire.WriteFrame(connection, data); err != nil {
			return err
		}
		if request.Method == "health" {
			return nil
		}
	}
}

func healthRequest(t *testing.T) api.Request {
	t.Helper()
	request := fixtureRequest(t)
	sum := sha256.Sum256([]byte(request.RequestID))
	request.Method, request.RequestSHA256 = "health", ""
	var err error
	request.Params, err = json.Marshal(api.HealthRequest{ClientVersion: "fixture-version", ArtifactSHA256: api.Digest(hex.EncodeToString(sum[:]))})
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestCallAfterHealth(t *testing.T) {
	for _, mode := range []string{"success", "refusal"} {
		t.Run(mode, func(t *testing.T) {
			c, dials := healthClient(t, mode == "refusal")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			response, err := c.Call(ctx, healthRequest(t))
			if mode == "refusal" {
				assertCode(t, err, api.CodeForbidden)
			} else if err != nil || response.Error != nil {
				t.Fatal("initial health control failed", err)
			}
			c.mu.Lock()
			retained := c.primary != nil || len(c.connections) != 0 || c.primaryReadSession
			c.mu.Unlock()
			if retained {
				t.Fatal("health call retained its one-request socket")
			}
			request := fixtureRequest(t)
			response, err = c.Call(ctx, request)
			if err != nil {
				t.Fatal("command after health failed", err)
			}
			var chunk api.BlobChunk
			if err := wire.Decode(response.Result, &chunk); err != nil || chunk.ObjectID != request.RequestID || string(chunk.Data) != string(request.RequestID)[:3] || *dials != 2 {
				t.Fatal("command after health lost its fresh connection or data", err)
			}
		})
	}
}

func TestHealthKeepsSession(t *testing.T) {
	c, dials := healthClient(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	session := fixtureRequest(t)
	session.Method, session.Params, session.RequestSHA256 = "human.session", json.RawMessage(`{}`), ""
	if _, err := c.Call(ctx, session); err != nil {
		t.Fatal("read session control failed", err)
	}
	c.mu.Lock()
	primary, sessionOpen := c.primary, c.primaryReadSession
	c.mu.Unlock()
	if primary == nil || !sessionOpen {
		t.Fatal("read session control did not retain its socket")
	}
	if _, err := c.Call(ctx, healthRequest(t)); err != nil {
		t.Fatal("health interrupted the existing read session", err)
	}
	c.mu.Lock()
	preserved := c.primary == primary && c.primaryReadSession && len(c.connections) == 1
	c.mu.Unlock()
	if !preserved || *dials != 2 {
		t.Fatal("health interrupted the existing read session")
	}
	if _, err := c.Call(ctx, fixtureRequest(t)); err != nil || *dials != 2 {
		t.Fatal("read session did not continue after health", err)
	}
}
