package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
)

type recordedConnection struct {
	requests []api.Request
	closed   int
	wrongID  bool
	closeErr error
}

func (c *recordedConnection) Call(_ context.Context, request api.Request) (api.Response, error) {
	c.requests = append(c.requests, request)
	var value any
	if request.Method == "human.session" {
		value = api.HumanSession{ID: "test-session", Config: request.Config, ExpiresAt: "2099-01-01T00:00:00Z",
			IdleExpiresAt: "2099-01-01T00:00:00Z", SimulatedPresence: request.Proof.SimulatedPresence}
	} else {
		value = map[string]any{"config": request.Config, "actor": api.Actor{Kind: "human", ID: "test-human"},
			"endpoint_generation": 1, "policy_generation": 1}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return api.Response{}, err
	}
	identifier := request.RequestID
	if c.wrongID {
		identifier = "another-request"
	}
	return api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: identifier, LastSeq: 1, Result: raw}, nil
}

func (c *recordedConnection) Close() error { c.closed++; return c.closeErr }

func proofFixture(t *testing.T) api.ProofRef {
	t.Helper()
	digest, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
		Config: "tree-a", Method: "human.session", Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	return api.ProofRef{ID: "session-proof", RequestSHA256: digest, ExpiresAt: "2099-01-01T00:00:00Z", SimulatedPresence: true}
}

func readInput(t *testing.T, count int) *bytes.Buffer {
	t.Helper()
	input := &bytes.Buffer{}
	for i := 0; i < count; i++ {
		request, err := client.PrepareRequest(api.Request{Config: "tree-a", Method: "identity.self", Params: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(input).Encode(request); err != nil {
			t.Fatal(err)
		}
	}
	return input
}

func TestOneConnectionForManyReads(t *testing.T) {
	conn, opened := &recordedConnection{}, 0
	output := &bytes.Buffer{}
	err := serve(context.Background(), client.Options{Config: "tree-a", BindingFile: "/protected/binding.json"},
		proofFixture(t), readInput(t, 100), output, func(_ context.Context, options client.Options) (connection, error) {
			opened++
			if options.Config != "tree-a" || options.BindingFile != "/protected/binding.json" {
				t.Fatal("reader replaced the installed binding")
			}
			return conn, nil
		})
	if err != nil || opened != 1 || conn.closed != 1 || len(conn.requests) != 101 {
		t.Fatalf("connection/session lifetime differs: opens=%d closes=%d calls=%d err=%v", opened, conn.closed, len(conn.requests), err)
	}
	for i, request := range conn.requests {
		if i == 0 {
			if request.Method != "human.session" || request.Proof == nil || !request.Proof.SimulatedPresence {
				t.Fatal("first call lost its verified session proof provenance")
			}
		} else if request.Method != "identity.self" || request.Proof != nil {
			t.Fatal("a read consumed another proof or changed method")
		}
	}
	decoder, replies := json.NewDecoder(output), 0
	for {
		var response api.Response
		if err := decoder.Decode(&response); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		replies++
	}
	if replies != len(conn.requests) {
		t.Fatal("reader omitted a real response")
	}
}

func TestAuthorityAndForeignConfigRefuse(t *testing.T) {
	for _, request := range []api.Request{
		{Config: "tree-b", Method: "identity.self", Params: json.RawMessage(`{}`)},
		{Config: "tree-a", Method: "lane.start", Params: json.RawMessage(`{}`)},
		{Config: "tree-a", Method: "identity.self", Params: json.RawMessage(`{}`), Proof: &api.ProofRef{ID: "ambient"}},
	} {
		request.Protocol, request.Schema = api.Protocol, api.SchemaVersion
		request.RequestID, request.IdempotencyKey = "correlation", "retained-key"
		input := &bytes.Buffer{}
		if err := json.NewEncoder(input).Encode(request); err != nil {
			t.Fatal(err)
		}
		conn := &recordedConnection{}
		err := serve(context.Background(), client.Options{Config: "tree-a"}, proofFixture(t), input, io.Discard,
			func(context.Context, client.Options) (connection, error) { return conn, nil })
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || len(conn.requests) != 1 || conn.closed != 1 {
			t.Fatalf("forbidden request reached the public connection: %v", err)
		}
	}
}

func TestNativeFailureAndCloseArePreserved(t *testing.T) {
	wanted := api.NotImplemented("lb-v2-service", "native client port")
	err := serve(context.Background(), client.Options{Config: "tree-a"}, proofFixture(t), readInput(t, 1), io.Discard,
		func(context.Context, client.Options) (connection, error) { return nil, wanted })
	if !errors.Is(err, wanted) {
		t.Fatal("reader hid the owning native failure")
	}
	conn := &recordedConnection{closeErr: wanted}
	err = serve(context.Background(), client.Options{Config: "tree-a"}, proofFixture(t), readInput(t, 1), io.Discard,
		func(context.Context, client.Options) (connection, error) { return conn, nil })
	if !errors.Is(err, wanted) || conn.closed != 1 {
		t.Fatal("reader ignored a failed connection close")
	}
}

func TestForeignReplyCannotOpenSession(t *testing.T) {
	conn := &recordedConnection{wrongID: true}
	err := serve(context.Background(), client.Options{Config: "tree-a"}, proofFixture(t), readInput(t, 1), io.Discard,
		func(context.Context, client.Options) (connection, error) { return conn, nil })
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Owner != "lb-v2-service" || len(conn.requests) != 1 {
		t.Fatalf("foreign reply was accepted: %v", err)
	}
}
