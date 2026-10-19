package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
)

type sessionStep struct {
	Name           string     `json:"name"`
	Method         api.Method `json:"method"`
	Request        string     `json:"request"`
	Proof          string     `json:"proof,omitempty"`
	RequestID      api.ID     `json:"request_id,omitempty"`
	IdempotencyKey api.ID     `json:"idempotency_key,omitempty"`
}

type sessionPlan struct {
	Schema string        `json:"schema"`
	Steps  []sessionStep `json:"steps"`
}

// The installed executable retains one ordinary public client connection.
// A flow grants no authority: every step uses the same typed invocation,
// request validation, native peer checks and service-side authorization.
type sessionTrace struct {
	integrateRPCClient
	name string
	out  io.Writer
}

func (s *sessionTrace) Call(ctx context.Context, request api.Request) (api.Response, error) {
	response, err := s.integrateRPCClient.Call(ctx, request)
	if err != nil {
		return response, err
	}
	err = json.NewEncoder(s.out).Encode(struct {
		Name     string       `json:"name"`
		Request  api.Request  `json:"request"`
		Response api.Response `json:"response"`
	}{s.name, request, response})
	return response, err
}

func (*sessionTrace) Stream(context.Context, api.Request) (api.EventStream, error) {
	return nil, &api.Error{Code: api.CodeUnsupported, Owner: "lb-v2-integrate",
		Message: "session flows record individual request and reply calls",
		Instead: "Use the ordinary event follow or lane attach command for a stream."}
}

func sessionPath(base, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

func sessionWait(ctx context.Context, path, name, step string, wait time.Duration, out io.Writer) ([]byte, error) {
	deadline := time.Now().Add(wait)
	reported := false
	for {
		_, statErr := os.Stat(path)
		if !errors.Is(statErr, os.ErrNotExist) {
			return ReadInput(path, api.MaxFrameBytes)
		}
		failure := &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-identity",
			Message: "session flow awaits its next input file",
			Instead: "Supply the retained request or genuine confirmation proof; no step is completed by waiting."}
		if !reported {
			if err := json.NewEncoder(out).Encode(map[string]any{"name": name, "wait": failure,
				"step": step, "completed": false}); err != nil {
				return nil, err
			}
			reported = true
		}
		if !time.Now().Before(deadline) {
			return nil, failure
		}
		timer := time.NewTimer(min(200*time.Millisecond, time.Until(deadline)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func runSessionFlow(ctx context.Context, call Invocation) (resultErr error) {
	flags := integrateFlags(call)
	path := flags.String("flow", "", "file-backed public request sequence")
	wait := flags.Duration("wait", 120*time.Second, "maximum wait for each dependent input")
	format := flags.String("format", "json", "JSON line records")
	if err := integrateParse(flags, call.Args); err != nil {
		return err
	}
	if *path == "" || *wait < 0 || *format != "json" || call.ProofFile == "" {
		return identityCLIError(api.CodePrerequisite, "session flow requires its plan and genuine session proof files")
	}
	raw, err := ReadInput(*path, api.MaxFrameBytes)
	if err != nil {
		return err
	}
	var plan sessionPlan
	if err := api.DecodeObject(raw, &plan); err != nil {
		return err
	}
	if plan.Schema != "laneboss.client-flow.v2" || len(plan.Steps) == 0 {
		return integrateInputError("session flow requires a typed nonempty plan")
	}
	for _, step := range plan.Steps {
		if _, ok := api.Methods[step.Method]; !ok || step.Name == "" || step.Request == "" {
			return integrateInputError("session flow step requires its name, catalog method and request file")
		}
	}
	base := filepath.Dir(*path)
	if _, err := sessionWait(ctx, call.ProofFile, "human-session", "human_confirmation", *wait, call.Stdout); err != nil {
		return err
	}
	socket := call.integrateSocket
	if socket == nil {
		socket = &integrateSocket{options: client.Options{Config: call.Config}}
		if call.Client == nil {
			defer func() {
				if socket.connection != nil {
					resultErr = errors.Join(resultErr, socket.connection.Close())
				}
			}()
		}
	}
	var connection integrateRPCClient
	if call.Client != nil {
		connection = call.Client
	} else {
		connection = socket.connection
	}
	if connection == nil {
		connection, err = client.Open(ctx, socket.options)
		if err != nil {
			return err
		}
	}
	trace := &sessionTrace{integrateRPCClient: connection, name: "human-session", out: call.Stdout}
	socket.connection = trace
	defer func() { socket.connection = connection }()
	call.Client, call.integrateSocket = nil, socket
	call.Stdout, call.Args = io.Discard, nil
	if err := call.InvokeRaw(ctx, json.RawMessage(`{}`)); err != nil {
		return err
	}
	for _, step := range plan.Steps {
		trace.name = step.Name
		body, err := sessionWait(ctx, sessionPath(base, step.Request), step.Name, "fixture_preparation", *wait, trace.out)
		if err != nil {
			return err
		}
		call.Method, call.ProofFile = step.Method, ""
		call.RequestID, call.IdempotencyKey = step.RequestID, step.IdempotencyKey
		if step.Proof != "" {
			call.ProofFile = sessionPath(base, step.Proof)
			if _, err := sessionWait(ctx, call.ProofFile, step.Name, "human_confirmation", *wait, trace.out); err != nil {
				return err
			}
		}
		if err := call.InvokeRaw(ctx, body); err != nil {
			return err
		}
	}
	return nil
}
