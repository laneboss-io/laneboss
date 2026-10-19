//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Native identity and the CLI transport are explicit component inputs. Task
// reads, history bytes, the stand-in turn, its OS pipe and capture events are
// real. This test does not enroll a service or claim an installed lane pass.
type startupStoreRPC struct {
	t     *testing.T
	f     *fx.Fixture
	scope api.Scope
}

func (r *startupStoreRPC) call(ctx context.Context, method string, body, out any) error {
	var value any
	switch method {
	case "identity.self":
		value = r.scope
	case "lane.status":
		request, ok := body.(api.LifeRef)
		if !ok || request != r.f.Reservation.Target {
			return errors.New("startup requested another life")
		}
		lane, err := r.f.State.Lane(ctx, r.scope, request)
		if err != nil {
			return err
		}
		value = lane
	case "grants.get":
		request, ok := body.(api.GrantGetRequest)
		if !ok || request.GrantSetID != r.f.Lane.GrantSetID {
			return errors.New("startup requested another grant set")
		}
		grants, err := r.f.State.Grants(ctx, request.GrantSetID)
		if err != nil {
			return err
		}
		value = grants
	default:
		return errors.New("unsupported startup component method")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func (r *startupStoreRPC) blob(ctx context.Context, ref api.BlobRef) ([]byte, error) {
	chunk, err := r.f.State.Blob(ctx, r.scope, api.BlobReadRequest{ObjectID: ref.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		return nil, err
	}
	if int64(len(chunk.Data)) != ref.Bytes || api.Digest(digest(chunk.Data)) != ref.SHA256 {
		return nil, errors.New("startup task bytes differ from their retained reference")
	}
	return chunk.Data, nil
}

func (r *startupStoreRPC) history(ctx context.Context, raw []byte) (api.BlobRef, error) {
	ref := api.BlobRef{ID: fx.ID(r.t), Class: "record", Bytes: int64(len(raw)), SHA256: api.Digest(digest(raw))}
	cause := r.f.Intent(r.t, api.InternalOrgBootstrap)
	_, err := r.f.State.Transact(ctx, api.Transaction{Scope: r.f.Execution, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{{
		ObjectKey: ref.ID, Class: ref.Class, Bytes: raw, SHA256: ref.SHA256, Origin: "service",
		ACL: api.ObjectACL{Config: r.f.Deps.Config, Owner: r.scope.Actor, Audience: "owner", Generation: 1}}}}})
	return ref, err
}

func (r *startupStoreRPC) historyDenied(ctx context.Context, id api.ID) bool {
	_, err := r.f.State.Blob(ctx, r.scope, api.BlobReadRequest{ObjectID: id, Limit: 1})
	var typed *api.Error
	return errors.As(err, &typed) && (typed.Code == api.CodeNotFound || typed.Code == api.CodeForbidden)
}

func TestBaselinePrimaryFromAssignedTask(t *testing.T) {
	f := fx.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	plan := task{Schema: "laneboss.secret-task.v1", Mode: "baseline", ReservedName: "PATH", Nonce: digest(random(t))}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	ref := api.BlobRef{ID: fx.ID(t), Class: "task", Bytes: int64(len(raw)), SHA256: api.Digest(digest(raw))}
	cause := f.Intent(t, api.InternalOrgBootstrap)
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{{
		ObjectKey: ref.ID, Class: ref.Class, Bytes: raw, SHA256: ref.SHA256, Origin: "service",
		ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Human.Actor, Audience: "owner", Generation: 1}}}}}); err != nil {
		t.Fatal(err)
	}
	f.Start.Task = ref
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	f.Opened(t)
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := os.MkdirTemp("", "lb-v2-case-secrets-start-")
	if err != nil {
		t.Fatal(err)
	}
	keep := func(name string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(evidence, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	keep("agent.test", self)
	keep("binary.sha256", []byte(digest(self)+"\n"))
	keep("task.input", raw)
	prompt, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: f.Plan.Runner.Prompt.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	keep("prompt.input", prompt.Data)
	t.Logf("retained startup capture evidence: %s; binary_sha256=%s", evidence, digest(self))
	in := options{Config: f.Deps.Config, Life: string(f.Lane.LifeID), Run: uint(f.Lane.Run), Driver: string(api.DriverCodex),
		Challenge: digest(random(t)), WaitMS: 300000}
	selected := f.Plan.Inputs.Grants.Profiles[0]
	auth, err := json.Marshal(map[string]any{"program": "laneboss-e2e-authenticator", "config": in.Config,
		"challenge": in.Challenge, "profile_id": selected.ProfileID, "driver": selected.Driver, "vendor_stood_in": true,
		"runtime": api.Executable{ID: "component-test-runtime", Version: "component", SHA256: api.Digest(digest(self))}})
	if err != nil {
		t.Fatal(err)
	}
	login, err := json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": map[string]string{"access_token": base64.StdEncoding.EncodeToString(auth)}})
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", home)
	if err := os.WriteFile(filepath.Join(home, "auth.json"), login, 0400); err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if err := reader.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var native bytes.Buffer
	finished := make(chan error, 1)
	go func() {
		err := runTurn(ctx, in, &startupStoreRPC{t: t, f: f, scope: f.LaneScope(t)}, prompt.Data, writer, &native)
		finished <- errors.Join(err, writer.Close())
	}()
	primary, readErr := bufio.NewReader(reader).ReadBytes('\n')
	cancel()
	turnErr := <-finished
	if readErr != nil || turnErr != nil || len(primary) == 0 || primary[len(primary)-1] != '\n' {
		t.Fatal("secrets baseline did not produce its actual newline primary stdout", readErr, turnErr)
	}
	keep("primary.capture", primary)
	keep("native.capture", native.Bytes())
	var observed struct {
		Own bool `json:"own_profile_turn"`
	}
	if json.Unmarshal(primary, &observed) != nil || !observed.Own {
		t.Fatal("baseline primary did not compare the selected credential")
	}
	data := f.CaptureData(t, primary)
	if _, err := f.State.AppendCapture(context.Background(), f.Worker, f.AppendRequest(t, &data, false)); err != nil {
		t.Fatal(err)
	}
	events, err := f.State.Events(context.Background(), f.Execution, api.EventTailRequest{LifeID: f.Lane.LifeID, Run: f.Lane.Run})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events.Events {
		var capture api.CaptureRecord
		if event.Kind == "capture.appended" && json.Unmarshal(event.Payload, &capture) == nil && capture.Stream == "stdout" {
			found = event.Origin == "service" && capture.Primary && capture.Data == data && capture.Target == f.Reservation.Target
		}
	}
	if !found {
		t.Fatal("baseline stdout has no real correlated primary capture event")
	}
	retained, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	keep("events.json", retained)
}
