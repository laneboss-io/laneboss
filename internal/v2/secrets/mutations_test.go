package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

func TestSecretLifecycle(t *testing.T) {
	s, backend, state, clock, _ := mutationFixture(t)
	ctx := context.Background()
	one, two := syntheticBytes(t, 96), syntheticBytes(t, 97)
	stage, connection := stageValue(t, s, clock, nil, "canary", "one", one, false)
	request := api.SecretImportRequest{Name: stage.Name, Version: stage.Version, SealedUploadID: stage.ID}
	scope := mutationScope(t, clock, connection, "secret.import", request, state)
	info, err := s.SecretImport(ctx, scope, request)
	if err != nil || info.Name != request.Name || info.Version != request.Version {
		t.Fatal("secret import did not commit its source")
	}
	got := fetchMutation(t, backend, clock, info)
	if !bytes.Equal(got, one) {
		t.Fatal("imported source differs from actual sealed bytes")
	}
	clear(got)
	if len(state.used) != 1 || len(state.events) != 1 || state.attempts != 1 || backend.stores != 1 {
		t.Fatal("import did not atomically consume one proof with one event and reply")
	}
	before, err := os.ReadFile(filepath.Join(state.directory, string(info.SourceHandle)+".json"))
	if err != nil {
		t.Fatal("cannot retain imported ciphertext")
	}
	replayed, err := s.SecretImport(ctx, scope, request)
	if err != nil || replayed != info || backend.stores != 1 || state.attempts != 1 || state.checked != 1 {
		t.Fatal("completed import retry performed another backend write proof check or commit")
	}
	stage, _ = stageValue(t, s, clock, connection, "canary", "two", two, false)
	rotate := api.SecretRotateRequest{Name: stage.Name, ExpectedVersion: "one", SealedUploadID: stage.ID}
	rotateScope := mutationScope(t, clock, connection, "secret.rotate", rotate, state)
	rotated, err := s.SecretRotate(ctx, rotateScope, rotate)
	if err != nil || rotated.Version != "two" || rotated.SourceHandle == info.SourceHandle {
		t.Fatal("rotation did not create its exact new version")
	}
	got = fetchMutation(t, backend, clock, rotated)
	if !bytes.Equal(got, two) {
		t.Fatal("rotated source differs from actual sealed bytes")
	}
	clear(got)
	staleStage, _ := stageValue(t, s, clock, connection, "canary", "three", syntheticBytes(t, 92), false)
	staleRequest := api.SecretRotateRequest{Name: "canary", ExpectedVersion: "one", SealedUploadID: staleStage.ID}
	stale := mutationScope(t, clock, connection, "secret.rotate", staleRequest, state)
	_, err = s.SecretRotate(ctx, stale, staleRequest)
	stageCode(t, err, api.CodeConflict)
	if backend.stores != 2 || len(state.used) != 2 || len(state.events) != 2 {
		t.Fatal("stale rotation changed the backend or consumed proof")
	}
	revoke := api.SecretRevokeRequest{Name: "canary", ExpectedVersion: "two"}
	revokeScope := mutationScope(t, clock, connection, "secret.revoke", revoke, state)
	operation, err := s.SecretRevoke(ctx, revokeScope, revoke)
	if err != nil || operation.Status != "succeeded" || operation.ID == "" {
		t.Fatal("revocation did not commit a completed operation")
	}
	_, err = backend.Fetch(ctx, api.SecretGrant{ID: "grant-a", Name: rotated.Name, Version: rotated.Version, SourceHandle: rotated.SourceHandle,
		ExpiresAt: api.Timestamp(clock.now.Add(time.Minute).Format(time.RFC3339Nano))})
	stageCode(t, err, api.CodeForbidden)
	revoked, err := os.ReadFile(filepath.Join(state.directory, string(rotated.SourceHandle)+".json"))
	if err != nil {
		t.Fatal("cannot retain revoked ciphertext")
	}
	retryOperation, err := s.SecretRevoke(ctx, revokeScope, revoke)
	if err != nil || retryOperation != operation || backend.revokes != 1 || len(state.used) != 3 || len(state.events) != 3 {
		t.Fatal("revocation retry changed the backend or consumed proof twice")
	}
	unchanged, err := os.ReadFile(filepath.Join(state.directory, string(rotated.SourceHandle)+".json"))
	if err != nil || !bytes.Equal(revoked, unchanged) {
		t.Fatal("revocation retry rewrote ciphertext")
	}
	unchanged, err = os.ReadFile(filepath.Join(state.directory, string(info.SourceHandle)+".json"))
	if err != nil || !bytes.Equal(before, unchanged) {
		t.Fatal("rotation changed an immutable earlier version")
	}
	events, err := json.Marshal(state.events)
	if err != nil {
		t.Fatal("cannot inspect names-only event evidence")
	}
	for _, value := range [][]byte{one, two, []byte(base64.StdEncoding.EncodeToString(one)), []byte(base64.StdEncoding.EncodeToString(two))} {
		if bytes.Contains(events, value) {
			t.Fatal("secret material escaped into an event")
		}
	}
}

func TestImportCrashRetry(t *testing.T) {
	s, backend, state, clock, key := mutationFixture(t)
	value := syntheticBytes(t, 105)
	stage, connection := stageValue(t, s, clock, nil, "canary", "one", value, false)
	request := api.SecretImportRequest{Name: stage.Name, Version: stage.Version, SealedUploadID: stage.ID}
	scope := mutationScope(t, clock, connection, "secret.import", request, state)
	state.fail = wire.Error(api.CodeUnavailable, "synthetic commit interruption")
	_, err := s.SecretImport(context.Background(), scope, request)
	stageCode(t, err, api.CodeUnavailable)
	var failure *api.Error
	if !errors.As(err, &failure) || failure.OperationID == "" || !failure.Retryable {
		t.Fatal("interrupted commit omitted its retryable operation reference")
	}
	if len(state.used) != 0 || len(state.events) != 0 || state.attempts != 1 || backend.stores != 1 {
		t.Fatal("interrupted commit consumed proof or published an event")
	}
	entries, err := os.ReadDir(state.directory)
	if err != nil || len(entries) != 3 {
		t.Fatal("interrupted import did not retain exactly one protected source")
	}
	var recordName string
	for _, entry := range entries {
		if entry.Name()[0] != '.' {
			recordName = entry.Name()
		}
	}
	before, err := os.ReadFile(filepath.Join(state.directory, recordName))
	if err != nil {
		t.Fatal("cannot retain interrupted source bytes")
	}
	// Another operation cannot advance around a source whose event never committed.
	unrelatedStage, _ := stageValue(t, s, clock, connection, "canary", "other", syntheticBytes(t, 99), false)
	unrelated := api.SecretImportRequest{Name: unrelatedStage.Name, Version: unrelatedStage.Version, SealedUploadID: unrelatedStage.ID}
	unrelatedScope := mutationScope(t, clock, connection, "secret.import", unrelated, state)
	_, err = s.SecretImport(context.Background(), unrelatedScope, unrelated)
	stageCode(t, err, api.CodeConflict)
	if err := backend.Close(); err != nil {
		t.Fatal("cannot restart interrupted backend")
	}
	backend = openMutationBackend(t, state.directory, clock, key)
	s = newMutationService(t, backend, state, clock) // No stage survives this restart.
	state.fail = nil
	info, err := s.SecretImport(context.Background(), scope, request)
	if err != nil || info.Name != request.Name || info.Version != request.Version {
		t.Fatal("interrupted import did not reconcile its original request")
	}
	after, err := os.ReadFile(filepath.Join(state.directory, recordName))
	if err != nil || !bytes.Equal(before, after) || backend.stores != 0 {
		t.Fatal("interrupted import retry wrote a second ciphertext")
	}
	got := fetchMutation(t, backend, clock, info)
	if !bytes.Equal(got, value) {
		t.Fatal("reconciled source differs from original material")
	}
	clear(got)
	if len(state.used) != 1 || len(state.events) != 1 || state.attempts != 2 {
		t.Fatal("reconciled import did not commit proof event and reply once")
	}
}

func TestBackendFailureDoesNotCommit(t *testing.T) {
	s, backend, state, clock, _ := mutationFixture(t)
	stage, connection := stageValue(t, s, clock, nil, "canary", "one", syntheticBytes(t, 93), false)
	request := api.SecretImportRequest{Name: stage.Name, Version: stage.Version, SealedUploadID: stage.ID}
	scope := mutationScope(t, clock, connection, "secret.import", request, state)
	backend.failStore = wire.Error(api.CodeUnavailable, "synthetic backend interruption")
	_, err := s.SecretImport(context.Background(), scope, request)
	stageCode(t, err, api.CodeUnavailable)
	if state.attempts != 0 || len(state.used) != 0 || len(state.events) != 0 {
		t.Fatal("backend failure committed proof event or reply")
	}
	backend.failStore = nil
	info, err := s.SecretImport(context.Background(), scope, request)
	if err != nil || info.Version != request.Version || state.attempts != 1 || len(state.used) != 1 {
		t.Fatal("backend failure prevented exact retry")
	}
}

func TestProofBeforeBackend(t *testing.T) {
	s, backend, state, clock, _ := mutationFixture(t)
	stage, connection := stageValue(t, s, clock, nil, "canary", "one", syntheticBytes(t, 95), false)
	request := api.SecretImportRequest{Name: stage.Name, Version: stage.Version, SealedUploadID: stage.ID}
	scope := mutationScope(t, clock, connection, "secret.import", request, state)
	delete(state.issued, scope.Request.Proof.ID)
	_, err := s.SecretImport(context.Background(), scope, request)
	stageCode(t, err, api.CodeForbidden)
	if backend.scopes != 0 || backend.stores != 0 || state.attempts != 0 || len(state.used) != 0 {
		t.Fatal("unverified proof reached protected backend work")
	}
}

func TestStageTamperAtImport(t *testing.T) {
	s, backend, state, clock, _ := mutationFixture(t)
	stage, connection := stageValue(t, s, clock, nil, "canary", "one", syntheticBytes(t, 89), true)
	request := api.SecretImportRequest{Name: stage.Name, Version: stage.Version, SealedUploadID: stage.ID}
	scope := mutationScope(t, clock, connection, "secret.import", request, state)
	_, err := s.SecretImport(context.Background(), scope, request)
	stageCode(t, err, api.CodeIntegrity)
	if backend.stores != 0 || state.attempts != 0 || len(state.used) != 0 {
		t.Fatal("tampered encrypted stage changed backend or proof state")
	}
}

func TestImportSessionBinding(t *testing.T) {
	for _, field := range []string{"principal", "connection", "session", "endpoint", "expiry"} {
		t.Run(field, func(t *testing.T) {
			s, backend, state, clock, _ := mutationFixture(t)
			stage, connection := stageValue(t, s, clock, nil, "canary", "one", syntheticBytes(t, 91), false)
			c := connection.(*connectionFixture)
			switch field {
			case "principal":
				c.authority.PrincipalID = "human-b"
			case "connection":
				c.id = "connection-b"
				c.authority.ConnectionID = c.id
			case "session":
				c.authority.SessionID = "read-b"
			case "endpoint":
				c.binding.EndpointGeneration++
				c.authority.EndpointGeneration = c.binding.EndpointGeneration
			case "expiry":
				clock.now = clock.now.Add(120 * time.Second)
			}
			request := api.SecretImportRequest{Name: stage.Name, Version: stage.Version, SealedUploadID: stage.ID}
			scope := mutationScope(t, clock, connection, "secret.import", request, state)
			_, err := s.SecretImport(context.Background(), scope, request)
			stageCode(t, err, api.CodeNotFound)
			if backend.stores != 0 || state.attempts != 0 || len(state.used) != 0 {
				t.Fatal("stage escaped its live human session")
			}
		})
	}
}

func TestMutationIntentRetry(t *testing.T) {
	s, backend, state, clock, _ := mutationFixture(t)
	stage, connection := stageValue(t, s, clock, nil, "canary", "one", syntheticBytes(t, 94), false)
	request := api.SecretImportRequest{Name: stage.Name, Version: stage.Version, SealedUploadID: stage.ID}
	scope := mutationScope(t, clock, connection, "secret.import", request, state)
	if _, err := s.SecretImport(context.Background(), scope, request); err != nil {
		t.Fatal("cannot establish exact receipt control")
	}
	changed := request
	changed.Version = "other"
	altered := mutationScope(t, clock, connection, "secret.import", changed, state)
	altered.Request.IdempotencyKey = scope.Request.IdempotencyKey
	altered = framedScope(altered)
	_, err := s.SecretImport(context.Background(), altered, changed)
	stageCode(t, err, api.CodeIdempotencyConflict)
	newKey, err := client.NewRequestID()
	if err != nil {
		t.Fatal("cannot retain consumed-proof retry control")
	}
	scope.Request.IdempotencyKey = newKey
	scope = framedScope(scope)
	_, err = s.SecretImport(context.Background(), scope, request)
	stageCode(t, err, api.CodeForbidden)
	if backend.stores != 1 || state.attempts != 1 || len(state.used) != 1 {
		t.Fatal("changed retry intent or consumed proof mutated the backend")
	}
}

func TestConcurrentRotations(t *testing.T) {
	one, firstBackend, state, clock, key := mutationFixture(t)
	stage, connection := stageValue(t, one, clock, nil, "canary", "one", syntheticBytes(t, 90), false)
	request := api.SecretImportRequest{Name: stage.Name, Version: stage.Version, SealedUploadID: stage.ID}
	scope := mutationScope(t, clock, connection, "secret.import", request, state)
	if _, err := one.SecretImport(context.Background(), scope, request); err != nil {
		t.Fatal("cannot establish concurrent rotation base")
	}
	secondBackend := openMutationBackend(t, state.directory, clock, key)
	two := newMutationService(t, secondBackend, state, clock)
	stageA, _ := stageValue(t, one, clock, connection, "canary", "two", syntheticBytes(t, 90), false)
	stageB, _ := stageValue(t, two, clock, connection, "canary", "three", syntheticBytes(t, 90), false)
	requests := []api.SecretRotateRequest{{Name: "canary", ExpectedVersion: "one", SealedUploadID: stageA.ID},
		{Name: "canary", ExpectedVersion: "one", SealedUploadID: stageB.ID}}
	scopes := []api.Scope{mutationScope(t, clock, connection, "secret.rotate", requests[0], state), mutationScope(t, clock, connection, "secret.rotate", requests[1], state)}
	results := make(chan error, 2)
	var group sync.WaitGroup
	for i, service := range []*Service{one, two} {
		group.Go(func() { _, err := service.SecretRotate(context.Background(), scopes[i], requests[i]); results <- err })
	}
	group.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else {
			stageCode(t, err, api.CodeConflict)
		}
	}
	if success != 1 || len(state.events) != 2 || len(state.used) != 2 || firstBackend.stores+secondBackend.stores != 2 {
		t.Fatal("concurrent rotations advanced the same expected version twice")
	}
}

func TestRevokeCrashRetry(t *testing.T) {
	s, backend, state, clock, key := mutationFixture(t)
	stage, connection := stageValue(t, s, clock, nil, "canary", "one", syntheticBytes(t, 98), false)
	request := api.SecretImportRequest{Name: stage.Name, Version: stage.Version, SealedUploadID: stage.ID}
	scope := mutationScope(t, clock, connection, "secret.import", request, state)
	info, err := s.SecretImport(context.Background(), scope, request)
	if err != nil {
		t.Fatal("cannot establish revocation retry base")
	}
	revoke := api.SecretRevokeRequest{Name: info.Name, ExpectedVersion: info.Version}
	revokeScope := mutationScope(t, clock, connection, "secret.revoke", revoke, state)
	state.fail = wire.Error(api.CodeUnavailable, "synthetic revoke commit interruption")
	_, err = s.SecretRevoke(context.Background(), revokeScope, revoke)
	stageCode(t, err, api.CodeUnavailable)
	if len(state.events) != 1 || len(state.used) != 1 {
		t.Fatal("interrupted revocation consumed proof or event")
	}
	path := filepath.Join(state.directory, string(info.SourceHandle)+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot retain interrupted tombstone")
	}
	state.fail = nil
	other := mutationScope(t, clock, connection, "secret.revoke", revoke, state)
	_, err = s.SecretRevoke(context.Background(), other, revoke)
	stageCode(t, err, api.CodeConflict)
	if len(state.events) != 1 || len(state.used) != 1 {
		t.Fatal("another operation adopted the interrupted tombstone")
	}
	if err := backend.Close(); err != nil {
		t.Fatal("cannot restart revoked backend")
	}
	backend = openMutationBackend(t, state.directory, clock, key)
	s = newMutationService(t, backend, state, clock)
	state.fail = nil
	operation, err := s.SecretRevoke(context.Background(), revokeScope, revoke)
	if err != nil || operation.Status != "succeeded" || len(state.events) != 2 || len(state.used) != 2 {
		t.Fatal("original revocation did not reconcile proof event and reply")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("revocation reconciliation wrote another tombstone")
	}
}

func TestStageIntentAndClaim(t *testing.T) {
	s, _, state, clock, _ := mutationFixture(t)
	stage, connection := stageValue(t, s, clock, nil, "canary", "one", syntheticBytes(t, 103), false)
	request := api.SecretImportRequest{Name: stage.Name, Version: stage.Version, SealedUploadID: stage.ID}
	scope := mutationScope(t, clock, connection, "secret.import", request, state)
	_, err := s.claimStage(context.Background(), scope, stage.ID, "other", stage.Version, "")
	stageCode(t, err, api.CodeForbidden)
	claimed, err := s.claimStage(context.Background(), scope, stage.ID, stage.Name, stage.Version, "")
	if err != nil {
		t.Fatal("exact stage intent was refused")
	}
	clear(claimed.request.Ciphertext)
	other := mutationScope(t, clock, connection, "secret.import", request, state)
	_, err = s.claimStage(context.Background(), other, stage.ID, stage.Name, stage.Version, "")
	stageCode(t, err, api.CodeConflict)
}
