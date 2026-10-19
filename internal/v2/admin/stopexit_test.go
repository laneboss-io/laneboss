//go:build linux

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Refuse the terminal observation at the storage publication boundary. The
// real file store remains the source of Records; no successful write is faked.
type exitCommitStore struct {
	*fileLeaseStore
	refusal error
	pending *leaseRecord
}

func (s *exitCommitStore) Save(record leaseRecord) error {
	if s.pending == nil && record.Gate != nil && record.Gate.Observation != nil && record.Credentials.Stop == nil {
		s.pending = &record
		return s.refusal
	}
	return s.fileLeaseStore.Save(record)
}

func refuseExitCommit(t *testing.T, ctx context.Context, m *leaseManager, target api.HelperObserveRequest) {
	t.Helper()
	fileStore, ok := m.store.(*fileLeaseStore)
	if !ok {
		t.Fatal("exit fixture requires the actual file journal")
	}
	store := &exitCommitStore{fileLeaseStore: fileStore, refusal: errors.New("terminal journal publication failed")}
	m.store = store
	if _, err := m.observeGate(ctx, target); !errors.Is(err, store.refusal) {
		t.Fatalf("exit did not reach the failed publication: %v", err)
	}
	if store.pending == nil || !committedExit(*store.pending) {
		t.Fatal("failed publication did not contain the observed natural exit")
	}
	records, err := store.Records()
	if err != nil || len(records) != 1 || records[0].Gate.State != "opened" || records[0].Gate.Observation != nil || records[0].Credentials.Stop != nil {
		t.Fatal("failed publication changed the durable exit or stop record")
	}
}

func naturalCanaryExit(t *testing.T, ctx context.Context, owner *stopCanaryOwner) {
	t.Helper()
	if err := owner.finish.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-owner.gate.done:
	case <-ctx.Done():
		t.Fatal("natural canary exit was not reaped")
	}
	observation, err := owner.gate.Observe(ctx, owner.handle)
	if err != nil || observation.ExitCode == nil || *observation.ExitCode != 0 || observation.Signal != nil {
		t.Fatalf("canary did not exit naturally: %v", err)
	}
	if err := owner.WaitContainmentEmpty(ctx, leaseRecord{}); err != nil {
		t.Fatal(err)
	}
}

func stopExitRequest(reg gateOpenRegistration) api.HelperStopRequest {
	cause := reg.Request.Cause
	cause.Kind = api.InternalHelperStop
	return api.HelperStopRequest{Cause: cause, Target: api.HelperObserveRequest{LeaseID: reg.Binding.Record.UIDLeaseID, Handle: gateHandleFrom(reg)}, Reason: "stop exit race", OperationID: cause.CauseOperationID, EffectID: cause.EffectID}
}

// The helper serves requests serially. Exercise both journal commit orders
// with a real EOF-driven exit, including an exit not yet committed by Observe.
func TestStopExitOrder(t *testing.T) {
	for _, order := range []string{"exit-first", "stop-first", "uncommitted"} {
		t.Run(order, func(t *testing.T) {
			m, reg, _, store, owner, broker, _ := stopCredentialFixture(t, true)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			request := stopExitRequest(reg)
			if order == "stop-first" {
				r, err := m.find(request.Target.LeaseID)
				if err != nil {
					t.Fatal(err)
				}
				if err := m.fenceStopped(&r, request.Cause, "revoked"); err != nil {
					t.Fatal(err)
				}
			}
			naturalCanaryExit(t, ctx, owner)
			if order == "uncommitted" {
				refuseExitCommit(t, ctx, m, request.Target)
			} else {
				if _, err := m.observeGate(ctx, request.Target); err != nil {
					t.Fatal(err)
				}
			}
			_, err := m.stopGate(ctx, request)
			if !errors.Is(err, broker.failure) {
				t.Fatalf("broker refusal was lost: %v", err)
			}
			records, err := store.Records()
			if err != nil || len(records) != 1 {
				t.Fatal("stop decision was not retained")
			}
			r := records[0]
			release := order == "exit-first"
			if r.Credentials.Stop == nil || (r.Credentials.Stop.Reason == "release") != release || r.Revoked == release || (broker.request.Reason == "release") != release {
				t.Fatal("stop ignored the committed exit order")
			}
			data, err := json.Marshal(r.Credentials.Stop)
			if err != nil || bytes.Contains(data, []byte("stop arrived after natural exit")) != release {
				t.Fatal("stop decision lost its after-exit audit record")
			}
			if release {
				if _, err := m.openGate(ctx, reg); err == nil {
					t.Fatal("late stop restored the consumed launch permit")
				}
				original, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				for _, field := range []string{"observation", "note", "cause"} {
					var changed leaseRecord
					if err := decodeStrict(original, &changed); err != nil {
						t.Fatal(err)
					}
					switch field {
					case "observation":
						changed.Gate.Observation = nil
					case "note":
						changed.Credentials.Stop.Note = ""
					case "cause":
						changed.Credentials.Stop.Cause.Kind = api.InternalHelperAbort
					}
					if err := m.save(changed); err == nil {
						t.Fatal("late stop accepted an unproved release exception")
					}
				}
			}
			// A later observation/retry cannot change the first fence decision.
			if _, err := m.observeGate(ctx, request.Target); err != nil {
				t.Fatal(err)
			}
			_, err = m.stopGate(ctx, request)
			if !errors.Is(err, broker.failure) || (broker.request.Reason == "release") != release {
				t.Fatalf("stop retry changed the committed race winner: err=%v context=%v release_matches=%t", err, ctx.Err(), (broker.request.Reason == "release") == release)
			}
		})
	}
}
