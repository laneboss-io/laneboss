package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestReceiptScope(t *testing.T) {
	for _, phase := range []string{"lookup", "await"} {
		t.Run(phase, func(t *testing.T) {
			for name, edit := range map[string]func(*api.MutationReceipt){
				"config":    func(r *api.MutationReceipt) { r.Config = "other-config" },
				"kind":      func(r *api.MutationReceipt) { r.Actor.Kind = "human" },
				"principal": func(r *api.MutationReceipt) { r.Actor.ID = "other-principal" },
				"life":      func(r *api.MutationReceipt) { r.Actor.LifeID = "other-life" },
				"method":    func(r *api.MutationReceipt) { r.Key.Method = "org.change.apply" },
				"key":       func(r *api.MutationReceipt) { r.Key.IdempotencyKey = "other-key" },
				"digest":    func(r *api.MutationReceipt) { r.Key.RequestSHA256 = testDigest([]byte("other intent")) },
			} {
				t.Run(name, func(t *testing.T) {
					f := newFixture(t)
					scope := f.bound("org.change.propose", f.request, false)
					raw, err := json.Marshal(f.store.change)
					if err != nil {
						t.Fatal(err)
					}
					original := f.store.receipts[fixtureDomain(scope, requestKey(scope))]
					original.Operation.Status, original.Reply = "succeeded", &api.RPCReply{Result: raw}
					candidate := original
					edit(&candidate)
					if phase == "lookup" {
						// Inject foreign backend metadata after lookup; the normal
						// fixture rejects a caller's changed digest as a key conflict.
						f.store.lookup = func(api.Scope, api.RequestKey) (api.MutationReceipt, error) { return candidate, nil }
						_, err = f.service.OrgChangePropose(context.Background(), scope, f.request)
					} else {
						// Test the AwaitReceipt consumer independently of the
						// guarded publication transaction.
						f.store.await = func(api.Scope, api.RequestKey) (api.MutationReceipt, error) { return candidate, nil }
						_, err = f.service.publicationReply(context.Background(), scope, original.Operation.ID, nil)
					}
					codeIs(t, err, api.CodeIntegrity)
					if f.store.changes != 0 || f.store.reads != 0 {
						t.Fatal("foreign receipt reached retained data")
					}
					f.noEffects()
				})
			}
		})
	}
}

func TestReceiptDomains(t *testing.T) {
	f := newFixture(t)
	scope := f.bound("org.change.propose", f.request, false)
	key := requestKey(scope)
	original, err := f.store.LookupReceipt(context.Background(), scope, key)
	if err != nil || original.Config != scope.Config {
		t.Fatalf("fixture did not retain its original receipt: %v", err)
	}
	for name, edit := range map[string]func(*api.Scope, *api.RequestKey){
		"config":    func(s *api.Scope, _ *api.RequestKey) { s.Config = "other-config" },
		"kind":      func(s *api.Scope, _ *api.RequestKey) { s.Actor.Kind = "human" },
		"principal": func(s *api.Scope, _ *api.RequestKey) { s.Actor.ID = "other-principal" },
		"life":      func(s *api.Scope, _ *api.RequestKey) { s.Actor.LifeID = "other-life" },
		"method":    func(_ *api.Scope, k *api.RequestKey) { k.Method = "org.change.apply" },
		"key":       func(_ *api.Scope, k *api.RequestKey) { k.IdempotencyKey = "other-key" },
	} {
		t.Run(name, func(t *testing.T) {
			other, otherKey := scope, key
			edit(&other, &otherKey)
			_, err := f.store.LookupReceipt(context.Background(), other, otherKey)
			codeIs(t, err, api.CodeNotFound)
		})
	}
	changed := key
	changed.RequestSHA256 = testDigest([]byte("changed bytes under retained key"))
	_, err = f.store.LookupReceipt(context.Background(), scope, changed)
	codeIs(t, err, api.CodeIdempotencyConflict)
	again, err := f.store.LookupReceipt(context.Background(), scope, key)
	if err != nil || !reflect.DeepEqual(original, again) {
		t.Fatal("fixture rebuilt its original receipt from a later caller")
	}
}

func TestProofBeforeReplay(t *testing.T) {
	for _, name := range []string{"lane", "id", "digest"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			request := api.ChangeApproveRequest{ChangeID: f.store.change.ID,
				ManifestSHA256: f.store.change.ManifestSHA256, BaseGeneration: 7}
			value := testApproval(f.store.change)
			scope := f.bound("org.change.approve", request, true)
			switch name {
			case "lane":
				// All non-kind human facts remain valid; the kind check alone
				// decides whether this completed approval may be replayed.
				scope.Actor.Kind = "lane"
			case "id":
				scope.Request.Proof.ID = "invalid/proof"
			case "digest":
				scope.Request.Proof.RequestSHA256 = testDigest([]byte("other proof intent"))
			}
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			retained := f.store.receipts[fixtureDomain(scope, requestKey(scope))]
			retained.Config, retained.Actor, retained.Key = scope.Config, scope.Actor, requestKey(scope)
			retained.Operation.ID = "operation-one"
			retained.Operation.Status, retained.Reply = "succeeded", &api.RPCReply{Result: raw}
			f.store.receipts[fixtureDomain(scope, requestKey(scope))] = retained
			_, err = handlerForReplay(f, scope.Request.Method)(context.Background(), scope, scope.Request.Params)
			codeIs(t, err, api.CodeForbidden)
			if f.store.changes != 0 || f.store.reads != 0 {
				t.Fatal("malformed or lane proof reached replay data")
			}
			f.noEffects()
		})
	}
}

func TestAwaitOriginalReply(t *testing.T) {
	f := newFixture(t)
	scope := f.bound("org.change.propose", f.request, false)
	raw, err := json.Marshal(f.store.change)
	if err != nil {
		t.Fatal(err)
	}
	retained := f.store.receipts[fixtureDomain(scope, requestKey(scope))]
	retained.Operation.Status, retained.Reply = "succeeded", &api.RPCReply{Result: raw}
	f.store.await = func(api.Scope, api.RequestKey) (api.MutationReceipt, error) { return retained, nil }
	reply, err := f.service.publicationReply(context.Background(), scope, retained.Operation.ID, nil)
	if err != nil || reply == nil || !bytes.Equal(reply.Result, raw) {
		t.Fatalf("await did not return the exact original scoped reply: %v", err)
	}
	f.noEffects()
}
