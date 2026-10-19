package messaging

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This boundary fixture delegates the real recording store and corrupts only
// the selected retained receipt. It does not synthesize a successful result.
type foreignReceiptStore struct {
	api.StateStore
	stage  string
	change func(*api.MutationReceipt)
}

func (s foreignReceiptStore) LookupReceipt(ctx context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	receipt, err := s.StateStore.LookupReceipt(ctx, scope, key)
	if err == nil {
		if s.stage == "lookup" {
			s.change(&receipt)
		} else {
			receipt.Reply = nil
		}
	}
	return receipt, err
}

func (s foreignReceiptStore) AwaitReceipt(ctx context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	receipt, err := s.StateStore.LookupReceipt(ctx, scope, key)
	if err == nil {
		s.change(&receipt)
	}
	return receipt, err
}

func TestMailReplayBinding(t *testing.T) {
	for _, stage := range []string{"lookup", "await"} {
		for _, field := range []string{"config", "kind", "principal", "life", "method", "key", "digest"} {
			t.Run(stage+"-"+field, func(t *testing.T) {
				f := newFixture(t)
				request := api.MailSendRequest{RecipientLifeID: "peer3", Content: f.blob(t, []byte("Retained reply identity\n"))}
				scope := f.scope(t, "a3", "mail.send", request)
				if _, err := f.service.MailSend(context.Background(), scope, request); err != nil {
					t.Fatal(err)
				}
				f.service.deps.Store = foreignReceiptStore{StateStore: f.store, stage: stage, change: func(receipt *api.MutationReceipt) {
					switch field {
					case "config":
						receipt.Config = "other"
					case "kind":
						receipt.Actor.Kind = "human"
					case "principal":
						receipt.Actor.ID = randomID(t)
					case "life":
						receipt.Actor.LifeID = randomID(t)
					case "method":
						receipt.Key.Method = "report.submit"
					case "key":
						receipt.Key.IdempotencyKey = randomID(t)
					case "digest":
						receipt.Key.RequestSHA256 = hashBytes([]byte(randomID(t)))
					}
				}}
				_, err := f.service.MailSend(context.Background(), scope, request)
				wantCode(t, err, api.CodeIntegrity)
				if len(f.store.events) != 1 || len(f.store.effects) != 1 {
					t.Fatal("foreign receipt lookup changed the mail state")
				}
			})
		}
	}
}

func TestMailProofReplay(t *testing.T) {
	for _, field := range []string{"id", "digest", "expiry"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t)
			request := api.MailSendRequest{RecipientLifeID: "a3", Content: f.blob(t, []byte("Verified human retry\n"))}
			scope := f.scope(t, "reviewer", "mail.send", request)
			scope.Request.Proof = &api.ProofRef{ID: randomID(t), RequestSHA256: scope.Request.RequestSHA256, ExpiresAt: api.Timestamp(f.clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
			f.confirmProof(t, scope)
			first, err := f.service.MailSend(context.Background(), scope, request)
			if err != nil {
				t.Fatal(err)
			}
			second, err := f.service.MailSend(context.Background(), scope, request)
			if err != nil || second.ID != first.ID || len(f.store.events) != 1 {
				t.Fatalf("used proof did not replay its original mail: %v", err)
			}
			switch field {
			case "id":
				scope.Request.Proof.ID = ""
			case "digest":
				scope.Request.Proof.RequestSHA256 = hashBytes([]byte("foreign intent"))
			case "expiry":
				scope.Request.Proof.ExpiresAt = "invalid"
			}
			_, err = f.service.MailSend(context.Background(), scope, request)
			wantCode(t, err, api.CodeUnauthenticated)
		})
	}
	f := newFixture(t)
	request := api.MailSendRequest{RecipientLifeID: "peer3", Content: f.blob(t, []byte("Lane retry cannot use a human proof\n"))}
	scope := f.scope(t, "a3", "mail.send", request)
	if _, err := f.service.MailSend(context.Background(), scope, request); err != nil {
		t.Fatal(err)
	}
	scope.Request.Proof = &api.ProofRef{ID: randomID(t), RequestSHA256: scope.Request.RequestSHA256, ExpiresAt: api.Timestamp(f.clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
	_, err := f.service.MailSend(context.Background(), scope, request)
	wantCode(t, err, api.CodeForbidden)
}

func TestHumanProofAtomic(t *testing.T) {
	f := newFixture(t)
	request := api.MailSendRequest{RecipientLifeID: "a3", Content: f.blob(t, []byte("Proof race input\n"))}
	scope := f.scope(t, "reviewer", "mail.send", request)
	scope.Request.Proof = &api.ProofRef{ID: randomID(t), RequestSHA256: scope.Request.RequestSHA256, ExpiresAt: api.Timestamp(f.clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
	f.confirmProof(t, scope)
	f.store.beforeCommit = func() {
		proof := f.store.proofs[scope.Request.Proof.ID]
		proof.ConsumedBy = randomID(t)
		f.store.proofs[proof.Ref.ID] = proof
	}
	_, err := f.service.MailSend(context.Background(), scope, request)
	wantCode(t, err, api.CodeUnauthenticated)
	if len(f.store.events) != 0 || len(f.store.effects) != 0 || len(f.store.mail) != 0 {
		t.Fatal("a raced human nonce wrote mail before its atomic guard")
	}
}

func TestMailSenderEpoch(t *testing.T) {
	f := newFixture(t)
	request := api.MailSendRequest{RecipientLifeID: "peer3", Content: f.blob(t, []byte("Sender epoch input\n"))}
	scope := f.scope(t, "a3", "mail.send", request)
	f.store.beforeCommit = func() {
		row := f.store.lanes[scope.Actor.LifeID]
		row.CancellationEpoch++
		f.store.lanes[row.LifeID] = row
	}
	_, err := f.service.MailSend(context.Background(), scope, request)
	wantCode(t, err, api.CodeConflict)
	if len(f.store.events) != 0 || len(f.store.effects) != 0 {
		t.Fatal("a cancelled sender queued a new delivery effect")
	}
}
