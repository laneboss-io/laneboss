package messaging

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestDeliveryEffectState(t *testing.T) {
	f := newFixture(t)
	mail := f.send(t, "a5", "a3")
	scope, request := f.delivery(t, mail)
	request.Lease.Record.State = "running"
	f.store.effectRows[request.Lease.Record.Effect.ID] = request.Lease.Record
	_, err := f.service.BeginDelivery(context.Background(), scope, request)
	if err == nil {
		t.Fatal("delivery accepted an operation status as an effect state")
	}
	wantCode(t, err, api.CodeConflict)
	if f.store.mail[mail.ID].Status != "queued" {
		t.Fatal("rejected effect state changed the mail queue")
	}
}

func TestBeginDeliveryChecks(t *testing.T) {
	for _, cell := range []string{"ready", "epoch", "later-grants", "later-relation", "mail-race", "sender-race"} {
		t.Run(cell, func(t *testing.T) {
			f := newFixture(t)
			first, second := f.send(t, "a5", "a3"), f.send(t, "peer3", "a3")
			scope, request := f.delivery(t, first, second)
			switch cell {
			case "epoch":
				row := f.store.lanes[request.Target.LifeID]
				row.CancellationEpoch++
				f.store.lanes[row.LifeID] = row
			case "later-grants":
				grants := f.store.grants[f.store.lanes[second.Sender.LifeID].GrantSetID]
				grants.Revoked = true
				f.store.grants[grants.ID] = grants
			case "later-relation":
				mail := f.store.mail[second.ID]
				mail.Sender = api.Actor{Kind: "lane", ID: "b3", LifeID: "b3", Level: 3, Role: "executor"}
				f.store.mail[mail.ID] = mail
			case "mail-race":
				f.store.beforeCommit = func() {
					mail := f.store.mail[second.ID]
					mail.Generation++
					f.store.mail[mail.ID] = mail
				}
			case "sender-race":
				f.store.beforeCommit = func() {
					grants := f.store.grants[f.store.lanes[second.Sender.LifeID].GrantSetID]
					grants.Generation++
					grants.Revoked = true
					f.store.grants[grants.ID] = grants
				}
			}
			batch, err := f.service.BeginDelivery(context.Background(), scope, request)
			if cell == "ready" {
				if err != nil || len(batch.Mail) != 2 || batch.Intent.Actor != scope.Actor || batch.Intent.RequestedBy != request.Lease.Record.Effect.Context.RequestedBy || batch.Intent.RequestedBy == first.Sender {
					t.Fatalf("leased delivery lost its batch or actual actor: %v", err)
				}
				for i, original := range []api.Mail{first, second} {
					mail := batch.Mail[i]
					if mail.ID != original.ID || mail.Sender != original.Sender || mail.Status != "delivering" || mail.Generation != original.Generation+1 || mail.LogicalTurnID != request.LogicalTurnID || f.store.mail[mail.ID].Status != "delivering" {
						t.Fatal("leased delivery did not commit each mail generation and turn")
					}
				}
				return
			}
			code := api.CodeConflict
			if cell == "later-grants" || cell == "later-relation" {
				code = api.CodeForbidden
			}
			wantCode(t, err, code)
			if len(f.store.events) != 2 || f.store.mail[first.ID].Status != "queued" || f.store.mail[second.ID].Status != "queued" {
				t.Fatal("a failed internal delivery changed the queue")
			}
		})
	}
}

func completedDelivery(t *testing.T) (*fixture, api.Scope, api.DeliveryReceiptRequest) {
	t.Helper()
	f := newFixture(t)
	mail := f.send(t, "a5", "a3")
	scope, request := f.delivery(t, mail)
	batch, err := f.service.BeginDelivery(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	mail = batch.Mail[0]
	turn := f.store.turns[request.LogicalTurnID]
	prompt := f.typedBlob(t, []byte("Prepared recipient prompt\n"), "prompt")
	turn.Prompt, turn.Status = &prompt, "written"
	f.store.turns[turn.LogicalTurnID] = turn
	observed := api.Timestamp(f.clock.now.Format(time.RFC3339Nano))
	capture := api.CaptureRecord{ID: randomID(t), Target: request.Target, Stream: "stdout", Data: f.typedBlob(t, []byte("Outside captured completion\n"), "capture"), Primary: true, Coverage: "complete", ObservedAt: observed}
	turnEvent := api.TurnEvent{Task: turn.Task, Prompt: prompt, Status: "written", MailIDs: request.MailIDs,
		Trigger: api.Trigger{Kind: "mail", MailIDs: request.MailIDs, CausingSeqs: []api.Sequence{mail.QueuedSeq}}}
	promptEvent := turnEvent
	promptEvent.Status = "completed"
	zero, survivors := 0, uint64(0)
	end := api.RunEndEvent{LaunchID: randomID(t), Reason: "exit", Observation: api.ProcessObservation{
		Handle: api.ProcessHandle{ID: randomID(t), Target: request.Target, ContainmentID: randomID(t), Generation: string(randomID(t))},
		State:  "exited", ExitCode: &zero, Survivors: &survivors, PromptStatus: "completed", ObservedAt: observed}}
	for _, row := range []struct {
		kind    api.EventKind
		payload any
	}{{"lane.turn", turnEvent}, {"prompt.observed", promptEvent}, {"capture.appended", capture}, {"lane.ended", end}} {
		raw, err := json.Marshal(row.payload)
		if err != nil {
			t.Fatal(err)
		}
		f.store.seq++
		f.store.events = append(f.store.events, api.Event{Schema: api.SchemaVersion, ID: randomID(t), Config: scope.Config,
			Seq: f.store.seq, Kind: row.kind, Actor: scope.Actor, RequestedBy: batch.Intent.RequestedBy,
			LifeID: request.Target.LifeID, Run: request.Target.Run, LogicalTurnID: request.LogicalTurnID, Origin: "service", Payload: raw})
	}
	return f, scope, api.DeliveryReceiptRequest{Intent: batch.Intent, MailID: mail.ID, ExpectedGeneration: mail.Generation, CaptureIDs: []api.ID{capture.ID},
		Receipt: api.MailReceipt{MailID: mail.ID, Target: request.Target, LogicalTurnID: request.LogicalTurnID, Status: "delivered", PromptStatus: "completed", Cause: "exit", ObservedAt: observed}}
}

func TestRecordDeliveryChecks(t *testing.T) {
	for _, cell := range []string{"ready", "capture", "prompt", "legacy-capture", "mail-race", "limit", "effect-actor"} {
		t.Run(cell, func(t *testing.T) {
			f, scope, request := completedDelivery(t)
			before := len(f.store.events)
			switch cell {
			case "capture":
				request.CaptureIDs = []api.ID{randomID(t)}
			case "prompt":
				turn := f.store.turns[request.Intent.LogicalTurnID]
				prompt := f.typedBlob(t, []byte("Different retained prompt\n"), "prompt")
				turn.Prompt = &prompt
				f.store.turns[turn.LogicalTurnID] = turn
			case "legacy-capture":
				f.store.events[before-2].Origin = "legacy_import"
			case "effect-actor":
				effect := f.store.effectRows[request.Intent.EffectID]
				parent := *effect.Effect.Context
				parent.Actor.ID = randomID(t)
				effect.Effect.Context = &parent
				f.store.effectRows[effect.Effect.ID] = effect
			case "mail-race":
				f.store.beforeCommit = func() {
					mail := f.store.mail[request.MailID]
					mail.Generation++
					f.store.mail[mail.ID] = mail
				}
			case "limit":
				last := &f.store.events[before-1]
				var end api.RunEndEvent
				if err := json.Unmarshal(last.Payload, &end); err != nil {
					t.Fatal(err)
				}
				end.Reason, end.ProfileContinuation = "limit", true
				raw, err := json.Marshal(end)
				if err != nil {
					t.Fatal(err)
				}
				last.Payload = raw
				request.Receipt.Cause = "limit"
			}
			operation, err := f.service.RecordDelivery(context.Background(), scope, request)
			if cell == "ready" {
				mail := f.store.mail[request.MailID]
				if err != nil || operation.Status != "succeeded" || mail.Status != "delivered" || mail.Generation != request.ExpectedGeneration+1 || len(f.store.events) != before+1 {
					t.Fatalf("observed delivery was not committed: %v", err)
				}
				last := f.store.events[before]
				if last.Kind != "mail.delivered" || last.Actor != scope.Actor || last.RequestedBy != request.Intent.RequestedBy {
					t.Fatal("committed delivery borrowed a carried sender's actor")
				}
				return
			}
			code := api.CodeConflict
			if cell == "effect-actor" {
				code = api.CodeForbidden
			}
			wantCode(t, err, code)
			if len(f.store.events) != before || f.store.mail[request.MailID].Status != "delivering" {
				t.Fatal("uncorrelated receipt acknowledged logical-turn mail")
			}
		})
	}
}
