package messaging

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestChannelGrantExactness(t *testing.T) {
	for _, cell := range []string{"missing", "expired", "borrowed"} {
		t.Run(cell, func(t *testing.T) {
			f := newFixture(t)
			from := f.store.lanes["a5"]
			grants := f.store.grants[from.GrantSetID]
			granted := api.ChannelGrant{ID: randomID(t), ChannelID: randomID(t), ExpiresAt: grants.ExpiresAt}
			grants.Channels = []api.ChannelGrant{granted}
			f.store.grants[grants.ID] = grants
			f.enroll(t, granted.ChannelID)
			request := api.MailSendRequest{ChannelGrantID: granted.ID, Content: f.blob(t, []byte("Exact channel selection\n"))}
			_, err := f.service.MailSend(context.Background(), f.scope(t, "a5", "mail.send", request), request)
			wantCode(t, err, api.CodeNotImplemented)
			switch cell {
			case "missing":
				request.ChannelGrantID = randomID(t)
			case "expired":
				grants.Channels[0].ExpiresAt = api.Timestamp(f.clock.now.Add(-time.Second).Format(time.RFC3339Nano))
				f.store.grants[grants.ID] = grants
			case "borrowed":
				root := f.store.grants[f.store.lanes["root"].GrantSetID]
				other := granted
				other.ID = randomID(t)
				root.Channels = []api.ChannelGrant{other}
				f.store.grants[root.ID] = root
				request.ChannelGrantID = other.ID
			}
			_, err = f.service.MailSend(context.Background(), f.scope(t, "a5", "mail.send", request), request)
			wantCode(t, err, api.CodeForbidden)
			if len(f.store.events) != 0 || len(f.store.effects) != 0 {
				t.Fatal("a missing, expired or borrowed channel created a delivery")
			}
		})
	}
}

func TestDeliveryRelationRecheck(t *testing.T) {
	valid := newFixture(t)
	one, two := valid.send(t, "a5", "a3"), valid.send(t, "peer3", "a3")
	observer, prepared := valid.delivery(t, one, two)
	if _, err := valid.service.BeginDelivery(context.Background(), observer, prepared); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	first, second := f.send(t, "a5", "a3"), f.send(t, "peer3", "a3")
	scope, request := f.delivery(t, first, second)
	changed := f.store.mail[second.ID]
	changed.Sender = api.Actor{Kind: "lane", ID: "b3", LifeID: "b3", Level: 3, Role: "executor"}
	f.store.mail[second.ID] = changed
	_, err := f.service.BeginDelivery(context.Background(), scope, request)
	wantCode(t, err, api.CodeForbidden)
	if len(f.store.events) != 2 || f.store.mail[second.ID].Status != "queued" {
		t.Fatal("a failed delivery relation changed the queue")
	}
}

func TestTurnRejectsRetiredSender(t *testing.T) {
	valid := newFixture(t)
	original := valid.send(t, "peer3", "a3")
	observer, prepared := valid.delivery(t, original)
	if _, err := valid.service.BeginDelivery(context.Background(), observer, prepared); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	mail := f.send(t, "peer3", "a3")
	scope, request := f.delivery(t, mail)
	old := f.store.lanes["peer3"]
	old.Cleaned, old.State, old.Generation = true, "merged", old.Generation+1
	f.store.lanes[old.LifeID] = old
	f.add("new-peer", "b4", 3)
	replacement := f.store.lanes["new-peer"]
	replacement.Name = old.Name
	f.store.lanes[replacement.LifeID] = replacement
	_, err := f.service.BeginDelivery(context.Background(), scope, request)
	wantCode(t, err, api.CodeForbidden)
	if f.store.mail[mail.ID].Sender.LifeID != old.LifeID {
		t.Fatal("a reused display name changed the original mail sender")
	}
}

func receiptFixture(t *testing.T) (*fixture, api.Scope, api.MailReceipt) {
	t.Helper()
	f := newFixture(t)
	mail := f.send(t, "a5", "a3")
	mail.Status, mail.LogicalTurnID = "delivering", randomID(t)
	f.store.mail[mail.ID] = mail
	target := api.LifeRef{LifeID: mail.RecipientLifeID, Run: 2}
	zero, survivors := 0, uint64(0)
	now := api.Timestamp(f.clock.now.Format(time.RFC3339Nano))
	turn := api.TurnEvent{
		Trigger: api.Trigger{Kind: "mail", MailIDs: []api.ID{mail.ID}, CausingSeqs: []api.Sequence{mail.QueuedSeq}},
		Prompt:  mail.Content, Status: "written", MailIDs: []api.ID{mail.ID},
	}
	end := api.RunEndEvent{
		LaunchID: randomID(t), Reason: "exit", BudgetRemaining: api.Budget{Currency: "USD"},
		Observation: api.ProcessObservation{
			Handle: api.ProcessHandle{ID: randomID(t), Target: target, ContainmentID: randomID(t), Generation: string(randomID(t))},
			State:  "exited", ExitCode: &zero, Survivors: &survivors, PromptStatus: "completed", ObservedAt: now,
		},
	}
	for i, value := range []any{turn, end} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		kind, run := api.EventKind("lane.turn"), api.RunNumber(1)
		if i == 1 {
			kind, run = "lane.ended", target.Run
		}
		f.store.events = append(f.store.events, api.Event{
			Schema: api.SchemaVersion, ID: randomID(t), Seq: mail.QueuedSeq + api.Sequence(i+1),
			Config: "fixture", Kind: kind, LifeID: target.LifeID, Run: run, LogicalTurnID: mail.LogicalTurnID,
			Actor: api.Actor{Kind: "scheduler", ID: randomID(t)}, RequestedBy: mail.Sender,
			StarterChain: append([]api.ID{}, f.store.lanes[target.LifeID].StarterChain...),
			RecordedAt:   now, RequestedAt: now, ObservedAt: now, Origin: "service", Payload: raw,
		})
	}
	scope := api.Scope{Config: "fixture", Source: "worker", Actor: api.Actor{Kind: "service", ID: "observer"}}
	receipt := api.MailReceipt{MailID: mail.ID, Target: target, LogicalTurnID: mail.LogicalTurnID, Status: "delivered", PromptStatus: "completed", Cause: "exit", ObservedAt: now}
	return f, scope, receipt
}

func TestReceiptRunAndOrigin(t *testing.T) {
	for _, cell := range []string{"legacy", "wrong-run", "wrong-life", "wrong-turn", "survivors"} {
		t.Run(cell, func(t *testing.T) {
			f, scope, receipt := receiptFixture(t)
			if err := f.service.ValidateReceipt(context.Background(), scope, receipt); err != nil {
				t.Fatal(err)
			}
			last := &f.store.events[len(f.store.events)-1]
			switch cell {
			case "legacy":
				last.Origin = "legacy_import"
			case "wrong-run":
				last.Run = receipt.Target.Run - 1
			case "wrong-life":
				last.LifeID = "b3"
			case "wrong-turn":
				last.LogicalTurnID = randomID(t)
			case "survivors":
				var end api.RunEndEvent
				if err := json.Unmarshal(last.Payload, &end); err != nil {
					t.Fatal(err)
				}
				remaining := uint64(1)
				end.Observation.Survivors = &remaining
				var err error
				last.Payload, err = json.Marshal(end)
				if err != nil {
					t.Fatal(err)
				}
			}
			wantCode(t, f.service.ValidateReceipt(context.Background(), scope, receipt), api.CodeConflict)
			if f.store.mail[receipt.MailID].Status != "delivering" {
				t.Fatal("an invalid observation acknowledged logical-turn mail")
			}
		})
	}
}
