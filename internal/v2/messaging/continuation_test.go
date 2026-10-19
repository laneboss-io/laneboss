package messaging

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func continuationDelivery(t *testing.T) (*fixture, api.Scope, api.DeliveryReceiptRequest) {
	t.Helper()
	f, scope, request := completedDelivery(t)
	last := &f.store.events[len(f.store.events)-1]
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
	target := request.Receipt.Target
	target.Run++
	life := f.store.lanes[target.LifeID]
	life.Run, life.Generation = target.Run, life.Generation+1
	f.store.lanes[life.LifeID] = life
	turn := f.store.turns[request.Intent.LogicalTurnID]
	turn.Target = target
	f.store.turns[turn.LogicalTurnID] = turn
	var capture api.CaptureRecord
	if err := json.Unmarshal(f.store.events[len(f.store.events)-2].Payload, &capture); err != nil {
		t.Fatal(err)
	}
	capture.ID, capture.Target = randomID(t), target
	request.CaptureIDs = []api.ID{capture.ID}
	var prompt api.TurnEvent
	if err := json.Unmarshal(f.store.events[len(f.store.events)-3].Payload, &prompt); err != nil {
		t.Fatal(err)
	}
	end.Reason, end.ProfileContinuation = "exit", false
	end.LaunchID = randomID(t)
	end.Observation.Handle.ID = randomID(t)
	end.Observation.Handle.Target = target
	for _, row := range []struct {
		kind  api.EventKind
		value any
	}{{"prompt.observed", prompt}, {"capture.appended", capture}, {"lane.ended", end}} {
		raw, err := json.Marshal(row.value)
		if err != nil {
			t.Fatal(err)
		}
		f.store.seq++
		f.store.events = append(f.store.events, api.Event{Schema: api.SchemaVersion, ID: randomID(t), Seq: f.store.seq, Config: scope.Config, LifeID: target.LifeID, Run: target.Run,
			LogicalTurnID: request.Intent.LogicalTurnID, Actor: scope.Actor, RequestedBy: request.Intent.RequestedBy, Kind: row.kind, Origin: "service", Payload: raw})
	}
	request.Intent.Target, request.Receipt.Target = target, target
	return f, scope, request
}

func TestReceiptContinuation(t *testing.T) {
	for _, cell := range []string{"ready", "cancelled", "stale-target"} {
		t.Run(cell, func(t *testing.T) {
			f, scope, request := continuationDelivery(t)
			if cell == "cancelled" {
				row := f.store.lanes[request.Receipt.Target.LifeID]
				row.CancellationEpoch++
				f.store.lanes[row.LifeID] = row
			}
			if cell == "stale-target" {
				request.Intent.Target.Run--
			}
			before := len(f.store.events)
			operation, err := f.service.RecordDelivery(context.Background(), scope, request)
			if cell == "ready" {
				mail := f.store.mail[request.MailID]
				if err != nil || operation.Status != "succeeded" || mail.Status != "delivered" || mail.LogicalTurnID != request.Intent.LogicalTurnID || len(f.store.events) != before+1 || f.store.events[before].Run != 2 {
					t.Fatalf("profile continuation receipt failed: %v", err)
				}
				return
			}
			wantCode(t, err, api.CodeConflict)
			if f.store.mail[request.MailID].Status != "delivering" || len(f.store.events) != before {
				t.Fatal("invalid continuation acknowledged mail")
			}
		})
	}
}

func TestReceiptAfterQueue(t *testing.T) {
	f, scope, receipt := receiptFixture(t)
	f.store.events[len(f.store.events)-2].Seq = f.store.mail[receipt.MailID].QueuedSeq
	wantCode(t, f.service.ValidateReceipt(context.Background(), scope, receipt), api.CodeIntegrity)
}

func TestCaptureEventEnvelopes(t *testing.T) {
	for _, cell := range []string{"schema", "id", "zero", "oversize", "duplicate", "order"} {
		t.Run(cell, func(t *testing.T) {
			f, scope, request := completedDelivery(t)
			if err := f.service.receiptCaptures(context.Background(), scope, request); err != nil {
				t.Fatal(err)
			}
			capture := &f.store.events[len(f.store.events)-2]
			previous := f.store.events[len(f.store.events)-3]
			switch cell {
			case "schema":
				capture.Schema = 0
			case "id":
				capture.ID = ""
			case "zero":
				capture.Seq = 0
			case "oversize":
				capture.Seq = maxExact + 1
			case "duplicate":
				capture.ID = previous.ID
			case "order":
				capture.Seq = previous.Seq
			}
			wantCode(t, f.service.receiptCaptures(context.Background(), scope, request), api.CodeIntegrity)
		})
	}
}
