package lifecycle

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPlanTurnMail(t *testing.T) {
	for _, fault := range []string{"valid", "order", "requester", "unbound"} {
		t.Run(fault, func(t *testing.T) {
			f := newLaunchFixture(t)
			previous, lane := f.endedPlan(t)
			first := api.Mail{ID: launchIDForTest(), Generation: 1, Sender: api.Actor{Kind: "human", ID: "carried-sender"},
				RecipientLifeID: lane.LifeID, Content: f.fixture.blob(launchIDForTest(), "mail", []byte("first mail bytes\n")),
				Artifacts: []api.BlobRef{}, QueuedSeq: f.store.seq + 1, Source: "manual", Status: "queued", Ask: true}
			second := first
			second.ID, second.QueuedSeq = launchIDForTest(), first.QueuedSeq+1
			second.Content = f.fixture.blob(launchIDForTest(), "mail", []byte("second mail bytes\n"))
			f.store.mail[first.ID], f.store.mail[second.ID] = first, second
			request := api.TurnRequest{Target: previous.Reservation.Target, ExpectedGeneration: lane.Generation,
				MailIDs: []api.ID{second.ID, first.ID}, Budget: lane.BudgetRemaining}
			scope := f.fixture.scope("lane.turn", request, f.parent)
			operation, err := f.service.LaneTurn(context.Background(), scope, request)
			if err != nil {
				t.Fatal(err)
			}
			var record api.LaunchPlanRecord
			for _, candidate := range f.store.plans {
				if candidate.Reservation.OperationID == operation.ID {
					record = candidate
				}
			}
			f.store.mailHook = func(batch *api.DeliveryBatch) {
				if fault == "order" {
					batch.Mail[0], batch.Mail[1] = batch.Mail[1], batch.Mail[0]
				}
				if fault == "requester" {
					batch.Intent.RequestedBy = first.Sender
				}
			}
			if fault == "unbound" {
				f.service.deps.Delivery = nil
			}
			internal, planRequest := f.claim(t, record)
			plan, err := f.service.PlanLaunch(context.Background(), internal, planRequest)
			if fault != "valid" {
				if err == nil || f.ports.calls["acquire"] != 1 {
					t.Fatalf("turn prompt used foreign or unbound mail claims: %v", err)
				}
				if fault == "unbound" {
					if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-messaging" {
						t.Fatalf("missing delivery lost its owning typed failure: %v", err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("turn prompt did not consume the real ordered delivery claim: %v", err)
			}
			var prompt launchPrompt
			if err := api.DecodeObject(f.store.blobs[plan.Runner.Prompt.ID], &prompt); err != nil || len(prompt.Mail) != 2 ||
				prompt.Mail[0].Mail.ID != second.ID || prompt.Mail[1].Mail.ID != first.ID ||
				prompt.Mail[0].Content != string(f.store.blobs[second.Content.ID]) || prompt.Mail[1].Mail.Sender != first.Sender ||
				!prompt.Mail[1].Mail.Ask || plan.Reservation.RequestedBy != f.parent {
				t.Fatalf("turn prompt changed mail order, input bytes or authentic requester: %v", err)
			}
			for _, mail := range f.store.mail {
				if mail.Status != "delivering" {
					t.Fatal("prompt preparation acknowledged undelivered mail")
				}
			}
		})
	}
}

func TestPlanGuidance(t *testing.T) {
	for _, status := range []string{"scored", "unavailable", "foreign_turn", "foreign_source"} {
		t.Run(status, func(t *testing.T) {
			f := newLaunchFixture(t)
			content := f.fixture.blob(launchIDForTest(), "artifact", []byte("actual selected guidance bytes\n"))
			source := api.SourceRef{ID: launchIDForTest(), Path: "decisions/reminder.md", SHA256: content.SHA256, Generation: 1}
			f.store.sources[source.ID] = api.RetainedSource{Source: source, Content: content}
			f.ports.guidanceItems = []api.GuidanceItem{{DecisionID: launchIDForTest(), Source: source, Weight: 1}}
			f.ports.guidanceHook = func(guidance *api.Guidance) {
				if status == "unavailable" {
					guidance.Status, guidance.Items, guidance.Notice = "unavailable", []api.GuidanceItem{}, "actual unavailable guidance result"
				}
				if status == "foreign_turn" {
					guidance.LogicalTurnID = "foreign-turn"
				}
				if status == "foreign_source" {
					guidance.Items[0].Source.SHA256 = digestOf([]byte("different source bytes"))
				}
			}
			_, record := f.reserve(t)
			internal, request := f.claim(t, record)
			plan, err := f.service.PlanLaunch(context.Background(), internal, request)
			if status == "foreign_turn" || status == "foreign_source" {
				if err == nil || f.ports.calls["acquire"] != 0 {
					t.Fatalf("planner used guidance outside its retained turn or source: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var prompt launchPrompt
			if err := api.DecodeObject(f.store.blobs[plan.Runner.Prompt.ID], &prompt); err != nil {
				t.Fatal(err)
			}
			if prompt.GuidanceStatus != status || status == "scored" && (len(prompt.Guidance) != 1 ||
				prompt.Guidance[0].Content != string(f.store.blobs[content.ID]) || prompt.Guidance[0].Selection.Source != source) ||
				status == "unavailable" && (len(prompt.Guidance) != 0 || prompt.GuidanceNotice != "actual unavailable guidance result") {
				t.Fatal("prompt lost actual selected guidance bytes or visible unavailability")
			}
		})
	}
}
