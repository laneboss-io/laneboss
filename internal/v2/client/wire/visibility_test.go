package wire

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPrivateEventVisibility(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	scope := api.Scope{Config: "visibility-fixture", Actor: api.Actor{Kind: "lane", ID: id, LifeID: id, Level: 3, Role: "executor"}}
	for _, kind := range []api.EventKind{"human.challenge", "human.confirmed", "human.session", "human.proof.used", "ticket.issued", "ticket.redeemed", "secret.imported", "secret.rotated", "secret.revoked", "channel.delivered", "channel.failed"} {
		visible, err := EventVisible(context.Background(), scope, api.Event{Kind: kind})
		if err != nil || visible {
			t.Fatal("administrative event leaked to lane", kind, err)
		}
	}
	other, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	receipt := api.MailReceipt{MailID: other, Target: api.LifeRef{LifeID: id, Run: 1}, LogicalTurnID: other, Status: "delivered", PromptStatus: "written", ObservedAt: "2026-01-01T00:00:00Z"}
	payload, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	visible, err := EventVisible(context.Background(), scope, api.Event{Kind: "mail.delivered", Actor: api.Actor{Kind: "service", ID: other}, Payload: payload})
	if err != nil || !visible {
		t.Fatal("own delivery receipt was hidden", err)
	}
	receipt.Target.LifeID = other
	payload, err = json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	visible, err = EventVisible(context.Background(), scope, api.Event{Kind: "mail.delivered", Payload: payload})
	if err != nil || visible {
		t.Fatal("foreign delivery receipt leaked", err)
	}
}

func TestLaunchMetadataPrivacy(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	lane := api.Scope{Config: "visibility-fixture", Actor: api.Actor{Kind: "lane", ID: id, LifeID: id, Level: 3, Role: "executor"}}
	service := api.Scope{Config: lane.Config, Actor: api.Actor{Kind: "service", ID: id}}
	for _, kind := range []api.EventKind{"launch.planned", "capture.bound", "capture.refused"} {
		event := api.Event{Kind: kind, LifeID: id}
		visible, err := EventVisible(context.Background(), lane, event)
		if err != nil || visible {
			t.Fatal("private launch or capture metadata leaked to lane", kind, err)
		}
		visible, err = EventVisible(context.Background(), service, event)
		if err != nil || !visible {
			t.Fatal("service could not read retained launch metadata", kind, err)
		}
	}
	visible, err := EventVisible(context.Background(), lane, api.Event{Kind: "capture.gap", LifeID: id})
	if err != nil || !visible {
		t.Fatal("life capture-gap projection was hidden", err)
	}
}
