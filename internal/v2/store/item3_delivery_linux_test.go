//go:build linux

package store_test

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/messaging"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestItem3PreparedMailSelection(t *testing.T) {
	f := fx.New(t)
	// The store must resolve preparation before a Lane projection exists.
	f.Reserve(t)
	f.Source(t)
	request := api.DeliveryTurnRequest{Lease: f.Claim, Target: f.Reservation.Target,
		LogicalTurnID: f.Claim.Record.Effect.Context.LogicalTurnID, MailIDs: []api.ID{},
		ExpectedGeneration: f.Reservation.Generation, CancellationEpoch: f.Reservation.CancellationEpoch}
	batch, err := f.State.MailForTurn(context.Background(), f.Execution, request)
	if err != nil {
		t.Fatal("reserved turn could not select its actual prepared mail batch", err)
	}
	if batch.Target != request.Target || batch.LogicalTurnID != request.LogicalTurnID || batch.Generation != request.ExpectedGeneration || batch.Mail == nil || len(batch.Mail) != 0 || batch.Intent.Actor != f.Execution.Actor || batch.Intent.RequestedBy != f.Human.Actor {
		t.Fatal("prepared batch lost its actual turn, claim or manual requester")
	}
	for _, control := range []string{"foreign-claim", "foreign-target", "stale-generation", "unselected-mail"} {
		bad := request
		switch control {
		case "foreign-claim":
			bad.Lease.ClaimID = fx.ID(t)
		case "foreign-target":
			bad.Target.LifeID = fx.ID(t)
		case "stale-generation":
			bad.ExpectedGeneration++
		case "unselected-mail":
			bad.MailIDs = []api.ID{fx.ID(t)}
		}
		if _, err := f.State.MailForTurn(context.Background(), f.Execution, bad); err == nil {
			t.Fatal("mail selection admitted " + control)
		}
	}
	if _, err := f.State.MailForTurn(context.Background(), f.Human, request); err == nil {
		t.Fatal("public lane obtained the private prepared-mail port")
	}
}

func TestItem3MailSelectionReplay(t *testing.T) {
	f := fx.ControlledChild(t)
	f.Human.Connection.(*fx.Connection).Endpoint.ContractRevision = api.ContractRevision
	messages, err := messaging.New(messaging.Dependencies{Store: f.State, Clock: fx.Clock{}})
	if err != nil {
		t.Fatal(err)
	}
	senders := []*fx.Fixture{item3Sibling(t, f), item3Sibling(t, f)}
	refs := []api.BlobRef{}
	for _, sender := range senders {
		ref := sender.Retain(t, "report", []byte("selected actual bytes "+string(fx.ID(t))), sender.Binding.Record.Actor, sender.Lane.LifeID)
		refs = append(refs, ref)
		sender.Opened(t)
		sender.Human = sender.LaneScope(t)
		sender.Human.Connection.(*fx.Connection).Endpoint.ContractRevision = api.ContractRevision
	}
	ids := []api.ID{}
	for i, ref := range refs {
		request := api.MailSendRequest{RecipientLifeID: f.Lane.LifeID, Content: ref}
		ctx := item3Admit(t, senders[i], "mail.send", request)
		mail, err := messages.MailSend(ctx, senders[i].Human, request)
		if err != nil {
			t.Fatal("actual selected mail did not enqueue", err)
		}
		ids = append(ids, mail.ID)
	}
	f.Opened(t)
	f.Ended(t)
	inputs := f.Plan.Inputs
	f.Admit(t, "lane.turn", api.TurnRequest{Target: f.Reservation.Target, ExpectedGeneration: f.Lane.Generation,
		MailIDs: ids, Budget: f.Lane.BudgetRemaining})
	f.Reserve(t)
	request := api.DeliveryTurnRequest{Lease: f.Claim, Target: f.Reservation.Target, LogicalTurnID: f.Claim.Record.Effect.Context.LogicalTurnID,
		MailIDs: ids, ExpectedGeneration: f.Reservation.Generation, CancellationEpoch: f.Reservation.CancellationEpoch}
	if _, err := f.State.MailForTurn(context.Background(), f.Execution, request); err == nil {
		t.Fatal("mail selected before its sourced runtime and grants existed")
	}
	// A retained run uses its existing approved grant set and runtime. It must
	// not issue a new grant generation merely to make this fixture advance.
	inputs.Sources.ReservationID = f.Reservation.ID
	record := f.Record
	record.Generation++
	record.Phase, record.Inputs = "sourced", &inputs
	cause := f.Intent(t, api.InternalLaunchPlan)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause,
		Writes:  api.StateWrites{LaunchPlans: []api.LaunchPlanRecord{record}},
		Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: f.Reservation.ID, Generation: f.Record.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: f.Reservation.Target.LifeID, Epoch: f.Reservation.CancellationEpoch}}}}); err != nil {
		t.Fatal("retained source pins did not commit", err)
	}
	batch, err := messages.BeginDelivery(context.Background(), f.Execution, request)
	if err != nil {
		t.Fatal("actual reserved turn did not select its ordered mail", err)
	}
	if len(batch.Mail) != 2 || batch.Intent.RequestedBy != f.Human.Actor || batch.Intent.Actor != f.Execution.Actor || batch.Intent.RequestedBy == batch.Mail[0].Sender {
		t.Fatal("mail selection substituted sender for the actual turn requester")
	}
	for i, mail := range batch.Mail {
		if mail.ID != ids[i] || mail.Content != refs[i] || mail.Generation != 2 || mail.Status != "delivering" || mail.LogicalTurnID != request.LogicalTurnID {
			t.Fatal("selection changed immutable bytes, order or consume-once generation")
		}
	}
	replay, err := messages.BeginDelivery(context.Background(), f.Execution, request)
	if err != nil || !reflect.DeepEqual(replay, batch) {
		t.Fatal("mail selection replay changed the retained batch", err)
	}
	bad := request
	bad.MailIDs = []api.ID{ids[1], ids[0]}
	if _, err := messages.BeginDelivery(context.Background(), f.Execution, bad); err == nil {
		t.Fatal("replayed turn accepted a different mail order")
	}
	bad = request
	bad.Lease.ClaimID = fx.ID(t)
	if _, err := messages.BeginDelivery(context.Background(), f.Execution, bad); err == nil {
		t.Fatal("foreign claim acquired selected mail")
	}
	// This changes the protected grant projection as a component control; it
	// does not claim that the public revoke/cascade or native cleanup ran.
	later := senders[1]
	grants, err := later.State.Grants(context.Background(), later.Lane.GrantSetID)
	if err != nil {
		t.Fatal(err)
	}
	grants.Generation++
	grants.Revoked = true
	revocation := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalOrgBootstrap, Config: f.Deps.Config, Actor: f.Execution.Actor, RequestedBy: f.Execution.Actor}
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &revocation, Writes: api.StateWrites{Grants: []api.GrantSet{grants}}}); err != nil {
		t.Fatal("protected later-sender revocation control failed", err)
	}
	if _, err := messages.BeginDelivery(context.Background(), f.Execution, request); err == nil {
		t.Fatal("selection replay ignored a later carried sender's revoked rights")
	}
	page, err := f.State.Mail(context.Background(), f.Execution, api.ListRequest{LifeID: f.Lane.LifeID, Limit: 200})
	if err != nil || len(page.Messages) != 2 {
		t.Fatal("refused replay changed the actual mailbox", err)
	}
	for _, mail := range page.Messages {
		if mail.Generation != 2 || mail.Status != "delivering" {
			t.Fatal("later-sender refusal acknowledged or reselected mail")
		}
	}
}

func item3Sibling(t *testing.T, recipient *fx.Fixture) *fx.Fixture {
	t.Helper()
	sibling := *recipient
	sibling.Start.Lane = string(fx.ID(t))
	sibling.PreparedClaim = api.EffectLease{}
	sibling.Admit(t, "lane.start", sibling.Start)
	sibling.Reserve(t)
	sibling.Source(t)
	sibling.BuildPlan(t, true)
	sibling.Spec(t)
	sibling.Bind(t)
	return &sibling
}
