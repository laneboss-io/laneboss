//go:build linux

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/messaging"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestItem3HostedDeliveryWait(t *testing.T) {
	f := fx.ControlledChild(t)
	f.Human.Connection.(*fx.Connection).Endpoint.ContractRevision = api.ContractRevision
	messages, err := messaging.New(messaging.Dependencies{Store: f.State, Clock: fx.Clock{}})
	if err != nil {
		t.Fatal(err)
	}
	content := f.Retain(t, "report", []byte("hosted queue input "+string(fx.ID(t))), f.Human.Actor, f.Human.Actor.LifeID)
	params := api.MailSendRequest{RecipientLifeID: f.Lane.LifeID, Content: content}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: "mail.send", RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, params)}
	request.RequestSHA256, err = wire.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	f.Human.Request = request
	raw := fx.JSON(t, request)
	f.Human.Frame = &fx.Frame{Raw: raw}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx, retire := f.State.TrackMutation(ctx)
	defer retire()
	if _, won, err := f.State.ReserveMutation(ctx, api.RequestReservation{Scope: f.Human, RawRequest: raw, Deadline: fx.Expiry()}); err != nil || !won {
		t.Fatal("mail dispatcher did not reserve its actual invocation", err)
	}
	mail, err := messages.MailSend(ctx, f.Human, params)
	if err != nil {
		t.Fatal("real hosted delivery input failed to enqueue", err)
	}
	effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var effect api.Effect
	for _, candidate := range effects {
		if candidate.Deliver != nil && candidate.Deliver.ID == mail.ID {
			effect = candidate
		}
	}
	if effect.ID == "" {
		t.Fatal("real queue commit has no delivery intent")
	}
	host := fixtureServer(t)
	host.deps.Store, host.deps.Clock = f.State, fx.Clock{}
	host.runtime.Store, host.runtime.Delivery = f.State, messages
	if err := supportsEffect(host.runtime, effect); err != nil {
		t.Fatal("installed host still refuses its owning mail coordinator", err)
	}
	scope := f.Execution
	scope.Actor.ID = fx.ID(t)
	claim, err := f.State.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: scope.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal("actual queued-mail effect could not acquire its live claim", err)
	}
	if _, err := host.runEffect(ctx, scope, claim); err == nil {
		t.Fatal("queued mail without a recipient turn fabricated completed delivery")
	} else {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeUnavailable || !typed.Retryable {
			t.Fatal("missing recipient turn lost its explicit typed wait", err)
		}
	}
	bad := scope
	bad.Actor.ID = fx.ID(t)
	if _, err := host.runEffect(ctx, bad, claim); err == nil {
		t.Fatal("foreign claimant executed a queued delivery")
	}
	outcome := api.EffectOutcome{EffectID: effect.ID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Record.Generation, Status: "succeeded"}
	if _, err := f.State.CompleteEffect(ctx, scope, outcome); err == nil {
		t.Fatal("unmeasured mail effect was marked complete")
	}
	page, err := f.State.Mail(ctx, scope, api.ListRequest{LifeID: f.Lane.LifeID, Limit: 200})
	if err != nil || len(page.Messages) != 1 || page.Messages[0].Status != "queued" || page.Messages[0].Generation != 1 {
		t.Fatal("typed wait acknowledged or returned the unselected mail", err)
	}
}
