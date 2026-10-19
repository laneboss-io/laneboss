//go:build linux

package store_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/messaging"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func item3Admit(t *testing.T, f *fx.Fixture, method api.Method, params any) context.Context {
	t.Helper()
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: method,
		RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, params)}
	var err error
	request.RequestSHA256, err = wire.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	f.Human.Request, f.Raw = request, fx.JSON(t, request)
	f.Human.Frame = &fx.Frame{Raw: f.Raw}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	ctx, retire := f.State.TrackMutation(ctx)
	t.Cleanup(retire)
	var won bool
	f.Receipt, won, err = f.State.ReserveMutation(ctx, api.RequestReservation{Scope: f.Human, RawRequest: f.Raw, Deadline: fx.Expiry()})
	if err != nil || !won {
		t.Fatal("actual invocation did not win its original mutation reservation", err)
	}
	return ctx
}

func item3Control(t *testing.T, f *fx.Fixture) api.Transaction {
	t.Helper()
	request := api.LoopRequest{Target: f.Reservation.Target, ExpectedGeneration: f.Lane.Generation, BackoffMS: 1000}
	f.Admit(t, "lane.loop", request)
	next := f.Lane
	next.Generation++
	event := f.Event(t, "lane.loop", request)
	event.Actor, event.RequestedBy = f.Human.Actor, f.Human.Actor
	event.RequestID, event.OperationID = f.Human.Request.RequestID, ""
	return api.Transaction{Scope: f.Human, RawRequest: f.Raw, Compare: []api.Compare{{Kind: api.CompareLane, ID: f.Lane.LifeID, Generation: f.Lane.Generation}},
		Events: []api.Event{event}, Writes: api.StateWrites{Lanes: []api.Lane{next}}, Reply: &api.RPCReply{Result: fx.JSON(t, api.Operation{ID: f.Receipt.Operation.ID, Status: "succeeded", LifeID: next.LifeID, Run: next.Run})}}
}

func TestItem3LaneControlCommit(t *testing.T) {
	f := fx.ControlledChild(t)
	input := item3Control(t, f)
	commit, err := f.State.Transact(context.Background(), input)
	if err != nil {
		t.Fatal("authentic parent control did not commit through the real store", err)
	}
	if commit.Operation.Status != "succeeded" || commit.Operation.LifeID != f.Lane.LifeID {
		t.Fatal("control lost its child target")
	}
	replay, err := f.State.Transact(context.Background(), input)
	if err != nil || !replay.Replayed || replay.LastSeq != commit.LastSeq {
		t.Fatal("parent control replay appended another decision", err)
	}
}

func TestItem3LaneEventFences(t *testing.T) {
	for _, control := range []string{"foreign-life", "foreign-lineage", "stale-cas", "missing-launch", "wrong-method", "actor-substitution"} {
		t.Run(control, func(t *testing.T) {
			f := fx.ControlledChild(t)
			input := item3Control(t, f)
			before, err := f.State.Events(context.Background(), f.Execution, api.EventTailRequest{LifeID: f.Lane.LifeID})
			if err != nil {
				t.Fatal(err)
			}
			switch control {
			case "foreign-life":
				input.Events[0].LifeID = fx.ID(t)
			case "foreign-lineage":
				input.Events[0].RootLifeID = fx.ID(t)
			case "stale-cas":
				input.Compare[0].Generation++
			case "missing-launch":
				input.Scope.LaunchID = ""
			case "wrong-method":
				input.Scope.Request.Method = "records.append"
			case "actor-substitution":
				input.Events[0].Actor = f.Execution.Actor
			}
			if _, err := f.State.Transact(context.Background(), input); err == nil {
				t.Fatal("public lane event admitted " + control)
			}
			after, err := f.State.Events(context.Background(), f.Execution, api.EventTailRequest{LifeID: f.Lane.LifeID})
			if err != nil || !reflect.DeepEqual(before.Events, after.Events) {
				t.Fatal("refused lane event changed the committed journal", err)
			}
			lane, err := f.State.Lane(context.Background(), f.Execution, f.Reservation.Target)
			if err != nil || lane.Generation != f.Lane.Generation || lane.Run != f.Lane.Run || lane.LaunchID != f.Lane.LaunchID {
				t.Fatal("refused event changed the actual lane", err)
			}
		})
	}
}

func TestItem3LaneMailCommit(t *testing.T) {
	f := fx.ControlledChild(t)
	f.Human.Connection.(*fx.Connection).Endpoint.ContractRevision = api.ContractRevision
	service, err := messaging.New(messaging.Dependencies{Store: f.State, Clock: fx.Clock{}})
	if err != nil {
		t.Fatal(err)
	}
	content := f.Retain(t, "report", []byte("authentic parent mail "+string(fx.ID(t))), f.Human.Actor, f.Human.Actor.LifeID)
	request := api.MailSendRequest{RecipientLifeID: f.Lane.LifeID, Content: content}
	ctx := item3Admit(t, f, "mail.send", request)
	first, err := service.MailSend(ctx, f.Human, request)
	if err != nil {
		t.Fatal("authenticated parent mail did not commit through the real store", err)
	}
	if first.Sender != f.Human.Actor || first.RecipientLifeID != f.Lane.LifeID || first.Status != "queued" || first.QueuedSeq == 0 || first.Content != content {
		t.Fatal("mail commit lost its actual requester, recipient or immutable input")
	}
	second, err := service.MailSend(context.Background(), f.Human, request)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("mail replay changed its durable result", err)
	}
	page, err := f.State.Events(context.Background(), f.Execution, api.EventTailRequest{LifeID: f.Human.Actor.LifeID})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range page.Events {
		if event.Kind == "mail.queued" {
			count++
			if event.Actor != first.Sender || event.RequestedBy != first.Sender || event.Origin != "service" || event.Seq != first.QueuedSeq {
				t.Fatal("queue event borrowed another principal")
			}
		}
	}
	if count != 1 {
		t.Fatalf("mail replay appended %d queue events", count)
	}
}

func TestItem3LaneReportCommit(t *testing.T) {
	f := fx.ControlledChild(t)
	f.Human = f.LaneScope(t)
	f.Human.Connection.(*fx.Connection).Endpoint.ContractRevision = api.ContractRevision
	service, err := messaging.New(messaging.Dependencies{Store: f.State, Clock: fx.Clock{}})
	if err != nil {
		t.Fatal(err)
	}
	content := f.Retain(t, "report", []byte("direct child report "+string(fx.ID(t))), f.Human.Actor, f.Lane.LifeID)
	f.Opened(t)
	request := api.ReportRequest{Content: content, Artifacts: []api.BlobRef{}}
	ctx := item3Admit(t, f, "report.submit", request)
	mail, err := service.ReportSubmit(ctx, f.Human, request)
	if err != nil {
		t.Fatal("direct child report could not commit its actual parent relation", err)
	}
	page, err := f.State.Events(context.Background(), f.Execution, api.EventTailRequest{LifeID: f.Lane.LifeID})
	if err != nil {
		t.Fatal(err)
	}
	queued, report := api.Sequence(0), api.Sequence(0)
	for _, event := range page.Events {
		if event.Kind == "mail.queued" {
			queued = event.Seq
		}
		if event.Kind == "report.submitted" {
			report = event.Seq
		}
	}
	if queued == 0 || report <= queued || mail.QueuedSeq != queued {
		t.Fatal("report changed its original causal mail queue sequence")
	}
	if replay, err := service.ReportSubmit(context.Background(), f.Human, request); err != nil || !reflect.DeepEqual(replay, mail) {
		t.Fatal("report replay changed the committed mail", err)
	}
}

func TestItem3RelatedProjectionPrivacy(t *testing.T) {
	f := fx.ControlledChild(t)
	child := f.LaneScope(t)
	parent, err := f.State.Relation(context.Background(), child, f.Lane.ParentLifeID)
	if err != nil || parent.LifeID != f.Lane.ParentLifeID || parent.Level <= f.Lane.Level {
		t.Fatal("D7 could not resolve the authentic direct starter", err)
	}
	if _, err := f.State.Lane(context.Background(), child, api.LifeRef{LifeID: parent.LifeID}); err == nil {
		t.Fatal("relation resolution widened public raw lane visibility")
	}
	if _, err := f.State.Relation(context.Background(), child, fx.ID(t)); err == nil {
		t.Fatal("relation projection returned an invented life")
	}
}
