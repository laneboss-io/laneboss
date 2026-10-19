//go:build linux

package store_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/messaging"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Enrollment is an explicit component prerequisite, not a D6 confirmation.
func channelReady(t *testing.T) (*fx.Fixture, api.ChannelPrepareRequest) {
	t.Helper()
	f := fx.New(t)
	executable := api.Executable{ID: fx.ID(t), Version: "component", SHA256: fx.Digest([]byte("channel executable"))}
	runtimeBytes := fx.JSON(t, api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: executable, Bootstrap: executable,
		Objects: []api.RuntimeObject{}, Bindings: []api.InstalledBinding{}})
	runtime := api.BlobRef{ID: fx.ID(t), Class: "manifest", Bytes: int64(len(runtimeBytes)), SHA256: fx.Digest(runtimeBytes)}
	channel := api.EnrolledChannel{ID: fx.ID(t), Config: f.Deps.Config, Generation: 1, ExpiresAt: fx.Expiry(),
		Source:       api.SourceRef{ID: fx.ID(t), Path: "channel.toml", SHA256: fx.Digest([]byte("enrolled channel")), Generation: 1},
		Runtime:      &api.ChannelRuntime{Executable: executable, Manifest: runtime, Reconcile: "provider_key"},
		Destinations: []api.ChannelDestination{{ID: fx.ID(t), Transport: "http-json", EndpointID: fx.ID(t), CredentialHandle: fx.ID(t), DeliverySemantics: "provider_key"}}}
	grants := f.Ceiling
	grants.Channels = []api.ChannelGrant{{ID: fx.ID(t), ChannelID: channel.ID, Delegate: true, ExpiresAt: grants.ExpiresAt}}
	grants.SHA256 = ""
	var err error
	grants.SHA256, err = manifest.HashValue(grants)
	if err != nil {
		t.Fatal(err)
	}
	f.Replace(t, "grants", grants.ID, grants.Generation, grants)
	f.Ceiling = grants
	f.Start.Grants.Channels = []api.ChannelDelegation{{ParentGrantID: grants.Channels[0].ID, ChannelID: channel.ID, Delegate: true, ExpiresAt: f.Start.Grants.Data[0].ExpiresAt}}
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	f.Opened(t)
	grants = f.Plan.Inputs.Grants
	cause := f.Intent(t, api.InternalOrgBootstrap)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause,
		Writes: api.StateWrites{Channels: []api.EnrolledChannel{channel}, Objects: []api.ObjectWrite{{ObjectKey: runtime.ID, Class: runtime.Class, Bytes: runtimeBytes,
			SHA256: runtime.SHA256, Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}}}}}); err != nil {
		t.Fatal(err)
	}
	f.Human = f.LaneScope(t)
	raw := []byte("channel text " + string(fx.ID(t)))
	content, err := f.State.RetainObject(context.Background(), f.Execution, api.RetainObjectRequest{Intent: f.Intent(t, api.InternalObjectRetain),
		Object: api.ObjectWrite{ObjectKey: fx.ID(t), Class: "report", Bytes: raw, SHA256: fx.Digest(raw), Origin: "service",
			ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Human.Actor, LifeID: f.Lane.LifeID, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	f.Admit(t, "mail.send", api.MailSendRequest{ChannelGrantID: grants.Channels[0].ID, Content: content})
	return f, api.ChannelPrepareRequest{OperationID: f.Receipt.Operation.ID, ChannelGrantID: grants.Channels[0].ID, DestinationID: channel.Destinations[0].ID}
}

func TestChannelPrep(t *testing.T) {
	f, request := channelReady(t)
	ctx := context.Background()
	job, err := f.State.PrepareChannelJob(ctx, f.Execution, request)
	if err != nil {
		t.Fatal("channel preparation unavailable", err)
	}
	if err := api.ValidateChannelJob(job); err != nil {
		t.Fatal(err)
	}
	again, err := f.State.PrepareChannelJob(ctx, f.Execution, request)
	if err != nil || !reflect.DeepEqual(job, again) {
		t.Fatal("staging changed the durable provider key", err)
	}
	if job.Lease.OperationID != request.OperationID || job.Lease.Target != f.Reservation.Target || job.Content.ID == "" {
		t.Fatal("staging lost original request identity")
	}
	if _, err := f.State.WorkerLease(ctx, f.Execution, job.Lease.ID); err == nil {
		t.Fatal("inert preparation published an executable lease")
	}
	mail, err := f.State.Mail(ctx, f.Execution, api.ListRequest{Limit: 200})
	if err != nil || len(mail.Messages) != 0 {
		t.Fatal("preparation queued mail before the public commit", err)
	}
	if result, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !result.OK {
		t.Fatal("inert preparation damaged store integrity", err)
	}
}

func TestChannelPrepWait(t *testing.T) {
	f, request := channelReady(t)
	request.DestinationID = fx.ID(t)
	_, err := f.State.PrepareChannelJob(context.Background(), f.Execution, request)
	var owning *api.Error
	if !errors.As(err, &owning) || owning.Code != api.CodePrerequisite || owning.Message != "channel destination is not enrolled" {
		t.Fatal("channel lost its unenrolled-destination prerequisite", err)
	}
}

type channelPrep struct{ f *fx.Fixture }

func (p channelPrep) PrepareChannelJob(ctx context.Context, scope api.Scope, request api.ChannelPrepareRequest) (api.ChannelJob, error) {
	if scope.Actor != p.f.Human.Actor || scope.Request.RequestID != p.f.Human.Request.RequestID {
		return api.ChannelJob{}, &api.Error{Code: api.CodeForbidden, Message: "component received a different caller"}
	}
	return p.f.State.PrepareChannelJob(ctx, p.f.Execution, request)
}

func TestChannelQueue(t *testing.T) {
	f, _ := channelReady(t)
	var input api.MailSendRequest
	if err := api.DecodeObject(f.Human.Request.Params, &input); err != nil {
		t.Fatal(err)
	}
	f.Human.Connection.(*fx.Connection).Endpoint.ContractRevision = api.ContractRevision
	ctx := item3Admit(t, f, "mail.send", input)
	service, err := messaging.New(messaging.Dependencies{Store: f.State, Clock: f.Deps.Clock, Preparer: channelPrep{f}})
	if err != nil {
		t.Fatal(err)
	}
	mail, err := service.MailSend(ctx, f.Human, input)
	if err != nil {
		t.Fatal("channel request did not publish its staged job", err)
	}
	if mail.ChannelGrantID != input.ChannelGrantID || mail.QueuedSeq == 0 || mail.Status != "queued" || mail.Sender != f.Human.Actor {
		t.Fatal("channel queue lost its authenticated sender")
	}
	again, err := service.MailSend(ctx, f.Human, input)
	if err != nil || !reflect.DeepEqual(mail, again) {
		t.Fatal("channel queue replay changed its original reply", err)
	}
	effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, effect := range effects {
		if effect.Channel != nil && effect.Channel.MailID == mail.ID {
			count++
			lease, err := f.State.WorkerLease(ctx, f.Execution, effect.Channel.Lease.ID)
			if err != nil || !reflect.DeepEqual(lease, effect.Channel.Lease) {
				t.Fatal("published channel has no exact durable worker lease", err)
			}
		}
	}
	if count != 1 {
		t.Fatal("channel queue did not publish exactly one effect", count)
	}
}
