//go:build linux

package store_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/messaging"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Native allocation/process observations here are explicit component inputs.
// Identity commits, private input/receipt/result writes and replay use SQLite.
func TestChannelWorkerStore(t *testing.T) {
	f, _ := channelReady(t)
	var input api.MailSendRequest
	if err := api.DecodeObject(f.Human.Request.Params, &input); err != nil {
		t.Fatal(err)
	}
	f.Human.Connection.(*fx.Connection).Endpoint.ContractRevision = api.ContractRevision
	ctx := item3Admit(t, f, "mail.send", input)
	mail, err := messaging.New(messaging.Dependencies{Store: f.State, Clock: f.Deps.Clock, Preparer: channelPrep{f}})
	if err != nil {
		t.Fatal(err)
	}
	queued, err := mail.MailSend(ctx, f.Human, input)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var job api.ChannelJob
	for _, effect := range pending {
		if effect.Channel != nil && effect.Channel.MailID == queued.ID {
			job = *effect.Channel
		}
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: job.Lease.EffectID, ExpectedGeneration: 1,
		ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	actor := api.Actor{Kind: "worker", ID: fx.ID(t)}
	record := api.LaunchRecord{Kind: "worker", ID: fx.ID(t), Config: f.Deps.Config, Target: job.Lease.Target, Actor: actor,
		RootLifeID: f.Lane.RootLifeID, StarterChain: []api.ID{}, UIDLeaseID: fx.ID(t), HostUID: uint32(os.Geteuid()) + 1,
		ContainmentID: fx.ID(t), ProcessGeneration: "component:worker", GrantSetID: job.Lease.GrantSetID,
		GrantsSHA256: f.Plan.Inputs.Grants.SHA256, PolicyGeneration: 1, EndpointGeneration: 1}
	prepared := api.PreparedLaunch{ID: fx.ID(t), GateID: fx.ID(t), Target: record.Target, SpecSHA256: job.Lease.Input.SHA256,
		ContainmentID: record.ContainmentID, ProcessGeneration: record.ProcessGeneration, EndpointGeneration: 1}
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", Protocol: api.Protocol, APISchema: api.SchemaVersion, ContractRevision: api.ContractRevision,
		Config: f.Deps.Config, Class: api.EndpointWorker, InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()),
		Socket: "/runtime/laneboss-worker.sock", Backend: "linux-bwrap-landlock", ArtifactSHA256: job.Runtime.Executable.SHA256, ServiceVersion: "component",
		LaunchID: record.ID, Target: &record.Target, WorkerLeaseID: job.Lease.ID}
	lease := job.Lease
	lease.ConsumedBy = record.ID
	lease.Generation++
	cause := *claim.Record.Effect.Context
	cause.ID, cause.Kind, cause.Actor = fx.ID(t), api.InternalLifecycleEffect, f.Execution.Actor
	event := api.Event{Schema: api.SchemaVersion, ID: fx.ID(t), Config: f.Deps.Config, Kind: "identity.bound", Actor: f.Execution.Actor,
		RequestedBy: f.Human.Actor, OperationID: job.Lease.OperationID, RequestID: f.Human.Request.RequestID,
		LifeID: record.Target.LifeID, Run: record.Target.Run, RootLifeID: record.RootLifeID, StarterChain: []api.ID{}, Origin: "service", Payload: fx.JSON(t, record)}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Events: []api.Event{event},
		Writes: api.StateWrites{WorkerLeases: []api.WorkerLease{lease}, Endpoints: []api.EndpointProjection{{Binding: endpoint, Generation: 1}},
			IdentityBindings: []api.LaunchBindingRequest{{Record: record, Prepared: prepared}}}}); err != nil {
		t.Fatal("component worker identity did not commit", err)
	}
	facts := api.PeerFacts{HostUID: record.HostUID, HostGID: uint32(os.Getegid()) + 1, HostPID: os.Getpid(),
		ProcessGeneration: "component:connector", ContainmentID: record.ContainmentID}
	connection := &fx.Connection{Identity: fx.ID(t), Endpoint: endpoint, Verified: &fx.Peer{FactsValue: facts}}
	worker := api.Scope{Config: f.Deps.Config, Actor: actor, LaunchID: record.ID, EndpointGeneration: 1, PolicyGeneration: 1,
		Connection: connection, Frame: &fx.Frame{Raw: []byte("component private worker frame")}}
	if _, err := f.State.WorkerBinding(ctx, endpoint, facts); err != nil {
		t.Fatal("channel worker has no original committed principal", err)
	}
	sealed, err := f.State.WorkerInput(ctx, worker, api.WorkerInputRequest{LeaseID: lease.ID})
	if err != nil || sealed.Input != job.Lease.Input || fx.Digest(sealed.Bytes) != job.Lease.Input.SHA256 {
		t.Fatal("channel worker lost its exact sealed input", err)
	}
	payload, err := f.State.WorkerObject(ctx, worker, api.BlobReadRequest{ObjectID: job.Payload.ID, Limit: api.MaxChunkBytes})
	if err != nil || fx.Digest(payload.Data) != job.Payload.SHA256 {
		t.Fatal("channel payload reader changed the actual sealed bytes", err)
	}
	var sent []byte
	posts, reads := 0, 0
	var mu sync.Mutex
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPost {
			posts++
			var err error
			sent, err = io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
		} else {
			reads++
			if r.URL.Query().Get("key") != string(job.ProviderIdempotencyKey) || len(sent) == 0 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"receipt_id": "ack-" + string(fx.Digest(sent)), "payload_sha256": fx.Digest(sent)}); err != nil {
			t.Error(err)
		}
	}))
	defer provider.Close()
	evidence, err := dataworker.ExchangeChannel(ctx, dataworker.ChannelHTTP{URL: provider.URL, Client: provider.Client()}, job, payload.Data, false,
		func(ctx context.Context, raw []byte) (api.BlobRef, error) {
			return f.State.ChannelReceipt(ctx, worker, api.ChannelReceiptRequest{LeaseID: lease.ID, Bytes: raw})
		}, f.Deps.Clock)
	mu.Lock()
	measured := posts == 1 && reads == 1 && fx.Digest(sent) == job.Payload.SHA256
	mu.Unlock()
	if err != nil || evidence.Outcome != "confirmed" || !measured {
		t.Fatal("channel result omitted the actual provider exchange", err)
	}
	request := api.WorkerResultSubmission{LeaseID: lease.ID, ExpectedGeneration: lease.Generation, InputSHA256: lease.Input.SHA256, Result: fx.JSON(t, evidence)}
	before, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: record.Target.LifeID, Run: record.Target.Run})
	if err != nil {
		t.Fatal(err)
	}
	var beforeSeq api.Sequence
	for _, event := range before.Events {
		if event.Seq > beforeSeq {
			beforeSeq = event.Seq
		}
	}
	receipt, err := f.State.WorkerResult(ctx, worker, request)
	if err != nil || receipt.Result.SHA256 != fx.Digest(request.Result) || receipt.CommittedSeq <= beforeSeq {
		t.Fatal("channel result has no newly committed measured trace", err)
	}
	advanced, err := f.State.WorkerLease(ctx, f.Execution, lease.ID)
	if err != nil || advanced.Generation != receipt.Generation || advanced.ConsumedBy != lease.ConsumedBy {
		t.Fatal("channel result did not commit its acknowledged worker generation", err)
	}
	again, err := f.State.WorkerResult(ctx, worker, request)
	if err != nil || !reflect.DeepEqual(receipt, again) {
		t.Fatal("channel result replay changed the original receipt", err)
	}
	trace, err := f.State.Events(context.Background(), f.Execution, api.EventTailRequest{LifeID: record.Target.LifeID, Run: record.Target.Run, Since: beforeSeq})
	if err != nil || len(trace.Events) != 1 || trace.Events[0].Kind != "blob.committed" || trace.Events[0].Seq != receipt.CommittedSeq ||
		trace.Events[0].Actor != actor || trace.Events[0].OperationID != lease.OperationID {
		t.Fatal("channel acknowledgement was not its actual unique worker event", err)
	}
}
