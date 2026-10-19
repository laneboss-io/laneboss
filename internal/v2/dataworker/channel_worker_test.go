package dataworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// These byte-backed ports establish worker behavior only. They do not supply
// a native helper, authenticated peer or installed-service delivery proof.
type channelPorts struct {
	*archivePorts
	selected api.ChannelContext
}

func (p *channelPorts) ChannelContext(_ context.Context, scope api.Scope, request api.WorkerInputRequest) (api.ChannelContext, error) {
	if scope.Actor.Kind != "worker" || request.LeaseID != p.input.LeaseID {
		return api.ChannelContext{}, errors.New("foreign channel fixture context")
	}
	return p.selected, nil
}

func (p *channelPorts) ChannelReceipt(_ context.Context, scope api.Scope, request api.ChannelReceiptRequest) (api.BlobRef, error) {
	if scope.Actor.Kind != "worker" || request.LeaseID != p.input.LeaseID || len(request.Bytes) == 0 {
		return api.BlobRef{}, errors.New("foreign channel fixture receipt")
	}
	ref := api.BlobRef{ID: api.ID("receipt-" + string(manifest.Hash(request.Bytes))), Class: "channel_receipt", Bytes: int64(len(request.Bytes)), SHA256: manifest.Hash(request.Bytes)}
	p.objects[ref.ID] = append([]byte{}, request.Bytes...)
	return ref, nil
}

func TestChannelWorker(t *testing.T) {
	base, rawPorts := archiveFixture(t, "valid")
	p := base.Principal
	job, payload := httpJob()
	job.Lease = p.Lease
	job.Lease.Kind, job.Lease.RuntimeManifest = "channel", job.Runtime.Manifest
	input := api.ChannelSendInput{Schema: "laneboss.channel-input.v2", LeaseID: job.Lease.ID, MailID: job.MailID, ChannelID: job.ChannelID,
		ChannelGeneration: job.ChannelGeneration, DestinationID: job.DestinationID, ProviderIdempotencyKey: job.ProviderIdempotencyKey,
		Payload: job.Payload, Content: job.Content, Artifacts: job.Artifacts}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	job.Lease.Input = api.BlobRef{ID: "channel-input", Class: "channel_input", Bytes: int64(len(raw)), SHA256: manifest.Hash(raw)}
	p.Lease = job.Lease
	p.Claim.Record.Effect.Worker, p.Claim.Record.Effect.Channel = nil, &job
	rawPorts.input = api.WorkerJobInput{Schema: "laneboss.worker-input.v2", StageID: p.StageID, LeaseID: p.Lease.ID, Kind: "channel",
		OperationID: p.Lease.OperationID, EffectID: p.Lease.EffectID, Input: p.Lease.Input, Bytes: raw}
	rawPorts.objects[p.Lease.Input.ID], rawPorts.objects[job.Payload.ID] = raw, payload
	ports := &channelPorts{archivePorts: rawPorts, selected: api.ChannelContext{Job: job,
		Destination: api.ChannelDestination{ID: job.DestinationID, Transport: "http-json", EndpointID: "endpoint", CredentialHandle: "credential"},
		Credential:  api.WorkerCredential{Name: "channel", SourceHandle: "credential", Version: "v1", Delivery: "env", Target: "CHANNEL_CRED"}}}
	posts, reads := 0, 0
	var sent []byte
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer component-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
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
		if err := json.NewEncoder(w).Encode(channelAck{Receipt: "actual-receipt", Digest: manifest.Hash(sent)}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	materialReads := 0
	worker := ChannelWorkerJob{Principal: p, Scope: base.Scope, Bootstrap: ports, Channel: ports, Read: ports.read, Clock: base.Clock,
		Material: func(selected api.WorkerCredential) ([]byte, error) {
			if selected != ports.selected.Credential {
				return nil, errors.New("worker selected another credential")
			}
			materialReads++
			return json.Marshal(map[string]string{"endpoint_id": "endpoint", "url": server.URL, "token": "component-token"})
		}}
	receipt, err := RunInternalJob(context.Background(), p.Endpoint.Config,
		[]string{"--binding", "/runtime/laneboss-worker.json", "--lease", string(p.Lease.ID)}, worker)
	if err != nil {
		t.Fatal("fixed channel entry unavailable", err)
	}
	var result api.ChannelSendEvidence
	if err := api.DecodeObject(ports.result, &result); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if api.ValidateChannelSendEvidence(job, result) != nil || result.Outcome != "confirmed" || receipt.Result.SHA256 != manifest.Hash(ports.result) ||
		posts != 1 || reads != 1 || materialReads != 1 || ports.submissions != 1 || !bytes.Equal(sent, payload) {
		t.Fatal("worker omitted actual selected credential, payload, acknowledgement or read-back")
	}
	if result.Response == nil || result.ReadBack == nil || len(ports.objects[result.Response.ID]) == 0 || len(ports.objects[result.ReadBack.Response.ID]) == 0 ||
		bytes.Contains(ports.result, []byte("component-token")) || bytes.Contains(ports.result, []byte(server.URL)) {
		t.Fatal("worker result lost measured responses or retained credential material")
	}
}
