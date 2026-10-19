package dataworker

import (
	"context"
	"encoding/json"
	"os"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
)

type ChannelWorkerJob struct {
	Principal api.WorkerPrincipal
	Scope     api.Scope
	Bootstrap api.WorkerBootstrap
	Channel   api.ChannelBootstrap
	Read      archivejob.ReadObject
	Clock     api.Clock
	Material  func(api.WorkerCredential) ([]byte, error)
}

// RunChannelWorker executes only after the native worker bootstrap. In
// production, Material reads the one projected env/file credential here.
func RunChannelWorker(ctx context.Context, job ChannelWorkerJob) (api.WorkerResultReceipt, error) {
	p := job.Principal
	if p.Lease.Kind != "channel" || job.Scope.Actor != p.Record.Actor || job.Scope.LaunchID != p.Record.ID || job.Scope.Config != p.Endpoint.Config ||
		missing(job.Bootstrap) || missing(job.Channel) || missing(job.Clock) || job.Read == nil || job.Material == nil {
		return api.WorkerResultReceipt{}, lstate.Error(api.CodePrerequisite, "channel requires its native job bootstrap and selected credential projection")
	}
	if err := api.ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, api.WorkerInputRead, job.Clock.Now()); err != nil {
		return api.WorkerResultReceipt{}, err
	}
	input, err := job.Bootstrap.WorkerInput(ctx, job.Scope, api.WorkerInputRequest{LeaseID: p.Lease.ID})
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	if err := api.ValidateWorkerInput(p, input, job.Clock.Now()); err != nil {
		return api.WorkerResultReceipt{}, err
	}
	selected, err := job.Channel.ChannelContext(ctx, job.Scope, api.WorkerInputRequest{LeaseID: p.Lease.ID})
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	var sealed api.ChannelSendInput
	if err := api.DecodeObject(input.Bytes, &sealed); err != nil {
		return api.WorkerResultReceipt{}, err
	}
	if err := api.ValidateChannelInput(selected.Job, sealed); err != nil {
		return api.WorkerResultReceipt{}, err
	}
	if selected.Job.Lease.ID != p.Lease.ID || selected.Job.Lease.Input != p.Lease.Input || selected.Destination.ID != selected.Job.DestinationID ||
		selected.Credential.SourceHandle != selected.Destination.CredentialHandle || selected.Destination.Transport != "http-json" {
		return api.WorkerResultReceipt{}, lstate.Error(api.CodeUnsupported, "channel requires its enrolled HTTP JSON destination and selected credential")
	}
	material, err := job.Material(selected.Credential)
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	defer clear(material)
	var credential struct {
		Endpoint api.ID `json:"endpoint_id"`
		URL      string `json:"url"`
		Token    string `json:"token"`
	}
	if json.Unmarshal(material, &credential) != nil || credential.Endpoint != selected.Destination.EndpointID {
		return api.WorkerResultReceipt{}, lstate.Error(api.CodePrerequisite, "channel credential must name its enrolled endpoint and provider URL")
	}
	payload, err := readWorkerObject(ctx, job.Read, selected.Job.Payload)
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	keep := func(ctx context.Context, raw []byte) (api.BlobRef, error) {
		return job.Channel.ChannelReceipt(ctx, job.Scope, api.ChannelReceiptRequest{LeaseID: p.Lease.ID, Bytes: raw})
	}
	result, err := ExchangeChannel(ctx, ChannelHTTP{Endpoint: credential.Endpoint, URL: credential.URL, Token: credential.Token}, selected.Job, payload, selected.ReadOnly, keep, job.Clock)
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	raw, err := json.Marshal(result)
	if err == nil {
		raw, err = api.CanonicalJSON(raw)
	}
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	submission := api.WorkerResultSubmission{LeaseID: p.Lease.ID, ExpectedGeneration: p.Lease.Generation, InputSHA256: p.Lease.Input.SHA256, Result: raw}
	receipt, err := job.Bootstrap.WorkerResult(ctx, job.Scope, submission)
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	return receipt, api.ValidateWorkerResult(p, submission, receipt, job.Clock.Now())
}

func nativeChannelMaterial(p api.WorkerPrincipal) func(api.WorkerCredential) ([]byte, error) {
	return func(selected api.WorkerCredential) ([]byte, error) {
		if os.Geteuid() == 0 || uint32(os.Geteuid()) != p.Peer.HostUID || uint32(os.Getegid()) != p.Peer.HostGID ||
			uint32(os.Geteuid()) == p.Endpoint.ServiceUID {
			return nil, lstate.Error(api.CodeForbidden, "channel material is available only inside its distinct native worker")
		}
		switch selected.Delivery {
		case "env":
			value, found := os.LookupEnv(selected.Target)
			if !found {
				return nil, lstate.Error(api.CodePrerequisite, "channel selected environment credential was not projected")
			}
			return []byte(value), nil
		case "file":
			return os.ReadFile(selected.Target)
		}
		return nil, lstate.Error(api.CodeUnsupported, "channel credential delivery is unsupported")
	}
}
