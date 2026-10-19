package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	clientwire "laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/judge/job"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

// RunInternal is a trusted worker mode, never an arbitrary command endpoint.
// A label/argument cannot replace an installed binding and authenticated lease.
func RunInternal(ctx context.Context, config string, args []string) (resultErr error) {
	if config == "" || len(args) != 4 || args[0] != "--binding" || args[1] != "/runtime/laneboss-worker.json" || args[2] != "--lease" || !wire.ValidID(api.ID(args[3])) {
		return problem(api.CodeInvalid, "internal judge requires an installed job lease")
	}
	if err := ctx.Err(); err != nil {
		return problem(api.CodeCancelled, "internal judge cancelled before authentication")
	}
	connection, err := client.OpenWorker(ctx, client.Options{Config: config, BindingFile: args[1]}, api.ID(args[3]))
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, connection.Close()) }()
	p := connection.Principal()
	if p.Lease.Kind != "judge" || os.Geteuid() == 0 || uint32(os.Geteuid()) == p.Endpoint.ServiceUID {
		return problem(api.CodeForbidden, "judge requires its distinct native worker process")
	}
	sealed, err := clientwire.ReadWorkerInput(p.Lease.Input)
	if err != nil {
		return err
	}
	scope := api.Scope{Config: config, Actor: p.Record.Actor, LaunchID: p.Record.ID, EndpointGeneration: p.Record.EndpointGeneration, PolicyGeneration: p.Record.PolicyGeneration}
	_, err = RunNativeJob(ctx, NativeJob{Principal: p, Scope: scope, Bootstrap: connection, Channel: connection,
		Input: sealed, Clock: nativeClock{}})
	return err
}

type nativeClock struct{}

func (nativeClock) Now() time.Time { return time.Now() }

type NativeJob struct {
	Principal api.WorkerPrincipal
	Scope     api.Scope
	Bootstrap api.WorkerBootstrap
	Channel   job.Bootstrap
	Input     []byte
	Clock     api.Clock
}

// RunNativeJob uses only its native principal and immutable service input.
// No source path, provider, credential or execution claim comes from argv.
func RunNativeJob(ctx context.Context, j NativeJob) (api.WorkerResultReceipt, error) {
	p := j.Principal
	if p.Lease.Kind != "judge" || wire.Nil(j.Bootstrap) || wire.Nil(j.Channel) || wire.Nil(j.Clock) ||
		j.Scope.Actor != p.Record.Actor || j.Scope.LaunchID != p.Record.ID {
		return api.WorkerResultReceipt{}, problem(api.CodePrerequisite, "judge native bootstrap is incomplete")
	}
	if err := api.ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, api.WorkerInputRead, j.Clock.Now()); err != nil {
		return api.WorkerResultReceipt{}, err
	}
	input, err := j.Bootstrap.WorkerInput(ctx, j.Scope, api.WorkerInputRequest{LeaseID: p.Lease.ID})
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	if err := api.ValidateWorkerInput(p, input, j.Clock.Now()); err != nil {
		return api.WorkerResultReceipt{}, err
	}
	if !bytes.Equal(input.Bytes, j.Input) {
		return api.WorkerResultReceipt{}, problem(api.CodeIntegrity, "judge inherited input differs from its live service input")
	}
	var execution api.JudgeExecution
	if api.DecodeObject(input.Bytes, &execution) != nil || execution.Acquired || execution.ID != p.Lease.EffectID ||
		execution.ClaimID != p.Claim.ClaimID || execution.Deadline != p.Lease.ExpiresAt || execution.Intent.Target != p.Lease.Target {
		return api.WorkerResultReceipt{}, problem(api.CodeIntegrity, "judge native execution changed its original lease")
	}
	setup, err := j.Channel.JudgeSetup(ctx, j.Scope, api.WorkerInputRequest{LeaseID: p.Lease.ID})
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	defer clear(setup.Credential)
	if setup.Config != execution.Request.Config {
		return api.WorkerResultReceipt{}, problem(api.CodeIntegrity, "judge native setup changed its approved pins")
	}
	options := job.Options(setup)
	var fit api.TokenFit
	measure := options.Fit
	options.Fit = func(ctx context.Context, body []byte) (api.TokenFit, error) {
		actual, err := measure(ctx, body)
		fit = actual
		return actual, err
	}
	options.Retain = func(ctx context.Context, class string, raw []byte) (api.BlobRef, error) {
		return j.Channel.JudgeRetain(ctx, j.Scope, job.RetainRequest{LeaseID: p.Lease.ID, Class: class, Bytes: raw})
	}
	if setup.ProviderSocket != "" {
		if setup.ProviderSocket != "/runtime/judge-provider.sock" {
			return api.WorkerResultReceipt{}, problem(api.CodeForbidden, "judge native provider socket changed")
		}
		options.Client = &http.Client{Transport: &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", setup.ProviderSocket)
		}}}
	}
	adapter, err := wire.New(options)
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	reply, err := adapter.Evaluate(ctx, execution.Request)
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	if reserved, err := time.Parse(time.RFC3339Nano, string(execution.ReservedAt)); err == nil {
		elapsed := j.Clock.Now().Sub(reserved).Milliseconds()
		if elapsed < 0 {
			return api.WorkerResultReceipt{}, problem(api.CodeIntegrity, "judge native observation predates its reservation")
		}
		reply.LatencyMS = elapsed
	}
	// Preserve all observed fit fields, including explicit failed fit reasons.
	if !reflect.DeepEqual(reply.DeploymentSHA256, setup.Config.DeploymentSHA256) {
		return api.WorkerResultReceipt{}, problem(api.CodeIntegrity, "judge reply changed deployment")
	}
	raw, err := json.Marshal(job.Result{Reply: reply, Fit: fit})
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	submission := api.WorkerResultSubmission{LeaseID: p.Lease.ID, ExpectedGeneration: p.Lease.Generation, InputSHA256: p.Lease.Input.SHA256, Result: raw}
	receipt, err := j.Bootstrap.WorkerResult(ctx, j.Scope, submission)
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	return receipt, api.ValidateWorkerResult(p, submission, receipt, j.Clock.Now())
}
