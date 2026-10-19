package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type usageMeasurement struct {
	Principal api.WorkerPrincipal
	Producer  api.WorkerPrincipal
	Profile   bstate.Profile
	Input     api.WorkerJobInput
	Output    UsageCommandResult
	Receipt   api.WorkerResultReceipt
	Raw       api.BlobRef
}

// Every observer borrows the original live worker frames. The result remains
// blocked until the consuming observer has validated and retained its evidence.
func (s *Service) withUsageMeasurement(ctx context.Context, scope api.Scope, request api.UsageWindowRequest, consume func(usageMeasurement) error) (resultErr error) {
	if err := wire.Context(ctx); err != nil {
		return err
	}
	if err := s.usageReadScope(ctx, scope); err != nil {
		return err
	}
	profile, err := s.usageProfile(ctx, request)
	if err != nil {
		return err
	}
	if wire.Nil(s.deps.UsageJobs) || wire.Nil(s.deps.Bootstrap) {
		return wire.Error(api.CodePrerequisite, "outside usage requires the installed confined job and worker bootstrap adapters")
	}
	workerScope, err := s.deps.UsageJobs.StartUsage(ctx, scope, request)
	if err != nil {
		return err
	}
	if completion, ok := s.deps.UsageJobs.(interface {
		FinishUsage(context.Context, api.ID) error
	}); ok && !wire.Nil(workerScope.Connection) {
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
			defer cancel()
			resultErr = errors.Join(resultErr, completion.FinishUsage(cleanup, workerScope.Connection.Binding().WorkerLeaseID))
		}()
	}
	p, err := s.mappedWorker(ctx, workerScope, api.WorkerInputRead)
	if err != nil {
		return err
	}
	if p.Lease.Kind != "usage" || p.Lease.Target != request.Target || p.Lease.OperationID != request.OperationID || p.Lease.RuntimeManifest != request.RuntimeManifest || p.Claim.Record.Effect.Worker == nil {
		return wire.Error(api.CodeForbidden, "outside usage job belongs to another cause or runtime")
	}
	if err := s.usageGrants(ctx, p, profile, request); err != nil {
		return err
	}
	job, err := s.deps.Bootstrap.WorkerInput(ctx, workerScope, api.WorkerInputRequest{LeaseID: p.Lease.ID})
	if err != nil {
		return err
	}
	if err := api.ValidateWorkerInput(p, job, s.deps.Clock.Now()); err != nil {
		return err
	}
	var input UsageInput
	if err := api.DecodeObject(job.Bytes, &input); err != nil {
		return err
	}
	if input.Schema != "laneboss.usage-input.v1" || input.Request != request || input.VendorProfile != profile.Usage.VendorProfile || input.ProfileGeneration != profile.Generation || input.Source != profile.Source {
		return wire.Error(api.CodeForbidden, "outside usage job changed its protected from-profile input")
	}
	runtimeBytes, err := s.protectedObjectFor(ctx, request.RuntimeManifest, "", true)
	if err != nil {
		return err
	}
	var manifest api.RuntimeManifest
	if err := api.DecodeObject(runtimeBytes, &manifest); err != nil {
		return err
	}
	if manifest.Schema != "laneboss.runtime.v2" || manifest.Generation == 0 || manifest.Bootstrap != p.Claim.Record.Effect.Worker.Executable {
		return wire.Error(api.CodeForbidden, "outside usage job lost its pinned worker bootstrap")
	}
	pinned := false
	for _, object := range manifest.Objects {
		if object.ID == request.Executable.ID && object.Content.SHA256 == request.Executable.SHA256 {
			pinned = true
		}
	}
	if !pinned {
		return wire.Error(api.CodeForbidden, "outside usage executable is absent from the protected runtime")
	}
	output, err := s.deps.UsageJobs.RunUsage(ctx, p.StageID)
	if err != nil {
		return err
	}
	if output.ExitCode != 0 {
		return wire.Error(api.CodeUnavailable, "outside usage command did not exit successfully")
	}
	producer, err := s.mappedWorker(ctx, output.Scope, api.WorkerResultAppend)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(producer, p) {
		return wire.Error(api.CodeConflict, "outside usage producer claim changed during the command")
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		return wire.Error(api.CodeIntegrity, "cannot encode outside usage command result")
	}
	encoded, err = api.CanonicalJSON(encoded)
	if err != nil {
		return err
	}
	submission := api.WorkerResultSubmission{LeaseID: p.Lease.ID, ExpectedGeneration: p.Lease.Generation, InputSHA256: p.Lease.Input.SHA256, Result: encoded}
	receipt, err := s.deps.Bootstrap.WorkerResult(ctx, output.Scope, submission)
	if err != nil {
		return err
	}
	if err := api.ValidateWorkerResult(p, submission, receipt, s.deps.Clock.Now()); err != nil {
		return err
	}
	acknowledged, err := s.protectedObject(ctx, receipt.Result, p.Lease.OperationID)
	if err != nil {
		return err
	}
	ackMeta, err := s.deps.Store.ObjectMetadata(ctx, s.deps.ServiceScope, receipt.Result.ID)
	if err != nil {
		return err
	}
	if ackMeta.ACL.Owner != p.Record.Actor || ackMeta.ACL.LifeID != p.Lease.Target.LifeID {
		return wire.Error(api.CodeForbidden, "outside usage acknowledgement belongs to another producer")
	}
	if !bytes.Equal(acknowledged, encoded) {
		return wire.Error(api.CodeIntegrity, "outside usage result acknowledgement changed its bytes")
	}
	raw, err := s.retainUsage(ctx, p, credentialID("usage-raw", p.StageID, p.Lease.ID), "usage_raw", output.Raw, []api.BlobRef{job.Input, receipt.Result})
	if err != nil {
		return err
	}
	fresh, err := s.mappedWorker(ctx, output.Scope, api.WorkerResultAppend)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(fresh, producer) {
		return wire.Error(api.CodeConflict, "outside usage claim changed before returning its retained envelope")
	}
	latest, err := s.usageProfile(ctx, request)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(latest, profile) {
		return wire.Error(api.CodeConflict, "outside usage enrollment changed during measurement")
	}
	if err := s.usageGrants(ctx, fresh, latest, request); err != nil {
		return err
	}
	return consume(usageMeasurement{Principal: p, Producer: fresh, Profile: latest, Input: job, Output: output, Receipt: receipt, Raw: raw})
}
