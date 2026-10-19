package identity

import (
	"context"
	"reflect"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/judge/job"
)

// The private worker endpoint calls the existing authenticator with its closed
// WorkerOperation. These names are never registered as public RPC Methods.
func (s *Service) authorizeWorker(ctx context.Context, scope api.Scope, request api.Request) error {
	operation := api.WorkerOperation(request.Method)
	switch operation {
	case api.WorkerPrincipalRead, api.WorkerInputRead, api.WorkerObjectRead, api.WorkerResultAppend, api.WorkerArchivePart, api.WorkerCaptureState, api.WorkerCaptureAppend, api.WorkerCredentialInject, api.WorkerChannelContext, api.WorkerChannelReceipt, api.WorkerJudgeContext, api.WorkerJudgeRetain:
	default:
		return refusal(api.CodeForbidden, "worker endpoint cannot invoke public or unknown operations")
	}
	if request.Proof != nil {
		return refusal(api.CodeForbidden, "worker endpoint cannot carry human proof")
	}
	if err := s.verifyScope(ctx, scope); err != nil {
		return err
	}
	if nilDependency(scope.Frame) {
		return refusal(api.CodeUnauthenticated, "worker operation requires its verified frame")
	}
	if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
		return err
	}
	var framed api.Request
	if api.DecodeObject(scope.Frame.Bytes(), &framed) != nil || !reflect.DeepEqual(framed, request) {
		return refusal(api.CodeIntegrity, "worker request differs from its verified frame")
	}
	digest, err := api.RequestDigest(request)
	if err != nil || digest != request.RequestSHA256 || !validID(request.RequestID) || len(request.RequestID) < 22 ||
		!validID(request.IdempotencyKey) || len(request.IdempotencyKey) < 22 {
		return refusal(api.CodeInvalid, "invalid private worker request metadata")
	}
	principal, err := s.workerPrincipal(ctx, scope.Connection, operation)
	if err != nil {
		return err
	}
	switch operation {
	case api.WorkerArchivePart:
		var part archivejob.PartRequest
		if api.DecodeObject(request.Params, &part) != nil || part.LeaseID != principal.Lease.ID || len(part.Bytes) == 0 || len(part.Bytes) > api.MaxChunkBytes || part.Index >= 65536 {
			return refusal(api.CodeForbidden, "archive part differs from its current leased job")
		}
	case api.WorkerInputRead, api.WorkerChannelContext, api.WorkerJudgeContext:
		var input api.WorkerInputRequest
		if api.DecodeObject(request.Params, &input) != nil || input.LeaseID != principal.Lease.ID {
			return refusal(api.CodeForbidden, "worker input selector differs from its current leased job")
		}
	case api.WorkerResultAppend:
		var result api.WorkerResultSubmission
		if api.DecodeObject(request.Params, &result) != nil || result.LeaseID != principal.Lease.ID ||
			result.ExpectedGeneration != principal.Lease.Generation || principal.Lease.Generation >= 1<<53-1 ||
			result.InputSHA256 != principal.Lease.Input.SHA256 || len(result.Result) == 0 || len(result.Result) > api.MaxFrameBytes {
			return refusal(api.CodeForbidden, "worker result differs from its current lease, input or revision")
		}
	case api.WorkerJudgeRetain:
		var input job.RetainRequest
		if api.DecodeObject(request.Params, &input) != nil || input.LeaseID != principal.Lease.ID || len(input.Bytes) == 0 ||
			len(input.Bytes) > 1<<20 || input.Class != "judge_request" && input.Class != "judge_raw" {
			return refusal(api.CodeForbidden, "judge retention differs from its current leased worker")
		}
	case api.WorkerChannelReceipt:
		var input api.ChannelReceiptRequest
		if api.DecodeObject(request.Params, &input) != nil || input.LeaseID != principal.Lease.ID || len(input.Bytes) == 0 || len(input.Bytes) > api.MaxChunkBytes {
			return refusal(api.CodeForbidden, "channel receipt differs from its current leased worker")
		}
	}
	return nil
}

func (s *Service) workerPrincipal(ctx context.Context, connection api.ConnectionContext, operation api.WorkerOperation) (api.WorkerPrincipal, error) {
	var empty api.WorkerPrincipal
	if nilDependency(connection) || nilDependency(connection.Peer()) || connection.Binding().Class != api.EndpointWorker {
		return empty, refusal(api.CodeUnauthenticated, "worker mapping requires its native verified connection")
	}
	if err := connection.Peer().Alive(ctx); err != nil {
		return empty, err
	}
	facts, err := connection.Peer().Facts(ctx)
	if err != nil {
		return empty, err
	}
	endpoint := connection.Binding()
	principal, err := s.deps.Store.WorkerBinding(ctx, endpoint, facts)
	if err != nil {
		return empty, err
	}
	if operation == "" {
		operation = api.WorkerInputRead
		if principal.Lease.Kind == "capture" {
			operation = api.WorkerCaptureState
		}
	}
	if err := api.ValidateWorkerPrincipal(principal, endpoint, facts, operation, s.deps.Clock.Now()); err != nil {
		return empty, err
	}
	boot, _, _ := strings.Cut(facts.ProcessGeneration, ":")
	if principal.Record.Actor.LifeID != "" || principal.Record.Target != principal.Lease.Target || principal.BootID != boot {
		return empty, refusal(api.CodeContainmentUnknown, "worker boot or target differs from native authority")
	}
	containment, err := s.deps.Registry.ResolveContainment(ctx, facts, endpoint)
	if err != nil {
		return empty, err
	}
	if containment.Revoked || containment.Config != endpoint.Config || containment.Backend != endpoint.Backend ||
		containment.Target != principal.Lease.Target || containment.BootID != principal.BootID || containment.Generation != principal.AllocationGeneration ||
		containment.Lease.ID != principal.Record.UIDLeaseID || containment.Lease.UID != facts.HostUID || containment.Lease.GID != facts.HostGID ||
		containment.Lease.ContainmentID != principal.Record.ContainmentID || containment.Lease.EndpointGeneration != endpoint.EndpointGeneration {
		return empty, refusal(api.CodeContainmentUnknown, "worker allocation differs from the live helper registry")
	}
	grants, err := s.deps.Store.Grants(ctx, principal.Lease.GrantSetID)
	if err != nil {
		return empty, err
	}
	expires, expiryErr := utcTime(grants.ExpiresAt)
	if expiryErr != nil || !s.deps.Clock.Now().Before(expires) || grants.Revoked || grants.Generation == 0 ||
		!validID(grants.ID) || !validDigest(grants.SHA256) || grants.PolicyGeneration == 0 ||
		grants.ID != principal.Lease.GrantSetID || grants.LifeID != principal.Lease.Target.LifeID ||
		grants.SHA256 != principal.Record.GrantsSHA256 || grants.PolicyGeneration != principal.Record.PolicyGeneration {
		return empty, refusal(api.CodeForbidden, "worker issued grants are stale or revoked")
	}
	return principal, nil
}
