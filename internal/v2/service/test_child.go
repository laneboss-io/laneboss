package service

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/reviewjob"
	"laneboss.io/laneboss/internal/v2/testjob"
)

func (s *Server) testCaller(ctx context.Context, caller api.Scope, request api.TestChildRequest) (api.Scope, error) {
	control, err := s.controlScope()
	if err != nil {
		return control, err
	}
	if caller.Request.Method != "grants.test-child" || caller.Config != s.options.Config || caller.Connection == nil || caller.Frame == nil ||
		caller.Actor.Kind != "human" && caller.Actor.Kind != "lane" {
		return control, serviceError(api.CodeUnauthenticated, "TestChild requires its original authenticated dispatcher call")
	}
	if err := caller.Frame.Verify(ctx, caller.Connection); err != nil {
		return control, err
	}
	var framed api.Request
	var original api.TestChildRequest
	if api.DecodeObject(caller.Frame.Bytes(), &framed) != nil || !reflect.DeepEqual(framed, caller.Request) ||
		api.DecodeObject(framed.Params, &original) != nil || !reflect.DeepEqual(original, request) {
		return control, serviceError(api.CodeForbidden, "TestChild changed its exact native request")
	}
	current, err := s.authenticateConnection(ctx, caller.Connection)
	if err != nil {
		return control, err
	}
	if current.Actor != caller.Actor || current.LaunchID != caller.LaunchID || current.Config != caller.Config ||
		current.EndpointGeneration != caller.EndpointGeneration || current.PolicyGeneration != caller.PolicyGeneration {
		return control, serviceError(api.CodeUnauthenticated, "TestChild caller changed since dispatch")
	}
	return control, s.deps.Authenticator.Authorize(ctx, caller, caller.Request)
}

// SubmitChildTest commits the real worker effect and human proof together,
// then drives that same job through the existing native worker coordinator.
func (s *Server) SubmitChildTest(ctx context.Context, call testjob.Call, request api.TestChildRequest, grants api.GrantSet) (api.Operation, error) {
	control, err := s.testCaller(ctx, call.Scope, request)
	if err != nil {
		return api.Operation{}, err
	}
	if call.Scope.Actor.Kind == "human" && (len(call.Guards) != 1 || call.Guards[0].Proof == nil || call.Scope.Request.Proof == nil ||
		call.Guards[0].Proof.Proof != *call.Scope.Request.Proof) {
		return api.Operation{}, serviceError(api.CodeForbidden, "TestChild lost its atomic human proof guard")
	}
	state, ok := s.deps.Store.(interface {
		StageChildTest(context.Context, api.Scope, api.TestChildRequest, api.GrantSet, api.ReviewSubject) (testjob.Reservation, error)
	})
	source, sourceOK := s.deps.Store.(reviewjob.Source)
	if !ok || !sourceOK {
		return api.Operation{}, serviceError(api.CodePrerequisite, "TestChild requires the installed native test journal")
	}
	if err := s.awaitTestCapture(ctx, control, request.Child); err != nil {
		return api.Operation{}, err
	}
	subject, err := source.ReviewSnapshot(ctx, control, request.Child)
	if err != nil {
		return api.Operation{}, err
	}
	reservation, err := state.StageChildTest(ctx, call.Scope, request, grants, subject)
	if err != nil {
		return api.Operation{}, err
	}
	reply, err := json.Marshal(api.Operation{ID: reservation.Job.Intent.OperationID, Status: "pending", LifeID: request.Child.LifeID, Run: request.Child.Run})
	if err != nil {
		return api.Operation{}, err
	}
	commit, err := s.deps.Store.Transact(ctx, api.Transaction{Scope: call.Scope, RawRequest: call.Scope.Frame.Bytes(),
		Guards: call.Guards, Compare: reservation.Compare, Writes: api.StateWrites{WorkerLeases: []api.WorkerLease{reservation.Job.Lease}},
		Effects: []api.Effect{reservation.Effect}, Reply: &api.RPCReply{Result: reply}})
	if err != nil {
		return api.Operation{}, err
	}
	if commit.Reply == nil || commit.Reply.Error != nil || commit.Operation.ID != reservation.Job.Intent.OperationID {
		return api.Operation{}, serviceError(api.CodeIntegrity, "TestChild commit lost its reserved worker operation")
	}
	if err := s.ExecuteReviewWorker(ctx, call.Scope, reservation.Job); err != nil {
		return api.Operation{}, err
	}
	return s.deps.Store.Operation(ctx, call.Scope, commit.Operation.ID)
}

func testRequestKey(scope api.Scope) api.RequestKey {
	return api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
}

var _ testjob.Control = (*Server)(nil)

func (s *Server) awaitTestCapture(ctx context.Context, scope api.Scope, target api.LifeRef) error {
	lane, err := s.deps.Store.Lane(ctx, scope, target)
	if err != nil {
		return err
	}
	binding, err := s.deps.Store.LaunchBinding(ctx, lane.LaunchID)
	if err != nil {
		return err
	}
	if binding.Recovery == nil || binding.Recovery.Capture.Target != target || len(binding.Recovery.Capture.Streams) == 0 {
		return serviceError(api.CodeIntegrity, "TestChild has no original primary capture")
	}
	waitCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := s.deps.Store.CaptureState(waitCtx, scope, binding.Recovery.Capture.ID)
		if err != nil {
			return err
		}
		complete := len(state.Positions) == len(binding.Recovery.Capture.Streams)
		for _, stream := range binding.Recovery.Capture.Streams {
			count := 0
			for _, position := range state.Positions {
				if position.StreamID == stream.ID && position.EOF {
					count++
				}
			}
			complete = complete && count == 1
		}
		if complete {
			return nil
		}
		select {
		case <-waitCtx.Done():
			return contextError(waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func (s *Server) executeChildEffect(ctx context.Context, effect api.Effect) error {
	control, err := s.controlScope()
	if err != nil {
		return err
	}
	state, ok := s.deps.Store.(interface {
		AdmittedChildTest(context.Context, api.Scope, api.Effect) (archivejob.Job, error)
	})
	if !ok {
		return serviceError(api.CodePrerequisite, "native TestChild recovery admission reader is unavailable")
	}
	job, err := state.AdmittedChildTest(ctx, control, effect)
	if err != nil {
		return err
	}
	return s.executePostRunWorker(ctx, control, job)
}
