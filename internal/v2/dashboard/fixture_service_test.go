package dashboard

// Local module dispatch is only a projection-test fixture. Production HTTP
// always delegates to HumanTransport's authenticated durable dispatcher.
import (
	"context"
	"encoding/json"
	"errors"
	"laneboss.io/laneboss/internal/v2/api"
	"reflect"
)

type idempotencyRecord struct {
	requestSHA256 api.Digest
	response      api.Response
}

func (s *Service) checkOperationProof(ctx context.Context, scope api.Scope, req api.Request, targetID api.ID, baseGen api.Generation) error {
	if req.Method != "human.session" {
		var authErr error
		scope, authErr = s.currentHumanScope(ctx, scope)
		if authErr != nil {
			return authErr
		}
	}
	if req.Proof == nil {
		return forbiddenErr("operation-bound human proof is required for mutations", "Call human.challenge and human.confirm to obtain a proof.")
	}
	if req.Proof.ID == "" || !validID(req.Proof.ID) {
		return forbiddenErr("invalid proof identifier", "Obtain a valid ProofRef from human.confirm.")
	}
	if !validDigest(req.Proof.RequestSHA256) || req.Proof.RequestSHA256 != req.RequestSHA256 {
		return forbiddenErr("proof request_sha256 does not match request envelope digest", "Bind the challenge and proof to the exact request_sha256.")
	}
	expTime, err := parseTimestamp(req.Proof.ExpiresAt)
	if err != nil {
		return invalidErr("invalid proof expires_at timestamp", "Use RFC3339Nano UTC ending with Z.")
	}
	now := s.now().UTC()
	if !now.Before(expTime) {
		return forbiddenErr("operation-bound human proof has expired", "Request a fresh human.challenge and human.confirm.")
	}

	target := api.HumanChallengeRequest{
		Method:         req.Method,
		TargetID:       targetID,
		RequestSHA256:  req.RequestSHA256,
		BaseGeneration: baseGen,
	}
	if s.deps.Store != nil {
		if resolved, err := s.deps.Store.AuthorizationTarget(ctx, scope, req); err == nil {
			target = resolved
		} else {
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
				return wrapStoreErr(err, "authorization target could not be resolved")
			}
		}
	}
	verifiedProof, err := s.deps.Human.CheckProof(ctx, scope, *req.Proof, target)
	if err != nil {
		return err
	}
	if verifiedProof.ConsumedBy != "" {
		return forbiddenErr("operation-bound human proof was already consumed", "Request a fresh human.challenge and human.confirm.")
	}
	if verifiedProof.Config != "" && verifiedProof.Config != scope.Config {
		return forbiddenErr("human proof configuration mismatch", "Use a proof bound to this configuration.")
	}
	if verifiedProof.Ref.ID != "" && verifiedProof.Ref.ID != req.Proof.ID {
		return forbiddenErr("verified proof ID mismatch", "Use the exact confirmed proof reference.")
	}
	if verifiedProof.Ref.RequestSHA256 != "" && verifiedProof.Ref.RequestSHA256 != req.RequestSHA256 {
		return forbiddenErr("verified proof digest mismatch", "Bind the proof to the exact request digest.")
	}

	return nil
}

func (s *Service) dispatchReadRPC(ctx context.Context, scope api.Scope, method api.Method, rawParams json.RawMessage) (any, error) {
	var authErr error
	scope, authErr = s.currentHumanScope(ctx, scope)
	if authErr != nil {
		return nil, authErr
	}
	switch method {
	case "dashboard.tree", "dashboard.raw", "dashboard.decisions", "dashboard.refusals",
		"dashboard.plugins", "dashboard.resources", "dashboard.lifecycle", "dashboard.approvals":
		var q api.DashboardQuery
		if err := decodeStrictJSON(rawParams, &q); err != nil {
			return nil, err
		}
		switch method {
		case "dashboard.tree":
			return s.DashboardTree(ctx, scope, q)
		case "dashboard.raw":
			return s.DashboardRaw(ctx, scope, q)
		case "dashboard.decisions":
			return s.DashboardDecisions(ctx, scope, q)
		case "dashboard.refusals":
			return s.DashboardRefusals(ctx, scope, q)
		case "dashboard.plugins":
			return s.DashboardPlugins(ctx, scope, q)
		case "dashboard.resources":
			return s.DashboardResources(ctx, scope, q)
		case "dashboard.lifecycle":
			return s.DashboardLifecycle(ctx, scope, q)
		case "dashboard.approvals":
			return s.DashboardApprovals(ctx, scope, q)
		}
	case "lane.status":
		var ref api.LifeRef
		if err := decodeStrictJSON(rawParams, &ref); err != nil {
			return nil, err
		}
		if ref.LifeID == "" || !validID(ref.LifeID) {
			return nil, invalidErr("invalid life_id", "Provide a valid life_id.")
		}
		return s.deps.Lifecycle.LaneStatus(ctx, scope, ref)
	case "lane.list":
		var lr api.ListRequest
		if err := decodeStrictJSON(rawParams, &lr); err != nil {
			return nil, err
		}
		if lr.Limit < 1 || lr.Limit > maxPageLimit {
			return nil, invalidErr("limit must be between 1 and 200", "Provide limit in 1..200.")
		}
		return s.deps.Lifecycle.LaneList(ctx, scope, lr)
	case "mail.list":
		var lr api.ListRequest
		if err := decodeStrictJSON(rawParams, &lr); err != nil {
			return nil, err
		}
		if lr.Limit < 1 || lr.Limit > maxPageLimit {
			return nil, invalidErr("limit must be between 1 and 200", "Provide limit in 1..200.")
		}
		return s.deps.Messaging.MailList(ctx, scope, lr)
	case "org.change.get":
		var cgr api.ChangeGetRequest
		if err := decodeStrictJSON(rawParams, &cgr); err != nil {
			return nil, err
		}
		if cgr.ChangeID == "" || !validID(cgr.ChangeID) {
			return nil, invalidErr("invalid change_id", "Provide a valid change_id.")
		}
		return s.deps.Approval.OrgChangeGet(ctx, scope, cgr)
	case "operation.get":
		var ogr api.OperationGetRequest
		if err := decodeStrictJSON(rawParams, &ogr); err != nil {
			return nil, err
		}
		if ogr.OperationID == "" || !validID(ogr.OperationID) {
			return nil, invalidErr("invalid operation_id", "Provide a valid operation_id.")
		}
		return s.deps.Store.Operation(ctx, scope, ogr.OperationID)
	case "store.verify":
		var vr api.VerifyRequest
		if err := decodeStrictJSON(rawParams, &vr); err != nil {
			return nil, err
		}
		return s.deps.Store.Verify(ctx, vr)
	}
	return nil, forbiddenErr("read method is not exposed on the dashboard endpoint", "Use a supported dashboard read method.")
}

func validateBlobRefField(ref api.BlobRef, name string) error {
	if ref.ID == "" || !validID(ref.ID) {
		return invalidErr(name+" id is required", "Commit the blob first and pass its BlobRef.")
	}
	if !validDigest(ref.SHA256) {
		return invalidErr(name+" sha256 is invalid", "Provide a 64-character lowercase hex SHA-256 digest.")
	}
	if ref.Bytes <= 0 || ref.Bytes > api.MaxObjectBytes {
		return invalidErr(name+" bytes out of range", "Provide positive byte length within object limits.")
	}
	return nil
}

func validateBudgetField(b api.Budget) error {
	if b.WallMS <= 0 || b.CPUSeconds == 0 || b.MemoryBytes == 0 || b.Processes == 0 || b.DiskBytes == 0 {
		return invalidErr("launch/resume budget requires positive wall_ms, cpu_seconds, memory_bytes, processes and disk_bytes", "Specify positive resource ceilings.")
	}
	if b.SpendMicros < 0 || b.Currency == "" {
		return invalidErr("budget spend_micros must be nonnegative with a currency code", "Provide a valid budget.")
	}
	return nil
}

func (s *Service) verifyReviewForMark(ctx context.Context, scope api.Scope, params api.MarkRequest) error {
	if params.State != "accepted" && params.State != "merged" && params.State != "abandoned" {
		return invalidErr("mark state must be accepted, merged or abandoned", "Specify accepted, merged or abandoned.")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, params.Target)
	if err != nil {
		return wrapStoreErr(err, "target lane could not be read")
	}
	if lane.Cleaned {
		return conflictErr("cleaned lane cannot be marked", "Cleaned lanes are immutable retained records.")
	}
	if lane.Generation != params.ExpectedGeneration {
		return conflictErr("expected_generation does not match current lane generation", "Refresh the lane state and retry with its current generation.")
	}
	if params.State == "abandoned" {
		if lane.State == "merged" {
			return conflictErr("merged lane cannot be marked abandoned", "Merged lanes cannot transition to abandoned.")
		}
		return nil
	}

	// accepted and merged require an authentic service-created ReviewReceipt with complete coverage.
	rev := params.Review
	if rev.ID == "" || !validID(rev.ID) {
		return forbiddenErr("review receipt ID is required to mark accepted or merged", "Run lane.review first to obtain a service-issued ReviewReceipt.")
	}
	if rev.Coverage != "complete" {
		return forbiddenErr("review coverage must be complete before marking accepted or merged", "Resolve incomplete capture or coverage before accepting.")
	}
	if err := validateBlobRefField(rev.Diff, "review.diff"); err != nil {
		return err
	}
	if err := validateBlobRefField(rev.RecordInventory, "review.record_inventory"); err != nil {
		return err
	}

	if params.State == "accepted" && lane.State != "verifying" {
		return conflictErr("lane must be in verifying state before marking accepted", "Wait for the run to settle in verifying state.")
	}
	if params.State == "merged" && lane.State != "accepted" {
		return conflictErr("lane must be in accepted state before marking merged", "Mark the reviewed lane accepted before marking merged.")
	}

	// Verify against committed service events that rev.ID was genuinely issued by the service for this life.
	events, err := s.readAllEvents(ctx, scope, params.Target.LifeID, 0)
	if err != nil {
		return err
	}
	foundAuthenticReview := false
	for _, ev := range events {
		if ev.Origin != "service" || ev.Kind != "lane.reviewed" || ev.LifeID != params.Target.LifeID {
			continue
		}
		var stored api.ReviewReceipt
		if json.Unmarshal(ev.Payload, &stored) != nil {
			continue
		}
		if stored.ID == rev.ID && reflect.DeepEqual(stored, rev) && stored.Evidence != nil &&
			stored.Evidence.Subject.Target == (api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}) {
			if stored.Reviewer.Kind == "lane" && stored.Reviewer.LifeID == params.Target.LifeID {
				return forbiddenErr("self-review cannot satisfy acceptance", "Require an independent supervisor or human review.")
			}
			if err := api.ValidateReviewAcceptance(scope, stored, stored.Evidence.Subject, nil); err != nil {
				return err
			}
			foundAuthenticReview = true
			break
		}
	}
	if !foundAuthenticReview {
		return forbiddenErr("review receipt is not an authentic service-recorded review for this life", "Run lane.review through the service before marking accepted or merged.")
	}
	return nil
}

func (s *Service) dispatchMutationRPC(ctx context.Context, scope api.Scope, req api.Request) (any, api.Sequence, error) {
	var authErr error
	scope, authErr = s.currentHumanScope(ctx, scope)
	if authErr != nil {
		return nil, 0, authErr
	}
	switch req.Method {
	case "lane.stop":
		var params api.StopRequest
		if err := decodeStrictJSON(req.Params, &params); err != nil {
			return nil, 0, err
		}
		if params.Target.LifeID == "" || !validID(params.Target.LifeID) || params.ExpectedGeneration == 0 {
			return nil, 0, invalidErr("stop requires target.life_id and expected_generation", "Provide valid target and expected_generation.")
		}
		if err := validateBlobRefField(params.Reason, "reason"); err != nil {
			return nil, 0, err
		}
		if err := s.checkOperationProof(ctx, scope, req, params.Target.LifeID, params.ExpectedGeneration); err != nil {
			return nil, 0, err
		}
		op, err := s.deps.Lifecycle.LaneStop(ctx, scope, params)
		if err != nil {
			return nil, 0, err
		}
		return op, op.LastSeq, nil

	case "lane.resume":
		var params api.ResumeRequest
		if err := decodeStrictJSON(req.Params, &params); err != nil {
			return nil, 0, err
		}
		if params.Target.LifeID == "" || !validID(params.Target.LifeID) || params.ExpectedGeneration == 0 {
			return nil, 0, invalidErr("resume requires target.life_id and expected_generation", "Provide valid target and expected_generation.")
		}
		if err := validateBlobRefField(params.Message, "message"); err != nil {
			return nil, 0, err
		}
		if err := validateBudgetField(params.Budget); err != nil {
			return nil, 0, err
		}
		lane, err := s.deps.Store.Lane(ctx, scope, params.Target)
		if err != nil {
			return nil, 0, wrapStoreErr(err, "target lane could not be read")
		}
		if lane.Cleaned || lane.State == "merged" || lane.State == "abandoned" || lane.State == "running" || lane.State == "preparing" {
			return nil, 0, conflictErr("lane is not in a resumable state", "Resume requires an ended, uncleaned, non-merged, non-abandoned life.")
		}
		if lane.Generation != params.ExpectedGeneration {
			return nil, 0, conflictErr("expected_generation mismatch", "Refresh lane status and use current generation.")
		}
		if err := s.checkOperationProof(ctx, scope, req, params.Target.LifeID, params.ExpectedGeneration); err != nil {
			return nil, 0, err
		}
		op, err := s.deps.Lifecycle.LaneResume(ctx, scope, params)
		if err != nil {
			return nil, 0, err
		}
		return op, op.LastSeq, nil

	case "lane.mark":
		var params api.MarkRequest
		if err := decodeStrictJSON(req.Params, &params); err != nil {
			return nil, 0, err
		}
		if params.Target.LifeID == "" || !validID(params.Target.LifeID) || params.ExpectedGeneration == 0 {
			return nil, 0, invalidErr("mark requires target.life_id and expected_generation", "Provide valid target and expected_generation.")
		}
		if err := s.verifyReviewForMark(ctx, scope, params); err != nil {
			return nil, 0, err
		}
		if err := s.checkOperationProof(ctx, scope, req, params.Target.LifeID, params.ExpectedGeneration); err != nil {
			return nil, 0, err
		}
		op, err := s.deps.Lifecycle.LaneMark(ctx, scope, params)
		if err != nil {
			return nil, 0, err
		}
		return op, op.LastSeq, nil

	case "lane.review":
		var params api.ReviewRequest
		if err := decodeStrictJSON(req.Params, &params); err != nil {
			return nil, 0, err
		}
		if params.Target.LifeID == "" || !validID(params.Target.LifeID) {
			return nil, 0, invalidErr("review requires target.life_id", "Provide valid target.life_id.")
		}
		if err := validateBlobRefField(params.Diff, "diff"); err != nil {
			return nil, 0, err
		}
		if err := validateBlobRefField(params.RecordInventory, "record_inventory"); err != nil {
			return nil, 0, err
		}
		if err := s.checkOperationProof(ctx, scope, req, params.Target.LifeID, 0); err != nil {
			return nil, 0, err
		}
		rev, err := s.deps.Lifecycle.LaneReview(ctx, scope, params)
		if err != nil {
			return nil, 0, err
		}
		return rev, 0, nil

	case "mail.send":
		var params api.MailSendRequest
		if err := decodeStrictJSON(req.Params, &params); err != nil {
			return nil, 0, err
		}
		if params.RecipientLifeID == "" || !validID(params.RecipientLifeID) {
			return nil, 0, invalidErr("recipient_life_id is required", "Specify a valid recipient_life_id.")
		}
		if err := validateBlobRefField(params.Content, "content"); err != nil {
			return nil, 0, err
		}
		if params.Content.Bytes > maxMailBytes {
			return nil, 0, invalidErr("mail content exceeds 256 KiB limit", "Keep mail content within 262144 bytes.")
		}
		// Verify that the recipient life exists (may be any level L3..L6 for human sender).
		if _, err := s.deps.Store.Lane(ctx, scope, api.LifeRef{LifeID: params.RecipientLifeID}); err != nil {
			return nil, 0, wrapStoreErr(err, "recipient life could not be found")
		}
		// Screen mail content blob so secret-shaped strings are rejected before queuing.
		rawMail, err := s.readVerifiedBlob(ctx, scope, params.Content)
		if err != nil {
			return nil, 0, err
		}
		if screenString(string(rawMail)) != string(rawMail) {
			return nil, 0, invalidErr("mail content contains a credential-shaped value", "Remove secret material from mail content.")
		}
		if err := s.checkOperationProof(ctx, scope, req, params.RecipientLifeID, 0); err != nil {
			return nil, 0, err
		}
		mail, err := s.deps.Messaging.MailSend(ctx, scope, params)
		if err != nil {
			return nil, 0, err
		}
		return mail, mail.QueuedSeq, nil

	case "org.change.approve":
		var params api.ChangeApproveRequest
		if err := decodeStrictJSON(req.Params, &params); err != nil {
			return nil, 0, err
		}
		if params.ChangeID == "" || !validID(params.ChangeID) || !validDigest(params.ManifestSHA256) || params.BaseGeneration == 0 {
			return nil, 0, invalidErr("org.change.approve requires change_id, manifest_sha256 and base_generation", "Provide complete ChangeApproveRequest parameters.")
		}
		if err := s.checkOperationProof(ctx, scope, req, params.ChangeID, params.BaseGeneration); err != nil {
			return nil, 0, err
		}
		appr, err := s.deps.Approval.OrgChangeApprove(ctx, scope, params)
		if err != nil {
			return nil, 0, err
		}
		return appr, 0, nil
	}
	return nil, 0, forbiddenErr("unsupported dashboard mutation", "Use a documented human control method.")
}
