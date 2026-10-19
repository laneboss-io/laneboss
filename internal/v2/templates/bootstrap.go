package templates

import (
	"bytes"
	"context"
	"encoding/json"
	"path"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// bootstrap reserves an absent baseline and its publication effect. The RPC's
// Operation can be pending; org.bootstrapped belongs only to measured publisher
// completion. The dispatcher owns replay/reservation before module preflight.
func (s *Service) bootstrap(ctx context.Context, scope api.Scope, request api.BootstrapRequest) (api.Operation, error) {
	if err := checkScope(scope); err != nil {
		return api.Operation{}, err
	}
	if scope.Actor.Kind != "human" || scope.Request.Proof == nil {
		return api.Operation{}, problem(api.CodeForbidden, "org bootstrap requires operation-bound human verification",
			"Use initial administrator enrollment; existing org changes require L6 plus direct human D6 approval.")
	}
	if !safeID.MatchString(request.OrgName) || request.SourceManifest.Class != "manifest" {
		return api.Operation{}, invalid("bootstrap requires an org name and a committed source manifest")
	}
	var framed api.BootstrapRequest
	if scope.Request.Method != "org.bootstrap" || scope.Request.Config != scope.Config ||
		scope.Request.RequestID == "" || scope.Request.IdempotencyKey == "" ||
		DecodeJSON(scope.Request.Params, &framed) != nil || framed != request {
		return api.Operation{}, invalid("bootstrap requires its exact prepared request envelope")
	}
	digest, err := api.RequestDigest(scope.Request)
	if err != nil {
		return api.Operation{}, err
	}
	if !safeID.MatchString(string(scope.Request.Proof.ID)) || scope.Request.RequestSHA256 != digest || scope.Request.Proof.RequestSHA256 != digest {
		return api.Operation{}, invalid("bootstrap proof and prepared request digest differ")
	}
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: digest}
	reservation, err := s.deps.Store.LookupReceipt(ctx, scope, key)
	if err != nil {
		return api.Operation{}, err
	}
	if reservation.Config != scope.Config || reservation.Key != key || reservation.Actor != scope.Actor || !safeID.MatchString(string(reservation.Operation.ID)) {
		return api.Operation{}, integrity("bootstrap reservation differs from the authenticated request")
	}
	if reservation.Reply != nil {
		expected := reservation.SimulatedPresence || reservation.Operation.SimulatedPresence
		return bootstrapReply(reservation.Reply, reservation.Operation.ID, expected)
	}
	if reservation.Operation.Status != "pending" || scope.Frame == nil {
		return api.Operation{}, problem(api.CodePrerequisite, "bootstrap requires the dispatcher’s durable pending request and exact frame",
			"Reserve and authenticate the mutation before module preflight; never reconstruct original request bytes.")
	}
	raw := scope.Frame.Bytes()
	if len(raw) == 0 || len(raw) > api.MaxFrameBytes || !bytes.Equal(raw, reservation.RawRequest) {
		return api.Operation{}, integrity("bootstrap frame differs from the durable request reservation")
	}
	var exact api.Request
	if err := api.DecodeObject(raw, &exact); err != nil {
		return api.Operation{}, err
	}
	if exact.RequestID != scope.Request.RequestID || exact.IdempotencyKey != scope.Request.IdempotencyKey ||
		exact.RequestSHA256 != digest || exact.Method != scope.Request.Method || exact.Config != scope.Config ||
		exact.Proof == nil || *exact.Proof != *scope.Request.Proof {
		return api.Operation{}, integrity("bootstrap frame differs from the authenticated prepared request")
	}
	exactDigest, err := api.RequestDigest(exact)
	if err != nil || exactDigest != digest {
		return api.Operation{}, integrity("bootstrap frame differs from the authenticated prepared request")
	}
	if s.deps.Clock == nil || s.deps.Publisher == nil || s.deps.Human == nil ||
		!safeID.MatchString(string(s.deps.BootstrapRenderer.ID)) ||
		!safeDigest.MatchString(string(s.deps.BootstrapRenderer.SHA256)) || s.deps.BootstrapRenderer.Version == "" ||
		s.deps.BootstrapOwnership.Class != "manifest" {
		return api.Operation{}, problem(api.CodePrerequisite, "bootstrap requires a pinned publisher, renderer and ownership manifest",
			"Bind the protected initial-org renderer and ownership inventory in the service installation.")
	}
	target, err := s.deps.Store.AuthorizationTarget(ctx, scope, scope.Request)
	if err != nil {
		return api.Operation{}, err
	}
	if target.Method != scope.Request.Method || target.RequestSHA256 != digest || !safeID.MatchString(string(target.TargetID)) {
		return api.Operation{}, integrity("bootstrap authorization target is not an absent org baseline")
	}
	if target.BaseGeneration != 0 {
		return api.Operation{}, problem(api.CodeConflict, "org already exists; bootstrap cannot replace it",
			"Use an authenticated L6 exact-change proposal and direct human D6 approval.")
	}
	proof, err := s.deps.Human.CheckProof(ctx, scope, *scope.Request.Proof, target)
	if err != nil {
		return api.Operation{}, err
	}
	expires, parseErr := time.Parse(time.RFC3339Nano, string(proof.Ref.ExpiresAt))
	if parseErr != nil || !s.deps.Clock.Now().Before(expires) || proof.Ref != *scope.Request.Proof ||
		proof.SimulatedPresence != proof.Ref.SimulatedPresence || (reservation.SimulatedPresence && !proof.SimulatedPresence) ||
		proof.Config != scope.Config || proof.PrincipalID != scope.Actor.ID || proof.Target != target ||
		proof.EndpointClass != api.EndpointHuman || proof.EndpointGeneration != scope.EndpointGeneration ||
		proof.ConsumedBy != "" || !safeID.MatchString(string(proof.CredentialID)) || !safeID.MatchString(string(proof.NonceID)) {
		return api.Operation{}, problem(api.CodeForbidden, "bootstrap proof is expired, consumed or bound to another operation",
			"Confirm the exact initial-org operation through the authenticated human endpoint.")
	}
	data, err := s.readBlob(ctx, scope, request.SourceManifest)
	if err != nil {
		return api.Operation{}, err
	}
	var manifest api.ObjectManifest
	if err := DecodeJSON(data, &manifest); err != nil {
		return api.Operation{}, err
	}
	if manifest.Schema != "laneboss.objects.v2" || len(manifest.Entries) == 0 {
		return api.Operation{}, invalid("bootstrap requires a nonempty v2 source manifest")
	}
	files := map[string][]byte{}
	seen := map[string]bool{}
	for _, entry := range manifest.Entries {
		if path.IsAbs(entry.Path) || path.Clean(entry.Path) != entry.Path ||
			!strings.HasPrefix(entry.Path, ".laneboss/") || strings.ContainsAny(entry.Path, "\\\r\n\x00") ||
			entry.Kind != "file" || entry.Content == nil || entry.Assembly != nil || entry.LinkTarget != "" ||
			entry.Mode == 0 || entry.Mode&^uint32(0777) != 0 || seen[entry.Path] {
			return api.Operation{}, invalid("bootstrap source manifest has an unsafe, duplicate or unsupported entry")
		}
		seen[entry.Path] = true
		if isTemplateSource(entry.Path) && entry.Content.Bytes > MaxSourceBytes {
			return api.Operation{}, invalid("template source must be nonempty UTF-8 within 2 MiB")
		}
		contents, err := s.readBlob(ctx, scope, *entry.Content)
		if err != nil {
			return api.Operation{}, err
		}
		if isTemplateSource(entry.Path) {
			files[entry.Path] = contents
		}
	}
	if err := ValidateCatalog(files); err != nil {
		return api.Operation{}, err
	}
	if _, err := s.readBlob(ctx, scope, s.deps.BootstrapOwnership); err != nil {
		return api.Operation{}, err
	}
	effectID, err := newID()
	if err != nil {
		return api.Operation{}, err
	}
	intentID, err := newID()
	if err != nil {
		return api.Operation{}, err
	}
	intent := api.InternalIntent{ID: intentID, Kind: api.InternalOrgBootstrap, Config: scope.Config,
		Actor: api.Actor{Kind: "service", ID: "lb-v2-templates"}, RequestedBy: scope.Actor,
		CauseRequestID: scope.Request.RequestID, CauseOperationID: reservation.Operation.ID, EffectID: effectID}
	operation := reservation.Operation
	operation.SimulatedPresence = reservation.Operation.SimulatedPresence || proof.SimulatedPresence
	reply, err := json.Marshal(operation)
	if err != nil {
		return api.Operation{}, integrity("bootstrap reservation could not be encoded")
	}
	commit, err := s.deps.Store.Transact(ctx, api.Transaction{
		Scope: scope, RawRequest: raw, Reply: &api.RPCReply{Result: reply},
		Compare: []api.Compare{{Kind: api.CompareOrg, ID: target.TargetID, Generation: 0}},
		Guards:  []api.TransactionGuard{{Proof: &api.ProofUse{Proof: proof.Ref, Target: target}}},
		Effects: []api.Effect{{ID: effectID, OperationID: operation.ID, Context: &intent,
			Bootstrap: &api.BootstrapEffect{OrgID: target.TargetID, OrgName: request.OrgName,
				SourceManifest: request.SourceManifest, Renderer: s.deps.BootstrapRenderer,
				OwnershipManifest: s.deps.BootstrapOwnership}}},
	})
	if err != nil {
		return api.Operation{}, err
	}
	result, err := bootstrapReply(commit.Reply, operation.ID, operation.SimulatedPresence)
	if err != nil {
		return api.Operation{}, err
	}
	if !commit.Replayed && commit.Operation.SimulatedPresence != result.SimulatedPresence {
		return api.Operation{}, integrity("bootstrap reply lost verified presence provenance")
	}
	if !commit.Replayed && (commit.Operation.Status == "succeeded" || result.Status == "succeeded") {
		return api.Operation{}, integrity("queued bootstrap effect claimed publication success")
	}
	return result, nil
}

func bootstrapReply(reply *api.RPCReply, operationID api.ID, expectedPresence bool) (api.Operation, error) {
	if reply == nil || (reply.Error == nil) == (len(reply.Result) == 0) {
		return api.Operation{}, integrity("bootstrap commit omitted its typed durable reply")
	}
	if reply.Error != nil {
		return api.Operation{}, reply.Error
	}
	var operation api.Operation
	if err := DecodeJSON(reply.Result, &operation); err != nil {
		return api.Operation{}, err
	}
	if operation.ID != operationID || !safeID.MatchString(string(operation.ID)) {
		return api.Operation{}, integrity("bootstrap reply differs from its committed operation")
	}
	if operation.SimulatedPresence != expectedPresence {
		return api.Operation{}, integrity("bootstrap reply lost verified presence provenance")
	}
	if operation.Error != nil {
		return api.Operation{}, operation.Error
	}
	if !slicesContainStatus(operation.Status) {
		return api.Operation{}, integrity("bootstrap reply differs from its committed operation")
	}
	return operation, nil
}

func slicesContainStatus(status string) bool {
	return status == "pending" || status == "running" || status == "succeeded"
}
