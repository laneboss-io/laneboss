package guidance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

func integrity(message string) *api.Error {
	return &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-guidance", Message: message,
		Instead: "Preserve the retained turn, source snapshot and receipt evidence."}
}

// A different public idempotency key still needs its own atomic RPC receipt,
// even when it reuses a logical-turn result. It emits no second selection.
func (s *Service) sealReplay(ctx context.Context, scope api.Scope, target api.LifeRef, result api.Guidance) (api.Guidance, error) {
	var err error
	scope, err = authorizeTarget(ctx, scope, target)
	if err != nil {
		return api.Guidance{}, err
	}
	if scope.Request.Method != "guidance.select" {
		return result, nil
	}
	reservation, err := s.deps.Store.GuidanceReservation(ctx, scope, target, result.LogicalTurnID)
	if err != nil {
		return api.Guidance{}, err
	}
	if reservation.ID != result.ReservationID || reservation.Generation == 0 || reservation.Result == nil || reservation.Result.ID != result.ID {
		return api.Guidance{}, integrity("guidance replay lost its durable reservation")
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return api.Guidance{}, integrity("guidance replay could not encode its retained result")
	}
	transaction := api.Transaction{Scope: scope, Reply: &api.RPCReply{Result: payload},
		Compare: []api.Compare{{Kind: api.CompareGuidance, ID: reservation.ID, Generation: reservation.Generation}}}
	if scope.Frame != nil {
		transaction.RawRequest = append([]byte{}, scope.Frame.Bytes()...)
	}
	if err := api.ValidateTransactionShape(transaction); err != nil {
		return api.Guidance{}, err
	}
	commit, err := s.deps.Store.Transact(ctx, transaction)
	if err != nil {
		return api.Guidance{}, err
	}
	if commit.Operation.Error != nil {
		return api.Guidance{}, commit.Operation.Error
	}
	if commit.Reply == nil || commit.Operation.Status != "succeeded" {
		return api.Guidance{}, integrity("guidance replay omitted its completed durable reply")
	}
	if commit.Reply.Error != nil {
		return api.Guidance{}, commit.Reply.Error
	}
	var retained api.Guidance
	if api.DecodeObject(commit.Reply.Result, &retained) != nil {
		return api.Guidance{}, integrity("guidance replay returned an invalid reply shape")
	}
	encoded, err := json.Marshal(retained)
	if err != nil || string(encoded) != string(payload) {
		return api.Guidance{}, integrity("guidance replay returned a different turn result")
	}
	return retained, nil
}

// completedSelection never takes over another caller's pending claim. A
// completed result is immutable across profile runs, but the store rechecks
// this caller's current authority on every lookup.
func (s *Service) completedSelection(ctx context.Context, scope api.Scope, request api.GuidanceRequest, generation api.Generation) (*api.Guidance, error) {
	reservation, err := s.deps.Store.GuidanceReservation(ctx, scope, request.Target, request.LogicalTurnID)
	if err != nil {
		var typed *api.Error
		if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
			return nil, nil
		}
		return nil, err
	}
	return validateCompletedSelection(reservation, request, generation)
}

func validateCompletedSelection(reservation api.GuidanceReservation, request api.GuidanceRequest, generation api.Generation) (*api.Guidance, error) {
	if !validID(reservation.ID) || reservation.Target.LifeID != request.Target.LifeID || reservation.Target.Run == 0 || reservation.Target.Run > request.Target.Run ||
		reservation.LogicalTurnID != request.LogicalTurnID || reservation.Task != request.Task ||
		reservation.PolicyGeneration != generation || generation == 0 {
		return nil, integrity("guidance reservation does not match the retained turn input")
	}
	if reservation.Result == nil {
		return nil, &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-guidance", Retryable: true,
			Message: "logical-turn guidance is reserved but has no completed result",
			Instead: "Await or reconcile the original turn claim; do not start another judgment."}
	}
	result := *reservation.Result
	raw, err := json.Marshal(result)
	if err != nil || api.DecodeObject(raw, new(api.Guidance)) != nil ||
		!validID(result.ID) || result.ReservationID != reservation.ID ||
		result.Target != reservation.Target || result.Task != reservation.Task ||
		result.LogicalTurnID != reservation.LogicalTurnID ||
		result.PolicyGeneration != reservation.PolicyGeneration ||
		result.CandidateSnapshotID != reservation.CandidateSnapshotID ||
		!validID(result.CandidateSnapshotID) || result.PolicyGeneration == 0 {
		return nil, integrity("retained guidance receipt does not match its reservation")
	}
	if _, err := time.Parse(time.RFC3339Nano, string(result.AsOf)); err != nil || !strings.HasSuffix(string(result.AsOf), "Z") {
		return nil, integrity("retained guidance receipt has an invalid clock")
	}
	switch result.Status {
	case "scored", "empty":
		if result.WeightedScore == nil || math.IsNaN(*result.WeightedScore) ||
			math.IsInf(*result.WeightedScore, 0) || *result.WeightedScore < 0 || *result.WeightedScore > 1 ||
			result.Status == "empty" && *result.WeightedScore != 0 {
			return nil, integrity("retained scored guidance has no valid weighted score")
		}
	case "unavailable":
		if result.WeightedScore != nil || result.Notice == "" {
			return nil, integrity("retained unavailable guidance was changed into a score")
		}
	default:
		return nil, integrity("retained guidance has an unknown status")
	}
	judgments := make(map[api.ID]bool)
	for _, id := range result.JudgmentIDs {
		if !validID(id) || judgments[id] {
			return nil, integrity("retained guidance contains invalid judgment provenance")
		}
		judgments[id] = true
	}
	if result.JudgmentID != "" && !validID(result.JudgmentID) ||
		result.Status == "scored" && len(result.JudgmentIDs) == 0 ||
		result.Status == "empty" && (len(result.JudgmentIDs) != 0 || result.JudgmentID != "") {
		return nil, integrity("retained guidance status differs from its judgment provenance")
	}
	seen := make(map[api.ID]bool)
	reminders := 0
	for _, item := range result.Items {
		if !validID(item.DecisionID) || seen[item.DecisionID] || item.AgeSeconds < 0 || item.AgeSeconds > maxInteger ||
			!validID(item.Source.ID) || !validDigest(item.Source.SHA256) || item.Source.Generation == 0 ||
			math.IsNaN(item.Weight) || math.IsInf(item.Weight, 0) || item.Weight < 0 || item.Weight > 1 {
			return nil, integrity("retained guidance contains invalid or duplicate items")
		}
		seen[item.DecisionID] = true
		if item.Binding {
			if item.Weight != 1 || item.Probability != nil || item.Score != nil {
				return nil, integrity("retained binding guidance was relevance scored")
			}
		} else {
			reminders++
			if reminders > reminderLimit || result.Status != "scored" || item.Probability == nil || item.Score == nil {
				return nil, integrity("retained guidance violates the reminder or availability bound")
			}
			if math.IsNaN(*item.Probability) || math.IsInf(*item.Probability, 0) || *item.Probability < 0 || *item.Probability > 1 ||
				math.IsNaN(*item.Score) || math.IsInf(*item.Score, 0) || math.Abs(*item.Score-item.Weight**item.Probability) > 1e-12 {
				return nil, integrity("retained guidance item score differs from its actual probability and weight")
			}
		}
	}
	result.Items = append([]api.GuidanceItem{}, result.Items...)
	result.JudgmentIDs = append([]api.ID{}, result.JudgmentIDs...)
	return &result, nil
}

// candidateSnapshot pages both kinds against the same immutable snapshot.
// An explicit end is required; a missing cursor or repeated page is not empty.
func (s *Service) candidateSnapshot(ctx context.Context, scope api.Scope, target api.LifeRef, generation api.Generation) ([]api.DecisionCandidate, api.ID, error) {
	all := []api.DecisionCandidate{}
	var snapshot api.ID
	var asOf api.Timestamp
	seenIDs := make(map[api.ID]bool)
	seenSources := make(map[api.SourceRef]bool)
	for _, kind := range []string{"binding", "reminder"} {
		cursor := ""
		seenCursors := make(map[string]bool)
		for pages := 0; ; pages++ {
			if err := contextError(ctx); err != nil {
				return nil, "", err
			}
			if pages >= 64 {
				return nil, "", &api.Error{Code: api.CodeUnscored, Owner: "lb-v2-guidance",
					Message: "guidance candidate snapshot exceeds the complete retrieval bound",
					Instead: "Use a complete bounded snapshot; do not truncate binding policy or reminders."}
			}
			page, err := s.deps.Store.DecisionCandidates(ctx, scope, api.DecisionQuery{
				Target: target, SnapshotID: snapshot, Kind: kind, Cursor: cursor, Limit: 200,
			})
			if err != nil {
				return nil, "", err
			}
			if !validID(page.SnapshotID) || page.PolicyGeneration != generation || page.Candidates == nil || len(page.Candidates) > 200 {
				return nil, "", integrity("candidate backend returned an invalid snapshot page")
			}
			if snapshot == "" {
				snapshot, asOf = page.SnapshotID, page.AsOf
				if _, err := time.Parse(time.RFC3339Nano, string(asOf)); err != nil || !strings.HasSuffix(string(asOf), "Z") {
					return nil, "", integrity("candidate snapshot has no valid clock")
				}
			} else if page.SnapshotID != snapshot || page.AsOf != asOf {
				return nil, "", integrity("candidate backend mixed immutable snapshots")
			}
			for _, candidate := range page.Candidates {
				if seenIDs[candidate.ID] || candidate.Binding != (kind == "binding") ||
					!validAuthority(candidate) {
					return nil, "", integrity("candidate backend lost authority, identity or binding provenance")
				}
				seenIDs[candidate.ID] = true
				if candidate.Authority.Kind == "human" {
					projection, err := s.deps.Store.Decision(ctx, scope, candidate.ID)
					if err != nil {
						return nil, "", err
					}
					if projection.RecordID != candidate.ID || projection.Candidate.ID != candidate.ID ||
						projection.Candidate.Source != candidate.Source || projection.Candidate.Authority != candidate.Authority {
						return nil, "", integrity("human decision differs from its retained canonical projection")
					}
				} else if !seenSources[candidate.Source] {
					source, err := s.deps.Store.Source(ctx, scope, candidate.Source)
					if err != nil {
						return nil, "", err
					}
					if source.Source != candidate.Source || !validID(source.Content.ID) ||
						source.Content.SHA256 != candidate.Source.SHA256 || source.Content.Bytes < 0 ||
						source.Content.Bytes > api.MaxObjectBytes || source.Content.Class == "" {
						return nil, "", integrity("candidate source does not resolve to its exact retained generation")
					}
					seenSources[candidate.Source] = true
				}
				all = append(all, candidate)
			}
			if page.Complete {
				if page.Cursor != "" {
					return nil, "", integrity("complete candidate page retains a continuation cursor")
				}
				break
			}
			if page.Cursor == "" || seenCursors[page.Cursor] {
				return nil, "", integrity("candidate snapshot ended without complete coverage")
			}
			seenCursors[page.Cursor], cursor = true, page.Cursor
		}
	}
	if _, err := rankSelection(s.deps.Clock.Now(), 0, all, api.JudgeReply{}); err != nil {
		return nil, "", err
	}
	return all, snapshot, nil
}

func (s *Service) taskBytes(ctx context.Context, scope api.Scope, ref api.BlobRef) (result []byte, resultErr error) {
	if !validID(ref.ID) || !validDigest(ref.SHA256) || ref.Class != "task" || ref.Bytes < 0 || ref.Bytes > api.MaxObjectBytes {
		return nil, invalid("invalid retained task object reference")
	}
	scope, release, err := objectread.Bind(ctx, s.deps.Store, scope)
	if err != nil {
		return nil, err
	}
	defer release(&resultErr)
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return nil, err
	}
	if metadata.Ref != ref {
		return nil, integrity("task reference differs from committed object metadata")
	}
	data := make([]byte, 0, int(ref.Bytes))
	for int64(len(data)) < ref.Bytes {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		limit := min(api.MaxChunkBytes, int(ref.Bytes)-len(data))
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(data)), Limit: limit})
		if err != nil {
			return nil, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(data)) || len(chunk.Data) == 0 || len(chunk.Data) > limit || chunk.SHA256 != digestBytes(chunk.Data) {
			return nil, integrity("task backend returned invalid bytes, offset or chunk digest")
		}
		data = append(data, chunk.Data...)
	}
	end, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: ref.Bytes, Limit: 1})
	if err != nil {
		return nil, err
	}
	if end.ObjectID != ref.ID || end.Offset != ref.Bytes || len(end.Data) != 0 || end.SHA256 != digestBytes(nil) || digestBytes(data) != ref.SHA256 {
		return nil, integrity("task object is incomplete or differs from its retained digest")
	}
	return data, nil
}

func digestBytes(data []byte) api.Digest {
	sum := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(sum[:]))
}
