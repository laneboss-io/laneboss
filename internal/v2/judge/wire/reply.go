package wire

import (
	"math"

	"laneboss.io/laneboss/internal/v2/api"
)

// MeasuredUsage reports only usage from the strict retained provider envelope.
// Unknown/invalid bytes never release a durable cost reservation as zero.
func MeasuredUsage(raw []byte, request api.JudgeRequest) (int64, int64, bool) {
	_, ids, err := Payload(request)
	if err != nil {
		return 0, 0, false
	}
	decoded, _ := decodeResponse(raw, ids, request.Config.Model)
	return decoded.input, decoded.output, decoded.usageKnown
}

// AuditReply compares normalized output with the actual protected provider
// bytes and complete fit proof. A worker's success label alone is insufficient.
func AuditReply(reply api.JudgeReply, request api.JudgeRequest, fit api.TokenFit, raw []byte) error {
	body, ids, err := Payload(request)
	if err != nil {
		return err
	}
	invalid := func() error { return failure(api.CodeIntegrity, "judge audit disagrees with retained bytes") }
	if reply.ID != request.ID || reply.Results == nil || reply.InputBytes != len(body) ||
		reply.SelectedModel != request.Config.Model || reply.DeploymentSHA256 != request.Config.DeploymentSHA256 ||
		reply.LatencyMS < 0 || reply.CostMicros < 0 || reply.CostMicros > request.MaxCostMicros ||
		reply.Request == nil || reply.Request.Class != "judge_request" ||
		reply.Request.Bytes != int64(len(body)) || reply.Request.SHA256 != Digest(body) ||
		fit.InputBytes != len(body) || fit.ContextTokens != request.Config.ContextTokens ||
		fit.TokenizerSHA256 != request.Config.TokenizerSHA256 || fit.InputTokens < 0 || fit.InputTokens != reply.InputTokens {
		return invalid()
	}
	if reply.Raw == nil && len(raw) != 0 || reply.Raw != nil &&
		(reply.Raw.Class != "judge_raw" || reply.Raw.Bytes != int64(len(raw)) || reply.Raw.SHA256 != Digest(raw)) {
		return invalid()
	}
	if reply.Status != "scored" {
		if reply.Status != "partial" && reply.Status != "unavailable" || reply.UnavailableReason == "" || len(reply.Results) != len(ids) {
			return invalid()
		}
		seen := make(map[api.ID]bool, len(ids))
		for _, id := range ids {
			seen[id] = true
		}
		for _, result := range reply.Results {
			if !seen[result.QuestionID] || result.Probability != nil || result.Status != "unscored" {
				return invalid()
			}
			delete(seen, result.QuestionID)
		}
		return nil
	}
	if err := ScoredReply(reply, request); err != nil {
		return err
	}
	if !fit.Proved || fit.InputTokens < 1 || fit.InputTokens >= fit.ContextTokens {
		return invalid()
	}
	decoded, err := decodeResponse(raw, ids, request.Config.Model)
	if err != nil || decoded.partial || decoded.input != int64(fit.InputTokens) {
		return invalid()
	}
	for _, result := range reply.Results {
		if *result.Probability != decoded.answers[result.QuestionID] {
			return invalid()
		}
	}
	return nil
}

// ScoredReply checks a normalized result before a cache or worker publishes it.
// A reported success without every requested probability is an integrity error.
func ScoredReply(reply api.JudgeReply, request api.JudgeRequest) error {
	body, ids, err := Payload(request)
	if err != nil {
		return err
	}
	invalid := func() error { return failure(api.CodeIntegrity, "incomplete normalized judge score") }
	if reply.Status != "scored" || !ValidID(reply.ID) || reply.UnavailableReason != "" ||
		len(reply.Results) != len(ids) || reply.SelectedModel != request.Config.Model ||
		reply.ReportedModel != reply.SelectedModel ||
		reply.DeploymentSHA256 != request.Config.DeploymentSHA256 ||
		reply.InputBytes != len(body) || reply.InputTokens < 1 ||
		reply.InputTokens >= request.Config.ContextTokens || reply.LatencyMS < 0 ||
		reply.CostMicros < 0 || reply.CostMicros > request.MaxCostMicros ||
		reply.Request == nil || !ValidID(reply.Request.ID) ||
		reply.Request.Class != "judge_request" || reply.Request.Bytes != int64(len(body)) ||
		reply.Request.SHA256 != Digest(body) ||
		reply.Raw == nil || !ValidID(reply.Raw.ID) || !ValidDigest(reply.Raw.SHA256) ||
		reply.Raw.Class != "judge_raw" || reply.Raw.Bytes < 1 || reply.Raw.Bytes > MaxResponseBytes {
		return invalid()
	}
	batches := make(map[api.ID]bool, len(reply.BatchIDs))
	for _, id := range reply.BatchIDs {
		if !ValidID(id) || batches[id] {
			return invalid()
		}
		batches[id] = true
	}
	expected := make(map[api.ID]bool, len(ids))
	for _, id := range ids {
		expected[id] = true
	}
	for _, answer := range reply.Results {
		if !expected[answer.QuestionID] || answer.Status != "scored" || answer.Probability == nil ||
			math.IsNaN(*answer.Probability) || math.IsInf(*answer.Probability, 0) ||
			*answer.Probability < 0 || *answer.Probability > 1 {
			return invalid()
		}
		delete(expected, answer.QuestionID)
	}
	if len(expected) != 0 {
		return invalid()
	}
	return nil
}
