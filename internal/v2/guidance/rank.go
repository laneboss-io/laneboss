package guidance

import (
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

const (
	defaultHalfLife = 14 * 24 * 60 * 60
	relevanceCutoff = 0.5
	reminderLimit   = 5
)

// rankSelection is a private, pure stage. Its candidates must come from the
// service's authoritative projection, never a lane-authored content object.
// New RPC selection still requires the contract's claim-owner/recovery
// protocol. This stage does not acquire a claim, mint or persist a receipt.
func rankSelection(now time.Time, halfLife int64, candidates []api.DecisionCandidate, reply api.JudgeReply) (api.Guidance, error) {
	return rankWithCutoff(now, halfLife, relevanceCutoff, candidates, reply)
}

// RankMeasuredSnapshot is shared by selection and the store's independent
// completion verifier. It grants no authority and persists no score; callers
// must first join every result to its retained candidate and measured audit.
func RankMeasuredSnapshot(now time.Time, policy api.EffectivePolicy, candidates []api.DecisionCandidate, reply api.JudgeReply) (api.Guidance, error) {
	return rankWithCutoff(now, policy.GuidanceHalfLifeSeconds, policy.GuidanceMinRelevance, candidates, reply)
}

func rankWithCutoff(now time.Time, halfLife int64, cutoff float64, candidates []api.DecisionCandidate, reply api.JudgeReply) (api.Guidance, error) {
	now = now.UTC()
	result := api.Guidance{
		AsOf:  api.Timestamp(now.UTC().Format(time.RFC3339Nano)),
		Items: []api.GuidanceItem{}, Status: "unavailable", JudgmentIDs: []api.ID{},
	}
	if math.IsNaN(cutoff) || math.IsInf(cutoff, 0) || cutoff < 0 || cutoff > 1 {
		return api.Guidance{}, invalid("invalid approved guidance relevance cutoff")
	}
	// EffectivePolicy uses a scalar: zero is its unspecified/default value.
	if cutoff == 0 {
		cutoff = relevanceCutoff
	}
	if halfLife == 0 {
		halfLife = defaultHalfLife
	}
	if halfLife < 0 || halfLife > maxInteger || now.Year() < 0 || now.Year() > 9999 {
		return api.Guidance{}, invalid("invalid guidance clock or half-life")
	}
	byID := make(map[api.ID]api.DecisionCandidate, len(candidates))
	type decisionAge struct {
		seconds int64
		exact   float64
	}
	ages := make(map[api.ID]decisionAge, len(candidates))
	history := 0
	for _, candidate := range candidates {
		if _, duplicate := byID[candidate.ID]; duplicate {
			return api.Guidance{}, candidateError("duplicate authoritative decision ID")
		}
		if !validID(candidate.ID) || !validID(candidate.Source.ID) ||
			!validDigest(candidate.Source.SHA256) || candidate.Source.Generation == 0 ||
			candidate.Source.Generation > maxInteger || !validAuthority(candidate) ||
			!utf8.ValidString(candidate.Source.Path) || candidate.Text == "" ||
			!utf8.ValidString(candidate.Text) {
			return api.Guidance{}, candidateError("incomplete authoritative decision provenance")
		}
		effective, err := time.Parse(time.RFC3339Nano, string(candidate.EffectiveAt))
		if err != nil || !strings.HasSuffix(string(candidate.EffectiveAt), "Z") {
			return api.Guidance{}, candidateError("invalid authoritative decision time")
		}
		seconds := now.Unix() - effective.Unix()
		nanos := now.Nanosecond() - effective.Nanosecond()
		if nanos < 0 {
			seconds--
			nanos += 1e9
		}
		if seconds < 0 {
			seconds, nanos = 0, 0
		}
		age := decisionAge{seconds: seconds, exact: float64(seconds) + float64(nanos)/1e9}
		byID[candidate.ID], ages[candidate.ID] = candidate, age
		if candidate.Binding {
			result.Items = append(result.Items, api.GuidanceItem{
				DecisionID: candidate.ID, Source: candidate.Source,
				AgeSeconds: age.seconds, Weight: 1, Binding: true,
			})
		} else {
			history++
		}
	}
	sort.Slice(result.Items, func(i, j int) bool {
		return result.Items[i].DecisionID < result.Items[j].DecisionID
	})
	if history == 0 {
		zero := float64(0)
		result.Status, result.WeightedScore = "empty", &zero
		return result, nil
	}
	if validID(reply.ID) {
		result.JudgmentID = reply.ID
		result.JudgmentIDs = []api.ID{reply.ID}
	}
	if reply.Status != "scored" || !validID(reply.ID) || len(reply.Results) != history {
		result.Notice = "Historical guidance unavailable: judgment is absent or incomplete. Binding context is retained."
		return result, nil
	}
	probabilities := make(map[api.ID]float64, history)
	for _, answer := range reply.Results {
		candidate, exists := byID[answer.QuestionID]
		_, duplicate := probabilities[answer.QuestionID]
		if !exists || candidate.Binding || duplicate || answer.Status != "scored" ||
			answer.Probability == nil || math.IsNaN(*answer.Probability) ||
			math.IsInf(*answer.Probability, 0) || *answer.Probability < 0 || *answer.Probability > 1 {
			result.Notice = "Historical guidance unavailable: invalid or incomplete probabilities. Binding context is retained."
			return result, nil
		}
		probabilities[answer.QuestionID] = *answer.Probability
	}
	type ranked struct {
		item     api.GuidanceItem
		age      float64
		logScore float64
	}
	eligible := make([]ranked, 0, history)
	minAge := math.Inf(1)
	for id, probability := range probabilities {
		if probability < cutoff {
			continue
		}
		age := ages[id].exact
		weight := math.Exp2(-age / float64(halfLife))
		score := weight * probability
		eligible = append(eligible, ranked{
			item: api.GuidanceItem{
				DecisionID: id, Source: byID[id].Source, Probability: &probability,
				AgeSeconds: ages[id].seconds, Weight: weight, Score: &score,
			},
			age: age,
		})
		minAge = math.Min(minAge, age)
	}
	for index := range eligible {
		eligible[index].logScore = math.Log2(*eligible[index].item.Probability) -
			(eligible[index].age-minAge)/float64(halfLife)
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].logScore != eligible[j].logScore {
			return eligible[i].logScore > eligible[j].logScore
		}
		return eligible[i].item.DecisionID < eligible[j].item.DecisionID
	})
	// Scale every eligible weight by the same factor for the mean. This avoids
	// 0/0 for very old history without expiring it or changing ranking.
	var numerator, denominator float64
	for index, candidate := range eligible {
		weight := math.Exp2(-(candidate.age - minAge) / float64(halfLife))
		numerator += weight * *candidate.item.Probability
		denominator += weight
		if index < reminderLimit {
			result.Items = append(result.Items, candidate.item)
		}
	}
	mean := float64(0)
	if denominator > 0 {
		mean = numerator / denominator
	}
	result.Status, result.WeightedScore = "scored", &mean
	if len(eligible) > reminderLimit {
		result.Notice = "Only the five highest ranked historical reminders are offered. Binding context is retained separately."
	}
	return result, nil
}

func candidateError(message string) *api.Error {
	return &api.Error{
		Code: api.CodeIntegrity, Owner: "lb-v2-guidance", Message: message,
		Instead: "Preserve the authoritative decision snapshot and repair its projection.",
	}
}

func validAuthority(candidate api.DecisionCandidate) bool {
	authority := candidate.Authority
	if !validID(authority.ReceiptID) || authority.SourceSeq == 0 || authority.SourceSeq > maxInteger || authority.OrgGeneration > maxInteger {
		return false
	}
	switch authority.Kind {
	case "human":
		return authority.OrgGeneration == 0 && candidate.Source.ID == candidate.ID && candidate.Source.Path == ""
	case "d6":
		return authority.OrgGeneration > 0 && candidate.Source.Path != ""
	default:
		return false
	}
}
