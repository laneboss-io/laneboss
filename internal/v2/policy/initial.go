package policy

import "laneboss.io/laneboss/internal/v2/api"

// ValidateInitial uses the ordinary policy validator and content hash. The
// installer must supply an explicit first generation; it resolves no defaults
// and cannot claim a later capture-refusal approval.
func ValidateInitial(raw []byte) (api.EffectivePolicy, error) {
	var p api.EffectivePolicy
	if err := api.DecodeObject(raw, &p); err != nil {
		return p, err
	}
	j, err := api.ResolveJudgeConfig(p.Judge)
	if err != nil {
		return p, err
	}
	if j != p.Judge || p.Generation != 1 || p.Context.InstanceID != "" || p.AllowCaptureRefusal || p.CaptureRefusalApprovalID != "" {
		return p, invalid("initial policy requires explicit generation-one inputs")
	}
	if err := validatePolicy(p); err != nil {
		return p, err
	}
	digest, err := policyDigest(p)
	if err != nil {
		return p, err
	}
	if p.SHA256 != digest {
		return p, integrity("initial policy content hash differs")
	}
	return p, nil
}
