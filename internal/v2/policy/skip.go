package policy

import "laneboss.io/laneboss/internal/v2/api"

// SkipContextDigest describes the approved work independently of a launch or
// turn. It is never an authorization or positive-proof key. Reuse still needs
// a fresh scored allow bound to the full caller/life/grant/turn context.
func SkipContextDigest(config string, command api.CommandData, policy api.EffectivePolicy) (api.Digest, error) {
	return digest(struct {
		Version string          `json:"version"`
		Config  string          `json:"config"`
		Command api.CommandData `json:"command"`
		Role    api.RoleContext `json:"role"`
		Policy  api.Generation  `json:"policy_generation"`
		Judge   api.JudgeConfig `json:"judge"`
	}{"skip-context-v1", config, command, policy.Context, policy.Generation, policy.Judge})
}
