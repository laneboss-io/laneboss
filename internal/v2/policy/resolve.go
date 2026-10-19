// Package policy resolves organizational denies and evaluates their judged
// membership. It grants no OS, service, tool, or network authority.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

const (
	DefaultWarnThreshold = 0.50
	maxRules             = 512
	maxTextBytes         = 4096
)

// Layer is a service-internal source-loader input, never an RPC body. DefinedAt
// is nil for the org baseline. A role layer records its defining pair separately
// from each rule's applicability Scope. The source loader must retain and verify
// the exact D6-approved source bytes and calibration receipts before calling
// Resolve; this helper neither reads a lane file nor approves an org change.
type Layer struct {
	Source     api.SourceRef
	DefinedAt  *api.RoleContext
	Thresholds api.Thresholds
	Rules      []api.Rule
	Skip       []api.SkipEntry
}

// Resolve validates every source before selecting org + own pair + every higher
// role. Local thresholds apply only to entries defined in that local source.
// Missing local layers add nothing; they never remove the org baseline.
func Resolve(generation api.Generation, role api.RoleContext, layers []Layer, judge api.JudgeConfig, halfLife int64) (api.EffectivePolicy, error) {
	var empty api.EffectivePolicy
	if generation == 0 || !validRole(role) || len(layers) == 0 || len(layers) > maxRules || halfLife <= 0 {
		return empty, invalid("invalid policy source set")
	}
	var err error
	judge, err = api.ResolveJudgeConfig(judge)
	if err != nil {
		return empty, err
	}
	ordered := append([]Layer(nil), layers...)
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i].DefinedAt, ordered[j].DefinedAt
		if a == nil || b == nil {
			return a == nil && b != nil
		}
		if a.Level != b.Level {
			return a.Level < b.Level
		}
		return a.Role < b.Role
	})
	result := api.EffectivePolicy{
		Generation: generation, Context: role, Judge: judge,
		Rules: []api.Rule{}, Skip: []api.SkipEntry{}, Sources: []api.SourceRef{},
		GuidanceHalfLifeSeconds: halfLife, GuidanceMinRelevance: 0.50,
		ProfileExclusions: []api.ID{},
	}
	seenSources, seenPairs := map[api.ID]bool{}, map[string]bool{}
	orgCount, count := 0, 0
	var orgThresholds api.Thresholds
	for _, layer := range ordered {
		if !validSource(layer.Source) || seenSources[layer.Source.ID] {
			return empty, invalid("invalid or duplicate policy source")
		}
		seenSources[layer.Source.ID] = true
		pair := "org"
		selected := true
		if layer.DefinedAt == nil {
			orgCount++
			orgThresholds = layer.Thresholds
			result.GuidanceSource = layer.Source
		} else {
			if !validRole(*layer.DefinedAt) || layer.DefinedAt.InstanceID != "" {
				return empty, invalid("invalid defining role")
			}
			key, err := json.Marshal(layer.DefinedAt)
			if err != nil {
				return empty, invalid("invalid defining role encoding")
			}
			pair = string(key)
			selected = layer.DefinedAt.Level > role.Level ||
				(layer.DefinedAt.Level == role.Level && layer.DefinedAt.Role == role.Role)
		}
		thresholds := layer.Thresholds
		if thresholds == (api.Thresholds{}) {
			thresholds = orgThresholds
		}
		if seenPairs[pair] || !validThresholds(thresholds) || len(layer.Rules) > maxRules || len(layer.Skip) > maxRules {
			return empty, invalid("duplicate defining scope or invalid thresholds")
		}
		seenPairs[pair] = true
		if selected {
			result.Sources = append(result.Sources, layer.Source)
		}
		seenRules, seenSkips := map[api.ID]bool{}, map[api.ID]bool{}
		for _, sourceRule := range layer.Rules {
			count++
			rule := sourceRule
			rule.Scope = cloneScope(rule.Scope)
			if rule.Source != (api.SourceRef{}) && rule.Source != layer.Source {
				return empty, invalid("rule provenance differs from its defining source")
			}
			rule.Source = layer.Source
			if rule.Thresholds == (api.Thresholds{}) {
				rule.Thresholds = thresholds
			}
			if !validRule(rule) || seenRules[rule.ID] {
				return empty, invalid("invalid blacklist entry")
			}
			seenRules[rule.ID] = true
			if selected && applies(rule.Scope, role) {
				result.Rules = append(result.Rules, rule)
			}
		}
		for _, sourceSkip := range layer.Skip {
			skip := sourceSkip
			if skip.Source != (api.SourceRef{}) && skip.Source != layer.Source {
				return empty, invalid("skip provenance differs from its defining source")
			}
			skip.Source = layer.Source
			if !validSkip(skip) || seenSkips[skip.ID] {
				return empty, invalid("invalid skip entry")
			}
			seenSkips[skip.ID] = true
			if selected {
				result.Skip = append(result.Skip, skip)
			}
		}
	}
	if orgCount != 1 || count > maxRules {
		return empty, invalid("one org baseline and bounded rules are required")
	}
	if err := validatePolicy(result); err != nil {
		return empty, err
	}
	result.SHA256, err = policyDigest(result)
	if err != nil {
		return empty, err
	}
	return result, nil
}

func invalid(message string) *api.Error {
	return &api.Error{Code: api.CodeInvalid, Message: message,
		Instead: "Correct the file input or have L6 stage an exact D6 source change."}
}

func integrity(message string) *api.Error {
	return &api.Error{Code: api.CodeIntegrity, Message: message,
		Instead: "Retain the evidence and repair the protected service projection."}
}

func validID(value api.ID) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validDigest(value api.Digest) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func textOK(value string, limit int) bool {
	return utf8.ValidString(value) && len(value) <= limit && strings.TrimSpace(value) != "" && !strings.ContainsRune(value, 0)
}

func validRole(role api.RoleContext) bool {
	return role.Level >= 3 && role.Level <= 6 && validID(api.ID(role.Role)) &&
		(role.InstanceID == "" || validID(role.InstanceID))
}

func finiteProbability(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 1
}

func validThresholds(t api.Thresholds) bool {
	return finiteProbability(t.Match) &&
		finiteProbability(t.UncertainLow) && finiteProbability(t.UncertainHigh) &&
		t.UncertainLow <= t.UncertainHigh && validID(t.CalibrationID)
}

func validSource(source api.SourceRef) bool {
	return validID(source.ID) && textOK(source.Path, maxTextBytes) && validDigest(source.SHA256) && source.Generation > 0
}

func validRule(rule api.Rule) bool {
	if !validID(rule.ID) || !textOK(rule.Text, maxTextBytes) || !textOK(rule.Instead, maxTextBytes) ||
		(rule.Band != "refuse" && rule.Band != "warn") || !validSource(rule.Source) || !validThresholds(rule.Thresholds) ||
		rule.Scope.Levels == nil || rule.Scope.Roles == nil {
		return false
	}
	levels, roles := map[int]bool{}, map[string]bool{}
	for _, level := range rule.Scope.Levels {
		if level < 3 || level > 6 || levels[level] {
			return false
		}
		levels[level] = true
	}
	for _, role := range rule.Scope.Roles {
		if !validID(api.ID(role)) || roles[role] {
			return false
		}
		roles[role] = true
	}
	return true
}

func validSkip(skip api.SkipEntry) bool {
	return validID(skip.ID) && textOK(skip.Description, maxTextBytes) && validDigest(skip.RuleSetSHA256) &&
		validDigest(skip.ContextSHA256) && validSource(skip.Source)
}

func applies(scope api.RuleScope, role api.RoleContext) bool {
	levelOK, roleOK := len(scope.Levels) == 0, len(scope.Roles) == 0
	for _, level := range scope.Levels {
		levelOK = levelOK || level == role.Level
	}
	for _, name := range scope.Roles {
		roleOK = roleOK || name == role.Role
	}
	return levelOK && roleOK
}

func cloneScope(scope api.RuleScope) api.RuleScope {
	return api.RuleScope{Levels: append([]int{}, scope.Levels...), Roles: append([]string{}, scope.Roles...)}
}

func validateJudge(config api.JudgeConfig) bool {
	resolved, err := api.ResolveJudgeConfig(config)
	if err != nil {
		return false
	}
	config = resolved
	return textOK(config.Model, 256) &&
		validDigest(config.DeploymentSHA256) && validDigest(config.TokenizerSHA256) &&
		config.ContextTokens > 0 && config.MaxBytes > 0 && config.MaxBytes <= api.MaxJudgeBytes &&
		config.MaxQuestions > 0 && config.MaxQuestions <= 12 &&
		config.CommandDeadlineMS > 0 && config.CommandDeadlineMS <= 60000 &&
		config.GuidanceDeadlineMS > 0 && config.GuidanceDeadlineMS <= 60000 &&
		config.CacheTTLMS >= 0 && config.CacheTTLMS <= 30000 &&
		config.OutagePolicy == "critical-only"
}

func validatePolicy(policy api.EffectivePolicy) error {
	if policy.Generation == 0 || !validRole(policy.Context) || !validateJudge(policy.Judge) ||
		policy.GuidanceHalfLifeSeconds <= 0 || len(policy.Rules) > maxRules || len(policy.Skip) > maxRules ||
		len(policy.Sources) == 0 || len(policy.Sources) > maxRules || policy.Rules == nil || policy.Skip == nil ||
		!finiteProbability(policy.GuidanceMinRelevance) || policy.ProfileExclusions == nil {
		return invalid("invalid effective policy")
	}
	sources := map[api.ID]api.SourceRef{}
	for _, source := range policy.Sources {
		if !validSource(source) {
			return invalid("invalid policy provenance")
		}
		if _, found := sources[source.ID]; found {
			return invalid("duplicate policy source")
		}
		sources[source.ID] = source
	}
	if !validSource(policy.GuidanceSource) || sources[policy.GuidanceSource.ID] != policy.GuidanceSource {
		return invalid("invalid guidance defining source")
	}
	exclusions := map[api.ID]bool{}
	for _, id := range policy.ProfileExclusions {
		if !validID(id) || exclusions[id] {
			return invalid("invalid profile exclusion")
		}
		exclusions[id] = true
	}
	seen := map[api.ID]bool{}
	for _, rule := range policy.Rules {
		if !validRule(rule) || seen[rule.ID] || sources[rule.Source.ID] != rule.Source || !applies(rule.Scope, policy.Context) {
			return invalid("invalid, duplicate or out-of-scope effective entry")
		}
		seen[rule.ID] = true
	}
	seen = map[api.ID]bool{}
	for _, skip := range policy.Skip {
		if !validSkip(skip) || seen[skip.ID] || sources[skip.Source.ID] != skip.Source {
			return invalid("invalid effective skip provenance")
		}
		seen[skip.ID] = true
	}
	return nil
}

func digestBytes(data []byte) api.Digest {
	sum := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(sum[:]))
}

func digest(value any) (api.Digest, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", integrity("policy object cannot be encoded")
	}
	return digestBytes(data), nil
}

// These are versioned internal content hashes, not the RPC's JCS intent hash.
func policyDigest(policy api.EffectivePolicy) (api.Digest, error) {
	policy.SHA256 = ""
	return digest(policy)
}

// RuleSetDigest excludes skip sources, so approving an exemption is not a
// circular hash. Each rule still binds its exact defining-source version.
func RuleSetDigest(policy api.EffectivePolicy) (api.Digest, error) {
	return digest(struct {
		Version string          `json:"version"`
		Context api.RoleContext `json:"context"`
		Rules   []api.Rule      `json:"rules"`
		Judge   api.JudgeConfig `json:"judge"`
	}{"rules-v1", policy.Context, policy.Rules, policy.Judge})
}
