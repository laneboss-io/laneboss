package api

// R108 selects the default. Deployment/tokenizer pins and a proved context bound
// still come from protected installation/configuration, never invented defaults.
const (
	DefaultJudgeProvider = "clef-sglang"
	DefaultJudgeModel    = "Cloudflare/clef-flash"
)

// ResolveJudgeConfig applies R108 without inventing deployment/tokenizer pins,
// relaxing fit bounds or switching providers after an outage.
func ResolveJudgeConfig(config JudgeConfig) (JudgeConfig, error) {
	if config.Provider == "" {
		config.Provider = DefaultJudgeProvider
	}
	switch config.Provider {
	case DefaultJudgeProvider:
		if config.Model == "" {
			config.Model = DefaultJudgeModel
		}
		if config.Model != DefaultJudgeModel {
			return JudgeConfig{}, &Error{Code: CodeInvalid, Message: "self-hosted Clef requires its full pinned model name", Instead: "Configure Cloudflare/clef-flash and the verified deployment/tokenizer through D6."}
		}
		if !bindingDigest.MatchString(string(config.DeploymentSHA256)) || !bindingDigest.MatchString(string(config.TokenizerSHA256)) || config.ContextTokens <= 0 {
			return JudgeConfig{}, &Error{Code: CodeInvalid, Message: "self-hosted Clef requires deployment, tokenizer and context pins", Instead: "Approve the measured deployment/tokenizer digests and positive context bound through D6."}
		}
	case "typesafe":
		if config.Model == "" {
			return JudgeConfig{}, &Error{Code: CodeInvalid, Message: "explicit TypeSafe selection requires a full model name", Instead: "Supply the approved alternative model through D6."}
		}
	default:
		return JudgeConfig{}, &Error{Code: CodeInvalid, Message: "unknown judge provider", Instead: "Select self-hosted Clef or the explicit TypeSafe alternative through D6."}
	}
	return config, nil
}

// ResolveJudgeForScope pins the raw provider request to the approved policy.
// The scoped judge must additionally validate the authentic life/turn/grants
// and select only the installed port for this returned configuration.
func ResolveJudgeForScope(scope Scope, request JudgeRequest, policy EffectivePolicy) (JudgeConfig, error) {
	if policy.Generation == 0 || policy.Generation != scope.PolicyGeneration || request.Context.PolicyGeneration != scope.PolicyGeneration {
		return JudgeConfig{}, &Error{Code: CodeConflict, Message: "judge policy generation is stale", Instead: "Resolve the current approved policy for the authenticated scope."}
	}
	approved, err := ResolveJudgeConfig(policy.Judge)
	if err != nil {
		return JudgeConfig{}, err
	}
	resolved, err := ResolveJudgeConfig(request.Config)
	if err != nil {
		return JudgeConfig{}, err
	}
	if resolved != approved {
		return JudgeConfig{}, &Error{Code: CodeForbidden, Message: "judge configuration differs from the approved policy", Instead: "Use EffectivePolicy.Judge at the scope's policy generation; provider changes require D6."}
	}
	return approved, nil
}

type SourceRef struct {
	ID         ID         `json:"id"`
	Path       string     `json:"path"`
	SHA256     Digest     `json:"sha256"`
	Generation Generation `json:"generation"`
}

type RoleContext struct {
	Level      int    `json:"level"`
	Role       string `json:"role"`
	InstanceID ID     `json:"instance_id,omitempty"`
}

type Thresholds struct {
	Match         float64 `json:"match"`
	UncertainLow  float64 `json:"uncertain_low"`
	UncertainHigh float64 `json:"uncertain_high"`
	CalibrationID ID      `json:"calibration_id"`
}

type RuleScope struct {
	Levels []int    `json:"levels"`
	Roles  []string `json:"roles"`
}

type Rule struct {
	ID         ID         `json:"id"`
	Text       string     `json:"text"`
	Instead    string     `json:"instead"`
	Band       string     `json:"band"`
	Critical   bool       `json:"critical"`
	Scope      RuleScope  `json:"scope"`
	Source     SourceRef  `json:"source"`
	Thresholds Thresholds `json:"thresholds"`
}

type SkipEntry struct {
	ID            ID        `json:"id"`
	Description   string    `json:"description"`
	RuleSetSHA256 Digest    `json:"rule_set_sha256"`
	ContextSHA256 Digest    `json:"context_sha256"`
	Source        SourceRef `json:"source"`
}

type EffectivePolicy struct {
	AllowCaptureRefusal      bool        `json:"allow_capture_refusal,omitempty"`
	CaptureRefusalApprovalID ID          `json:"capture_refusal_approval_id,omitempty"`
	GuidanceMinRelevance     float64     `json:"guidance_min_relevance"`
	GuidanceSource           SourceRef   `json:"guidance_source"`
	ProfileExclusions        []ID        `json:"profile_exclusions"`
	Generation               Generation  `json:"generation"`
	SHA256                   Digest      `json:"sha256"`
	Context                  RoleContext `json:"context"`
	Rules                    []Rule      `json:"rules"`
	Skip                     []SkipEntry `json:"skip"`
	Sources                  []SourceRef `json:"sources"`
	Judge                    JudgeConfig `json:"judge"`
	GuidanceHalfLifeSeconds  int64       `json:"guidance_half_life_seconds"`
}

type JudgeConfig struct {
	Provider           string `json:"provider"`
	Model              string `json:"model"`
	DeploymentSHA256   Digest `json:"deployment_sha256"`
	TokenizerSHA256    Digest `json:"tokenizer_sha256"`
	ContextTokens      int    `json:"context_tokens"`
	MaxBytes           int    `json:"max_bytes"`
	MaxQuestions       int    `json:"max_questions"`
	CommandDeadlineMS  int64  `json:"command_deadline_ms"`
	GuidanceDeadlineMS int64  `json:"guidance_deadline_ms"`
	CacheTTLMS         int64  `json:"cache_ttl_ms"`
	OutagePolicy       string `json:"outage_policy"`
}

type PolicyGetRequest struct {
	LifeID ID `json:"life_id"`
}

type CommandData struct {
	Tool          string   `json:"tool"`
	Command       []byte   `json:"command"`
	Argv          []string `json:"argv"`
	DeclaredPaths []string `json:"declared_paths"`
	CWD           string   `json:"cwd"`
	RawSHA256     Digest   `json:"raw_sha256"`
}

type PolicyEvaluateRequest struct {
	Target        LifeRef     `json:"target"`
	LogicalTurnID ID          `json:"logical_turn_id"`
	Command       CommandData `json:"command"`
}

type RuleDecision struct {
	RuleID      ID         `json:"rule_id"`
	Result      string     `json:"result"`
	Probability *float64   `json:"probability,omitempty"`
	Critical    bool       `json:"critical"`
	Thresholds  Thresholds `json:"thresholds"`
	Reason      string     `json:"reason"`
	Instead     string     `json:"instead"`
	JudgmentID  ID         `json:"judgment_id,omitempty"`
}

type PolicyDecision struct {
	ID               ID             `json:"id"`
	Result           string         `json:"result"`
	Rules            []RuleDecision `json:"rules"`
	PolicyGeneration Generation     `json:"policy_generation"`
	Input            BlobRef        `json:"input"`
	CacheOf          ID             `json:"cache_of,omitempty"`
	SkipID           ID             `json:"skip_id,omitempty"`
	LatencyMS        int64          `json:"latency_ms"`
	AuditComplete    bool           `json:"audit_complete"`
}

type JudgeContext struct {
	Config           string      `json:"config"`
	Target           LifeRef     `json:"target"`
	Role             RoleContext `json:"role"`
	LogicalTurnID    ID          `json:"logical_turn_id"`
	GrantSetID       ID          `json:"grant_set_id"`
	GrantsSHA256     Digest      `json:"grants_sha256"`
	PolicyGeneration Generation  `json:"policy_generation"`
	CWD              string      `json:"cwd"`
}

type JudgeRule struct {
	ID              ID     `json:"id"`
	Text            string `json:"text"`
	SourceSHA256    Digest `json:"source_sha256"`
	CriteriaVersion string `json:"criteria_version"`
}

type DecisionCandidate struct {
	Authority   DecisionAuthority     `json:"authority"`
	AppliesTo   DecisionApplicability `json:"applies_to"`
	ID          ID                    `json:"id"`
	Text        string                `json:"text"`
	Source      SourceRef             `json:"source"`
	EffectiveAt Timestamp             `json:"effective_at"`
	Binding     bool                  `json:"binding"`
}

type JudgeRequest struct {
	ID            ID                  `json:"id"`
	Purpose       string              `json:"purpose"`
	Rules         []JudgeRule         `json:"rules"`
	Command       *CommandData        `json:"command,omitempty"`
	Decisions     []DecisionCandidate `json:"decisions"`
	Context       JudgeContext        `json:"context"`
	Task          []byte              `json:"task"`
	Config        JudgeConfig         `json:"config"`
	DeadlineMS    int64               `json:"deadline_ms"`
	MaxCostMicros int64               `json:"max_cost_micros"`
}

type Judgment struct {
	QuestionID  ID       `json:"question_id"`
	Status      string   `json:"status"`
	Probability *float64 `json:"probability,omitempty"`
	Reason      string   `json:"reason"`
}

type JudgeReply struct {
	Request           *BlobRef   `json:"request,omitempty"`
	BatchIDs          []ID       `json:"batch_ids,omitempty"`
	ID                ID         `json:"id"`
	Status            string     `json:"status"`
	Results           []Judgment `json:"results"`
	SelectedModel     string     `json:"selected_model"`
	ReportedModel     string     `json:"reported_model"`
	DeploymentSHA256  Digest     `json:"deployment_sha256"`
	LatencyMS         int64      `json:"latency_ms"`
	InputBytes        int        `json:"input_bytes"`
	InputTokens       int        `json:"input_tokens"`
	CostMicros        int64      `json:"cost_micros"`
	Raw               *BlobRef   `json:"raw,omitempty"`
	UnavailableReason string     `json:"unavailable_reason"`
}

type GuidanceRequest struct {
	Target        LifeRef `json:"target"`
	LogicalTurnID ID      `json:"logical_turn_id"`
	Task          BlobRef `json:"task"`
}

type GuidanceItem struct {
	DecisionID  ID        `json:"decision_id"`
	Source      SourceRef `json:"source"`
	Probability *float64  `json:"probability,omitempty"`
	AgeSeconds  int64     `json:"age_seconds"`
	Weight      float64   `json:"weight"`
	Score       *float64  `json:"score,omitempty"`
	Binding     bool      `json:"binding"`
}

type Guidance struct {
	Target              LifeRef        `json:"target"`
	Task                BlobRef        `json:"task"`
	PolicyGeneration    Generation     `json:"policy_generation"`
	CandidateSnapshotID ID             `json:"candidate_snapshot_id"`
	ReservationID       ID             `json:"reservation_id"`
	JudgmentIDs         []ID           `json:"judgment_ids"`
	ID                  ID             `json:"id"`
	LogicalTurnID       ID             `json:"logical_turn_id"`
	AsOf                Timestamp      `json:"as_of"`
	Items               []GuidanceItem `json:"items"`
	WeightedScore       *float64       `json:"weighted_score,omitempty"`
	JudgmentID          ID             `json:"judgment_id,omitempty"`
	Status              string         `json:"status"`
	Notice              string         `json:"notice"`
}

type TemplateRequest struct {
	Claim      LaunchClaim `json:"-"`
	Context    RoleContext `json:"context"`
	Task       BlobRef     `json:"task"`
	GrantSetID ID          `json:"grant_set_id"`
}

type BriefingRequest struct {
	Role   string `json:"role"`
	Level  int    `json:"level"`
	LifeID ID     `json:"life_id,omitempty"`
}

type Briefing struct {
	Markdown         BlobRef      `json:"markdown"`
	Template         TemplateRef  `json:"template"`
	PolicyGeneration Generation   `json:"policy_generation"`
	Sources          []SourceRef  `json:"sources"`
	Checks           []Capability `json:"checks"`
	LaneGroups       LaneGroups   `json:"lane_groups"`
}

type LaneGroups struct {
	Running  []ID `json:"running"`
	Ended    []ID `json:"ended"`
	Accepted []ID `json:"accepted"`
	Lost     []ID `json:"lost"`
	Idle     []ID `json:"idle"`
	Others   []ID `json:"others"`
}

type ConfigReadRequest struct {
	View    string       `json:"view"`
	Context *RoleContext `json:"context,omitempty"`
}

type ConfigView struct {
	Generation Generation  `json:"generation"`
	Sources    []SourceRef `json:"sources"`
	Projection BlobRef     `json:"projection"`
	Warnings   []string    `json:"warnings"`
}

type OrgValidateRequest struct {
	Generation Generation `json:"generation"`
}

type OrgValidation struct {
	Valid    bool     `json:"valid"`
	Problems []string `json:"problems"`
}
