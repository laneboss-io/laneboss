package api

import "context"

// JudgeView identifies the complete approved policy snapshot that selected the
// judge. Sources is that snapshot's inventory, not an invented per-setting
// defining source. Endpoints and credential material are never part of it.
type JudgeView struct {
	Schema           string      `json:"schema"`
	Config           string      `json:"config"`
	PolicyGeneration Generation  `json:"policy_generation"`
	PolicySHA256     Digest      `json:"policy_sha256"`
	Context          RoleContext `json:"context"`
	Judge            JudgeConfig `json:"judge"`
	Sources          []SourceRef `json:"sources"`
}

type JudgeViewStore interface {
	JudgeView(context.Context, Scope) (ConfigView, error)
}
