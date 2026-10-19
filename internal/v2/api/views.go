package api

type DashboardQuery struct {
	LifeID ID        `json:"life_id,omitempty"`
	Run    RunNumber `json:"run,omitempty"`
	Level  int       `json:"level,omitempty"`
	Driver Driver    `json:"driver,omitempty"`
	Since  Timestamp `json:"since,omitempty"`
	Until  Timestamp `json:"until,omitempty"`
	Cursor string    `json:"cursor"`
	Limit  int       `json:"limit"`
}

type TreeNode struct {
	InstanceID   ID     `json:"instance_id,omitempty"`
	LifeID       ID     `json:"life_id,omitempty"`
	ParentLifeID ID     `json:"parent_life_id,omitempty"`
	Level        int    `json:"level"`
	Role         string `json:"role"`
	State        string `json:"state"`
	Configured   bool   `json:"configured"`
	Live         bool   `json:"live"`
}

type TreeView struct {
	Nodes   []TreeNode `json:"nodes"`
	LastSeq Sequence   `json:"last_seq"`
	Cursor  string     `json:"cursor"`
}

type RawView struct {
	Records  []CaptureRecord `json:"records"`
	Messages []Mail          `json:"messages"`
	Gaps     []CaptureGap    `json:"gaps"`
	Cursor   string          `json:"cursor"`
}

type CaptureGap struct {
	BindingID   ID        `json:"binding_id,omitempty"`
	Target      LifeRef   `json:"target"`
	Stream      string    `json:"stream"`
	StartOffset int64     `json:"start_offset"`
	EndOffset   *int64    `json:"end_offset,omitempty"`
	Reason      string    `json:"reason"`
	ObservedAt  Timestamp `json:"observed_at"`
}

type RefusalCount struct {
	RuleID           ID     `json:"rule_id"`
	Level            int    `json:"level"`
	Refused          uint64 `json:"refused"`
	Warned           uint64 `json:"warned"`
	Unscored         uint64 `json:"unscored"`
	CriticalUnscored uint64 `json:"critical_unscored"`
	UnknownCoverage  bool   `json:"unknown_coverage"`
}

type RefusalView struct {
	Counts   []RefusalCount `json:"counts"`
	Receipts []ID           `json:"receipts"`
	Cursor   string         `json:"cursor"`
}

type Resource struct {
	ID             ID        `json:"id"`
	Kind           string    `json:"kind"`
	Path           string    `json:"path"`
	Version        string    `json:"version"`
	SHA256         Digest    `json:"sha256"`
	Source         BlobRef   `json:"source"`
	ApprovalID     ID        `json:"approval_id,omitempty"`
	Declared       bool      `json:"declared"`
	VerifiedLoaded bool      `json:"verified_loaded"`
	ObservedAt     Timestamp `json:"observed_at"`
}

type ResourceView struct {
	Resources  []Resource `json:"resources"`
	Generation Generation `json:"generation"`
	Cursor     string     `json:"cursor"`
}

type ApprovalView struct {
	Changes      []ChangeRequest  `json:"changes"`
	Approvals    []ChangeApproval `json:"approvals"`
	Applications []ChangeReceipt  `json:"applications"`
	Cursor       string           `json:"cursor"`
}

type DecisionView struct {
	Decisions []DecisionCandidate `json:"decisions"`
	Cursor    string              `json:"cursor"`
}
