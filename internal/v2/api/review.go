package api

import "context"

const (
	CoverageComplete    = "complete"
	CoveragePartial     = "partial"
	CoverageUnsupported = "unsupported"
	CoverageMissing     = "missing"
)

// The service resolves this subject from the actual ended run and a pinned
// post-drain read snapshot, never from the public review object's labels.
type ReviewSubject struct {
	Target           LifeRef                `json:"target"`
	LaunchID         ID                     `json:"launch_id"`
	Generation       Generation             `json:"generation"`
	EndEventID       ID                     `json:"end_event_id"`
	EndSeq           Sequence               `json:"end_seq"`
	Snapshot         BlobRef                `json:"snapshot"`
	SessionID        ID                     `json:"session_id"`
	InventorySeq     Sequence               `json:"inventory_seq"`
	CaptureBindingID ID                     `json:"capture_binding_id"`
	Streams          []CaptureStreamBinding `json:"streams"`
	RefusalIDs       []ID                   `json:"refusal_ids"`
}

type ReviewCheckFact struct {
	Name           string   `json:"name"`
	Receipt        BlobRef  `json:"receipt"`
	Target         LifeRef  `json:"target"`
	EndSeq         Sequence `json:"end_seq"`
	SnapshotSHA256 Digest   `json:"snapshot_sha256"`
	ExitCode       int      `json:"exit_code"`
	WorkerLeaseID  ID       `json:"worker_lease_id"`
	OperationID    ID       `json:"operation_id"`
}

type ReviewStreamFact struct {
	BindingID   ID    `json:"binding_id"`
	StreamID    ID    `json:"stream_id"`
	StartOffset int64 `json:"start_offset"`
	EndOffset   int64 `json:"end_offset"`
	EOF         bool  `json:"eof"`
	GapIDs      []ID  `json:"gap_ids"`
}

type ReviewInventory struct {
	Manifest     BlobRef            `json:"manifest"`
	ThroughSeq   Sequence           `json:"through_seq"`
	Streams      []ReviewStreamFact `json:"streams"`
	ToolRecords  BlobRef            `json:"tool_records"`
	ToolCoverage string             `json:"tool_coverage"`
}

type ReviewResolution struct {
	RefusalID ID       `json:"refusal_id"`
	EventSeq  Sequence `json:"event_seq"`
	Evidence  BlobRef  `json:"evidence"`
}

type ReviewFindingKind string

const (
	ReviewFindingFakeOnlyDiff ReviewFindingKind = "fake_only_diff"
	ReviewFindingEmptyDiff    ReviewFindingKind = "empty_diff"
)

// ReviewFinding is advisory evidence for the independent reviewer. It does
// not change measured coverage or prevent recording a result. A human or judge
// must clear the concern before treating the passing checks as proof of work.
type ReviewFinding struct {
	Kind    ReviewFindingKind `json:"kind"`
	Message string            `json:"message"`
}

type ReviewEvidence struct {
	Schema          string             `json:"schema"`
	Subject         ReviewSubject      `json:"subject"`
	VerifierLeaseID ID                 `json:"verifier_lease_id"`
	Diff            BlobRef            `json:"diff"`
	Checks          []ReviewCheckFact  `json:"checks"`
	Inventory       ReviewInventory    `json:"inventory"`
	Resolutions     []ReviewResolution `json:"resolutions"`
	Coverage        string             `json:"coverage"`
	Findings        []ReviewFinding    `json:"findings,omitempty"`
	Untrusted       bool               `json:"untrusted,omitempty"`
}

type ReviewVerifyRequest struct {
	Lease              WorkerLease
	Request            ReviewRequest
	ExpectedGeneration Generation
	EndEventID         ID
	EndSeq             Sequence
}

type ReviewVerifier interface {
	VerifyReview(context.Context, Scope, ReviewVerifyRequest) (ReviewEvidence, error)
}
