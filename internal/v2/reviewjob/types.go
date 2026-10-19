// Package reviewjob defines immutable input for the fixed confined verifier.
// These values carry no execution authority; the installed writer and native
// worker connection must authenticate their source, lease and measurement.
package reviewjob

import "laneboss.io/laneboss/internal/v2/api"

type Input struct {
	Schema      string                 `json:"schema"`
	Subject     api.ReviewSubject      `json:"subject"`
	Request     api.ReviewRequest      `json:"request"`
	Required    []string               `json:"required"`
	Base        api.BlobRef            `json:"base"`
	Checks      []api.ReviewCheckFact  `json:"checks"`
	Inventory   api.ReviewInventory    `json:"inventory"`
	Resolutions []api.ReviewResolution `json:"resolutions"`
}

// CheckRecord is written by the actual test worker. Its own object reference
// is supplied by the authoritative writer after persisting these exact bytes.
type CheckRecord struct {
	Schema         string       `json:"schema"`
	Name           string       `json:"name"`
	Target         api.LifeRef  `json:"target"`
	EndSeq         api.Sequence `json:"end_seq"`
	SnapshotSHA256 api.Digest   `json:"snapshot_sha256"`
	ExitCode       int          `json:"exit_code"`
	WorkerLeaseID  api.ID       `json:"worker_lease_id"`
	OperationID    api.ID       `json:"operation_id"`
}

type InventoryRecord struct {
	Schema       string                 `json:"schema"`
	ThroughSeq   api.Sequence           `json:"through_seq"`
	Streams      []api.ReviewStreamFact `json:"streams"`
	ToolRecords  api.BlobRef            `json:"tool_records"`
	ToolCoverage string                 `json:"tool_coverage"`
}

type Change struct {
	Path   string           `json:"path"`
	Before *api.ObjectEntry `json:"before,omitempty"`
	After  *api.ObjectEntry `json:"after,omitempty"`
}

type Diff struct {
	Schema  string     `json:"schema"`
	Base    api.Digest `json:"base"`
	Current api.Digest `json:"current"`
	Changes []Change   `json:"changes"`
}
