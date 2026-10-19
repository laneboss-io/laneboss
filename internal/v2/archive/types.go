// Package archive defines the private, immutable archive worker protocol.
// It confers no authority: the installed store/helper must supply the original
// reservation, measured freeze, current claim and authenticated object ports.
package archive

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

type Intent struct {
	Request           api.ArchiveRequest
	OperationID       api.ID
	CancellationEpoch api.Generation
	EndEventID        api.ID
	EndSeq            api.Sequence
}

type Job struct {
	ID     api.ID
	Intent Intent
	Lease  api.WorkerLease
	Plan   api.WorkerPlan
	Freeze api.BlobRef
}

// Nil counts mean unknown. Process quiescence alone is not a storage freeze.
type Freeze struct {
	Target            api.LifeRef    `json:"target"`
	LaunchID          api.ID         `json:"launch_id"`
	CancellationEpoch api.Generation `json:"cancellation_epoch"`
	Snapshot          api.BlobRef    `json:"snapshot"`
	Writers           *uint64        `json:"writers"`
	WritableExports   *uint64        `json:"writable_exports"`
	ObservedAt        api.Timestamp  `json:"observed_at"`
}

// Input is retained with the fixed WorkerLease. ReceiptID and StoreID are
// allocated by the single writer, never chosen by the confined worker.
type Input struct {
	Schema    string         `json:"schema"`
	JobID     api.ID         `json:"job_id"`
	Intent    Intent         `json:"intent"`
	Freeze    api.BlobRef    `json:"freeze"`
	ReceiptID api.ID         `json:"receipt_id"`
	StoreID   api.ID         `json:"store_id"`
	Budget    api.Budget     `json:"budget"`
	Inline    []FrozenObject `json:"inline,omitempty"`
}

// FrozenObject batches small already-retained source bytes in the immutable
// worker input. The worker still verifies each complete manifest pin; parts
// and completion independently read the original store objects.
type FrozenObject struct {
	Ref   api.BlobRef `json:"ref"`
	Bytes []byte      `json:"bytes"`
}

const MaxInlineBytes = 64 << 10

type Completion struct {
	Receipt api.ArchiveReceipt `json:"receipt"`
	Archive api.ObjectAssembly `json:"archive"`
}

type Control interface {
	ReserveArchive(context.Context, api.Scope, Intent) (Job, error)
	ArchiveJob(context.Context, api.Scope, api.ID) (Job, error)
}

// PartSink is a private installed capability, not a public blob upload port.
// The receiver must reauthenticate the native worker and check the exact live
// lease/claim/epoch on every append, retain the bytes under the original
// operation, and replay an index only for identical bytes. Read must load those
// committed bytes, not an upload buffer. A worker cannot supply an ACL or path.
type PartSink interface {
	ArchivePart(context.Context, api.Scope, api.ID, uint64, []byte) (api.BlobRef, error)
}

type ReadObject func(context.Context, api.BlobReadRequest) (api.BlobChunk, error)
