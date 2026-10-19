package archive

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// Snapshot is returned only by the installed storage owner, after withdrawing
// writable access. Objects contain current workspace, history and capture bytes;
// the original launch snapshot is not an implementation of this operation.
type Snapshot struct {
	Freeze  Freeze
	Objects []api.ObjectWrite
}

// Native is an installed administrator capability, never a request parameter.
// Freeze and CheckFreeze must resolve the same durable operation after a crash.
// They must hold the protected storage fence until archive/collection finishes.
type Native interface {
	FreezeArchive(context.Context, Intent, api.Lane) (Snapshot, error)
	CheckArchiveFreeze(context.Context, Intent, Freeze) error
}

type PartRequest struct {
	LeaseID api.ID `json:"lease_id"`
	Index   uint64 `json:"index"`
	Bytes   []byte `json:"bytes"`
}
