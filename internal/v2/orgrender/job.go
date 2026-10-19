// Package orgrender carries the private installed org-render job protocol.
package orgrender

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

// ErrNativeRender selects the native renderer for a noncanonical source tree.
// A malformed canonical tree returns its compiler error instead.
var ErrNativeRender = errors.New("org sources require native rendering")

type File struct {
	Path string
	Mode uint32
	Data []byte
}

type Stage struct {
	ID            api.ID
	OperationID   api.ID
	ClaimID       api.ID
	Generation    api.Generation
	Deadline      api.Timestamp
	ObservedAt    api.Timestamp
	ParentLeaseID api.ID
	Target        api.LifeRef
	Change        api.ChangeRequest
	Snapshot      api.OrgSnapshot
	Before        []File
	Sources       []File
	Derived       []File
}

type Result struct {
	JobID       api.ID
	ClaimID     api.ID
	Generation  api.Generation
	InputSHA256 api.Digest
	Renderer    api.Executable
	UID         uint32
	PID         int
	Files       []File
}

type Store interface {
	BeginRender(context.Context, api.Scope, api.ChangeRequest) (Stage, *api.ChangeRequest, error)
	FinishRender(context.Context, api.Scope, Stage, Result) (api.ChangeRequest, error)
}

type Executor interface {
	RenderOrg(context.Context, Stage) (Result, error)
}

func Digest(value any) api.Digest {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return api.Digest(hex.EncodeToString(sum[:]))
}
