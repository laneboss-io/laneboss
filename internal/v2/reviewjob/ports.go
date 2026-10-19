package reviewjob

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// Source is implemented by the single authoritative writer. Snapshot must
// resolve a retained native post-run freeze, never the launch-time source.
// Reservation must retain the original dispatcher operation and one worker;
// awaiting a result must not allocate a replacement after a lost response.
type Source interface {
	ReviewSnapshot(context.Context, api.Scope, api.LifeRef) (api.ReviewSubject, error)
	ReserveReviewWorker(context.Context, api.Scope, api.ReviewRequest, api.ReviewSubject, []string) (api.WorkerLease, error)
	AwaitReviewResult(context.Context, api.Scope, api.WorkerLease) (api.BlobRef, error)
}

// Requirements reads current protected project policy through the installed
// administrator. Neither the public request nor a supplied check list chooses it.
type Requirements interface {
	RequiredReviewChecks(context.Context, api.Scope, api.LifeRef) ([]string, error)
}

// ResultControl keeps private service read authority inside the installed
// coordinator. The original public actor is reauthenticated before and after
// waiting; no serialized actor label can obtain this callback.
type ResultControl interface {
	WithReviewResult(context.Context, api.Scope, api.ReviewVerifyRequest, func(api.Scope, api.BlobRef) error) error
}
