package api

import "context"

// RecordWorker is an optional confined backend, separate from the state owner.
// Implementations resolve source/plan handles, never arbitrary service paths.
// Import reserves a durable outbox operation before running a parser; export and
// search return only screened, authorized objects. No in-process legacy adapter.
type RecordWorker interface {
	Import(context.Context, Scope, TransferRequest) (Operation, error)
	Export(context.Context, Scope, RecordQuery) (BlobRef, error)
	Search(context.Context, Scope, RecordQuery) (RecordPage, error)
}

// ResourceWorker is a confined resource-capability broker, not an agent driver.
// It must reserve/reconcile jobs durably, verify delegated grant ceilings and
// harvest/read back before collection. A nil backend leaves these RPCs failing.
type ResourceWorker interface {
	Launch(context.Context, Scope, BoxLaunchRequest) (Box, error)
	Run(context.Context, Scope, BoxRunRequest) (Operation, error)
	Harvest(context.Context, Scope, BoxControlRequest) (BlobRef, error)
	End(context.Context, Scope, BoxControlRequest) (Operation, error)
	List(context.Context, Scope, ListRequest) (BoxPage, error)
}
