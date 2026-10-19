package boxcore

import (
	"context"
	"io"
)

// Transport runs shell command lines on a box. It is the ONLY way the orchestrator touches a box.
type Transport interface {
	// Exec runs command through the box's shell. stdin, stdout and stderr may be nil. The int is the command's exit
	// status. The error is non-nil only when the transport itself failed (the int is then -1).
	Exec(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error)
}

// Provider is one cloud. Implementations: internal/boxaws, internal/boxgcp.
type Provider interface {
	Name() string
	// Prepare is a cheap pre-flight (identity works, tools present, AWS: the ingress rule for this machine).
	Prepare(ctx context.Context, req Request) error
	// Candidates lists what may be tried, cheapest first, spread over zones and types.
	Candidates(ctx context.Context, req Request) ([]Candidate, error)
	// DryRun asks the provider whether the launch would be allowed, and creates nothing.
	DryRun(ctx context.Context, req Request, c Candidate, g Guest) (DryResult, error)
	// Launch creates the box. A capacity or quota refusal is an *Error of KindCapacity or KindQuota.
	Launch(ctx context.Context, req Request, c Candidate, g Guest) (Box, error)
	// WaitRunning blocks until the box runs and returns it with its address and provider facts filled in.
	WaitRunning(ctx context.Context, b Box) (Box, error)
	// Describe reads the box's state. A box the provider no longer knows is State{Name: StateGone}, not an error.
	Describe(ctx context.Context, b Box) (State, error)
	Transport(b Box, o TransportOptions) Transport
	// Teardown deletes the box. AWS returns KindUnsupported unless allow_terminate is set (the box's guard ends it).
	// It refuses a box whose name prefix or labels are not ours, with KindDenied.
	Teardown(ctx context.Context, b Box) error
	List(ctx context.Context, f ListFilter) ([]Box, error)
	// FetchHarvest copies what the box wrote to its object store (GCP) into dir and returns the file count.
	// AWS returns KindUnsupported.
	FetchHarvest(ctx context.Context, b Box, runID, dir string) (int, error)
}

// Ledger is the append-only record. Writable is called BEFORE any box is created.
type Ledger interface {
	Writable() error
	Append(event string, fields map[string]any) (map[string]any, error)
	Events() ([]map[string]any, error)
}
