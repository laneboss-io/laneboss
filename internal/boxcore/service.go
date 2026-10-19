package boxcore

import (
	"context"
	"io"
	"time"
)

// Put is one file to copy to the box before the suite runs.
type Put struct{ Local, Remote string }

// LaunchOptions describes a launch or dry run.
type LaunchOptions struct {
	Request Request
	DryRun  bool
}

// LaunchResult reports the chosen box or dry-run answer.
type LaunchResult struct {
	Box       Box
	Candidate Candidate
	Dry       *DryResult
	ExitCode  int
}

// EndOptions identifies a box and bounds termination polling.
type EndOptions struct {
	Provider string
	ID       string // instance id or name
	Address  string
	BoundSec int // default 600
	PollSec  int // default 15
}

// EndResult reports the termination evidence and billing duration.
type EndResult struct {
	State         string
	Basis         string
	TerminatedUTC string
	BilledSeconds int
	Pending       bool
	ExitCode      int
}

// RunOptions describes the source, suite and files for a run.
type RunOptions struct {
	Request    Request
	Archive    string // path of the source tar
	Puts       []Put
	Suite      string
	TimeoutMin int
	OutDir     string // "" = <run_dir>/<run id>
}

// RunResult reports the suite, harvest, termination and cost.
type RunResult struct {
	RunID          string
	Box            Box
	SuiteExit      int    // -1 when unknown
	Verdict        string // passed | failed | preempted | timeout | harvest-failed | cost-cap | access
	OutDir         string
	Files          int
	Bytes          int64
	ManifestSHA256 string
	Terminated     bool
	BilledSeconds  int
	CostUSD        float64
	ExitCode       int
}

// ListOptions selects boxes and optional orphan filtering.
type ListOptions struct {
	Provider     string
	Orphans      bool
	OlderThanMin int
}

// Listed combines a box's state with ledger and age evidence.
type Listed struct {
	Box         Box
	State       State
	LedgerEnded bool
	AgeMin      int
	Orphan      bool
}

// SweepOptions selects old orphan boxes and optional deletion.
type SweepOptions struct {
	Provider     string
	OlderThanMin int
	Delete       bool
}

// SweepResult reports the examined, deleted and refused boxes.
type SweepResult struct {
	Examined int
	Orphans  []Listed
	Deleted  []string
	Refused  []string
}

// Deps is everything the orchestrator needs; tests replace every field.
type Deps struct {
	Config    *Config
	Providers map[string]Provider
	Ledger    Ledger
	Guest     GuestRenderer
	Now       func() time.Time
	Sleep     func(ctx context.Context, d time.Duration) error // tests make it instant
	NewRunID  func() string
	Out, Err  io.Writer
	Version   string // goes to the ledger as launcher_version
	SelfSHA   string // sha256 of the running executable, "" when unknown
}

// Service is the orchestrator's API. internal/boxrun implements it; internal/box calls it.
type Service interface {
	Launch(ctx context.Context, o LaunchOptions) (LaunchResult, error)
	End(ctx context.Context, o EndOptions) (EndResult, error)
	Run(ctx context.Context, o RunOptions) (RunResult, error)
	List(ctx context.Context, o ListOptions) ([]Listed, error)
	Sweep(ctx context.Context, o SweepOptions) (SweepResult, error)
}
