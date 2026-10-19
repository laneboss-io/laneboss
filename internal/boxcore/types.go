package boxcore

// Request is what a caller asks for. Every field is provider-neutral.
type Request struct {
	Provider   string // "aws" | "gcp"
	Purpose    string // plain name, see PlainName
	Lane       string // plain name; defaults to Purpose
	Owner      string // plain name; "unknown" when none is known
	OwnerBasis string // "flag" | "env" | "unknown"
	RunID      string // from NewRunID; label value, ledger field, object prefix, run directory
	VCPU       int
	MemGiB     int    // 0 = no minimum
	Arch       string // "x86" | "arm64" | "any"
	Families   []string
	Type       string // explicit type; with Zone it bypasses the picker
	Zone       string
	RootGB     int
	IdleMin    int
	HardMin    int     // already reduced so the worst case fits CostCapUSD
	CostCapUSD float64 // the run's cap in USD
}

// Candidate is one (type, zone) the provider may try, cheapest first.
type Candidate struct {
	Type         string
	Zone         string
	Region       string
	Arch         string  // "x86" | "arm64"
	PriceUSDHour float64 // 0 when unknown
}

// Guest is the on-box text the provider attaches at launch.
type Guest struct {
	Startup  string // AWS user-data / GCP startup-script
	Shutdown string // GCP shutdown-script; empty on AWS
}

// GuestSpec is what the renderer needs; the orchestrator fills it from Config and Request.
type GuestSpec struct {
	Provider     string
	RunID        string
	IdleMin      int
	HardMin      int
	DoneFiles    []string
	BusyFiles    []string
	OutDir       string
	Bucket       string // GCP results bucket, "" on AWS
	ObjectPrefix string // GCP, e.g. "runs/<run id>"
	SyncSeconds  int    // GCP periodic upload of OutDir, default 60
	Tag          string // log tag, default "lb-box"
}

// GuestRenderer turns a GuestSpec into the on-box scripts.
type GuestRenderer interface {
	Render(spec GuestSpec) Guest
}

// Box is one machine, as the provider reported it.
type Box struct {
	Provider      string
	ID            string // AWS instance id, GCP instance name
	Name          string
	Type          string
	Zone          string
	Region        string
	Image         string
	Address       string // public address, or "" when reached through a tunnel
	SpotRequestID string
	LaunchTimeUTC string // YYYY-MM-DDTHH:MM:SSZ
	QuoteUSDHour  float64
	Project       string // GCP project; AWS project tag
	Labels        map[string]string
}

// State names, normalised across providers.
const (
	// StatePending means the box is starting.
	StatePending = "pending"
	// StateRunning means the box is running.
	StateRunning = "running"
	// StateStopping means the box is stopping.
	StateStopping = "stopping"
	// StateStopped means the box is stopped but still exists.
	StateStopped = "stopped" // GCP TERMINATED (a stopped VM), AWS stopped
	// StateTerminated means the provider confirmed termination.
	StateTerminated = "terminated"
	// StateGone means the provider no longer knows the box.
	StateGone = "gone" // the provider no longer knows the box (GCP: not found)
	// StateUnknown means no normalised state is known.
	StateUnknown = "unknown"
)

// State is one reading of a box's state.
type State struct {
	Name          string // one of the State constants
	Raw           string // the provider's own word
	Reason        string // provider reason text, e.g. a spot interruption code
	TransitionUTC string // YYYY-MM-DDTHH:MM:SSZ when the provider carries one, else ""
}

// ListFilter selects boxes for List.
type ListFilter struct {
	Org         string
	ManagedOnly bool // only boxes that carry the managed-by label or tag
}

// DryResult is the provider's answer to a dry run.
type DryResult struct {
	Allowed bool
	Code    string // provider error code when denied
	Detail  string
}

// TransportOptions parameterises a Transport.
type TransportOptions struct {
	KnownHostsFile string // per-box host key file inside the run directory
}
