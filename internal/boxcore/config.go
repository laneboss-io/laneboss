package boxcore

// Config is the parsed box.toml. internal/boxcfg builds it; defaults are applied there, not here.
type Config struct {
	Path     string // the file it was read from; "" for a Config built in code
	Org      string
	Ledger   LedgerConfig
	Defaults Defaults
	Guest    GuestConfig
	AWS      *AWSConfig // nil when [aws] is absent
	GCP      *GCPConfig // nil when [gcp] is absent
}

// LedgerConfig is [ledger].
type LedgerConfig struct {
	Path     string // absolute path, default applied by boxcfg
	Schema   string
	Registry string // "" = no registry file
}

// Defaults is [defaults].
type Defaults struct {
	Provider       string
	VCPU           int
	MemGiB         int
	Arch           string
	RootGB         int
	IdleMin        int
	HardMin        int
	CostCapUSD     float64
	DiskUSDGBMonth float64
	NamePrefix     string
	RunDir         string // absolute path, default applied by boxcfg
}

// GuestConfig is [guest].
type GuestConfig struct {
	DoneFiles []string
	BusyFiles []string
	OutDir    string
}

// AWSConfig is [aws].
type AWSConfig struct {
	Profile             string
	Region              string
	ProjectTag          string
	VPC                 string
	SecurityGroup       string
	AMI                 string
	ArmAMISSM           string
	KeyName             string
	SSHUser             string
	SSHIdentity         string // absolute path, ~ expanded
	FamiliesX86         []string
	FamiliesArm         []string
	MaxCandidates       int
	Subnets             map[string]string // zone -> subnet id, optional
	EnsureSSHIngress    bool
	MyAddressURL        string
	AllowDefaultProfile bool
	AllowTerminate      bool
}

// GCPShape is one row of [[gcp.shape]]: a machine type the lane may use.
type GCPShape struct {
	Type         string
	VCPU         int
	MemGiB       int
	Arch         string
	PriceUSDHour float64
}

// GCPConfig is [gcp].
type GCPConfig struct {
	Project                   string
	Region                    string
	Zones                     []string
	Network                   string
	Subnetwork                string
	ExternalIP                bool
	NetworkTags               []string
	BoxServiceAccount         string // account id; the email is <id>@<project>.iam.gserviceaccount.com
	ImpersonateServiceAccount string // account id, optional
	ResultsBucket             string
	ObjectPrefix              string
	ImageProject              string
	ImageFamilyX86            string
	ImageFamilyArm            string
	BootDiskType              string
	PreemptionNoticeSec       int
	GcloudConfigDir           string
	GcloudConfiguration       string
	Shapes                    []GCPShape
}
