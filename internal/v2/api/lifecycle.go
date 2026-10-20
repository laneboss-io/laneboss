package api

type TemplateRef struct {
	ID             ID         `json:"id"`
	SourceSHA256   Digest     `json:"source_sha256"`
	Generation     Generation `json:"generation"`
	RenderedSHA256 Digest     `json:"rendered_sha256"`
}

type Trigger struct {
	Kind        string     `json:"kind"`
	MailIDs     []ID       `json:"mail_ids"`
	CausingSeqs []Sequence `json:"causing_seqs"`
	CausingRun  RunNumber  `json:"causing_run,omitempty"`
}

type Workspace struct {
	ID         ID      `json:"id"`
	ProjectID  ID      `json:"project_id"`
	Base       string  `json:"base"`
	Branch     string  `json:"branch"`
	LogicalCWD string  `json:"logical_cwd"`
	Snapshot   BlobRef `json:"snapshot"`
}

type Lane struct {
	Task              BlobRef      `json:"task"`
	LaunchID          ID           `json:"launch_id"`
	CancellationEpoch Generation   `json:"cancellation_epoch"`
	Counters          TaskCounters `json:"counters"`
	ProfileGrantID    ID           `json:"profile_grant_id"`
	Model             string       `json:"model"`
	Effort            string       `json:"effort"`
	BudgetRemaining   Budget       `json:"budget_remaining"`
	LifeID            ID           `json:"life_id"`
	Name              string       `json:"name"`
	ParentLifeID      ID           `json:"parent_life_id,omitempty"`
	RootLifeID        ID           `json:"root_life_id"`
	StarterChain      []ID         `json:"starter_chain"`
	StarterEventSeq   Sequence     `json:"starter_event_seq"`
	Level             int          `json:"level"`
	Role              string       `json:"role"`
	State             string       `json:"state"`
	Generation        Generation   `json:"generation"`
	Run               RunNumber    `json:"run"`
	LogicalTurnID     ID           `json:"logical_turn_id,omitempty"`
	Session           Session      `json:"session"`
	Workspace         Workspace    `json:"workspace"`
	GrantSetID        ID           `json:"grant_set_id"`
	PolicyGeneration  Generation   `json:"policy_generation"`
	Cleaned           bool         `json:"cleaned"`
	Containment       string       `json:"containment"`
	LastSeq           Sequence     `json:"last_seq"`

	// Status enriches this from lane.cleaned; stored projections leave it nil.
	UnownedRetained *UnownedRetained `json:"unowned_retained,omitempty"`
	CredentialSpend *SpendBalance    `json:"credential_spend,omitempty"`
}

type StartRequest struct {
	Lane                     string       `json:"lane"`
	ProjectID                ID           `json:"project_id"`
	Level                    int          `json:"level"`
	Role                     string       `json:"role"`
	Task                     BlobRef      `json:"task"`
	Grants                   GrantRequest `json:"grants"`
	Driver                   Driver       `json:"driver"`
	ProfileGrantID           ID           `json:"profile_grant_id"`
	Model                    string       `json:"model"`
	Effort                   string       `json:"effort"`
	Budget                   Budget       `json:"budget"`
	RootTicketID             ID           `json:"root_ticket_id,omitempty"`
	ExpectedPolicyGeneration Generation   `json:"expected_policy_generation"`
}

type ResumeRequest struct {
	Target             LifeRef    `json:"target"`
	ExpectedGeneration Generation `json:"expected_generation"`
	Message            BlobRef    `json:"message"`
	Budget             Budget     `json:"budget"`
}

type TurnRequest struct {
	Target             LifeRef    `json:"target"`
	ExpectedGeneration Generation `json:"expected_generation"`
	MailIDs            []ID       `json:"mail_ids"`
	IdleMessage        *BlobRef   `json:"idle_message,omitempty"`
	Budget             Budget     `json:"budget"`
}

type StopRequest struct {
	Target             LifeRef    `json:"target"`
	ExpectedGeneration Generation `json:"expected_generation"`
	Reason             BlobRef    `json:"reason"`
}

type MarkRequest struct {
	Target             LifeRef       `json:"target"`
	ExpectedGeneration Generation    `json:"expected_generation"`
	State              string        `json:"state"`
	Review             ReviewReceipt `json:"review"`
}

type ReviewReceipt struct {
	Evidence          *ReviewEvidence `json:"evidence,omitempty"`
	ID                ID              `json:"id"`
	Reviewer          Actor           `json:"reviewer"`
	Diff              BlobRef         `json:"diff"`
	Checks            []BlobRef       `json:"checks"`
	RecordInventory   BlobRef         `json:"record_inventory"`
	RefusalResolution []ID            `json:"refusal_resolution"`
	Coverage          string          `json:"coverage"`
}

type ReviewRequest struct {
	Target            LifeRef   `json:"target"`
	Diff              BlobRef   `json:"diff"`
	Checks            []BlobRef `json:"checks"`
	RecordInventory   BlobRef   `json:"record_inventory"`
	RefusalResolution []ID      `json:"refusal_resolution"`
}

type CleanRequest struct {
	Target             LifeRef    `json:"target"`
	ExpectedGeneration Generation `json:"expected_generation"`
	ArchiveReceiptID   ID         `json:"archive_receipt_id"`
}

type AdoptRequest struct {
	ProfileGrantID           ID           `json:"profile_grant_id"`
	Model                    string       `json:"model"`
	Effort                   string       `json:"effort"`
	Task                     BlobRef      `json:"task"`
	RootTicketID             ID           `json:"root_ticket_id,omitempty"`
	Lane                     string       `json:"lane"`
	Level                    int          `json:"level"`
	Role                     string       `json:"role"`
	ImportManifest           BlobRef      `json:"import_manifest"`
	Grants                   GrantRequest `json:"grants"`
	Driver                   Driver       `json:"driver"`
	Budget                   Budget       `json:"budget"`
	ExpectedPolicyGeneration Generation   `json:"expected_policy_generation"`
}

type LoopRequest struct {
	Target             LifeRef    `json:"target"`
	ExpectedGeneration Generation `json:"expected_generation"`
	Enabled            bool       `json:"enabled"`
	IdleMessage        *BlobRef   `json:"idle_message,omitempty"`
	BackoffMS          int64      `json:"backoff_ms"`
}

type AttachRequest struct {
	Target LifeRef `json:"target"`
	Cursor string  `json:"cursor"`
	Mode   string  `json:"mode"`
}

type AttachInputRequest struct {
	Target    LifeRef `json:"target"`
	ChannelID ID      `json:"channel_id"`
	Input     []byte  `json:"input"`
	Columns   uint16  `json:"columns"`
	Rows      uint16  `json:"rows"`
}

type ArchiveRequest struct {
	Target             LifeRef    `json:"target"`
	ExpectedGeneration Generation `json:"expected_generation"`
}

type ArchiveReceipt struct {
	ID             ID        `json:"id"`
	LifeID         ID        `json:"life_id"`
	Manifest       BlobRef   `json:"manifest"`
	ArchiveSHA256  Digest    `json:"archive_sha256"`
	ReadBackSHA256 Digest    `json:"read_back_sha256"`
	VerifiedAt     Timestamp `json:"verified_at"`
	StoreID        ID        `json:"store_id"`
}

type RestoreRequest struct {
	Target             LifeRef    `json:"target"`
	ExpectedGeneration Generation `json:"expected_generation"`
	Path               string     `json:"path"`
	ArchiveReceiptID   ID         `json:"archive_receipt_id,omitempty"`
	AllowNestedGit     bool       `json:"allow_nested_git,omitempty"`
}

type RestoreReceipt struct {
	Target           LifeRef  `json:"target"`
	Path             string   `json:"path"`
	Head             string   `json:"head"`
	ArchiveReceiptID ID       `json:"archive_receipt_id"`
	Manifest         BlobRef  `json:"manifest"`
	ClearedModes     []string `json:"cleared_modes,omitempty"`
	SkippedPaths     []string `json:"skipped_paths,omitempty"`
}

type EventTailRequest struct {
	LifeID     ID        `json:"life_id"`
	Run        RunNumber `json:"run"`
	Since      Sequence  `json:"since"`
	Cursor     string    `json:"cursor"`
	Follow     bool      `json:"follow"`
	Until      EventKind `json:"until"`
	DeadlineMS int64     `json:"deadline_ms"`
}

type EventPage struct {
	Events   []Event `json:"events"`
	Cursor   string  `json:"cursor"`
	Complete bool    `json:"complete"`
}

type LanePage struct {
	Lanes  []Lane `json:"lanes"`
	Cursor string `json:"cursor"`
}
