package api

// CapabilityEnrollmentRequest is an exact human-approved enrollment proposal.
// Resources have no source_handle until the service assigns it. Secrets name
// an already imported protected source; no material crosses this request.
type CapabilityEnrollmentRequest struct {
	Resource *ResourceEnrollment `json:"resource,omitempty"`
	Secret   *SecretEnrollment   `json:"secret,omitempty"`
}

// Enrollment proposals omit issued grant IDs. A resource handle is assigned
// by the service; the optional source_handle is reserved and must be absent.
// Keeping it typed preserves rejection of caller-chosen handles at intake.
type ResourceEnrollment struct {
	SourceHandle      ID        `json:"source_handle,omitempty"`
	Provider          string    `json:"provider"`
	Regions           []string  `json:"regions"`
	ImageIDs          []string  `json:"image_ids"`
	MachineTypes      []string  `json:"machine_types"`
	MaxActive         uint32    `json:"max_active"`
	MaxHourlyMicros   int64     `json:"max_hourly_micros"`
	TotalBudgetMicros int64     `json:"total_budget_micros"`
	Delegate          bool      `json:"delegate"`
	ExpiresAt         Timestamp `json:"expires_at"`
}

type SecretEnrollment struct {
	Name         string    `json:"name"`
	SourceHandle ID        `json:"source_handle"`
	Version      string    `json:"version"`
	Delivery     string    `json:"delivery"`
	Target       string    `json:"target"`
	Delegate     bool      `json:"delegate"`
	ExpiresAt    Timestamp `json:"expires_at"`
}

// Grant converts approved proposal fields into the retained root capability.
// Its grant ID stays empty until a root or child grant set is issued.
func (p ResourceEnrollment) Grant() ResourceGrant {
	return ResourceGrant{SourceHandle: p.SourceHandle, Provider: p.Provider,
		Regions: p.Regions, ImageIDs: p.ImageIDs, MachineTypes: p.MachineTypes,
		MaxActive: p.MaxActive, MaxHourlyMicros: p.MaxHourlyMicros, TotalBudgetMicros: p.TotalBudgetMicros,
		Delegate: p.Delegate, ExpiresAt: p.ExpiresAt}
}

func (p SecretEnrollment) Grant() SecretGrant {
	return SecretGrant{Name: p.Name, SourceHandle: p.SourceHandle, Version: p.Version,
		Delivery: p.Delivery, Target: p.Target, Delegate: p.Delegate, ExpiresAt: p.ExpiresAt}
}

type GrantRequest struct {
	Resources []ResourceDelegation `json:"resources"`
	Data      []DataGrantRequest   `json:"data"`
	Secrets   []SecretDelegation   `json:"secrets"`
	Profiles  []ProfileDelegation  `json:"profiles"`
	Network   []NetworkDelegation  `json:"network"`
	Channels  []ChannelDelegation  `json:"channels"`
}

type DataGrantRequest struct {
	ParentGrantID ID        `json:"parent_grant_id"`
	RelativePath  string    `json:"relative_path"`
	Access        string    `json:"access"`
	Delivery      string    `json:"delivery"`
	Destination   string    `json:"destination"`
	Delegate      bool      `json:"delegate"`
	ExpiresAt     Timestamp `json:"expires_at"`
	PublicationID ID        `json:"publication_id,omitempty"`
}

type SecretDelegation struct {
	ParentGrantID ID        `json:"parent_grant_id"`
	Name          string    `json:"name"`
	Version       string    `json:"version"`
	Delivery      string    `json:"delivery"`
	Target        string    `json:"target"`
	Delegate      bool      `json:"delegate"`
	ExpiresAt     Timestamp `json:"expires_at"`
}

type ProfileDelegation struct {
	ParentGrantID ID        `json:"parent_grant_id"`
	ProfileID     ID        `json:"profile_id"`
	Delegate      bool      `json:"delegate"`
	ExpiresAt     Timestamp `json:"expires_at"`
}

type NetworkDelegation struct {
	ParentGrantID ID        `json:"parent_grant_id"`
	EndpointID    ID        `json:"endpoint_id"`
	Delegate      bool      `json:"delegate"`
	ExpiresAt     Timestamp `json:"expires_at"`
}

type ChannelDelegation struct {
	ParentGrantID ID        `json:"parent_grant_id"`
	ChannelID     ID        `json:"channel_id"`
	Delegate      bool      `json:"delegate"`
	ExpiresAt     Timestamp `json:"expires_at"`
}

type GrantSet struct {
	Resources        []ResourceGrant `json:"resources"`
	ID               ID              `json:"id"`
	LifeID           ID              `json:"life_id"`
	ParentLifeID     ID              `json:"parent_life_id,omitempty"`
	SHA256           Digest          `json:"sha256"`
	PolicyGeneration Generation      `json:"policy_generation"`
	Generation       Generation      `json:"generation"`
	Data             []DataGrant     `json:"data"`
	Secrets          []SecretGrant   `json:"secrets"`
	Profiles         []ProfileGrant  `json:"profiles"`
	Network          []NetworkGrant  `json:"network"`
	Channels         []ChannelGrant  `json:"channels"`
	ExpiresAt        Timestamp       `json:"expires_at"`
	Revoked          bool            `json:"revoked"`
}

type DataGrant struct {
	ID             ID        `json:"id"`
	ParentGrantID  ID        `json:"parent_grant_id,omitempty"`
	SourceObjectID ID        `json:"source_object_id"`
	SourceSHA256   Digest    `json:"source_sha256"`
	RelativePath   string    `json:"relative_path"`
	Access         string    `json:"access"`
	Delivery       string    `json:"delivery"`
	Destination    string    `json:"destination"`
	Delegate       bool      `json:"delegate"`
	ExpiresAt      Timestamp `json:"expires_at"`
	PublicationID  ID        `json:"publication_id,omitempty"`
	HistoryScope   string    `json:"history_scope"`
}

type SecretGrant struct {
	ID            ID        `json:"id"`
	ParentGrantID ID        `json:"parent_grant_id,omitempty"`
	Name          string    `json:"name"`
	SourceHandle  ID        `json:"source_handle"`
	Version       string    `json:"version"`
	Delivery      string    `json:"delivery"`
	Target        string    `json:"target"`
	Delegate      bool      `json:"delegate"`
	ExpiresAt     Timestamp `json:"expires_at"`
}

type ProfileGrant struct {
	ID            ID        `json:"id"`
	ParentGrantID ID        `json:"parent_grant_id,omitempty"`
	ProfileID     ID        `json:"profile_id"`
	Driver        Driver    `json:"driver"`
	Provider      string    `json:"provider"`
	Paid          bool      `json:"paid"`
	Delegate      bool      `json:"delegate"`
	ExpiresAt     Timestamp `json:"expires_at"`
}

type NetworkGrant struct {
	ID            ID        `json:"id"`
	ParentGrantID ID        `json:"parent_grant_id,omitempty"`
	EndpointID    ID        `json:"endpoint_id"`
	Mode          string    `json:"mode"`
	Delegate      bool      `json:"delegate"`
	ExpiresAt     Timestamp `json:"expires_at"`
}

type ChannelGrant struct {
	ID            ID        `json:"id"`
	ParentGrantID ID        `json:"parent_grant_id,omitempty"`
	ChannelID     ID        `json:"channel_id"`
	Delegate      bool      `json:"delegate"`
	ExpiresAt     Timestamp `json:"expires_at"`
}

type Materialization struct {
	GrantSetID ID                   `json:"grant_set_id"`
	Manifest   BlobRef              `json:"manifest"`
	Objects    []MaterializedObject `json:"objects"`
}

type MaterializedObject struct {
	GrantID             ID     `json:"grant_id"`
	SourceIdentity      string `json:"source_identity"`
	DestinationIdentity string `json:"destination_identity"`
	SnapshotSHA256      Digest `json:"snapshot_sha256"`
	WorkspaceID         ID     `json:"workspace_id"`
}

type GrantValidateRequest struct {
	ParentLifeID             ID           `json:"parent_life_id"`
	ChildLevel               int          `json:"child_level"`
	Requested                GrantRequest `json:"requested"`
	ExpectedPolicyGeneration Generation   `json:"expected_policy_generation"`
}

type GrantValidation struct {
	Effective GrantSet `json:"effective"`
	Warnings  []string `json:"warnings"`
}

type GrantGetRequest struct {
	GrantSetID ID `json:"grant_set_id"`
}

type GrantRevokeRequest struct {
	GrantSetID         ID         `json:"grant_set_id"`
	ExpectedGeneration Generation `json:"expected_generation"`
	Reason             BlobRef    `json:"reason"`
}

type RootGrantRequest struct {
	Manifest BlobRef `json:"manifest"`
	Budget   Budget  `json:"budget"`
}

type TestChildRequest struct {
	Child     LifeRef `json:"child"`
	Candidate BlobRef `json:"candidate"`
	TestPlan  BlobRef `json:"test_plan"`
	Budget    Budget  `json:"budget"`
}

type ResourceDelegation struct {
	ParentGrantID     ID        `json:"parent_grant_id"`
	Regions           []string  `json:"regions"`
	ImageIDs          []string  `json:"image_ids"`
	MachineTypes      []string  `json:"machine_types"`
	MaxActive         uint32    `json:"max_active"`
	MaxHourlyMicros   int64     `json:"max_hourly_micros"`
	TotalBudgetMicros int64     `json:"total_budget_micros"`
	Delegate          bool      `json:"delegate"`
	ExpiresAt         Timestamp `json:"expires_at"`
}

type ResourceGrant struct {
	ID                ID        `json:"id"`
	ParentGrantID     ID        `json:"parent_grant_id,omitempty"`
	SourceHandle      ID        `json:"source_handle"`
	Provider          string    `json:"provider"`
	Regions           []string  `json:"regions"`
	ImageIDs          []string  `json:"image_ids"`
	MachineTypes      []string  `json:"machine_types"`
	MaxActive         uint32    `json:"max_active"`
	MaxHourlyMicros   int64     `json:"max_hourly_micros"`
	TotalBudgetMicros int64     `json:"total_budget_micros"`
	Delegate          bool      `json:"delegate"`
	ExpiresAt         Timestamp `json:"expires_at"`
}
