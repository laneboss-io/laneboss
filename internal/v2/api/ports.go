package api

type Record struct {
	ID          ID         `json:"id"`
	Collection  string     `json:"collection"`
	LifeID      ID         `json:"life_id,omitempty"`
	Run         RunNumber  `json:"run,omitempty"`
	Content     BlobRef    `json:"content"`
	Actor       Actor      `json:"actor"`
	Origin      string     `json:"origin"`
	RecordedAt  Timestamp  `json:"recorded_at"`
	Generation  Generation `json:"generation"`
	RelatedIDs  []ID       `json:"related_ids,omitempty"`
	Action      string     `json:"action,omitempty"`
	Annotations []BlobRef  `json:"annotations,omitempty"`
	Feedback    []BlobRef  `json:"feedback,omitempty"`
}

type RecordQuery struct {
	RecordID   ID     `json:"record_id,omitempty"`
	Collection string `json:"collection"`
	LifeID     ID     `json:"life_id,omitempty"`
	Query      string `json:"query"`
	SearchMode string `json:"search_mode"`
	Cursor     string `json:"cursor"`
	Limit      int    `json:"limit"`
}

type RecordGetRequest struct {
	RecordID ID `json:"record_id"`
}

type RecordAppendRequest struct {
	Collection string  `json:"collection"`
	Content    BlobRef `json:"content"`
	RelatedIDs []ID    `json:"related_ids"`
}

type RecordPage struct {
	Records []Record `json:"records"`
	Cursor  string   `json:"cursor"`
}

type DecisionMutateRequest struct {
	Action             string     `json:"action"`
	RecordID           ID         `json:"record_id,omitempty"`
	Content            BlobRef    `json:"content"`
	ExpectedGeneration Generation `json:"expected_generation"`
}

type TransferRequest struct {
	Collection         string     `json:"collection"`
	Manifest           BlobRef    `json:"manifest"`
	ExpectedGeneration Generation `json:"expected_generation"`
}

type VerifyRequest struct {
	Scope    string `json:"scope"`
	ObjectID ID     `json:"object_id,omitempty"`
}

type Verification struct {
	OK       bool     `json:"ok"`
	Objects  uint64   `json:"objects"`
	Events   uint64   `json:"events"`
	Problems []string `json:"problems"`
	Manifest *BlobRef `json:"manifest,omitempty"`
}

type RebuildRequest struct {
	FrozenSnapshot BlobRef `json:"frozen_snapshot"`
}

type BoxLaunchRequest struct {
	Provider        string  `json:"provider"`
	ResourceGrantID ID      `json:"resource_grant_id"`
	Purpose         string  `json:"purpose"`
	Spec            BlobRef `json:"spec"`
	Budget          Budget  `json:"budget"`
}

type BoxRunRequest struct {
	BoxID              ID         `json:"box_id"`
	Source             BlobRef    `json:"source"`
	Plan               BlobRef    `json:"plan"`
	ExpectedGeneration Generation `json:"expected_generation"`
}

type BoxControlRequest struct {
	BoxID              ID         `json:"box_id"`
	ExpectedGeneration Generation `json:"expected_generation"`
}

type Box struct {
	ID              ID         `json:"id"`
	Provider        string     `json:"provider"`
	State           string     `json:"state"`
	Generation      Generation `json:"generation"`
	ResourceGrantID ID         `json:"resource_grant_id"`
	CostMicros      int64      `json:"cost_micros"`
	Evidence        []BlobRef  `json:"evidence"`
}

type BoxPage struct {
	Boxes  []Box  `json:"boxes"`
	Cursor string `json:"cursor"`
}

type MigrationPlanRequest struct {
	SourceVersion  string  `json:"source_version"`
	SourceManifest BlobRef `json:"source_manifest"`
}

type MigrationPlan struct {
	ID               ID       `json:"id"`
	SourceVersion    string   `json:"source_version"`
	SourceManifest   BlobRef  `json:"source_manifest"`
	TargetSchema     uint32   `json:"target_schema"`
	Changes          []string `json:"changes"`
	Problems         []string `json:"problems"`
	RequiresRelaunch []ID     `json:"requires_relaunch"`
}

type MigrationApplyRequest struct {
	PlanID ID `json:"plan_id"`
}

type ReleaseManifest struct {
	Version        string            `json:"version"`
	Protocol       string            `json:"protocol"`
	Schema         uint32            `json:"schema"`
	Artifacts      []ReleaseArtifact `json:"artifacts"`
	SourceSHA256   Digest            `json:"source_sha256"`
	VendorManifest BlobRef           `json:"vendor_manifest"`
}

type ReleaseArtifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	SHA256 Digest `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type UpgradePlanRequest struct {
	Release ReleaseManifest `json:"release"`
}

type UpgradePlan struct {
	ID           ID              `json:"id"`
	Release      ReleaseManifest `json:"release"`
	FrozenBackup *BlobRef        `json:"frozen_backup,omitempty"`
	Quiescent    bool            `json:"quiescent"`
	Problems     []string        `json:"problems"`
}

type UpgradeApplyRequest struct {
	PlanID ID `json:"plan_id"`
}

type BootstrapRequest struct {
	OrgName        string  `json:"org_name"`
	SourceManifest BlobRef `json:"source_manifest"`
}

type SecretKey struct {
	ID        ID        `json:"id"`
	Algorithm string    `json:"algorithm"`
	PublicKey []byte    `json:"public_key"`
	ExpiresAt Timestamp `json:"expires_at"`
}

type SecretStageRequest struct {
	KeyID              ID     `json:"key_id"`
	Name               string `json:"name"`
	Version            string `json:"version"`
	EphemeralPublicKey []byte `json:"ephemeral_public_key"`
	Nonce              []byte `json:"nonce"`
	Ciphertext         []byte `json:"ciphertext"`
}

type SecretStage struct {
	ID        ID        `json:"id"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	ExpiresAt Timestamp `json:"expires_at"`
}

type SecretList struct {
	Secrets []SecretInfo `json:"secrets"`
}
