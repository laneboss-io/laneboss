package api

type ResourceDelta struct {
	Path         string   `json:"path"`
	Action       string   `json:"action"`
	Mode         uint32   `json:"mode"`
	BeforeSHA256 Digest   `json:"before_sha256,omitempty"`
	After        *BlobRef `json:"after,omitempty"`
}

type ChangeProposeRequest struct {
	OrgID          ID              `json:"org_id"`
	BaseGeneration Generation      `json:"base_generation"`
	Files          []ResourceDelta `json:"files"`
	Reason         BlobRef         `json:"reason"`
}

type ChangeRequest struct {
	Config            string          `json:"config"`
	Reason            BlobRef         `json:"reason"`
	SourceSnapshot    OrgSnapshotRef  `json:"source_snapshot"`
	OwnershipManifest BlobRef         `json:"ownership_manifest"`
	ID                ID              `json:"id"`
	OrgID             ID              `json:"org_id"`
	Requester         Actor           `json:"requester"`
	BaseGeneration    Generation      `json:"base_generation"`
	Files             []ResourceDelta `json:"files"`
	Derived           []ResourceDelta `json:"derived"`
	ManifestSHA256    Digest          `json:"manifest_sha256"`
	Diff              BlobRef         `json:"diff"`
	Renderer          Executable      `json:"renderer"`
	Status            string          `json:"status"`
	CreatedAt         Timestamp       `json:"created_at"`
	ExpiresAt         Timestamp       `json:"expires_at"`
}

type ChangeGetRequest struct {
	ChangeID ID `json:"change_id"`
}

type ChangeApproveRequest struct {
	ChangeID       ID         `json:"change_id"`
	ManifestSHA256 Digest     `json:"manifest_sha256"`
	BaseGeneration Generation `json:"base_generation"`
}

type ChangeApproval struct {
	SimulatedPresence bool       `json:"simulated_presence,omitempty"`
	ID                ID         `json:"id"`
	ChangeID          ID         `json:"change_id"`
	RequesterLifeID   ID         `json:"requester_life_id"`
	ApproverKeyID     ID         `json:"approver_key_id"`
	ManifestSHA256    Digest     `json:"manifest_sha256"`
	BaseGeneration    Generation `json:"base_generation"`
	NonceID           ID         `json:"nonce_id"`
	ApprovedAt        Timestamp  `json:"approved_at"`
	ExpiresAt         Timestamp  `json:"expires_at"`
}

type ChangeApplyRequest struct {
	ChangeID           ID         `json:"change_id"`
	ApprovalID         ID         `json:"approval_id"`
	ExpectedGeneration Generation `json:"expected_generation"`
}

type ChangeReceipt struct {
	SimulatedPresence bool       `json:"simulated_presence,omitempty"`
	ID                ID         `json:"id"`
	ChangeID          ID         `json:"change_id"`
	ApprovalID        ID         `json:"approval_id"`
	OldGeneration     Generation `json:"old_generation"`
	NewGeneration     Generation `json:"new_generation"`
	ManifestSHA256    Digest     `json:"manifest_sha256"`
	AppliedAt         Timestamp  `json:"applied_at"`
}
