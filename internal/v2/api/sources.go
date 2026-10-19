package api

import "context"

// InitialPublicationMarker is the protected installer's existing immutable
// marker payload. Ordinary org bootstrap retains its ConfigView payload.
type InitialPublicationMarker struct {
	Schema   string  `json:"schema"`
	Config   string  `json:"config"`
	ID       ID      `json:"id"`
	Manifest BlobRef `json:"manifest"`
}

type OrgSnapshotRef struct {
	OrgID          ID         `json:"org_id"`
	Generation     Generation `json:"generation"`
	ManifestSHA256 Digest     `json:"manifest_sha256"`
}

type ResourceFile struct {
	Source             SourceRef
	Content            BlobRef
	Kind               string
	Mode               uint32
	RevisionGeneration Generation
}

type OrgSnapshot struct {
	Ref               OrgSnapshotRef
	Config            string
	Sources           []ResourceFile
	Derived           []ResourceFile
	Renderer          Executable
	OwnershipManifest BlobRef
	PublishedBy       ID
	PublishedAt       Timestamp
}

type OrgSnapshotRequest struct {
	OrgID      ID
	Generation Generation
}

type TemplateSource struct {
	Source  SourceRef
	Content BlobRef
}

type RoleTemplateSources struct {
	Prompt  TemplateSource
	Drivers TemplateSource
}

type TemplateSources struct {
	Snapshot    OrgSnapshotRef
	Context     RoleContext
	Org         RoleTemplateSources
	Local       *RoleTemplateSources
	LocalStatus string
}

type TemplateSourceRequest struct {
	OrgID      ID
	Generation Generation
	Context    RoleContext
}

type RetainedSource struct {
	Source  SourceRef
	Content BlobRef
}

// BriefingInput is resolved from a current/reserved authentic life or from a
// human read-only overview. An overview has no invented task, lane or launch.
type BriefingInput struct {
	Mode     string
	Lane     *Lane
	Task     *BlobRef
	GrantSet *GrantSet
	Policy   EffectivePolicy
	Sources  TemplateSources
	Groups   LaneGroups
	Checks   []Capability
}

type BriefingInputRequest struct {
	LifeID     ID
	GrantSetID ID
	Context    RoleContext
}

type PublishChangeRequest struct {
	Lease          EffectLease
	ChangeID       ID
	ApprovalID     ID
	BaseGeneration Generation
	ManifestSHA256 Digest
	Renderer       Executable
}

type BootstrapEffect struct {
	OrgID             ID
	OrgName           string
	SourceManifest    BlobRef
	Renderer          Executable
	OwnershipManifest BlobRef
}

type BootstrapReceipt struct {
	ID          ID
	OrgID       ID
	Generation  Generation
	Manifest    BlobRef
	Renderer    Executable
	OperationID ID
	PublishedAt Timestamp
}

// OrgPublisher performs an approved immutable-generation/pointer publication
// and reconciles its durable marker. Enqueueing intent is never its receipt.
type OrgPublisher interface {
	PublishChange(context.Context, Scope, PublishChangeRequest) (ChangeReceipt, error)
	ReconcileChange(context.Context, Scope, PublishChangeRequest) (ChangeReceipt, error)
	PublishBootstrap(context.Context, Scope, EffectLease) (BootstrapReceipt, error)
}

// ScopedOrgRenderer preserves the authenticated proposal/apply frame while
// the installed worker computes deterministic source-derived review outputs.
// It is an in-process capability, not an RPC or an actor selector.
type ScopedOrgRenderer interface {
	RenderForScope(context.Context, Scope, ChangeRequest) (ChangeRequest, error)
}

type OrgStore interface {
	OrgSnapshot(context.Context, Scope, OrgSnapshotRequest) (OrgSnapshot, error)
	TemplateSources(context.Context, Scope, TemplateSourceRequest) (TemplateSources, error)
	Source(context.Context, Scope, SourceRef) (RetainedSource, error)
	BriefingInput(context.Context, Scope, BriefingInputRequest) (BriefingInput, error)
	Approval(context.Context, Scope, ID) (ChangeApproval, error)
	Application(context.Context, Scope, ID) (ChangeReceipt, error)
}
