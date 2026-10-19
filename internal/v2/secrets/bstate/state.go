// Package bstate contains protected credential journal DTOs. These are
// never public RPCs, generic objects or authority derived from a caller's ID.
package bstate

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

type Profile struct {
	AccountSHA256  api.Digest      `json:"account_sha256,omitempty"`
	Usage          *UsageProfile   `json:"usage,omitempty"`
	Schema         string          `json:"schema"`
	Config         string          `json:"config"`
	ID             api.ID          `json:"id"`
	LoginID        api.ID          `json:"login_id"`
	Generation     api.Generation  `json:"generation"`
	Driver         api.Driver      `json:"driver"`
	Provider       string          `json:"provider"`
	Paid           bool            `json:"paid"`
	Mode           string          `json:"mode"`
	Source         api.SecretGrant `json:"source"`
	Runtime        api.Executable  `json:"runtime"`
	Models         []string        `json:"models"`
	VendorVersions []string        `json:"vendor_versions"`
	RefreshFields  []string        `json:"refresh_fields"`
	Evidence       api.BlobRef     `json:"evidence"`
	ExpiresAt      api.Timestamp   `json:"expires_at"`
}

// Installed metadata for the separately confined outside usage query. Vendor
// spelling is private enrollment, never inferred from a caller's profile ID.
type UsageProfile struct {
	VendorProfile   string         `json:"vendor_profile"`
	AdapterVersion  string         `json:"adapter_version"`
	Executable      api.Executable `json:"executable"`
	RuntimeManifest api.BlobRef    `json:"runtime_manifest"`
}

// Observation is metadata from an authenticated credential job retained by
// ObjectStore. It contains no credentials and does not authorize a login.
type Observation struct {
	Schema     string         `json:"schema"`
	Config     string         `json:"config"`
	ProfileID  api.ID         `json:"profile_id"`
	LoginID    api.ID         `json:"login_id"`
	Generation api.Generation `json:"generation"`
	Driver     api.Driver     `json:"driver"`
	Provider   string         `json:"provider"`
	Available  bool           `json:"available"`
	CheckedAt  api.Timestamp  `json:"checked_at"`
	ExpiresAt  api.Timestamp  `json:"expires_at"`
}

type Slot struct {
	PlanningClaim     api.LaunchClaim          `json:"planning_claim,omitempty"`
	ProjectionID      api.ID                   `json:"projection_id,omitempty"`
	Schema            string                   `json:"schema"`
	Config            string                   `json:"config"`
	ID                api.ID                   `json:"id"`
	Kind              string                   `json:"kind"`
	Target            api.LifeRef              `json:"target"`
	ReservationID     api.ID                   `json:"reservation_id"`
	LaunchID          api.ID                   `json:"launch_id"`
	HelperLeaseID     api.ID                   `json:"helper_lease_id"`
	Backend           string                   `json:"backend"`
	WorkerLeaseID     api.ID                   `json:"worker_lease_id"`
	WorkerLease       *api.WorkerLease         `json:"worker_lease,omitempty"`
	WorkerPlan        *api.WorkerPlan          `json:"worker_plan,omitempty"`
	Handoff           *api.PreparedSpecHandoff `json:"handoff,omitempty"`
	OperationID       api.ID                   `json:"operation_id"`
	RequestID         api.ID                   `json:"request_id"`
	RequestedBy       api.Actor                `json:"requested_by"`
	Injection         *api.Injection           `json:"injection,omitempty"`
	GrantSetID        api.ID                   `json:"grant_set_id"`
	GrantSHA256       api.Digest               `json:"grant_sha256"`
	PolicyGeneration  api.Generation           `json:"policy_generation"`
	Fingerprint       api.Digest               `json:"fingerprint"`
	ProfileID         api.ID                   `json:"profile_id"`
	ProfileGeneration api.Generation           `json:"profile_generation"`
	LoginID           api.ID                   `json:"login_id"`
	Credential        api.CredentialSlot       `json:"credential"`
	Grant             api.SecretGrant          `json:"grant"`
	Material          []byte                   `json:"material"`
	Returned          []byte                   `json:"returned"`
	Released          bool                     `json:"released"`
}

type Login struct {
	PendingRelease api.ID           `json:"pending_release,omitempty"`
	ProjectionID   api.ID           `json:"projection_id,omitempty"`
	AccountSHA256  api.Digest       `json:"account_sha256,omitempty"`
	Generation     api.Generation   `json:"generation"`
	RefreshObject  string           `json:"refresh_object,omitempty"`
	Quarantined    bool             `json:"quarantined,omitempty"`
	ID             api.ID           `json:"id"`
	SlotID         api.ID           `json:"slot_id"`
	Driver         api.Driver       `json:"driver,omitempty"`
	Provider       string           `json:"provider,omitempty"`
	Source         *api.SecretGrant `json:"source,omitempty"`
	Material       []byte           `json:"material,omitempty"`
	RefreshSlotID  api.ID           `json:"refresh_slot_id,omitempty"`
}

// Projection contains only private metadata. Descriptors and plaintext are
// never journaled. Fenced survives a lost reply or a broker restart.
type Projection struct {
	Authority     api.CredentialProjectionAuthority `json:"authority"`
	Facts         []api.CredentialDescriptorFact    `json:"facts"`
	Fenced        bool                              `json:"fenced"`
	Released      bool                              `json:"released"`
	RefreshObject string                            `json:"refresh_object,omitempty"`
	Refresh       *api.CredentialSourceVersion      `json:"refresh,omitempty"`
}

// PlanCleanup journals metadata only. The immutable request and native effect
// survive lost replies; a nonempty Broker ref marks the complete owner result.
type PlanCleanup struct {
	Request api.PlanCleanup
	Effect  api.Effect
	Receipt api.PlanCleanupReceipt
}

// Journal runs under the encrypted backend's cross-process lock. Bytes passed
// to Read/Write remain inside an AES-GCM envelope, separate from regular records.
type Journal interface {
	Read(string, api.ID, any) error
	Write(string, api.ID, any) error
	Fetch(context.Context, api.SecretGrant) (api.SecretMaterial, error)
	AcquireRefreshLease(api.ID) (RefreshLease, error)
}

// RefreshLease is a process-owned kernel lock, never a serialized ownership
// assertion. Held probes the pinned lock through an independent open handle.
type RefreshLease interface {
	Check() error
	Close() error
	Held() (bool, error)
}

type Backend interface {
	WithBroker(context.Context, func(Journal) error) error
}

// DurableBackend acquires with the caller context, then retains a bounded
// journal lifetime for failure fencing after that caller is cancelled.
type DurableBackend interface {
	WithBrokerDurable(context.Context, func(Journal) error) error
}
