package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// Invited test devices retain every software-presence marker while receiving
// distinct IDs. The initial test baseline keeps its existing canonical ID.
func InvitedCredentialID(raw []byte) ID {
	digest := sha256.Sum256(raw)
	return ID("invited-" + hex.EncodeToString(digest[:]))
}

// HumanAccessRequest is the D6 enrollment action. Its exact bytes, including
// the reviewed fingerprint and generation, are bound to a fresh human proof.
type HumanAccessRequest struct {
	Action             string     `json:"action"`
	InviteID           ID         `json:"invite_id,omitempty"`
	PrincipalID        ID         `json:"principal_id,omitempty"`
	Fingerprint        Digest     `json:"fingerprint,omitempty"`
	ExpectedGeneration Generation `json:"expected_generation,omitempty"`
	Role               string     `json:"role,omitempty"`
	CanApprove         bool       `json:"can_approve,omitempty"`
}

// Token is returned privately to the inviter, never placed in journal events
// or pending-list results. A fingerprint is SHA-256 of the attested DER key.
type HumanAdmission struct {
	ID                   ID         `json:"id"`
	Config               string     `json:"config"`
	InviterID            ID         `json:"inviter_id"`
	PrincipalID          ID         `json:"principal_id,omitempty"`
	Role                 string     `json:"role"`
	CanApprove           bool       `json:"can_approve"`
	State                string     `json:"state"`
	Fingerprint          Digest     `json:"fingerprint,omitempty"`
	Generation           Generation `json:"generation"`
	EnrollmentGeneration Generation `json:"enrollment_generation,omitempty"`
	CreatedAt            Timestamp  `json:"created_at"`
	ExpiresAt            Timestamp  `json:"expires_at"`
	Token                string     `json:"token,omitempty"`
}

type HumanPendingPage struct {
	Config        string           `json:"config"`
	Registrations []HumanAdmission `json:"registrations"`
}

type InvitedEnrollmentRequest struct {
	Token    string                    `json:"token"`
	Ceremony EnrollmentCeremonyRequest `json:"ceremony"`
}

// Optional private ports preserve fail-closed construction for older stores.
// These do not add anonymous/public read authority for a redeeming principal.
type HumanAdmissionStore interface {
	PrepareHumanChange(context.Context, Scope, HumanAccessRequest) (HumanAdmission, error)
	PendingHumans(context.Context, Scope) (HumanPendingPage, error)
	ReserveInvited(context.Context, InvitedEnrollmentRequest) (EnrollmentChallenge, error)
}

type InvitedEnrollment interface {
	BeginInvitedHuman(context.Context, InvitedEnrollmentRequest) (EnrollmentChallenge, error)
	CompleteInvitedHuman(context.Context, EnrollmentValidationRequest) (EnrollmentReceipt, error)
}

type humanEntryKey struct{}
type humanEntryCredential struct {
	Frame      FrameContext
	Credential ID
}

// A transport may retain its opening native frame solely as a staging
// selector. Identity still requires the key's proof for every new authority.
type HumanStaging struct {
	Frame        FrameContext
	PrincipalID  ID
	CredentialID ID
}

type HumanStagingSource interface {
	HumanStaging(context.Context) (HumanStaging, error)
}

// The transport supplies the original frame, never a caller-authored Scope.
// Selection still verifies the native peer/frame and the active inventory;
// ordinary reads and mutations keep their session/proof checks unchanged.
func WithHumanEntryFrame(ctx context.Context, frame FrameContext) context.Context {
	return context.WithValue(ctx, humanEntryKey{}, frame)
}

func HumanEntryFrame(ctx context.Context) FrameContext {
	if selected, ok := ctx.Value(humanEntryKey{}).(humanEntryCredential); ok {
		return selected.Frame
	}
	frame, _ := ctx.Value(humanEntryKey{}).(FrameContext)
	return frame
}

func WithHumanEntryCredential(ctx context.Context, frame FrameContext, credential ID) context.Context {
	return context.WithValue(ctx, humanEntryKey{}, humanEntryCredential{frame, credential})
}

func HumanEntryCredential(ctx context.Context) ID {
	selected, _ := ctx.Value(humanEntryKey{}).(humanEntryCredential)
	return selected.Credential
}

func ValidateHumanAccess(r HumanAccessRequest) error {
	clean := r
	clean.Action = ""
	switch r.Action {
	case "invite":
		clean.Role, clean.CanApprove = "", false
		if r.Role != "human" {
			return launchInvalid("invitations are bound to the human role")
		}
	case "approve", "reject":
		clean.InviteID, clean.Fingerprint, clean.ExpectedGeneration = "", "", 0
		if !launchID(r.InviteID) || !bindingDigest.MatchString(string(r.Fingerprint)) || !launchGeneration(r.ExpectedGeneration) {
			return launchInvalid("enrollment decision requires the exact pending fingerprint and generation")
		}
	case "revoke":
		clean.PrincipalID, clean.ExpectedGeneration = "", 0
		if !launchID(r.PrincipalID) || !launchGeneration(r.ExpectedGeneration) {
			return launchInvalid("revocation requires the exact enrolled principal and generation")
		}
	default:
		return launchInvalid("unknown human enrollment action")
	}
	if clean != (HumanAccessRequest{}) {
		return launchInvalid("human enrollment action contains unrelated fields")
	}
	return nil
}
