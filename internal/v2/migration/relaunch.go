package migration

import (
	"context"
	"fmt"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type RelaunchOptions struct {
	PlanID                   api.ID
	Lane                     string
	Level                    int
	Role                     string
	Driver                   api.Driver
	ProfileGrantID           api.ID
	Model                    string
	Effort                   string
	Task                     api.BlobRef
	Grants                   api.GrantRequest
	GrantSet                 api.GrantSet
	Budget                   api.Budget
	RootTicketID             api.ID
	ExpectedPolicyGeneration api.Generation
	UseLegacyLabelsForParent bool
	UseSharedLastHome        bool
}

type PreparedRelaunch struct {
	Manifest        api.AdoptionManifest `json:"manifest"`
	ManifestBytes   []byte               `json:"-"`
	ManifestBlobRef api.BlobRef          `json:"manifest_blob_ref"`
	AdoptRequest    api.AdoptRequest     `json:"adopt_request"`
	Materialization api.Materialization  `json:"materialization"`
}

// PrepareRelaunch prepares a verified AdoptionManifest and AdoptRequest to
// relaunch a selected unfinished legacy session in new v2 confinement.
func (s *Service) PrepareRelaunch(ctx context.Context, scope api.Scope, opts RelaunchOptions) (*PreparedRelaunch, error) {
	if err := validateScopeForPlan(scope); err != nil {
		return nil, err
	}
	if !ValidID(api.ID(opts.Lane)) || !legacyArgument(opts.Lane) {
		return nil, invalidErr("legacy.lane is invalid")
	}
	if opts.UseLegacyLabelsForParent {
		if !allowLabelParent() {
			return nil, forbiddenErr("cannot derive parent life or starter chain from legacy labels during relaunch")
		}
	}
	if opts.UseSharedLastHome {
		return nil, invalidErr("shared vendor home or --last continuation is forbidden; relaunch requires a private home and explicit session ID")
	}
	if opts.Level < 3 || opts.Level > 6 {
		return nil, invalidErr("relaunch level must be between 3 and 6")
	}
	if !ValidID(api.ID(opts.Role)) || !legacyArgument(opts.Role) {
		return nil, invalidErr("relaunch role is required")
	}
	if opts.Driver != api.DriverClaudock && opts.Driver != api.DriverCodex {
		return nil, invalidErr(fmt.Sprintf("unsupported relaunch driver %q; only claudock-cli and codex are permitted", opts.Driver))
	}
	if !ValidID(opts.ProfileGrantID) {
		return nil, invalidErr("relaunch profile_grant_id is required")
	}
	if err := ValidateBlobRef(opts.Task, "task"); err != nil {
		return nil, invalidErr("relaunch task: " + err.Error())
	}
	if opts.Budget.WallMS <= 0 || opts.Budget.CPUSeconds == 0 || opts.Budget.MemoryBytes == 0 || opts.Budget.Processes == 0 || opts.Budget.DiskBytes == 0 {
		return nil, invalidErr("relaunch budget limits must all be positive")
	}

	st, ok := s.lookupPlan(opts.PlanID)
	if !ok || st.config != scope.Config {
		return nil, &api.Error{
			Code:    api.CodeNotFound,
			Message: fmt.Sprintf("migration plan %s not found", opts.PlanID),
			Instead: "Run migration plan first and supply its plan_id.",
			Owner:   "lb-v2-migration",
		}
	}

	var target *LegacyUnfinishedSession
	for i := range st.bundle.Unfinished {
		if st.bundle.Unfinished[i].Lane == opts.Lane {
			target = &st.bundle.Unfinished[i]
			break
		}
	}
	if target == nil {
		return nil, &api.Error{
			Code:    api.CodeNotFound,
			Message: fmt.Sprintf("lane %q is not an unfinished session in migration plan %s", opts.Lane, opts.PlanID),
			Instead: "Select a lane listed in requires_relaunch.",
			Owner:   "lb-v2-migration",
		}
	}
	if err := validateLegacyRelaunch(*target); err != nil {
		return nil, err
	}
	selected := *target
	if opts.Model != "" {
		selected.Model = opts.Model
	}
	if opts.Effort != "" {
		selected.Effort = opts.Effort
	}
	if err := validateLegacyRelaunch(selected); err != nil {
		return nil, err
	}

	grantSet := opts.GrantSet
	if grantSet.ID != "" {
		unsigned := grantSet
		unsigned.SHA256 = ""
		encoded, err := CanonicalJCS(unsigned)
		expiry, expiryErr := time.Parse(time.RFC3339Nano, string(grantSet.ExpiresAt))
		if err != nil || !ValidDigest(grantSet.SHA256) || DigestBytes(encoded) != grantSet.SHA256 {
			return nil, invalidErr("relaunch.grant_set.sha256 is invalid")
		}
		if expiryErr != nil || !ValidTimestamp(grantSet.ExpiresAt) || !expiry.After(time.Now()) {
			return nil, invalidErr("relaunch.grant_set.expires_at is invalid")
		}
	}
	if grantSet.ID == "" {
		grantSet = api.GrantSet{
			ID:               DeterministicID("gset-relaunch-", string(opts.PlanID), opts.Lane),
			LifeID:           DeterministicID("life-relaunch-", string(opts.PlanID), opts.Lane),
			PolicyGeneration: opts.ExpectedPolicyGeneration,
			Generation:       1,
			Resources:        []api.ResourceGrant{},
			Data:             []api.DataGrant{},
			Secrets:          []api.SecretGrant{},
			Profiles:         []api.ProfileGrant{},
			Network:          []api.NetworkGrant{},
			Channels:         []api.ChannelGrant{},
			ExpiresAt:        api.Timestamp(time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano)),
		}
		jcsGrants, err := CanonicalJCS(grantSet)
		if err != nil {
			return nil, err
		}
		grantSet.SHA256 = DigestBytes(jcsGrants)
	}

	mat, err := s.deps.Worker.Materialize(ctx, grantSet)
	if err != nil {
		return nil, err
	}

	histBytes := target.SessionHistory
	if len(histBytes) == 0 {
		histBytes = []byte("{}\n")
	}
	histRef := api.BlobRef{
		ID:     DeterministicID("blob-hist-", string(opts.PlanID), opts.Lane),
		SHA256: DigestBytes(histBytes),
		Bytes:  int64(len(histBytes)),
		Class:  "transcript",
	}

	wsSnapshot := mat.Manifest
	if wsSnapshot.ID == "" {
		wsBytes, _ := CanonicalJCS(target.WorktreeFiles)
		wsSnapshot = api.BlobRef{
			ID:     DeterministicID("blob-ws-", string(opts.PlanID), opts.Lane),
			SHA256: DigestBytes(wsBytes),
			Bytes:  int64(len(wsBytes)),
			Class:  "archive",
		}
	}

	branch := target.Branch
	if branch == "" {
		branch = opts.Lane
	}
	baseCommit := target.Base

	workspace := api.Workspace{
		ID:         DeterministicID("ws-mig-", string(opts.PlanID), opts.Lane),
		ProjectID:  "migrated-project",
		Base:       baseCommit,
		Branch:     branch,
		LogicalCWD: "/work/main",
		Snapshot:   wsSnapshot,
	}

	session := api.Session{
		HistoryID:     DeterministicID("hist-mig-", string(opts.PlanID), opts.Lane),
		ID:            DeterministicID("sess-mig-", string(opts.PlanID), opts.Lane),
		Driver:        opts.Driver,
		VendorID:      target.SessionID,
		VendorVersion: st.bundle.Manifest.SourceVersion,
		HomeID:        DeterministicID("home-mig-", string(opts.PlanID), opts.Lane),
		LogicalCWD:    "/work/main",
	}

	adoptManifest := api.AdoptionManifest{
		Schema:         SchemaAdoptionManifest,
		Workspace:      workspace,
		Session:        session,
		PrivateHistory: histRef,
		Quiescence:     st.bundle.Manifest.Quiescence,
		SourceVersion:  st.bundle.Manifest.SourceVersion,
	}
	adoptBytes, err := CanonicalJCS(adoptManifest)
	if err != nil {
		return nil, err
	}
	adoptRef := api.BlobRef{
		ID:     DeterministicID("blob-adopt-", string(opts.PlanID), opts.Lane),
		SHA256: DigestBytes(adoptBytes),
		Bytes:  int64(len(adoptBytes)),
		Class:  "manifest",
	}

	model := opts.Model
	if model == "" {
		model = target.Model
	}
	effort := opts.Effort
	if effort == "" {
		effort = target.Effort
		if effort == "" {
			effort = "high"
		}
	}

	adoptReq := api.AdoptRequest{
		ProfileGrantID:           opts.ProfileGrantID,
		Model:                    model,
		Effort:                   effort,
		Task:                     opts.Task,
		RootTicketID:             opts.RootTicketID,
		Lane:                     opts.Lane,
		Level:                    opts.Level,
		Role:                     opts.Role,
		ImportManifest:           adoptRef,
		Grants:                   opts.Grants,
		Driver:                   opts.Driver,
		Budget:                   opts.Budget,
		ExpectedPolicyGeneration: opts.ExpectedPolicyGeneration,
	}

	return &PreparedRelaunch{
		Manifest:        adoptManifest,
		ManifestBytes:   adoptBytes,
		ManifestBlobRef: adoptRef,
		AdoptRequest:    adoptReq,
		Materialization: mat,
	}, nil
}
