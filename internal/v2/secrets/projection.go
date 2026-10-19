package secrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type projectionFlight struct {
	mu        sync.Mutex
	serial    chan struct{}
	peer      api.VerifiedPeer
	transfer  api.CredentialTransfer
	facts     []api.CredentialDescriptorFact
	refresh   []projectionRefreshLease
	fenced    bool
	closed    bool
	inventory *projectionInventory
}

func (s *Service) flight(id api.ID) *projectionFlight {
	s.projectionMu.Lock()
	defer s.projectionMu.Unlock()
	f := s.projections[id]
	if f == nil {
		f = &projectionFlight{serial: make(chan struct{}, 1)}
		s.projections[id] = f
	}
	return f
}
func (f *projectionFlight) enter(ctx context.Context) error {
	select {
	case f.serial <- struct{}{}:
		return nil
	case <-ctx.Done():
		return wire.Context(ctx)
	}
}
func (f *projectionFlight) leave()         { <-f.serial }
func (f *projectionFlight) fence()         { f.mu.Lock(); f.fenced = true; f.mu.Unlock() }
func (f *projectionFlight) isFenced() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.fenced }

func (s *Service) projectionPeer(ctx context.Context, peer api.VerifiedPeer, a api.CredentialProjectionAuthority) error {
	if wire.Nil(peer) {
		return wire.Error(api.CodeUnauthenticated, "credential projection requires its private native helper peer")
	}
	if err := peer.Alive(ctx); err != nil {
		return err
	}
	facts, err := peer.Facts(ctx)
	if err != nil {
		return err
	}
	if facts != a.HelperPeer || facts.HostUID != 0 || a.Request.Handoff.Config != s.deps.Config {
		return wire.Error(api.CodeForbidden, "credential projection helper differs from its installed native authority")
	}
	return verifyProjectionHost(a)
}

// Called while the outside canonical journal lock is held. Inventory versions
// are metadata, never hashes of credential values. Immutable task sources have
// generation one; canonical logins have a persisted refresh generation.
func (s *Service) projectionSlots(ctx context.Context, j bstate.Journal, a api.CredentialProjectionAuthority) ([]bstate.Slot, []api.CredentialSourceVersion, error) {
	r := a.Request
	if err := s.projectionPolicy(ctx, r); err != nil {
		return nil, nil, err
	}
	policy, err := s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ServiceScope)
	if err != nil {
		return nil, nil, err
	}
	if policy.Generation != r.Handoff.Spec.PolicyGeneration || !wire.Digest(policy.SHA256) {
		return nil, nil, wire.Error(api.CodeConflict, "credential projection policy changed during source selection")
	}
	grants, err := s.deps.Store.Grants(ctx, r.Handoff.Spec.Grants.ID)
	if err != nil {
		return nil, nil, err
	}
	if wire.Nil(s.deps.Grants) {
		return nil, nil, wire.Error(api.CodePrerequisite, "credential projection requires its current grant resolver")
	}
	var current api.GrantSet
	if r.Handoff.Spec.Kind == "agent" {
		plan, readErr := s.deps.Store.LaunchPlan(ctx, s.deps.ServiceScope, r.Handoff.Spec.PlanID)
		if readErr != nil {
			return nil, nil, readErr
		}
		if plan.Phase == "spec_retained" {
			current, err = s.deps.Grants.Resolve(ctx, s.deps.ServiceScope, api.GrantResolveRequest{ReservationID: plan.Reservation.ID})
		} else {
			current, err = s.deps.Grants.Revalidate(ctx, grants)
		}
	} else {
		current, err = s.deps.Grants.Revalidate(ctx, grants)
	}
	if err != nil {
		return nil, nil, err
	}
	if !reflect.DeepEqual(current, grants) || !reflect.DeepEqual(current, r.Handoff.Spec.Grants) || current.Revoked || !future(current.ExpiresAt, s.deps.Clock.Now()) {
		return nil, nil, wire.Error(api.CodeForbidden, "credential projection grants changed or were revoked")
	}
	result, sources := []bstate.Slot{}, []api.CredentialSourceVersion{}
	valid := false
	defer func() {
		if !valid {
			clearProjectionSlots(result)
		}
	}()
	for _, target := range a.Targets {
		var found bstate.Slot
		selected := false
		defer func() {
			if !selected {
				clear(found.Material)
				clear(found.Returned)
			}
		}()
		for _, id := range r.Handoff.Spec.Injection.SlotIDs {
			var slot bstate.Slot
			if err := j.Read("slot", id, &slot); err != nil {
				clear(slot.Material)
				clear(slot.Returned)
				return nil, nil, err
			}
			match := target.SlotID != "" && slot.ID == target.SlotID || target.SlotID == "" && slot.Grant.SourceHandle == target.SourceHandle && slot.Grant.Version == target.Version && (slot.Grant.ID == target.GrantID || r.Worker != nil && slot.Grant.Name == string(target.Key))
			if !match {
				clear(slot.Material)
				clear(slot.Returned)
				continue
			}
			if found.ID != "" {
				clear(slot.Material)
				clear(slot.Returned)
				return nil, nil, wire.Error(api.CodeConflict, "credential projection source selection is ambiguous")
			}
			found = slot
		}
		if found.ID == "" || found.Released || found.PolicyGeneration != r.Handoff.Spec.PolicyGeneration || found.ProjectionID != "" && found.ProjectionID != a.ID || found.Config != s.deps.Config || found.Target != r.Prepared.Target || found.GrantSetID != grants.ID || found.GrantSHA256 != grants.SHA256 || !future(found.Grant.ExpiresAt, s.deps.Clock.Now()) {
			return nil, nil, wire.Error(api.CodeForbidden, "credential projection has no exact live selected slot")
		}
		if r.Worker == nil && (found.LaunchID != r.Handoff.Spec.LaunchID || found.ReservationID != r.Handoff.Spec.PlanID || found.HelperLeaseID != r.Lease.ID) || r.Worker != nil && found.WorkerLeaseID != r.Worker.ID {
			return nil, nil, wire.Error(api.CodeForbidden, "credential projection slot belongs to another retained launch")
		}
		if r.Worker != nil && (found.WorkerPlan == nil || !reflect.DeepEqual(found.WorkerPlan, r.Handoff.Spec.Worker)) {
			return nil, nil, wire.Error(api.CodeForbidden, "credential worker projection changed its prepared fixed plan")
		}
		if r.Worker != nil {
			if found.Handoff != nil && !reflect.DeepEqual(*found.Handoff, r.Handoff) {
				return nil, nil, wire.Error(api.CodeConflict, "worker projection handoff changed")
			}
			if err := s.retainedWorkerSpecJournal(ctx, r.Handoff, found, false, j); err != nil {
				return nil, nil, err
			}
		}
		if target.SlotID == "" && (found.Grant.Delivery != target.Delivery || target.Delivery == "env" && found.Grant.Target != target.EnvironmentName || target.Delivery == "file" && ".laneboss-secrets/"+found.Grant.Target != target.RelativePath) {
			return nil, nil, wire.Error(api.CodeForbidden, "credential projection changed the selected fixed task destination")
		}
		material, err := j.Fetch(ctx, found.Grant)
		clear(material.Bytes)
		if err != nil {
			return nil, nil, err
		}
		source := api.CredentialSourceVersion{Key: target.Key, Generation: 1, Version: found.Grant.Version}
		if target.SlotID != "" {
			var profile bstate.Profile
			if err := j.Read("profile", found.ProfileID, &profile); err != nil {
				return nil, nil, err
			}
			if profile.Generation != found.ProfileGeneration || publicSlotMode(profile) != found.Credential.Mode || !future(profile.ExpiresAt, s.deps.Clock.Now()) || slices.Contains(policy.ProfileExclusions, profile.ID) {
				return nil, nil, wire.Error(api.CodeForbidden, "credential projection profile enrollment changed")
			}
			if profile.Mode == "codex-file" {
				if wire.Nil(s.deps.CodexValidator) {
					return nil, nil, wire.Error(api.CodePrerequisite, "credential projection requires its installed Codex validator")
				}
				if err := s.deps.CodexValidator.ValidateCodexCredential(profile.ID, profile.LoginID, profile.AccountSHA256, found.Material); err != nil {
					return nil, nil, wire.Error(api.CodeForbidden, "credential projection failed its pinned Codex account validation")
				}
			}
			if profile.Mode == "claudock-headless" {
				if wire.Nil(s.deps.HeadlessValidator) {
					return nil, nil, wire.Error(api.CodePrerequisite, "credential projection requires its installed headless validator")
				}
				if err := s.deps.HeadlessValidator.ValidateHeadlessCredential(string(profile.ID), string(profile.LoginID), found.Material); err != nil {
					return nil, nil, wire.Error(api.CodeForbidden, "credential projection failed its pinned headless token validation")
				}
			}
			if profile.Mode == "claude-api-key" {
				if wire.Nil(s.deps.APIKeyValidator) {
					return nil, nil, wire.Error(api.CodePrerequisite, "credential projection requires its installed API key validator")
				}
				if err := s.deps.APIKeyValidator.ValidateAPIKeyCredential(string(profile.ID), string(profile.LoginID), found.Material); err != nil {
					return nil, nil, wire.Error(api.CodeForbidden, "credential projection failed its pinned API key validation")
				}
			}
			if found.Credential != r.Handoff.Spec.Runner.Slot || !future(found.Credential.ExpiresAt, s.deps.Clock.Now()) {
				return nil, nil, wire.Error(api.CodeForbidden, "credential projection profile lease expired or changed")
			}
			if found.Credential.Mode == "codex-file" {
				var login bstate.Login
				if err := j.Read("login", found.LoginID, &login); err != nil {
					clear(login.Material)
					return nil, nil, err
				}
				clear(login.Material)
				if login.Quarantined || login.PendingRelease != "" || login.SlotID != found.ID || login.Generation == 0 {
					return nil, nil, wire.Error(api.CodeForbidden, "credential projection lost its canonical refresh owner")
				}
				source.Generation = login.Generation
			}
		}
		result, sources = append(result, found), append(sources, source)
		selected = true
	}
	valid = true
	return result, sources, nil
}
func clearProjectionSlots(slots []bstate.Slot) {
	for i := range slots {
		clear(slots[i].Material)
		clear(slots[i].Returned)
	}
}

func (s *Service) projectionPolicy(ctx context.Context, r api.CredentialProjectionRequest) error {
	policy, err := s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ServiceScope)
	if err != nil {
		return err
	}
	if policy.Generation != r.Handoff.Spec.PolicyGeneration || !wire.Digest(policy.SHA256) {
		return wire.Error(api.CodeConflict, "credential gate policy changed before opening")
	}
	return nil
}

func (s *Service) projectionRecord(ctx context.Context, a api.CredentialProjectionAuthority) (api.CredentialProjectionRecord, error) {
	record, err := s.deps.Store.CredentialProjection(ctx, s.deps.Config, a.Request.Prepared.ID)
	if err != nil {
		return record, err
	}
	if !reflect.DeepEqual(record.Authority, a) {
		return record, wire.Error(api.CodeIntegrity, "credential projection changed its protected prepared authority")
	}
	return record, nil
}

func (s *Service) projectionInputs(ctx context.Context, r api.CredentialProjectionRequest) error {
	if wire.Nil(s.deps.Control) || wire.Nil(s.deps.Helper) {
		return wire.Error(api.CodePrerequisite, "credential projection requires its installed handoff and runtime ports")
	}
	handoff, err := s.deps.Control.Handoff(ctx, r.Handoff.Spec)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(handoff, r.Handoff) {
		return wire.Error(api.CodeForbidden, "credential projection changed its retained complete handoff")
	}
	data, err := s.protectedObject(ctx, handoff.Original, handoff.OperationID, r.Prepared.Target.LifeID)
	if err != nil {
		return err
	}
	var spec api.LaunchSpec
	if err := api.DecodeObject(data, &spec); err != nil {
		return err
	}
	if !reflect.DeepEqual(spec, r.Handoff.Spec) {
		return wire.Error(api.CodeIntegrity, "credential projection differs from its exact retained spec bytes")
	}
	runtime, err := s.deps.Helper.ResolveRuntime(ctx, handoff)
	if err != nil {
		return err
	}
	if runtime.SpecReceipt.Config != s.deps.Config || runtime.SpecReceipt.Target != r.Prepared.Target || runtime.SpecReceipt.OperationID != handoff.OperationID || runtime.SpecReceipt.SpecSHA256 != handoff.SpecSHA256 || runtime.SpecReceipt.LeaseID != r.Lease.ID || runtime.SpecReceipt.SpecID != spec.ID || runtime.SpecReceipt.RuntimeManifest != spec.RuntimeManifest || runtime.Home != r.Home.Home || runtime.Workspace != spec.Workspace {
		return wire.Error(api.CodeForbidden, "credential projection changed its opened runtime or held home")
	}
	if spec.Runner != nil {
		if err := s.agentRuntime(ctx, spec.RuntimeManifest, runtime.Manifest, spec.Runner.Executable); err != nil {
			return err
		}
	}
	if spec.Worker != nil && runtime.Manifest.Bootstrap != spec.Worker.Executable {
		return wire.Error(api.CodeForbidden, "credential projection runtime bootstrap differs from its selected executable")
	}
	if spec.Kind == "agent" {
		record, err := s.deps.Store.LaunchPlan(ctx, s.deps.ServiceScope, spec.PlanID)
		if err != nil {
			return err
		}
		if record.Plan == nil || record.Handoff == nil || !reflect.DeepEqual(*record.Handoff, handoff) || record.Plan.Data.Home != r.Home || record.Plan.Lease != r.Lease {
			return wire.Error(api.CodeForbidden, "credential projection has no exact retained agent plan")
		}
		return api.ValidateAgentLaunchSpec(spec, *record.Plan)
	}
	if r.Worker == nil || spec.Worker == nil {
		return wire.Error(api.CodeInvalid, "credential projection worker is absent")
	}
	lease, err := s.deps.Store.WorkerLease(ctx, s.deps.ServiceScope, r.Worker.ID)
	if err != nil {
		return err
	}
	if lease != *r.Worker || spec.Worker.Input != lease.Input || spec.Worker.GrantSetID != lease.GrantSetID {
		return wire.Error(api.CodeForbidden, "credential projection changed its actual worker lease and input")
	}
	_, err = s.protectedObject(ctx, lease.Input, lease.OperationID)
	return err
}

// The enrolled vendor executable is a runtime object; Bootstrap is the
// separately pinned gate program. Older combined runtimes use Bootstrap for
// both roles, so that exact executable remains a supported shape.
func projectionAgentExecutable(manifest api.RuntimeManifest, executable api.Executable, installed api.RuntimeManifest) bool {
	if manifest.Bootstrap != installed.Bootstrap {
		return false
	}
	if manifest.Bootstrap == executable {
		return true
	}
	if executable.ID == "claudock" || executable.ID == "claude" {
		// Vendor files have their own canonical roles. They must agree with
		// the independent protected installation, including the root/path,
		// complete content pin and immutable executable mode. Count every
		// object bearing this ID, including duplicates with an invalid role.
		observed, observedOK := projectionVendorObject(manifest, executable.ID)
		enrolled, enrolledOK := projectionVendorObject(installed, executable.ID)
		return observedOK && enrolledOK && reflect.DeepEqual(observed, enrolled) &&
			manifest.Schema == installed.Schema && manifest.Generation == installed.Generation &&
			observed.Role == string(executable.ID) && observed.RelativePath == observed.Role &&
			wire.ID(string(observed.RootID)) && observed.Mode == 0555 &&
			observed.Content.ID == observed.ID && observed.Content.Class == "artifact" &&
			observed.Content.Bytes > 0 && observed.Content.Bytes <= api.MaxVendorBytes &&
			wire.Digest(observed.Content.SHA256) && observed.Content.SHA256 == executable.SHA256
	}
	matches := 0
	for _, object := range manifest.Objects {
		agentRole := object.Role == "agent" || standInAgentRole != "" && object.Role == standInAgentRole
		if object.ID == executable.ID && agentRole && object.Content.SHA256 == executable.SHA256 && object.Mode&0111 != 0 {
			matches++
		}
	}
	return matches == 1
}

func projectionVendorObject(manifest api.RuntimeManifest, id api.ID) (api.RuntimeObject, bool) {
	var selected api.RuntimeObject
	count := 0
	for _, object := range manifest.Objects {
		if object.ID == id {
			selected = object
			count++
		}
	}
	return selected, count == 1
}

// The native observation and the retained installed-runtime pin are independent
// reads. Selecting a legitimate agent object cannot replace the gate program.
func (s *Service) agentRuntime(ctx context.Context, ref api.BlobRef, observed api.RuntimeManifest, executable api.Executable) error {
	metadata, err := s.deps.Store.ObjectMetadata(ctx, s.deps.ServiceScope, ref.ID)
	if err != nil {
		return err
	}
	if ref.Class != "manifest" || metadata.Ref != ref || metadata.ACL.Owner.Kind != "service" || !wire.ID(string(metadata.SourceOperationID)) {
		return wire.Error(api.CodeForbidden, "credential runtime lacks its protected installed manifest pin")
	}
	raw, err := s.protectedObjectFor(ctx, ref, metadata.SourceOperationID, true, metadata.ACL.LifeID)
	if err != nil {
		return err
	}
	var installed api.RuntimeManifest
	if err := api.DecodeObject(raw, &installed); err != nil {
		return err
	}
	gate := installed.Bootstrap
	// The same conditions, named so a refusal says which one failed (item 1 diagnosis, box 72).
	agentObjects := 0
	for _, object := range observed.Objects {
		if object.ID == executable.ID {
			agentObjects++
		}
	}
	for _, c := range []struct {
		name string
		bad  bool
	}{
		{"schema", installed.Schema != "laneboss.runtime.v2"}, {"generation", installed.Generation == 0},
		{"gate_pin", !wire.ID(string(gate.ID)) || !wire.Digest(gate.SHA256) || gate.Version == ""},
		{"observed_bootstrap", observed.Bootstrap != gate},
		{fmt.Sprintf("agent_object objects_with_id=%d executable_is_bootstrap=%t", agentObjects, observed.Bootstrap == executable), !projectionAgentExecutable(observed, executable, installed)},
	} {
		if c.bad {
			return wire.Error(api.CodeForbidden, "credential agent or gate bootstrap differs from its installed runtime pin ("+c.name+")")
		}
	}
	return nil
}

func (s *Service) TransferCredentials(ctx context.Context, peer api.VerifiedPeer, request api.CredentialProjectionRequest) (api.CredentialTransfer, error) {
	return s.transferCredentials(ctx, peer, request, nil)
}
func (s *Service) transferCredentials(ctx context.Context, peer api.VerifiedPeer, request api.CredentialProjectionRequest, exchange func(bstate.Journal, *projectionFlight) error) (api.CredentialTransfer, error) {
	var empty api.CredentialTransfer
	if err := wire.Context(ctx); err != nil {
		return empty, err
	}
	if err := api.ValidateCredentialProjectionRequest(request, s.deps.Clock.Now()); err != nil {
		return empty, err
	}
	// Retain verified native metadata before identity selects that protected
	// record. No descriptor is exported until both owners validate it below.
	if _, err := s.deps.Store.ReserveCredentialProjection(ctx, s.deps.ServiceScope, request); err != nil {
		return empty, err
	}
	a, err := s.deps.ProjectionIdentity.AuthorizeCredentialProjection(ctx, peer, request)
	if err != nil {
		return empty, err
	}
	if !reflect.DeepEqual(a.Request, request) {
		return empty, wire.Error(api.CodeForbidden, "credential projection identity returned another request")
	}
	f := s.flight(a.ID)
	if err := f.enter(ctx); err != nil {
		return empty, err
	}
	defer f.leave()
	err = s.projectionJournal(ctx, f, a.ID, func(j bstate.Journal) error {
		if err := s.transferLocked(ctx, j, f, peer, a); err != nil {
			return err
		}
		if exchange != nil {
			return exchange(j, f)
		}
		return nil
	})
	if err != nil {
		return empty, err
	}
	return api.CredentialTransfer{Authority: f.transfer.Authority, Files: append([]*os.File(nil), f.transfer.Files...)}, nil
}
func (s *Service) transferLocked(ctx context.Context, j bstate.Journal, f *projectionFlight, peer api.VerifiedPeer, a api.CredentialProjectionAuthority) error {
	if f.isFenced() {
		return wire.Error(api.CodeConflict, "credential projection is fenced for withdrawal")
	}
	if err := s.projectionPeer(ctx, peer, a); err != nil {
		return err
	}
	if err := s.projectionInputs(ctx, a.Request); err != nil {
		return err
	}
	if err := s.projectionClaim(ctx, a.Request); err != nil {
		return err
	}
	request := a.Request
	slots, sources, err := s.projectionSlots(ctx, j, a)
	defer clearProjectionSlots(slots)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(sources, a.Sources) {
		return wire.Error(api.CodeConflict, "credential projection source inventory changed")
	}
	var prior bstate.Projection
	if err := j.Read("projection", a.ID, &prior); err == nil {
		if prior.Fenced || prior.Released || !reflect.DeepEqual(prior.Authority, a) || f.peer == nil || f.closed {
			return wire.Error(api.CodeConflict, "credential projection restart or acknowledgement requires reconciliation without another export")
		}
		return f.checkRefreshLeases()
	} else if !hasCode(err, api.CodeNotFound) {
		return err
	}
	f.transfer = api.CredentialTransfer{Authority: a, Files: []*os.File{}}
	pending := bstate.Projection{Authority: a, Facts: []api.CredentialDescriptorFact{}, Fenced: true}
	if err := j.Write("projection", a.ID, pending); err != nil {
		return err
	}
	record, err := s.deps.Store.CredentialProjection(ctx, s.deps.Config, request.Prepared.ID)
	if err != nil {
		return err
	}
	if record.State != "reserved" || record.Generation != a.Generation || record.Receipt != nil || record.Fence != nil || !reflect.DeepEqual(record.Authority, a) {
		return wire.Error(api.CodeIntegrity, "credential reserve did not retain its exact prepared authority")
	}
	if _, err := s.projectionRecord(ctx, a); err != nil {
		return err
	}
	for i := range slots {
		bindProjectionSlot(&slots[i], a)
		if err := j.Write("slot", slots[i].ID, slots[i]); err != nil {
			return err
		}
		if slots[i].Credential.Mode == "codex-file" {
			var login bstate.Login
			if err := j.Read("login", slots[i].LoginID, &login); err != nil {
				return err
			}
			login.ProjectionID = a.ID
			if err := j.Write("login", login.ID, login); err != nil {
				clear(login.Material)
				return err
			}
			clear(login.Material)
		}
	}
	if err := f.acquireRefreshLeases(j, slots); err != nil {
		return err
	}
	f.transfer = api.CredentialTransfer{Authority: a, Files: []*os.File{}}
	transfer := &f.transfer
	for _, slot := range slots {
		file, err := exportCredential(slot.Material)
		if err != nil {
			return err
		}
		transfer.Files = append(transfer.Files, file)
		fact, err := credentialFact(file)
		if err != nil {
			return err
		}
		pending.Facts = append(pending.Facts, fact)
	}
	if err := api.ValidateCredentialTransfer(*transfer, pending.Facts, s.deps.Clock.Now()); err != nil {
		return err
	}
	if err := s.projectionClaim(ctx, a.Request); err != nil {
		return err
	}
	fresh, versions, err := s.projectionSlots(ctx, j, a)
	clearProjectionSlots(fresh)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(versions, a.Sources) {
		return wire.Error(api.CodeConflict, "credential sources changed during export")
	}
	pending.Fenced = false
	if err := j.Write("projection", a.ID, pending); err != nil {
		return err
	}
	f.peer, f.facts = peer, pending.Facts
	return nil
}

func closeProjectionFiles(files []*os.File) error {
	var failed bool
	for _, file := range files {
		if file != nil {
			if _, err := file.Stat(); errors.Is(err, os.ErrClosed) {
				continue
			}
			if err := file.Close(); err != nil {
				failed = true
			}
		}
	}
	if failed {
		return wire.Error(api.CodeIntegrity, "credential export descriptor close was incomplete")
	}
	return nil
}

func (s *Service) projectionReleased(ctx context.Context, slot bstate.Slot) error {
	if slot.ProjectionID == "" {
		return nil
	}
	backend, err := s.brokerBackend()
	if err != nil {
		return err
	}
	return backend.WithBroker(ctx, func(j bstate.Journal) error {
		return s.projectionReleasedLocked(ctx, j, slot)
	})
}

// The caller owns the canonical journal lock through any following tombstone
// or owner-release write. Never acquire WithBroker recursively from this path.
func (s *Service) projectionReleasedLocked(ctx context.Context, j bstate.Journal, slot bstate.Slot) error {
	if slot.ProjectionID == "" {
		return nil
	}
	var journal bstate.Projection
	if err := j.Read("projection", slot.ProjectionID, &journal); err != nil {
		return err
	}
	record, err := s.projectionRecord(ctx, journal.Authority)
	if err != nil {
		return err
	}
	if !journal.Released || record.State != "withdrawn" || record.Generation < 2 || record.Withdrawal == nil {
		return wire.Error(api.CodeConflict, "credential projection must withdraw before ordinary slot release or reuse")
	}
	return api.ValidateCredentialWithdrawal(api.CredentialProjectionRecord{Authority: record.Authority, Generation: record.Generation - 1, State: "withdrawing", Receipt: record.Receipt, Fence: record.Fence}, *record.Withdrawal)
}

func (s *Service) AcknowledgeCredentials(ctx context.Context, receipt api.CredentialProjectionReceipt) (api.CredentialProjectionRecord, error) {
	var result api.CredentialProjectionRecord
	f := s.flight(receipt.ProjectionID)
	if err := f.enter(ctx); err != nil {
		return result, err
	}
	defer f.leave()
	err := s.projectionJournal(ctx, f, receipt.ProjectionID, func(j bstate.Journal) error {
		var err error
		result, err = s.acknowledgeLocked(ctx, j, f, receipt)
		return err
	})
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	return result, nil
}
func (s *Service) acknowledgeLocked(ctx context.Context, j bstate.Journal, f *projectionFlight, receipt api.CredentialProjectionReceipt) (api.CredentialProjectionRecord, error) {
	var empty api.CredentialProjectionRecord
	if f.peer == nil || f.isFenced() || receipt.ProjectionID != f.transfer.Authority.ID {
		return empty, wire.Error(api.CodeConflict, "credential acknowledgement has no matching live export")
	}
	a := f.transfer.Authority
	if err := f.checkRefreshLeases(); err != nil {
		return empty, err
	}
	if err := s.projectionPeer(ctx, f.peer, a); err != nil {
		return empty, err
	}
	var prior bstate.Projection
	if err := j.Read("projection", a.ID, &prior); err != nil {
		return empty, err
	}
	if prior.Fenced || prior.Released || !reflect.DeepEqual(prior.Authority, a) || !reflect.DeepEqual(prior.Facts, f.facts) {
		return empty, wire.Error(api.CodeConflict, "credential acknowledgement is durably fenced or changed")
	}
	if err := s.projectionClaim(ctx, a.Request); err != nil {
		return empty, err
	}
	if wire.Nil(s.deps.Helper) {
		return empty, wire.Error(api.CodePrerequisite, "credential acknowledgement requires the installed helper observer")
	}
	actual, err := s.deps.Helper.ObserveCredentials(ctx, a.ID)
	if err != nil {
		return empty, err
	}
	if err := api.ValidateCredentialProjectionReceipt(f.transfer, f.facts, receipt, s.deps.Clock.Now()); err != nil {
		return empty, err
	}
	if api.ValidateCredentialReobservation(a, receipt, actual, s.deps.Clock.Now()) != nil {
		return empty, wire.Error(api.CodeIntegrity, "credential acknowledgement differs from the helper held observation")
	}
	if !f.closed {
		for i, file := range f.transfer.Files {
			fact, err := credentialFact(file)
			if err != nil {
				return empty, err
			}
			if !reflect.DeepEqual(fact, f.facts[i]) {
				return empty, wire.Error(api.CodeIntegrity, "credential originals changed before acknowledgement")
			}
		}
	}
	slots, sources, err := s.projectionSlots(ctx, j, a)
	defer clearProjectionSlots(slots)
	if err != nil {
		return empty, err
	}
	if !reflect.DeepEqual(sources, a.Sources) {
		return empty, wire.Error(api.CodeConflict, "credential source changed before acknowledgement")
	}
	record, err := s.projectionRecord(ctx, a)
	if err != nil {
		return empty, err
	}
	if record.State == "held" {
		if record.Receipt == nil || !reflect.DeepEqual(*record.Receipt, receipt) {
			return empty, wire.Error(api.CodeConflict, "credential acknowledgement replay changed")
		}
	} else {
		if record.State != "reserved" || f.closed {
			return empty, wire.Error(api.CodeConflict, "credential acknowledgement lost its reserved state")
		}
		// The store's native metadata recheck may call the outside inventory
		// port. Retain this actual journal read capability for that bounded
		// callback instead of recursively acquiring the canonical journal.
		releaseInventory := f.retainInventory(j, a)
		committed, err := s.deps.Store.CommitCredentialProjection(ctx, s.deps.ServiceScope, receipt)
		releaseInventory()
		if err != nil {
			return empty, err
		}
		read, err := s.projectionRecord(ctx, a)
		if err != nil {
			return empty, err
		}
		if read.State != "held" || read.Generation != receipt.Generation || read.Receipt == nil || !reflect.DeepEqual(*read.Receipt, receipt) || !reflect.DeepEqual(read, committed) {
			return empty, wire.Error(api.CodeIntegrity, "credential acknowledgement was not durably read back")
		}
		record = read
	}
	if !f.closed {
		if err := closeProjectionFiles(f.transfer.Files); err != nil {
			return empty, err
		}
		f.closed = true
	}
	return record, nil
}

func (s *Service) projectionLookup(ctx context.Context, id api.ID) (bstate.Projection, api.CredentialProjectionRecord, error) {
	var journal bstate.Projection
	backend, err := s.brokerBackend()
	if err != nil {
		return journal, api.CredentialProjectionRecord{}, err
	}
	if err := backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("projection", id, &journal) }); err != nil {
		return journal, api.CredentialProjectionRecord{}, err
	}
	record, err := s.projectionRecord(ctx, journal.Authority)
	return journal, record, err
}

func (s *Service) BeginCredentialWithdrawal(ctx context.Context, request api.CredentialWithdrawalRequest) (api.CredentialProjectionRecord, error) {
	var result api.CredentialProjectionRecord
	f := s.flight(request.ProjectionID)
	f.fence()
	if err := f.enter(ctx); err != nil {
		return result, err
	}
	defer f.leave()
	err := s.projectionJournal(ctx, f, request.ProjectionID, func(j bstate.Journal) error {
		var journal bstate.Projection
		if err := j.Read("projection", request.ProjectionID, &journal); err != nil {
			return err
		}
		if journal.Released {
			return wire.Error(api.CodeConflict, "credential withdrawal cannot fence a released projection")
		}
		record, err := s.projectionRecord(ctx, journal.Authority)
		if err != nil {
			return err
		}
		if err := verifyProjectionHost(record.Authority); err != nil {
			return err
		}
		if record.State == "withdrawing" && record.Fence != nil && reflect.DeepEqual(*record.Fence, request) {
			journal.Fenced = true
			if err := j.Write("projection", request.ProjectionID, journal); err != nil {
				return err
			}
			if err := readProjectionFence(j, request.ProjectionID, journal); err != nil {
				return err
			}
			result = record
			return nil
		}
		// A later ordinary stop cannot lower an already persisted revocation.
		if record.State == "withdrawing" && record.Revoked && record.Fence != nil &&
			record.Fence.Reason == "revoked" && request.Reason == api.CredentialStopReason &&
			request.ExpectedGeneration == record.Generation && request.Cause == record.Fence.Cause {
			result = record
			return nil
		}
		if err := api.ValidateCredentialWithdrawalRequest(record, request); err != nil {
			return err
		}
		journal.Fenced = true
		if err := j.Write("projection", request.ProjectionID, journal); err != nil {
			return err
		}
		if err := readProjectionFence(j, request.ProjectionID, journal); err != nil {
			return err
		}
		fenced, err := s.deps.Store.FenceCredentialProjection(ctx, s.deps.ServiceScope, request)
		if err != nil {
			return err
		}
		read, err := s.projectionRecord(ctx, journal.Authority)
		if err != nil {
			return err
		}
		prior := record.PriorFence
		if record.State == "withdrawing" {
			prior = record.Fence
		}
		if read.State != "withdrawing" || read.Generation != request.ExpectedGeneration+1 || read.Fence == nil || read.Revoked != (record.Revoked || request.Reason == "revoked") || !reflect.DeepEqual(read.PriorFence, prior) || !reflect.DeepEqual(*read.Fence, request) || !reflect.DeepEqual(read, fenced) {
			return wire.Error(api.CodeIntegrity, "credential withdrawal fence was not durably read back")
		}
		result = read
		return nil
	})
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	return result, nil
}

func (s *Service) AcceptCredentialRefresh(ctx context.Context, peer api.VerifiedPeer, refresh api.CredentialRefresh) (api.CredentialSourceVersion, error) {
	var result api.CredentialSourceVersion
	if refresh.File == nil {
		return result, wire.Error(api.CodeInvalid, "credential refresh requires its received descriptor")
	}
	closed := false
	defer func() {
		if !closed {
			refresh.File.Close()
		}
	}()
	f := s.flight(refresh.ProjectionID)
	if err := f.enter(ctx); err != nil {
		return result, err
	}
	defer f.leave()
	err := s.projectionJournal(ctx, f, refresh.ProjectionID, func(j bstate.Journal) (outErr error) {
		defer func() {
			closed = true
			if err := refresh.File.Close(); err != nil {
				outErr = wire.Error(api.CodeIntegrity, "credential refresh descriptor close was incomplete")
			}
		}()
		var journal bstate.Projection
		if err := j.Read("projection", refresh.ProjectionID, &journal); err != nil {
			return err
		}
		record, err := s.projectionRecord(ctx, journal.Authority)
		if err != nil {
			return err
		}
		if !journal.Fenced || journal.Released {
			return wire.Error(api.CodeConflict, "credential refresh lost its private withdrawal fence")
		}
		if err := f.checkRefreshLease(refresh.SlotID); err != nil {
			return err
		}
		if err := s.projectionPeer(ctx, peer, record.Authority); err != nil {
			return err
		}
		fact, err := credentialFact(refresh.File)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(fact, refresh.Fact) {
			return wire.Error(api.CodeIntegrity, "credential refresh differs from its actual received descriptor")
		}
		if err := api.ValidateCredentialRefresh(record, refresh, s.deps.Clock.Now()); err != nil {
			return err
		}
		if err := s.projectionPolicy(ctx, record.Authority.Request); err != nil {
			return err
		}
		if wire.Nil(s.deps.Helper) || wire.Nil(s.deps.Grants) {
			return wire.Error(api.CodePrerequisite, "credential refresh requires installed helper and grant validation")
		}
		actual, err := s.deps.Helper.ObserveGate(ctx, api.HelperObserveRequest{LeaseID: record.Authority.Request.Lease.ID, Handle: refresh.Observation.Handle})
		if err != nil {
			return err
		}
		if actual.State != refresh.Observation.State || actual.Handle != refresh.Observation.Handle || actual.Survivors == nil || *actual.Survivors != 0 {
			return wire.Error(api.CodeContainmentUnknown, "credential refresh did not observe the original stopped process")
		}
		var slot bstate.Slot
		if err := j.Read("slot", refresh.SlotID, &slot); err != nil {
			return err
		}
		defer clear(slot.Material)
		defer clear(slot.Returned)
		var profile bstate.Profile
		if err := j.Read("profile", slot.ProfileID, &profile); err != nil {
			return err
		}
		var login bstate.Login
		if err := j.Read("login", slot.LoginID, &login); err != nil {
			return err
		}
		defer func() { clear(login.Material) }()
		if slot.Released || slot.ProjectionID != refresh.ProjectionID || slot.Credential.Mode != "codex-file" || login.Quarantined || login.PendingRelease != "" || login.SlotID != slot.ID || profile.Generation != slot.ProfileGeneration || !future(slot.Credential.ExpiresAt, s.deps.Clock.Now()) || !future(profile.ExpiresAt, s.deps.Clock.Now()) {
			return wire.Error(api.CodeForbidden, "credential refresh lost its live canonical profile owner")
		}
		grants, err := s.deps.Store.Grants(ctx, slot.GrantSetID)
		if err != nil {
			return err
		}
		current, err := s.deps.Grants.Revalidate(ctx, grants)
		if err != nil {
			return err
		}
		if current.Revoked || !future(current.ExpiresAt, s.deps.Clock.Now()) || !reflect.DeepEqual(current, grants) || !reflect.DeepEqual(current, record.Authority.Request.Handoff.Spec.Grants) || current.SHA256 != slot.GrantSHA256 {
			return wire.Error(api.CodeForbidden, "credential refresh grants are expired revoked or changed")
		}
		policy, err := s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ServiceScope)
		if err != nil {
			return err
		}
		if slot.PolicyGeneration != policy.Generation || slices.Contains(policy.ProfileExclusions, profile.ID) {
			return wire.Error(api.CodeForbidden, "credential refresh policy excludes its selected profile")
		}
		material, err := j.Fetch(ctx, slot.Grant)
		clear(material.Bytes)
		if err != nil {
			return err
		}
		if journal.Refresh != nil {
			if journal.RefreshObject != fact.ObjectID {
				return wire.Error(api.CodeConflict, "credential refresh retry changed its immutable return object")
			}
			result = *journal.Refresh
			return nil
		}
		data, err := io.ReadAll(io.NewSectionReader(refresh.File, 0, fact.Size))
		defer clear(data)
		if err != nil || int64(len(data)) != fact.Size {
			return wire.Error(api.CodeIntegrity, "credential refresh descriptor read was incomplete")
		}
		if login.RefreshObject != fact.ObjectID {
			if login.Generation != refresh.ExpectedSourceGeneration {
				return wire.Error(api.CodeConflict, "credential refresh source generation changed")
			}
			if wire.Nil(s.deps.CodexValidator) {
				return wire.Error(api.CodePrerequisite, "credential refresh requires its installed Codex validator")
			}
			if err := s.deps.CodexValidator.ValidateCodexCredential(profile.ID, profile.LoginID, profile.AccountSHA256, data); err != nil {
				return wire.Error(api.CodeForbidden, "credential refresh failed its pinned Codex account validation")
			}
			clear(login.Material)
			login.Material = append([]byte(nil), data...)
			login.Generation++
			login.RefreshObject, login.RefreshSlotID = fact.ObjectID, slot.ID
			if err := j.Write("login", login.ID, login); err != nil {
				return err
			}
		}
		result = api.CredentialSourceVersion{Key: slot.ID, Generation: login.Generation, Version: slot.Grant.Version}
		journal.RefreshObject, journal.Refresh = fact.ObjectID, &result
		return j.Write("projection", refresh.ProjectionID, journal)
	})
	if err != nil {
		return api.CredentialSourceVersion{}, err
	}
	return result, nil
}

func (s *Service) FinishCredentialWithdrawal(ctx context.Context, claimed api.CredentialProjectionRecord, receipt api.CredentialWithdrawalReceipt) (api.CredentialProjectionRecord, error) {
	var result api.CredentialProjectionRecord
	id := claimed.Authority.ID
	f := s.flight(id)
	if err := f.enter(ctx); err != nil {
		return result, err
	}
	defer f.leave()
	err := s.projectionJournal(ctx, f, id, func(j bstate.Journal) error {
		var journal bstate.Projection
		if err := j.Read("projection", id, &journal); err != nil {
			return err
		}
		record, err := s.projectionRecord(ctx, journal.Authority)
		if err != nil {
			return err
		}
		if err := verifyProjectionHost(record.Authority); err != nil {
			return err
		}
		if !journal.Fenced || journal.Released && record.State != "withdrawn" || !reflect.DeepEqual(record.Authority, claimed.Authority) {
			return wire.Error(api.CodeConflict, "credential withdrawal lost its durable fence")
		}
		if !reflect.DeepEqual(f.transfer.Authority, record.Authority) {
			return wire.Error(api.CodeConflict, "credential export lifetime requires protected reconciliation")
		}
		if receipt.BrokerDescriptors != nil || receipt.RefreshLeases != nil {
			return wire.Error(api.CodeForbidden, "credential withdrawal supplied broker resource counts")
		}
		actual := receipt
		validationRecord := record
		if record.State == "withdrawn" {
			if record.Generation == 0 || record.Withdrawal == nil {
				return wire.Error(api.CodeIntegrity, "credential withdrawal lost its retained completion")
			}
			validationRecord.State, validationRecord.Generation = "withdrawing", record.Generation-1
		} else {
			if !reflect.DeepEqual(record, claimed) {
				return wire.Error(api.CodeForbidden, "credential withdrawal supplied broker counts or another fence")
			}
			if wire.Nil(s.deps.Helper) {
				return wire.Error(api.CodePrerequisite, "credential withdrawal requires actual helper cleanup")
			}
			if !wire.Nil(s.deps.WithdrawalNative) {
				actual, err = s.deps.WithdrawalNative.ReadCredentialWithdrawal(ctx, record)
			} else {
				actual, err = s.deps.Helper.WithdrawCredentials(ctx, record)
			}
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(actual, receipt) {
				return wire.Error(api.CodeIntegrity, "credential withdrawal differs from actual helper collection")
			}
		}
		// A bad helper observation cannot retire the live refresh capability or
		// publish a tombstone. This check never invents broker counts.
		if err := api.ValidateCredentialWithdrawalHelper(validationRecord, actual); err != nil {
			return err
		}
		if !f.closed {
			if err := closeProjectionFiles(f.transfer.Files); err != nil {
				if quarantineErr := s.quarantineProjection(j, record.Authority); quarantineErr != nil {
					return quarantineErr
				}
				return err
			}
			f.closed = true
		}
		descriptors, err := f.brokerDescriptorCount()
		if err != nil {
			return err
		}
		retireCodexCopy := false
		retireStoppedCopy := false
		unopened := actual.AgentExecuted != nil && !*actual.AgentExecuted
		exposed := actual.RotationRequired || (record.Fence != nil && record.Fence.Reason != "release" && actual.Observation.State != "absent" && !unopened)
		if exposed || descriptors != 0 {
			if err := s.quarantineProjection(j, record.Authority); err != nil {
				return err
			}
			seatLogin, err := projectionHasRetirableCopy(j, record.Authority, record.Fence != nil && record.Fence.Reason == "release")
			if err != nil {
				return err
			}
			// L6 ruling B: a normal HelperRelease may retire a zero-descriptor
			// lane copy while retaining the canonical quarantine as the
			// LB-301 source-reuse gate. Cancel and revoke keep the seat blocked.
			stopped := !record.Revoked && !record.Authority.Revoked && record.Fence != nil && (record.Fence.Reason == api.CredentialStopReason || record.Fence.Reason == "release")
			if seatLogin {
				decision := EvaluateCredentialRotationPolicy(CredentialRotationPolicyInput{
					Cause: credentialStopForWithdrawalReason(record.Fence.Reason), LeakHit: descriptors != 0})
				// A requested stop completes only its measured lane withdrawal.
				// Keep the cancelled cause, rotation receipt and canonical quarantine;
				// a different cancellation or revocation cannot use this completion.
				retireStoppedCopy = stopped && record.Fence.Reason == api.CredentialStopReason &&
					record.Fence.Cause.Kind == api.InternalHelperStop && actual.Observation.State == "exited" &&
					actual.AgentExecuted != nil && *actual.AgentExecuted && actual.RotationRequired
				if descriptors != 0 || decision.BlockSeat && !retireStoppedCopy {
					return wire.Error(api.CodeContainmentUnknown, "credential exposure is quarantined pending protected rotation")
				}
				retireCodexCopy = decision.RetireLaneCopy || retireStoppedCopy
			} else if descriptors != 0 || !stopped {
				return wire.Error(api.CodeContainmentUnknown, "credential exposure is quarantined pending protected rotation")
			}
		}
		// Validate every slot and owner before the store completion or any release.
		slots := []bstate.Slot{}
		defer func() { clearProjectionSlots(slots) }()
		owners := map[api.ID]bstate.Login{}
		defer func() {
			for _, o := range owners {
				clear(o.Material)
			}
		}()
		for _, slotID := range record.Authority.Request.Handoff.Spec.Injection.SlotIDs {
			var slot bstate.Slot
			if err := j.Read("slot", slotID, &slot); err != nil {
				return err
			}
			slots = append(slots, slot)
			if slot.Target != record.Authority.Request.Prepared.Target || slot.ProjectionID != id {
				return wire.Error(api.CodeConflict, "credential withdrawal selected a changed slot")
			}
			if slot.Credential.Mode == "codex-file" {
				var owner bstate.Login
				if err := j.Read("login", slot.LoginID, &owner); err != nil {
					return err
				}
				if owner.Quarantined && !retireCodexCopy || owner.SlotID != "" && owner.SlotID != slot.ID ||
					retireStoppedCopy && owner.ProjectionID != "" && owner.ProjectionID != id {
					clear(owner.Material)
					return wire.Error(api.CodeConflict, "credential withdrawal changed its canonical owner")
				}
				owners[slot.LoginID] = owner
			}
		}
		if err := f.closeRefreshLeases(); err != nil {
			return err
		}
		leases, err := f.refreshLeaseCount()
		if err != nil {
			return err
		}
		actual.BrokerDescriptors, actual.RefreshLeases = &descriptors, &leases
		if err := api.ValidateCredentialWithdrawal(validationRecord, actual); err != nil {
			return err
		}
		if record.State == "withdrawn" && !reflect.DeepEqual(actual, *record.Withdrawal) {
			return wire.Error(api.CodeConflict, "credential withdrawal retry changed its original receipt")
		}
		if record.State != "withdrawn" {
			record, err = s.completeWithdrawal(ctx, record, actual)
			if err != nil {
				return err
			}
		}
		b := &stagedJournal{Journal: j}
		defer b.clear()
		for _, slot := range slots {
			if owner, ok := owners[slot.LoginID]; ok && owner.SlotID != "" {
				owner.PendingRelease = slot.ID
				if err := b.Write("login", owner.ID, owner); err != nil {
					return err
				}
			}
			clear(slot.Material)
			clear(slot.Returned)
			slot.Material, slot.Returned, slot.Released = []byte{}, []byte{}, true
			if err := b.Write("slot", slot.ID, slot); err != nil {
				return err
			}
		}
		journal.Released = true
		if err := b.Write("projection", id, journal); err != nil {
			return err
		}
		for _, owner := range owners {
			owner.SlotID = ""
			owner.PendingRelease = ""
			if retireStoppedCopy {
				// The completed lane copy no longer owns a live projection. Keep
				// Quarantined set so only protected rotation can enable reuse.
				owner.ProjectionID = ""
			}
			if err := b.Write("login", owner.ID, owner); err != nil {
				return err
			}
		}
		if err := b.flush(""); err != nil {
			return err
		}
		result = record
		return nil
	})
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	return result, nil
}
