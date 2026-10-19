package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

const reuseSchema = "laneboss.api-key-reuse.v2"

// Projection journals are already retained by both native storage inventories.
// Domain-separated IDs keep these source fences and release observations apart
// from the projection authority itself. No new file kind is silently admitted.
const reuseJournalKind = "projection"

// APIKeyCredentialStatus is value-free metadata for the credential in lane
// status. Journal is the single retained scan line, not reconstructed output.
type APIKeyCredentialStatus struct {
	Mode             string           `json:"mode"`
	Scan             APIKeyScanResult `json:"scan"`
	RotationRequired bool             `json:"rotation_required"`
	Journal          string           `json:"journal"`
}

type reuseSource struct {
	Schema     string
	Config     string
	Source     api.ID
	Version    string
	Projection api.ID
	State      string
	Place      string
}

type reuseRelease struct {
	Schema     string
	Config     string
	Source     api.ID
	Version    string
	Projection api.ID
	Slot       api.ID
	Target     api.LifeRef
	Status     APIKeyCredentialStatus
}

// NewWithAPIKeyReuseGate installs the gate before publishing any broker port.
// The native release scanner is an additional private capability of the
// installed WithdrawalNative reader. Missing capability refuses release.
func NewWithAPIKeyReuseGate(deps Dependencies) (*Service, error) {
	s, err := New(deps)
	if err != nil {
		return nil, err
	}
	if err := s.EnableAPIKeyReuseGate(nil); err != nil {
		return nil, err
	}
	return s, nil
}

// EnableAPIKeyReuseGate is the one installation hook. Install before the first
// projection on EVERY broker process, including after restart. It decorates
// the canonical journal rather than relying on a process-local blacklist.
// The slot-release write calls the scan before its tombstone can be committed;
// every subsequent projection's source Fetch checks that same protected state.
// A nil scanner selects the installed native reader, and absence fails closed.
func (s *Service) EnableAPIKeyReuseGate(scanner APIKeyReleaseScanner) error {
	s.projectionMu.Lock()
	defer s.projectionMu.Unlock()
	if _, ok := s.deps.Backend.(*reuseBackend); ok {
		return nil
	}
	if len(s.projections) != 0 {
		return wire.Error(api.CodePrerequisite, "API key reuse gate must precede credential projection")
	}
	backend, err := s.brokerBackend()
	if err != nil {
		return err
	}
	durable, ok := backend.(bstate.DurableBackend)
	if !ok {
		return wire.Error(api.CodePrerequisite, "API key reuse gate requires its durable encrypted journal")
	}
	if wire.Nil(scanner) {
		scanner, _ = s.deps.WithdrawalNative.(APIKeyReleaseScanner)
	}
	s.deps.Backend = &reuseBackend{SecretBackend: s.deps.Backend, backend: backend, durable: durable, service: s, scanner: scanner}
	return nil
}

type reuseBackend struct {
	api.SecretBackend
	backend bstate.Backend
	durable bstate.DurableBackend
	service *Service
	scanner APIKeyReleaseScanner
}

type reuseJournal struct {
	bstate.Journal
	owner      *reuseBackend
	ctx        context.Context
	projection api.ID
	seen       map[api.ID]bool
}

func reuseID(prefix string, ids ...string) api.ID {
	// Hash metadata only, never plaintext. The token remains under 40 bytes.
	h := sha256.New()
	for _, id := range ids {
		h.Write([]byte(id))
		h.Write([]byte{0})
	}
	return api.ID(prefix + hex.EncodeToString(h.Sum(nil)[:16]))
}

func reuseRefusal(place string) error {
	return reuseScanRefusal(place, APIKeyScanResult{})
}

func reuseScanRefusal(place string, result APIKeyScanResult) error {
	if !reusePlace(place) {
		place = "release-state"
	}
	message := "API key rotation required: " + place
	for i, known := range reusePlaces {
		if place == known {
			if result[i].Path != "" {
				message += " path=" + strconv.Quote(result[i].Path)
			}
			if result[i].UnreadablePath != "" {
				message += " unreadable_path=" + strconv.Quote(result[i].UnreadablePath)
			}
		}
	}
	return wire.Error(api.CodeForbidden, message)
}

func reusePlace(place string) bool {
	if place == "release-state" || place == "cancelled" || place == "revoked" {
		return true
	}
	for _, known := range reusePlaces {
		if place == known {
			return true
		}
	}
	return false
}

func readReuseSource(j bstate.Journal, config string, grant api.SecretGrant) (reuseSource, bool, error) {
	var source reuseSource
	err := j.Read(reuseJournalKind, reuseID("rs-", config, string(grant.SourceHandle)), &source)
	if hasCode(err, api.CodeNotFound) {
		return source, false, nil
	}
	if err != nil || source.Schema != reuseSchema || source.Config != config || source.Source != grant.SourceHandle || source.Version != grant.Version ||
		(source.State != "active" && source.State != "scanning" && source.State != "clean" && source.State != "rotation") ||
		!wire.ID(string(source.Projection)) || !reusePlace(source.Place) {
		return reuseSource{}, false, reuseRefusal("release-state")
	}
	return source, true, nil
}

func writeReuseSource(j bstate.Journal, source reuseSource) error {
	id := reuseID("rs-", source.Config, string(source.Source))
	if err := j.Write(reuseJournalKind, id, source); err != nil {
		return reuseRefusal("release-state")
	}
	var read reuseSource
	if err := j.Read(reuseJournalKind, id, &read); err != nil || read != source {
		return reuseRefusal("release-state")
	}
	return nil
}

func (j *reuseJournal) Fetch(ctx context.Context, grant api.SecretGrant) (api.SecretMaterial, error) {
	source, found, err := readReuseSource(j.Journal, j.owner.service.deps.Config, grant)
	if err != nil {
		return api.SecretMaterial{}, err
	}
	if found && source.State != "clean" && !(source.State == "active" && source.Projection == j.projection) {
		return api.SecretMaterial{}, reuseRefusal(source.Place)
	}
	return j.Journal.Fetch(ctx, grant)
}

func (j *reuseJournal) Read(kind string, id api.ID, out any) error {
	if err := j.Journal.Read(kind, id, out); err != nil {
		return err
	}
	switch record := out.(type) {
	case *bstate.Projection:
		if kind == "projection" {
			j.projection = record.Authority.ID
			j.seen[record.Authority.ID] = true
		}
	case *bstate.Slot:
		if kind == "slot" && record.ProjectionID != "" {
			j.projection = record.ProjectionID
		}
	}
	return nil
}

func decodeReuseValue(value any, out any) error {
	data, err := json.Marshal(value)
	defer clear(data)
	if err != nil || json.Unmarshal(data, out) != nil {
		return reuseRefusal("release-state")
	}
	return nil
}

func (j *reuseJournal) Write(kind string, id api.ID, value any) error {
	if kind == "projection" {
		var p bstate.Projection
		if err := decodeReuseValue(value, &p); err != nil {
			return err
		}
		j.projection = p.Authority.ID
		j.seen[p.Authority.ID] = true
	}
	if kind == "slot" {
		var after bstate.Slot
		if err := decodeReuseValue(value, &after); err != nil {
			return err
		}
		defer clear(after.Material)
		defer clear(after.Returned)
		if after.Credential.Mode == "claude-api-key" && after.ProjectionID != "" {
			if after.ID != id || after.Config != j.owner.service.deps.Config {
				return reuseRefusal("release-state")
			}
			j.projection = after.ProjectionID
			j.seen[after.ProjectionID] = true
			if after.Released {
				var before bstate.Slot
				if err := j.Journal.Read("slot", id, &before); err != nil {
					return reuseRefusal("release-state")
				}
				defer clear(before.Material)
				defer clear(before.Returned)
				if before.Credential != after.Credential || before.ProjectionID != after.ProjectionID || before.Grant != after.Grant || before.Target != after.Target {
					return reuseRefusal("release-state")
				}
				if !before.Released {
					if err := j.scanRelease(before, false); err != nil {
						return err
					}
				}
			} else if err := j.activate(after); err != nil {
				return err
			}
		}
	}
	return j.Journal.Write(kind, id, value)
}

func (j *reuseJournal) activate(slot bstate.Slot) error {
	source, found, err := readReuseSource(j.Journal, slot.Config, slot.Grant)
	if err != nil {
		return err
	}
	if found && source.State != "clean" && !(source.State == "active" && source.Projection == slot.ProjectionID) {
		return reuseRefusal(source.Place)
	}
	if found && source.State == "active" {
		return nil
	}
	return writeReuseSource(j.Journal, reuseSource{Schema: reuseSchema, Config: slot.Config, Source: slot.Grant.SourceHandle,
		Version: slot.Grant.Version, Projection: slot.ProjectionID, State: "active", Place: "release-state"})
}

func (j *reuseJournal) scanRelease(slot bstate.Slot, failed bool) error {
	var projection bstate.Projection
	if err := j.Journal.Read("projection", slot.ProjectionID, &projection); err != nil {
		return reuseRefusal("release-state")
	}
	a := projection.Authority
	record, err := j.owner.service.deps.Store.CredentialProjection(j.ctx, slot.Config, a.Request.Prepared.ID)
	if err != nil || !reflect.DeepEqual(record.Authority, a) || record.Fence == nil ||
		record.State != "withdrawing" && record.State != "withdrawn" || a.Request.Prepared.Target != slot.Target ||
		a.Request.Lease.ID != slot.HelperLeaseID || a.Request.Handoff.Spec.Runner == nil || a.Request.Handoff.Spec.Runner.Slot != slot.Credential {
		return reuseRefusal("release-state")
	}
	force := failed || record.Fence.Reason != "release" || record.Withdrawal != nil && record.Withdrawal.RotationRequired
	place := "release-state"
	if record.Fence.Reason == "cancelled" || record.Fence.Reason == "revoked" {
		place = record.Fence.Reason
	}
	id := reuseID("rr-", slot.Config, string(slot.ProjectionID), string(slot.ID))
	var prior reuseRelease
	if err := j.Journal.Read(reuseJournalKind, id, &prior); err == nil {
		if !sameReuseRelease(prior, slot) {
			return reuseRefusal("release-state")
		}
		source, found, readErr := readReuseSource(j.Journal, slot.Config, slot.Grant)
		if readErr != nil || !found {
			return reuseRefusal("release-state")
		}
		if force && source.State != "rotation" {
			source.State, source.Place = "rotation", place
			if err := writeReuseSource(j.Journal, source); err != nil {
				return err
			}
		}
		if (record.Fence.Reason == api.CredentialStopReason || record.Fence.Reason == "release") && !failed && prior.Status.Scan.Clean() {
			return nil
		}
		if source.State != "clean" || !prior.Status.Scan.Clean() || prior.Status.RotationRequired {
			return reuseScanRefusal(source.Place, prior.Status.Scan.Redacted(slot.Material))
		}
		return nil
	} else if !hasCode(err, api.CodeNotFound) {
		return reuseRefusal("release-state")
	}
	source, found, err := readReuseSource(j.Journal, slot.Config, slot.Grant)
	if err != nil {
		return err
	}
	sticky := found && (source.State == "rotation" || source.State == "scanning")
	if found && source.Projection != slot.ProjectionID {
		return reuseRefusal("release-state")
	}
	if !found {
		source = reuseSource{Schema: reuseSchema, Config: slot.Config, Source: slot.Grant.SourceHandle,
			Version: slot.Grant.Version, Projection: slot.ProjectionID, Place: "release-state"}
	}
	if !sticky {
		source.State = "scanning"
		if err := writeReuseSource(j.Journal, source); err != nil {
			return err
		}
	}
	result := unreadableAPIKeyScan()
	if !wire.Nil(j.owner.scanner) && len(slot.Material) >= 8 {
		// Give adapters their own buffer; a failed adapter cannot mutate the
		// retained source. Never serialize it or include its error in output.
		key := append([]byte(nil), slot.Material...)
		defer clear(key)
		result, err = j.owner.scanner.ScanAPIKeyRelease(j.ctx, a, api.SecretMaterial{Bytes: key})
		if err != nil {
			result = unreadableAPIKeyScan()
		}
	}
	result = result.Redacted(slot.Material)
	if hit := result.FirstHit(); hit != "" {
		place = hit
	}
	rotation := sticky || force || !result.Clean()
	if rotation {
		source.State, source.Place = "rotation", place
	} else {
		source.State, source.Place = "clean", "release-state"
	}
	// A hit is fenced first. A clean source stays in scanning until its exact
	// immutable release line has been committed and read back.
	if rotation {
		if err := writeReuseSource(j.Journal, source); err != nil {
			return err
		}
	}
	release := reuseRelease{Schema: reuseSchema, Config: slot.Config, Source: slot.Grant.SourceHandle, Version: slot.Grant.Version,
		Projection: slot.ProjectionID, Slot: slot.ID, Target: slot.Target,
		Status: APIKeyCredentialStatus{Mode: "claude-api-key", Scan: result, RotationRequired: rotation, Journal: result.Line()}}
	if err := j.Journal.Write(reuseJournalKind, id, release); err != nil {
		// A failed receipt never leaves a clean source eligible for reuse.
		source.State, source.Place = "rotation", "release-state"
		if fenceErr := writeReuseSource(j.Journal, source); fenceErr != nil {
			return fenceErr
		}
		return reuseRefusal("release-state")
	}
	var read reuseRelease
	if err := j.Journal.Read(reuseJournalKind, id, &read); err != nil || !reflect.DeepEqual(read, release) {
		source.State, source.Place = "rotation", "release-state"
		if fenceErr := writeReuseSource(j.Journal, source); fenceErr != nil {
			return fenceErr
		}
		return reuseRefusal("release-state")
	}
	if !rotation {
		if err := writeReuseSource(j.Journal, source); err != nil {
			return err
		}
	}
	if rotation && !(!failed && (record.Fence.Reason == api.CredentialStopReason || record.Fence.Reason == "release") && result.Clean()) {
		return reuseScanRefusal(place, result)
	}
	return nil
}

func sameReuseRelease(release reuseRelease, slot bstate.Slot) bool {
	return release.Schema == reuseSchema && release.Config == slot.Config && release.Source == slot.Grant.SourceHandle &&
		release.Version == slot.Grant.Version && release.Projection == slot.ProjectionID && release.Slot == slot.ID && release.Target == slot.Target &&
		release.Status.Mode == "claude-api-key" && release.Status.Journal == release.Status.Scan.Line()
}

func (b *reuseBackend) run(ctx context.Context, raw bstate.Journal, fn func(bstate.Journal) error) error {
	// This remains inside the native durable lock. Failure fencing has its own
	// bounded lifetime even after cancellation of the originating request.
	journalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	j := &reuseJournal{Journal: raw, owner: b, ctx: journalCtx, seen: map[api.ID]bool{}}
	err := fn(j)
	if err == nil {
		return nil
	}
	// Cancel/revoke and uncertain withdrawal can return before the release
	// tombstone. Retain their source rotation fence through that path as well.
	for projectionID := range j.seen {
		var p bstate.Projection
		if raw.Read("projection", projectionID, &p) != nil {
			return reuseRefusal("release-state")
		}
		r, readErr := b.service.deps.Store.CredentialProjection(journalCtx, b.service.deps.Config, p.Authority.Request.Prepared.ID)
		if readErr != nil {
			return reuseRefusal("release-state")
		}
		if r.Fence == nil || r.State != "withdrawing" && r.State != "withdrawn" {
			continue
		}
		for _, id := range p.Authority.Request.Handoff.Spec.Injection.SlotIDs {
			var slot bstate.Slot
			if raw.Read("slot", id, &slot) != nil {
				return reuseRefusal("release-state")
			}
			if slot.Credential.Mode == "claude-api-key" {
				scanErr := j.scanRelease(slot, true)
				clear(slot.Material)
				clear(slot.Returned)
				if scanErr != nil {
					return scanErr
				}
			} else {
				clear(slot.Material)
				clear(slot.Returned)
			}
		}
	}
	return err
}

func (b *reuseBackend) WithBroker(ctx context.Context, fn func(bstate.Journal) error) error {
	return b.backend.WithBroker(ctx, func(j bstate.Journal) error { return b.run(ctx, j, fn) })
}

func (b *reuseBackend) WithBrokerDurable(ctx context.Context, fn func(bstate.Journal) error) error {
	return b.durable.WithBrokerDurable(ctx, func(j bstate.Journal) error { return b.run(ctx, j, fn) })
}

func (b *reuseBackend) Fetch(ctx context.Context, grant api.SecretGrant) (api.SecretMaterial, error) {
	var material api.SecretMaterial
	err := b.WithBroker(ctx, func(j bstate.Journal) error {
		var err error
		material, err = j.Fetch(ctx, grant)
		return err
	})
	if err != nil {
		clear(material.Bytes)
		return api.SecretMaterial{}, err
	}
	return material, nil
}

func (b *reuseBackend) WithMetadata(ctx context.Context, fn func([]api.SecretInfo) error) error {
	backend, ok := b.SecretBackend.(metadataBackend)
	if !ok {
		return wire.Error(api.CodePrerequisite, "API key backend lacks protected metadata")
	}
	return backend.WithMetadata(ctx, fn)
}

func (b *reuseBackend) WithMutation(ctx context.Context, id api.ID, fn func(api.SecretBackend, []api.SecretInfo) error) error {
	backend, ok := b.SecretBackend.(mutationBackend)
	if !ok {
		return wire.Error(api.CodePrerequisite, "API key backend lacks protected mutation serialization")
	}
	return backend.WithMutation(ctx, id, fn)
}

// APIKeyReleaseStatus is an internal credential-status port. Its caller must
// resolve this projection from the authenticated lane; it is not an RPC.
func (s *Service) APIKeyReleaseStatus(ctx context.Context, projection, slotID api.ID) (APIKeyCredentialStatus, error) {
	backend, err := s.brokerBackend()
	if err != nil {
		return APIKeyCredentialStatus{}, err
	}
	var result APIKeyCredentialStatus
	err = backend.WithBroker(ctx, func(j bstate.Journal) error {
		var slot bstate.Slot
		if err := j.Read("slot", slotID, &slot); err != nil {
			return reuseRefusal("release-state")
		}
		defer clear(slot.Material)
		defer clear(slot.Returned)
		if slot.Config != s.deps.Config || slot.ProjectionID != projection || slot.Credential.Mode != "claude-api-key" {
			return reuseRefusal("release-state")
		}
		var release reuseRelease
		if err := j.Read(reuseJournalKind, reuseID("rr-", s.deps.Config, string(projection), string(slotID)), &release); err != nil {
			return wire.Error(api.CodeNotFound, "API key release scan is not recorded")
		}
		if !sameReuseRelease(release, slot) {
			return reuseRefusal("release-state")
		}
		source, found, err := readReuseSource(j, slot.Config, slot.Grant)
		if err != nil || !found {
			return reuseRefusal("release-state")
		}
		result = release.Status
		result.RotationRequired = result.RotationRequired || source.State == "rotation" || source.State == "scanning"
		return nil
	})
	return result, err
}
