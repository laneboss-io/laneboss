package secrets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

func usageName(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && !strings.ContainsAny(value, "\t\r\n\x00")
}

type usageRow struct {
	Index  int
	Window string
	Used   float64
	Reset  api.Timestamp
}

// The ordered v1 TSV grammar is deliberately closed. All rows are checked,
// including rows other than the selected profile; PLAN cannot drift per login.
func parseUsageRows(raw []byte, vendorProfile string, now time.Time) (usageRow, error) {
	if len(raw) == 0 || len(raw) > api.MaxFrameBytes || !utf8.Valid(raw) || !usageName(vendorProfile) {
		return usageRow{}, wire.Error(api.CodeInvalid, "outside usage bytes are empty invalid or unbounded")
	}
	reader := csv.NewReader(bytes.NewReader(raw))
	reader.Comma, reader.FieldsPerRecord = '\t', 5
	rows, err := reader.ReadAll()
	if err != nil || len(rows) < 2 || strings.Join(rows[0], "\t") != "PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC" {
		return usageRow{}, wire.Error(api.CodeInvalid, "outside usage requires the exact ordered five-column TSV")
	}
	plans := map[string]string{}
	var selected usageRow
	for index, fields := range rows[1:] {
		used, err := strconv.ParseFloat(fields[3], 64)
		reset, resetErr := time.Parse(time.RFC3339Nano, fields[4])
		unknown := fields[4] == "" || fields[4] == "unknown" || fields[4] == "-" || fields[4] == "—"
		if !usageName(fields[0]) || !usageName(fields[1]) || !usageName(fields[2]) || err != nil || math.IsNaN(used) || math.IsInf(used, 0) || used < 0 ||
			!unknown && (resetErr != nil || !strings.HasSuffix(fields[4], "Z")) || plans[fields[0]] != "" && plans[fields[0]] != fields[1] {
			return usageRow{}, wire.Error(api.CodeInvalid, "outside usage contains malformed or conflicting rows")
		}
		plans[fields[0]] = fields[1]
		if selected.Index == 0 && fields[0] == vendorProfile && used >= 100 && !unknown && reset.After(now) {
			selected = usageRow{Index: index + 1, Window: fields[2], Used: used, Reset: api.Timestamp(fields[4])}
		}
	}
	if selected.Index == 0 {
		return selected, wire.Error(api.CodeUnavailable, "outside from-profile usage has no known live exhausted window")
	}
	return selected, nil
}

func (s *Service) usageProfile(ctx context.Context, request api.UsageWindowRequest) (bstate.Profile, error) {
	binding, err := s.deps.Store.LaunchBinding(ctx, request.LaunchID)
	if err != nil {
		return bstate.Profile{}, err
	}
	if binding.Recovery == nil {
		return bstate.Profile{}, wire.Error(api.CodeIntegrity, "usage query has no retained causing launch")
	}
	record, err := s.deps.Store.LaunchPlan(ctx, s.deps.ServiceScope, binding.Recovery.PlanID)
	if err != nil {
		return bstate.Profile{}, err
	}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		return bstate.Profile{}, err
	}
	if record.Plan == nil {
		return bstate.Profile{}, wire.Error(api.CodeIntegrity, "usage query has no complete causing plan")
	}
	if err := api.ValidateLaunchBindingPlan(binding, *record.Plan); err != nil {
		return bstate.Profile{}, err
	}
	if binding.Record.Target != request.Target || binding.Record.ID != request.LaunchID || record.Plan.Capture.Status != "registered" || record.Plan.Runner.Driver != api.DriverClaudock {
		return bstate.Profile{}, wire.Error(api.CodeForbidden, "usage query differs from its captured causing run")
	}
	if record.Plan.Runner.Slot.ProfileGrantID != request.ProfileGrantID || record.Plan.Runner.Slot.ProfileID != request.ProfileID {
		return bstate.Profile{}, wire.Error(api.CodeForbidden, "usage query must measure the causing from-profile")
	}
	lane, err := s.deps.Store.Lane(ctx, s.deps.ServiceScope, request.Target)
	if err != nil {
		return bstate.Profile{}, err
	}
	if lane.Cleaned || lane.LifeID != request.Target.LifeID || lane.Run != request.Target.Run || lane.LaunchID != request.LaunchID || lane.GrantSetID != binding.Record.GrantSetID || lane.CancellationEpoch != record.Reservation.CancellationEpoch {
		return bstate.Profile{}, wire.Error(api.CodeConflict, "usage query causing run or cancellation fence changed")
	}
	grants, err := s.deps.Store.Grants(ctx, binding.Record.GrantSetID)
	if err != nil {
		return bstate.Profile{}, err
	}
	if wire.Nil(s.deps.Grants) {
		return bstate.Profile{}, wire.Error(api.CodePrerequisite, "usage query requires current grant revalidation")
	}
	current, err := s.deps.Grants.Revalidate(ctx, grants)
	if err != nil {
		return bstate.Profile{}, err
	}
	if !reflect.DeepEqual(current, grants) || current.SHA256 != binding.Record.GrantsSHA256 || current.ID != grants.ID || current.LifeID != request.Target.LifeID || current.Revoked || !future(current.ExpiresAt, s.deps.Clock.Now()) {
		return bstate.Profile{}, wire.Error(api.CodeForbidden, "usage profile grants are no longer authorized")
	}
	var grant api.ProfileGrant
	for _, item := range current.Profiles {
		if item.ID == request.ProfileGrantID && item.ProfileID == request.ProfileID && item.Provider == request.Provider && item.Driver == api.DriverClaudock {
			grant = item
			break
		}
	}
	if grant.ID == "" {
		return bstate.Profile{}, wire.Error(api.CodeForbidden, "usage query has no current exact from-profile grant")
	}
	profile, err := s.loadProfile(ctx, grant)
	if err != nil {
		return profile, err
	}
	if profile.Usage == nil || profile.Usage.Executable != request.Executable || profile.Usage.RuntimeManifest != request.RuntimeManifest || profile.Usage.AdapterVersion != request.AdapterVersion {
		return profile, wire.Error(api.CodeForbidden, "usage query differs from protected usage runtime enrollment")
	}
	query := api.EventTailRequest{LifeID: request.Target.LifeID, Run: request.Target.Run}
	for page := 0; page < 256; page++ {
		events, err := s.deps.Store.Events(ctx, s.deps.ServiceScope, query)
		if err != nil {
			return profile, err
		}
		for _, event := range events.Events {
			if event.Kind != "lane.ended" || event.Config != s.deps.Config || event.LifeID != request.Target.LifeID || event.Run != request.Target.Run || event.OperationID != request.OperationID || event.Origin != "service" || event.Actor.Kind != "service" || event.Seq == 0 {
				continue
			}
			var end api.RunEndEvent
			if err := api.DecodeObject(event.Payload, &end); err != nil {
				return profile, err
			}
			if end.LaunchID == request.LaunchID && end.Observation.ObservedAt == request.RunEndedAt && end.Observation.Handle.ContainmentID == binding.Record.ContainmentID && end.Observation.Handle.Generation == binding.Record.ProcessGeneration {
				if err := quiescent(ctx, end.Observation, request.Target); err != nil {
					return profile, err
				}
				return profile, nil
			}
		}
		if events.Complete {
			break
		}
		if events.Cursor == "" || events.Cursor == query.Cursor {
			return profile, wire.Error(api.CodeIntegrity, "usage end-event cursor did not advance")
		}
		query.Cursor = events.Cursor
	}
	return profile, wire.Error(api.CodeIntegrity, "usage query lacks the exact actual run-end observation")
}

func (s *Service) retainUsage(ctx context.Context, p api.WorkerPrincipal, id api.ID, class string, data []byte, inputs []api.BlobRef) (api.BlobRef, error) {
	sum := sha256.Sum256(data)
	digest := api.Digest(hex.EncodeToString(sum[:]))
	cause := p.Claim.Record.Effect.Context
	if cause == nil || cause.Kind != api.InternalObjectRetain {
		return api.BlobRef{}, wire.Error(api.CodeForbidden, "usage retention requires its actual object-retain worker claim")
	}
	ref, err := s.deps.Store.RetainObject(ctx, s.deps.ServiceScope, api.RetainObjectRequest{Intent: *cause, Object: api.ObjectWrite{ObjectKey: id, Class: class, Bytes: data, SHA256: digest,
		ACL: api.ObjectACL{Config: s.deps.Config, Owner: p.Record.Actor, LifeID: p.Lease.Target.LifeID, Audience: "service", Generation: 1}, Origin: "service", InputRefs: inputs}})
	if err != nil {
		return ref, err
	}
	if ref.ID != id || ref.Class != class || ref.Bytes != int64(len(data)) || ref.SHA256 != digest {
		return ref, wire.Error(api.CodeIntegrity, "usage retention returned another immutable object")
	}
	actual, err := s.protectedObject(ctx, ref, p.Lease.OperationID)
	if err != nil {
		return ref, err
	}
	meta, err := s.deps.Store.ObjectMetadata(ctx, s.deps.ServiceScope, ref.ID)
	if err != nil {
		return ref, err
	}
	if meta.ACL.Owner != p.Record.Actor || meta.ACL.LifeID != p.Lease.Target.LifeID || !bytes.Equal(actual, data) {
		return ref, wire.Error(api.CodeIntegrity, "usage retained bytes or producer ACL differ")
	}
	return ref, nil
}

// The installed outbox gives a usage job its own protected set. It has only
// the selected credential and bounded nondelegable network capabilities; it
// cannot borrow the agent's workspace, profiles, channels or resource grants.
func (s *Service) usageGrants(ctx context.Context, p api.WorkerPrincipal, profile bstate.Profile, request api.UsageWindowRequest) error {
	binding, err := s.deps.Store.LaunchBinding(ctx, request.LaunchID)
	if err != nil {
		return err
	}
	if p.Lease.GrantSetID == binding.Record.GrantSetID {
		return wire.Error(api.CodeForbidden, "usage worker must have its own narrow grant set")
	}
	grants, err := s.deps.Store.Grants(ctx, p.Lease.GrantSetID)
	if err != nil {
		return err
	}
	current, err := s.deps.Grants.Revalidate(ctx, grants)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, grants) || current.ID != p.Lease.GrantSetID || current.LifeID != p.Lease.Target.LifeID || current.SHA256 != p.Record.GrantsSHA256 || current.Revoked || !future(current.ExpiresAt, s.deps.Clock.Now()) ||
		len(current.Data)+len(current.Resources)+len(current.Profiles)+len(current.Channels) != 0 || len(current.Secrets) != 1 || current.Secrets[0] != profile.Source || len(current.Network) > 8 {
		return wire.Error(api.CodeForbidden, "usage worker grants exceed its protected credential query")
	}
	seen := map[api.ID]bool{}
	for _, network := range current.Network {
		if !wire.ID(string(network.ID)) || !wire.ID(string(network.EndpointID)) || network.Delegate || seen[network.EndpointID] || !future(network.ExpiresAt, s.deps.Clock.Now()) {
			return wire.Error(api.CodeForbidden, "usage worker network grants are not bounded current endpoints")
		}
		seen[network.EndpointID] = true
	}
	backend, err := s.brokerBackend()
	if err != nil {
		return err
	}
	return backend.WithBroker(ctx, func(j bstate.Journal) error {
		material, err := j.Fetch(ctx, profile.Source)
		clear(material.Bytes)
		return err
	})
}

func (s *Service) ReadUsageWindow(ctx context.Context, scope api.Scope, request api.UsageWindowRequest) (api.UsageWindowEvidence, error) {
	var value api.UsageWindowEvidence
	err := s.withUsageMeasurement(ctx, scope, request, func(m usageMeasurement) error {
		p, producer, profile, output, receipt, raw := m.Principal, m.Producer, m.Profile, m.Output, m.Receipt, m.Raw
		row, err := parseUsageRows(output.Raw, profile.Usage.VendorProfile, s.deps.Clock.Now())
		if err != nil {
			return err
		}
		evidence := api.UsageWindowEvidence{Schema: "laneboss.usage-window.v2", ID: credentialID("usage-window", p.StageID, p.Lease.ID), Target: request.Target, LaunchID: request.LaunchID, OperationID: request.OperationID,
			ProfileGrantID: request.ProfileGrantID, ProfileID: request.ProfileID, Provider: request.Provider, AdapterVersion: request.AdapterVersion, Executable: request.Executable, RuntimeManifest: request.RuntimeManifest,
			WorkerLeaseID: p.Lease.ID, ProducerID: p.Record.Actor.ID, ProducerGeneration: p.Peer.ProcessGeneration, BootID: p.BootID, ObservedAt: output.ObservedAt, Window: row.Window, UsedPercent: row.Used, ResetsAt: row.Reset, ExitCode: output.ExitCode, Raw: raw, Row: row.Index}
		if err := api.ValidateUsageWindow(evidence, request, producer, s.deps.Clock.Now()); err != nil {
			return err
		}
		if err := api.ValidateUsageSource(evidence, output.Raw, profile.Usage.VendorProfile); err != nil {
			return err
		}
		data, err := json.Marshal(evidence)
		if err != nil {
			return wire.Error(api.CodeIntegrity, "cannot encode outside usage envelope")
		}
		data, err = api.CanonicalJSON(data)
		if err != nil {
			return err
		}
		envelope, err := s.retainUsage(ctx, p, evidence.ID, "usage_window", data, []api.BlobRef{raw, receipt.Result})
		if err != nil {
			return err
		}
		if err := s.keepUsageProvenance(ctx, evidence, envelope, producer, profile, request); err != nil {
			return err
		}
		value = evidence
		return nil
	})
	if err != nil {
		return api.UsageWindowEvidence{}, err
	}
	return value, nil
}
