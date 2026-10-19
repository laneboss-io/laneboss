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
	"laneboss.io/laneboss/internal/v2/objectread"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type roomWindow struct {
	Window string        `json:"window"`
	Used   float64       `json:"used_percent"`
	Reset  api.Timestamp `json:"resets_at"`
}

type roomObservation struct {
	Schema         string        `json:"schema"`
	Target         api.LifeRef   `json:"target"`
	ProfileGrantID api.ID        `json:"profile_grant_id"`
	ProfileID      api.ID        `json:"profile_id"`
	WorkerLeaseID  api.ID        `json:"worker_lease_id"`
	Raw            api.BlobRef   `json:"raw"`
	CheckedAt      api.Timestamp `json:"checked_at"`
	ExpiresAt      api.Timestamp `json:"expires_at"`
	Available      bool          `json:"available"`
	Windows        []roomWindow  `json:"windows"`
}

type retainedRoom struct {
	Schema      string
	Config      string
	Grant       api.ProfileGrant
	Profile     bstate.Profile
	Request     api.UsageWindowRequest
	Producer    api.WorkerPrincipal
	Room        api.Room
	Observation roomObservation
}

// ProfileGrant carries no life selector. Resolve its exact issued membership
// through the existing service reader, never by a guessed latest-run sentinel.
func (s *Service) roomLane(ctx context.Context, grant api.ProfileGrant) (api.Lane, error) {
	var selected api.Lane
	cursor, seen := "", map[string]bool{}
	for pages := 0; pages < 4096; pages++ {
		page, err := s.deps.Store.Lanes(ctx, s.deps.ServiceScope, api.ListRequest{Cursor: cursor, Limit: 200})
		if err != nil {
			return selected, err
		}
		for _, lane := range page.Lanes {
			if lane.Cleaned || lane.State == "merged" || lane.State == "abandoned" {
				continue
			}
			grants, err := s.deps.Store.Grants(ctx, lane.GrantSetID)
			if err != nil {
				return selected, err
			}
			for _, member := range grants.Profiles {
				if member.ID != grant.ID {
					continue
				}
				if member != grant || selected.LifeID != "" {
					return selected, wire.Error(api.CodeForbidden, "room profile has no unique exact current delegation")
				}
				selected = lane
			}
		}
		if page.Cursor == "" {
			if selected.LifeID == "" {
				return selected, wire.Error(api.CodeForbidden, "room profile has no current delegated life")
			}
			return selected, nil
		}
		if page.Cursor == cursor || seen[page.Cursor] {
			return selected, wire.Error(api.CodeIntegrity, "room life lookup repeated its cursor")
		}
		seen[page.Cursor], cursor = true, page.Cursor
	}
	return selected, wire.Error(api.CodeBudget, "room life lookup exceeded its bound")
}

func (s *Service) roomRequest(ctx context.Context, lane api.Lane, grant api.ProfileGrant) (api.UsageWindowRequest, error) {
	var request api.UsageWindowRequest
	target := api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}
	current, err := s.currentGrants(ctx, target)
	if err != nil {
		return request, err
	}
	found := false
	for _, member := range current.Profiles {
		found = found || member == grant
	}
	if !found {
		return request, wire.Error(api.CodeForbidden, "room selection left its current grant set")
	}
	binding, err := s.deps.Store.LaunchBinding(ctx, lane.LaunchID)
	if err != nil {
		return request, err
	}
	if binding.Recovery == nil {
		return request, wire.Error(api.CodeIntegrity, "room query has no retained causing launch")
	}
	plan, err := s.deps.Store.LaunchPlan(ctx, s.deps.ServiceScope, binding.Recovery.PlanID)
	if err != nil {
		return request, err
	}
	if err := api.ValidateLaunchPlanRecord(plan); err != nil {
		return request, err
	}
	if plan.Plan == nil || api.ValidateLaunchBindingPlan(binding, *plan.Plan) != nil {
		return request, wire.Error(api.CodeIntegrity, "room query changed its causing plan")
	}
	var from api.ProfileGrant
	for _, member := range current.Profiles {
		if member.ID == plan.Plan.Runner.Slot.ProfileGrantID {
			from = member
		}
	}
	profile, err := s.loadProfile(ctx, from)
	if err != nil {
		return request, err
	}
	if profile.Usage == nil || from.Driver != grant.Driver || from.Provider != grant.Provider {
		return request, wire.Error(api.CodeForbidden, "room query crossed its causing provider or driver")
	}
	request = api.UsageWindowRequest{Target: target, LaunchID: lane.LaunchID, ProfileGrantID: from.ID, ProfileID: from.ProfileID, Provider: from.Provider,
		AdapterVersion: profile.Usage.AdapterVersion, Executable: profile.Usage.Executable, RuntimeManifest: profile.Usage.RuntimeManifest}
	query := api.EventTailRequest{LifeID: lane.LifeID, Run: lane.Run}
	for pages := 0; pages < 256; pages++ {
		page, err := s.deps.Store.Events(ctx, s.deps.ServiceScope, query)
		if err != nil {
			return request, err
		}
		for _, event := range page.Events {
			if event.Kind != "lane.ended" || event.Config != s.deps.Config || event.LifeID != lane.LifeID || event.Run != lane.Run || event.Actor.Kind != "service" || event.Origin != "service" {
				continue
			}
			var end api.RunEndEvent
			if err := api.DecodeObject(event.Payload, &end); err != nil {
				return request, err
			}
			if end.LaunchID == lane.LaunchID && event.Seq > 0 {
				if err := quiescent(ctx, end.Observation, target); err != nil {
					return request, err
				}
				request.OperationID, request.RunEndedAt = event.OperationID, end.Observation.ObservedAt
				return request, nil
			}
		}
		if page.Complete {
			break
		}
		if page.Cursor == "" || page.Cursor == query.Cursor {
			return request, wire.Error(api.CodeIntegrity, "room end-event cursor did not advance")
		}
		query.Cursor = page.Cursor
	}
	return request, wire.Error(api.CodePrerequisite, "room query needs its actual quiescent causing run end")
}

func parseRoomWindows(raw []byte, vendor string, now time.Time) ([]roomWindow, bool, error) {
	if len(raw) == 0 || len(raw) > api.MaxFrameBytes || !utf8.Valid(raw) || !usageName(vendor) {
		return nil, false, wire.Error(api.CodeInvalid, "room source has invalid vendor bytes")
	}
	reader := csv.NewReader(bytes.NewReader(raw))
	reader.Comma, reader.FieldsPerRecord = '\t', 5
	rows, err := reader.ReadAll()
	if err != nil || len(rows) < 2 || strings.Join(rows[0], "\t") != "PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC" {
		return nil, false, wire.Error(api.CodeInvalid, "room source requires the exact ordered vendor TSV")
	}
	plans, seen := map[string]string{}, map[string]bool{}
	windows, available := []roomWindow{}, true
	for _, fields := range rows[1:] {
		used, e := strconv.ParseFloat(fields[3], 64)
		reset, re := time.Parse(time.RFC3339Nano, fields[4])
		unknown := fields[4] == "" || fields[4] == "unknown" || fields[4] == "-" || fields[4] == "—"
		key := fields[0] + "\x00" + fields[2]
		if !usageName(fields[0]) || !usageName(fields[1]) || !usageName(fields[2]) || e != nil || math.IsNaN(used) || math.IsInf(used, 0) || used < 0 ||
			!unknown && (re != nil || !strings.HasSuffix(fields[4], "Z")) || plans[fields[0]] != "" && plans[fields[0]] != fields[1] || seen[key] {
			return nil, false, wire.Error(api.CodeInvalid, "room source contains malformed or conflicting vendor rows")
		}
		plans[fields[0]], seen[key] = fields[1], true
		if fields[0] != vendor {
			continue
		}
		if unknown || !reset.After(now) {
			return nil, false, wire.Error(api.CodeUnavailable, "room source has no current known vendor reset")
		}
		windows = append(windows, roomWindow{Window: fields[2], Used: used, Reset: api.Timestamp(fields[4])})
		available = available && used < 100
	}
	if len(windows) == 0 {
		return nil, false, wire.Error(api.CodeUnavailable, "room source omitted its protected selected profile")
	}
	return windows, available, nil
}

func (s *Service) usageRoom(ctx context.Context, grant api.ProfileGrant, profile bstate.Profile) (api.Room, error) {
	lane, err := s.roomLane(ctx, grant)
	if err != nil {
		return api.Room{}, err
	}
	request, err := s.roomRequest(ctx, lane, grant)
	if err != nil {
		return api.Room{}, err
	}
	var result api.Room
	err = s.withUsageMeasurement(ctx, s.deps.ServiceScope, request, func(m usageMeasurement) error {
		if profile.Usage == nil || profile.Usage.Executable != request.Executable || profile.Usage.RuntimeManifest != request.RuntimeManifest || profile.Usage.AdapterVersion != request.AdapterVersion {
			return wire.Error(api.CodeForbidden, "room profile differs from the measured provider runtime")
		}
		observed, e := time.Parse(time.RFC3339Nano, string(m.Output.ObservedAt))
		ended, endErr := time.Parse(time.RFC3339Nano, string(request.RunEndedAt))
		now := s.deps.Clock.Now()
		if e != nil || endErr != nil || observed.After(now) || observed.Before(ended) || now.Sub(observed) > 30*time.Second {
			return wire.Error(api.CodeIntegrity, "room command has no fresh post-exit observation")
		}
		windows, available, e := parseRoomWindows(m.Output.Raw, profile.Usage.VendorProfile, now)
		if e != nil {
			return e
		}
		expires := api.Timestamp(observed.Add(time.Minute).UTC().Format(time.RFC3339Nano))
		for _, bound := range append([]api.Timestamp{grant.ExpiresAt, profile.ExpiresAt}, roomResets(windows)...) {
			if timestampBefore(bound, expires) {
				expires = bound
			}
		}
		observation := roomObservation{Schema: "laneboss.room-observation.v1", Target: request.Target, ProfileGrantID: grant.ID, ProfileID: grant.ProfileID,
			WorkerLeaseID: m.Producer.Lease.ID, Raw: m.Raw, CheckedAt: m.Output.ObservedAt, ExpiresAt: expires, Available: available, Windows: windows}
		ref, e := s.retainRoomObservation(ctx, lane, m, observation)
		if e != nil {
			return e
		}
		reason := "outside_provider_room"
		if !available {
			reason = "outside_provider_no_room"
		}
		result = api.Room{ProfileID: grant.ProfileID, Available: available, CheckedAt: observation.CheckedAt, ExpiresAt: expires, Evidence: ref, Reason: reason}
		latest, e := s.loadProfile(ctx, grant)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(latest, profile) {
			return wire.Error(api.CodeConflict, "room profile enrollment changed during measurement")
		}
		backend, e := s.brokerBackend()
		if e != nil {
			return e
		}
		saved := retainedRoom{Schema: "laneboss.retained-room.v1", Config: s.deps.Config, Grant: grant, Profile: profile, Request: request, Producer: m.Producer, Room: result, Observation: observation}
		return backend.WithBroker(ctx, func(j bstate.Journal) error {
			var old retainedRoom
			if e := j.Read("usage", ref.ID, &old); e == nil {
				if !reflect.DeepEqual(old, saved) {
					return wire.Error(api.CodeIdempotencyConflict, "room observation changed its original measured bytes")
				}
				return nil
			} else if !hasCode(e, api.CodeNotFound) {
				return e
			}
			return j.Write("usage", ref.ID, saved)
		})
	})
	if err != nil {
		return api.Room{}, err
	}
	return result, nil
}

func roomResets(windows []roomWindow) []api.Timestamp {
	out := make([]api.Timestamp, 0, len(windows))
	for _, w := range windows {
		out = append(out, w.Reset)
	}
	return out
}

func roomParticipants(lane api.Lane) []api.ID {
	participants, seen := []api.ID{}, map[api.ID]bool{}
	for _, id := range append([]api.ID{lane.LifeID, lane.RootLifeID, lane.ParentLifeID}, lane.StarterChain...) {
		if id != "" && !seen[id] {
			participants = append(participants, id)
			seen[id] = true
		}
	}
	return participants
}

func (s *Service) retainRoomObservation(ctx context.Context, lane api.Lane, m usageMeasurement, value roomObservation) (api.BlobRef, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return api.BlobRef{}, err
	}
	raw, err = api.CanonicalJSON(raw)
	if err != nil {
		return api.BlobRef{}, err
	}
	sum := sha256.Sum256(raw)
	participants := roomParticipants(lane)
	ref, err := s.deps.Store.RetainObject(ctx, s.deps.ServiceScope, api.RetainObjectRequest{Intent: *m.Producer.Claim.Record.Effect.Context,
		Object: api.ObjectWrite{ObjectKey: credentialID("room-observation", m.Producer.StageID, m.Producer.Lease.ID, value.ProfileID), Class: "manifest", Bytes: raw, SHA256: api.Digest(hex.EncodeToString(sum[:])), Origin: "service",
			ACL: api.ObjectACL{Config: s.deps.Config, Owner: m.Producer.Record.Actor, LifeID: lane.LifeID, Audience: "participants", Participants: participants, Generation: 1}, InputRefs: []api.BlobRef{m.Raw, m.Receipt.Result}}})
	if err != nil {
		return ref, err
	}
	actual, err := s.readRoomObject(ctx, ref, m.Producer, lane.LifeID)
	if err != nil {
		return ref, err
	}
	meta, err := s.deps.Store.ObjectMetadata(ctx, s.deps.ServiceScope, ref.ID)
	if err != nil {
		return ref, err
	}
	if !bytes.Equal(raw, actual) || ref.Class != "manifest" || meta.ACL.Owner != m.Producer.Record.Actor || meta.ACL.Audience != "participants" || !reflect.DeepEqual(meta.ACL.Participants, participants) {
		return ref, wire.Error(api.CodeIntegrity, "room observation lost its immutable producer ownership")
	}
	return ref, nil
}

// Only the nonsecret normalized room envelope has the supervising tree as
// participants. Raw vendor bytes retain their private service-only ACL.
func (s *Service) readRoomObject(ctx context.Context, ref api.BlobRef, p api.WorkerPrincipal, life api.ID) (data []byte, resultErr error) {
	if ref.Class != "manifest" || !wire.ID(string(ref.ID)) || !wire.Digest(ref.SHA256) || ref.Bytes < 1 || ref.Bytes > api.MaxFrameBytes {
		return nil, wire.Error(api.CodeInvalid, "room evidence reference is invalid")
	}
	scope, release, err := objectread.Bind(ctx, s.deps.Store, s.deps.ServiceScope)
	if err != nil {
		return nil, err
	}
	defer release(&resultErr)
	meta, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return nil, err
	}
	if meta.Ref != ref || meta.Origin != "service" || meta.ACL.Config != s.deps.Config || meta.ACL.Owner != p.Record.Actor || meta.ACL.LifeID != life || meta.ACL.Audience != "participants" || meta.SourceOperationID != p.Lease.OperationID {
		return nil, wire.Error(api.CodeForbidden, "room evidence lost its actual producing worker")
	}
	for int64(len(data)) < ref.Bytes {
		limit := min(api.MaxChunkBytes, int(ref.Bytes-int64(len(data))))
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(data)), Limit: limit})
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(chunk.Data)
		if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(data)) || len(chunk.Data) == 0 || len(chunk.Data) > limit || chunk.SHA256 != api.Digest(hex.EncodeToString(sum[:])) {
			return nil, wire.Error(api.CodeIntegrity, "room evidence chunk differs")
		}
		data = append(data, chunk.Data...)
	}
	sum := sha256.Sum256(data)
	if api.Digest(hex.EncodeToString(sum[:])) != ref.SHA256 {
		return nil, wire.Error(api.CodeIntegrity, "room evidence bytes differ")
	}
	return data, nil
}
