package codex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

const maxRecordBytes = 1024 * 1024
const maxCaptureLineBytes = api.MaxObjectBytes

// readBlob accepts exact immutable bytes from the scoped store. It checks both
// chunk and object hashes and never returns or logs the store's private errors.
func (s *Service) readBlob(ctx context.Context, reference api.BlobRef) (result []byte, resultErr error) {
	if !blob(reference) {
		return nil, problem(api.CodeIntegrity, "Codex blob reference is invalid")
	}
	scope, release, err := objectread.Bind(ctx, s.deps.Store, s.deps.ReadScope)
	if err != nil {
		return nil, dependencyError(err)
	}
	defer release(&resultErr)
	if err := s.blobMetadataScope(ctx, scope, reference); err != nil {
		return nil, err
	}
	data := make([]byte, 0, min(reference.Bytes, api.MaxChunkBytes))
	for int64(len(data)) < reference.Bytes {
		if err := cancelled(ctx); err != nil {
			return nil, err
		}
		remaining := reference.Bytes - int64(len(data))
		limit := int(min(int64(api.MaxChunkBytes), remaining))
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{
			ObjectID: reference.ID, Offset: int64(len(data)), Limit: limit,
		})
		if err != nil {
			return nil, dependencyError(err)
		}
		hash := sha256.Sum256(chunk.Data)
		if chunk.ObjectID != reference.ID || chunk.Offset != int64(len(data)) || len(chunk.Data) == 0 ||
			len(chunk.Data) > limit || api.Digest(hex.EncodeToString(hash[:])) != chunk.SHA256 {
			return nil, problem(api.CodeIntegrity, "Codex blob chunk identity, range or hash differs")
		}
		data = append(data, chunk.Data...)
	}
	hash := sha256.Sum256(data)
	if int64(len(data)) != reference.Bytes || api.Digest(hex.EncodeToString(hash[:])) != reference.SHA256 {
		return nil, problem(api.CodeIntegrity, "Codex blob bytes differ from their retained reference")
	}
	return data, nil
}

func (s *Service) blobMetadata(ctx context.Context, reference api.BlobRef) error {
	return s.blobMetadataScope(ctx, s.deps.ReadScope, reference)
}

func (s *Service) blobMetadataScope(ctx context.Context, scope api.Scope, reference api.BlobRef) error {
	if !blob(reference) {
		return problem(api.CodeIntegrity, "Codex blob reference is invalid")
	}
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, reference.ID)
	if err != nil {
		return dependencyError(err)
	}
	if metadata.Ref != reference || metadata.ACL.Config != s.deps.ReadScope.Config {
		return problem(api.CodeIntegrity, "Codex blob reference differs from its committed metadata")
	}
	if reference.Class == "capture" && metadata.Origin != "service" {
		return problem(api.CodeIntegrity, "Codex capture object has no outside service provenance")
	}
	return nil
}

func (s *Service) events(ctx context.Context, target api.LifeRef) ([]api.Event, error) {
	var events []api.Event
	cursor := ""
	seen := map[string]bool{}
	var sequence api.Sequence
	for {
		if err := cancelled(ctx); err != nil {
			return nil, err
		}
		page, err := s.deps.Store.Events(ctx, s.deps.ReadScope, api.EventTailRequest{
			LifeID: target.LifeID, Run: target.Run, Cursor: cursor,
		})
		if err != nil {
			return nil, dependencyError(err)
		}
		for _, event := range page.Events {
			if event.Kind == "lane.turn" && !id(event.LogicalTurnID) {
				return nil, problem(api.CodeIntegrity, "Codex turn event has no logical turn identity")
			}
			if event.Origin != "service" || event.Config != s.deps.ReadScope.Config || event.LifeID != target.LifeID ||
				(target.Run != 0 && event.Run != target.Run) || event.Seq <= sequence {
				return nil, problem(api.CodeIntegrity, "Codex event history has a scope or sequence mismatch")
			}
			sequence = event.Seq
			events = append(events, event)
			if len(events) > 131072 {
				return nil, problem(api.CodeUnavailable, "Codex event snapshot exceeds the adapter bound")
			}
		}
		if page.Cursor == "" {
			if !page.Complete {
				return nil, problem(api.CodeUnavailable, "Codex event snapshot is incomplete")
			}
			return events, nil
		}
		if seen[page.Cursor] {
			return nil, problem(api.CodeIntegrity, "Codex event cursor repeated without completion")
		}
		seen[page.Cursor] = true
		cursor = page.Cursor
	}
}

type captured struct {
	data   []byte
	events []api.Event
	lane   api.Lane
}

func (s *Service) captured(ctx context.Context, record api.CaptureRecord, final bool) (captured, error) {
	var empty captured
	if err := cancelled(ctx); err != nil {
		return empty, err
	}
	if err := s.installedRuntime(); err != nil {
		return empty, err
	}
	if s == nil || s.deps.Store == nil || s.deps.Clock == nil {
		return empty, problem(api.CodePrerequisite, "Codex capture reader is not configured")
	}
	if !id(record.ID) || !id(record.Target.LifeID) || record.Target.Run == 0 ||
		record.Data.Class != "capture" ||
		record.Offset < 0 || record.Offset > api.MaxObjectBytes || !record.Primary || record.ReplacementOf != "" ||
		(record.Stream != "stdout" && record.Stream != "vendor") ||
		(record.Coverage != "partial" && record.Coverage != "unsupported") {
		return empty, problem(api.CodeIntegrity, "Codex needs original primary output with honest partial coverage")
	}
	if _, err := timestamp(record.ObservedAt); err != nil {
		return empty, err
	}
	lane, err := s.boundLane(ctx, record.Target)
	if err != nil {
		return empty, err
	}
	if lane.Session.Driver != api.DriverCodex || lane.Session.VendorVersion != s.deps.Runtime.Executable.Version ||
		!id(lane.Session.ID) || !id(lane.Session.HomeID) || !id(lane.Session.HistoryID) || !absolute(lane.Session.LogicalCWD) ||
		lane.Session.LogicalCWD != lane.Workspace.LogicalCWD {
		return empty, problem(api.CodeIntegrity, "Codex capture does not match its pinned session")
	}
	home, err := s.boundHome(ctx, record.Target)
	if err != nil {
		return empty, err
	}
	if lane.Session.HomeID != home.ID || lane.Session.HistoryID != home.HistoryID || lane.Workspace.ID != home.WorkspaceID {
		return empty, problem(api.CodeIntegrity, "Codex capture history differs from its authoritative home")
	}
	events, err := s.events(ctx, record.Target)
	if err != nil {
		return empty, err
	}
	source, err := s.captureSource(ctx, record, lane, events)
	if err != nil {
		return empty, err
	}
	if source.plan.Data.Home.Home != home {
		return empty, problem(api.CodeIntegrity, "Codex capture home differs from the retained launch")
	}
	var records []api.CaptureRecord
	found := false
	for _, event := range events {
		if event.Kind == "capture.gap" {
			var gap api.CaptureGap
			if decode(event.Payload, &gap) != nil || gap.BindingID != record.BindingID || !captureCause(event, source) || gap.Stream == record.Stream {
				return empty, problem(api.CodeIntegrity, "Codex primary output has a recorded gap")
			}
		}
		if event.Kind != "capture.appended" {
			continue
		}
		var candidate api.CaptureRecord
		if err := decode(event.Payload, &candidate); err != nil {
			return empty, err
		}
		if candidate.ID == record.ID {
			if found || candidate != record {
				return empty, problem(api.CodeIntegrity, "Codex capture record differs from the outside spool")
			}
			found = true
		}
		if candidate.Stream == record.Stream && candidate.Primary {
			if candidate.BindingID != record.BindingID || !captureCause(event, source) ||
				candidate.Data.Class != "capture" || candidate.Target != record.Target || candidate.ReplacementOf != "" ||
				(candidate.Coverage != "partial" && candidate.Coverage != "unsupported") {
				return empty, problem(api.CodeIntegrity, "Codex capture provenance or coverage is invalid")
			}
			records = append(records, candidate)
		}
	}
	if !found {
		return empty, problem(api.CodeIntegrity, "Codex record has no outside capture event")
	}
	slices.SortStableFunc(records, func(a, b api.CaptureRecord) int {
		if a.Offset < b.Offset {
			return -1
		}
		if a.Offset > b.Offset {
			return 1
		}
		return 0
	})
	var data []byte
	for _, candidate := range records {
		if candidate.Offset > record.Offset {
			if final {
				return empty, problem(api.CodeConflict, "Codex limit classification needs the final capture record")
			}
			break
		}
		if candidate.Offset != int64(len(data)) || candidate.Data.Bytes > api.MaxObjectBytes-int64(len(data)) {
			return empty, problem(api.CodeIntegrity, "Codex primary output has a gap, overlap or exceeded bound")
		}
		part, err := s.readBlob(ctx, candidate.Data)
		if err != nil {
			return empty, err
		}
		data = append(data, part...)
		metadata, err := s.deps.Store.ObjectMetadata(ctx, s.deps.ReadScope, candidate.Data.ID)
		if err != nil {
			return empty, dependencyError(err)
		}
		if metadata.SourceOperationID != source.state.Binding.OperationID || metadata.ACL.LifeID != record.Target.LifeID ||
			int64(len(data)) > source.position.NextOffset {
			return empty, problem(api.CodeIntegrity, "Codex capture bytes exceed their committed source or position")
		}
	}
	if final && !captureDrained(source, events, int64(len(data))) {
		return empty, problem(api.CodeUnavailable, "Codex limit analysis needs acknowledged capture EOF")
	}
	return captured{data: data, events: events, lane: lane}, nil
}

func vendorRecords(data []byte) ([]map[string]json.RawMessage, error) {
	return parseVendorRecords(data, false)
}

func parseVendorRecords(data []byte, inProgress bool) ([]map[string]json.RawMessage, error) {
	var records []map[string]json.RawMessage
	mapped := false
	for len(data) > 0 {
		line, rest, terminated := bytes.Cut(data, []byte{'\n'})
		if len(bytes.TrimSpace(line)) == 0 {
			data = rest
			continue
		}
		if len(line) > maxCaptureLineBytes {
			return nil, problem(api.CodeIntegrity, "Codex structured record exceeds the parser bound")
		}
		if !terminated && !json.Valid(line) {
			if inProgress && mapped {
				return records, nil
			}
			return nil, problem(api.CodeUnavailable, "Codex capture ends within a structured record")
		}
		if len(bytes.TrimSpace(line)) != 0 {
			var record map[string]json.RawMessage
			if err := decodeJSON(line, &record, false); err != nil {
				return nil, err
			}
			records = append(records, record)
			mapped = mapped || (terminated && textField(record, "type") == "thread.started" && uuid(textField(record, "thread_id")))
		}
		data = rest
	}
	return records, nil
}

func textField(record map[string]json.RawMessage, name string) string {
	var value string
	if json.Unmarshal(record[name], &value) != nil {
		return ""
	}
	return value
}

// codexSession recognizes only a top-level vendor thread.started object. It
// accepts no user/tool quotation and invents no session ID. It is independent of
// worker activity so a replayed outside capture can bind after worker restart.
func codexSession(line []byte) (string, error) {
	if len(line) > maxCaptureLineBytes {
		return "", problem(api.CodeIntegrity, "Codex session record is oversized")
	}
	var event map[string]json.RawMessage
	if err := decodeJSON(line, &event, false); err != nil {
		return "", err
	}
	if textField(event, "type") != "thread.started" {
		return "", problem(api.CodeNotFound, "Codex record does not establish a vendor session")
	}
	id := textField(event, "thread_id")
	if !uuid(id) {
		return "", problem(api.CodeIntegrity, "Codex thread.started has an invalid vendor session")
	}
	return id, nil
}

func (s *Service) SessionFromCapture(ctx context.Context, record api.CaptureRecord) (api.Session, error) {
	var empty api.Session
	capture, err := s.captured(ctx, record, false)
	if err != nil {
		return empty, err
	}
	records, err := parseVendorRecords(capture.data, true)
	if err != nil {
		return empty, err
	}
	var vendor string
	for _, event := range records {
		if textField(event, "type") != "thread.started" {
			continue
		}
		candidate := textField(event, "thread_id")
		if !uuid(candidate) || (vendor != "" && vendor != candidate) {
			return empty, problem(api.CodeIntegrity, "Codex capture has an invalid or conflicting session")
		}
		vendor = candidate
	}
	if vendor == "" {
		return empty, problem(api.CodeNotFound, "Codex capture has no thread.started record")
	}
	session := capture.lane.Session
	if session.VendorID != "" && session.VendorID != vendor {
		return empty, problem(api.CodeIntegrity, "Codex vendor session differs from its life mapping")
	}
	session.VendorID = vendor
	return session, nil
}

// LimitFromCapture never treats plain text, model/tool text, guard or auth errors
// as quota evidence. Even recognized structured codes require a reviewed pinned
// schema receipt. The watchdog separately verifies room and remaining budget.
func (s *Service) LimitFromCapture(ctx context.Context, record api.CaptureRecord, exit api.ProcessObservation) (*api.LimitSignal, error) {
	capture, err := s.captured(ctx, record, true)
	if err != nil {
		return nil, err
	}
	if !quiescent(exit, record.Target) {
		return nil, problem(api.CodeContainmentUnknown, "Codex limit needs a real exit and zero survivors")
	}
	observed := false
	var slot api.CredentialSlot
	for _, event := range capture.events {
		switch event.Kind {
		case "run.observed":
			var candidate api.ProcessObservation
			if err := decode(event.Payload, &candidate); err != nil {
				return nil, err
			}
			observed = observed || reflect.DeepEqual(candidate, exit)
		case "lane.ended":
			var end api.RunEndEvent
			if err := decode(event.Payload, &end); err != nil {
				return nil, err
			}
			observed = observed || reflect.DeepEqual(end.Observation, exit)
		case "credential.leased":
			var leased api.CredentialEvent
			if err := decode(event.Payload, &leased); err != nil {
				return nil, err
			}
			if slot.ID != "" && leased.Slot != slot {
				return nil, problem(api.CodeIntegrity, "Codex run has ambiguous credential identity")
			}
			slot = leased.Slot
		}
	}
	if !observed {
		return nil, problem(api.CodeIntegrity, "Codex exit is absent from the outside observations")
	}
	records, err := vendorRecords(capture.data)
	if err != nil {
		return nil, err
	}
	var providerError []byte
	failed := false
	for _, event := range records {
		switch textField(event, "type") {
		case "turn.started", "turn.completed":
			providerError = nil
			failed = false
		case "turn.failed":
			providerError, err = errorObject(event["error"])
			if err != nil {
				return nil, err
			}
			failed = true
		}
	}
	if !failed {
		return nil, nil
	}
	// No guessed wording or unsourced provider codes. A reviewed outside
	// receipt supplies the actual pinned failure samples and their categories.
	proof, err := s.loadCompatibility(ctx, s.deps.Runtime.LimitEvidence, "structured-errors")
	if err != nil {
		return nil, err
	}
	kind := ""
	for _, sample := range proof.Limits {
		if sample.Kind != "usage_limit" && sample.Kind != "session_limit" && sample.Kind != "rate_limit" {
			return nil, problem(api.CodeIntegrity, "Codex quota fixture has an unsupported category")
		}
		data, err := s.readBlob(ctx, sample.Capture)
		if err != nil {
			return nil, err
		}
		sampleRecords, err := vendorRecords(data)
		if err != nil {
			return nil, err
		}
		if len(sampleRecords) != 1 || textField(sampleRecords[0], "type") != "turn.failed" {
			return nil, problem(api.CodeIntegrity, "Codex quota source is not a provider failure record")
		}
		retained, err := errorObject(sampleRecords[0]["error"])
		if err != nil {
			return nil, err
		}
		if bytes.Equal(retained, providerError) {
			if kind != "" && kind != sample.Kind {
				return nil, problem(api.CodeIntegrity, "Codex quota source categories conflict")
			}
			kind = sample.Kind
		}
	}
	if len(proof.Limits) == 0 {
		return nil, problem(api.CodeUnsupported, "Codex quota compatibility receipt has no sourced records")
	}
	if kind == "" {
		return nil, nil
	}
	if exit.ExitCode == nil || exit.Signal != nil {
		return nil, problem(api.CodeIntegrity, "Codex provider limit has no process exit code")
	}
	if !id(slot.ID) || !id(slot.ProfileID) || slot.Mode != "codex-file" {
		return nil, problem(api.CodeIntegrity, "Codex limit has no selected profile evidence")
	}
	grants, err := s.deps.Store.Grants(ctx, capture.lane.GrantSetID)
	if err != nil {
		return nil, dependencyError(err)
	}
	if slot.ProfileGrantID != capture.lane.ProfileGrantID || grants.ID != capture.lane.GrantSetID || grants.LifeID != capture.lane.LifeID {
		return nil, problem(api.CodeIntegrity, "Codex limit profile differs from its reserved life grants")
	}
	provider := ""
	var selected api.ProfileGrant
	matched := 0
	for _, grant := range grants.Profiles {
		if grant.ID == slot.ProfileGrantID && grant.ProfileID == slot.ProfileID && grant.Driver == api.DriverCodex {
			provider = grant.Provider
			selected = grant
			matched++
		}
	}
	if matched != 1 || !label(provider) || strings.ContainsAny(provider, "\r\n") {
		return nil, problem(api.CodeIntegrity, "Codex limit profile has no provider binding")
	}
	usage, err := s.outsideUsage(ctx, capture.lane, selected, exit)
	if err != nil {
		return nil, err
	}
	code := *exit.ExitCode
	return &api.LimitSignal{Target: record.Target, Kind: kind, ProfileID: slot.ProfileID, Provider: provider,
		CaptureID: record.ID, CaptureSHA256: record.Data.SHA256, ExitCode: &code,
		AdapterVersion: AdapterVersion, ObservedAt: record.ObservedAt, UsageEvidence: &usage}, nil
}

// The complete error object is compared with reviewed retained bytes. A code
// is not assumed to exist; a message-only vendor shape is still exact data.
func errorObject(raw []byte) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := decodeJSON(raw, &fields, false); err != nil {
		return nil, err
	}
	if textField(fields, "code") == "" && textField(fields, "message") == "" {
		return nil, api.NotImplemented("lb-v2-codex", "Codex provider error without a retained code or message shape")
	}
	canonical, err := api.CanonicalJSON(raw)
	if err != nil {
		return nil, problem(api.CodeIntegrity, "Codex provider error object is not canonicalizable")
	}
	return canonical, nil
}
