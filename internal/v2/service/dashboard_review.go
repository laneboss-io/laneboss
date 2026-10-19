package service

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

type dashboardReviewInputs struct {
	Subject  api.ReviewSubject `json:"subject"`
	Required []string          `json:"required_checks"`
	Missing  []string          `json:"missing_checks"`
	Request  api.ReviewRequest `json:"request"`
}

// This native preparation reads the actual post-run producer. It neither
// creates a check verdict nor reserves/completes the public review operation.
func (s *Server) prepareDashboardReview(ctx context.Context, caller api.Scope, target api.LifeRef) (dashboardReviewInputs, error) {
	var result dashboardReviewInputs
	if !wire.ValidID(string(target.LifeID)) || target.Run == 0 {
		return result, wire.Invalid("review input target is invalid")
	}
	if _, err := api.WithReadAuthority(ctx, caller); err != nil {
		return result, err
	}
	control, err := s.controlScope()
	if err != nil {
		return result, err
	}
	source, ok := s.deps.Store.(reviewjob.Source)
	if !ok {
		return result, serviceError(api.CodePrerequisite, "installed review snapshot producer is unavailable")
	}
	s.mu.RLock()
	requirements, ok := s.runtime.Helper.(reviewjob.Requirements)
	s.mu.RUnlock()
	if !ok {
		return result, serviceError(api.CodePrerequisite, "installed protected review requirements are unavailable")
	}
	lane, err := s.deps.Store.Lane(ctx, control, target)
	if err != nil {
		return result, err
	}
	if lane.LifeID != target.LifeID || lane.Run != target.Run || lane.Session.Driver != api.DriverClaudock || lane.State != "verifying" || lane.Cleaned {
		return result, serviceError(api.CodeConflict, "dashboard review requires its current ended Claudock fixture")
	}
	binding, err := s.deps.Store.LaunchBinding(ctx, lane.LaunchID)
	if err != nil {
		return result, err
	}
	if binding.Recovery == nil {
		return result, serviceError(api.CodeIntegrity, "review preparation lost its launch recovery")
	}
	framer, ok := s.deps.Store.(interface {
		FrameCapture(context.Context, api.Scope, api.ID) ([]api.CaptureRecord, error)
	})
	if !ok {
		return result, api.NotImplemented("lb-v2-store", "FrameCapture")
	}
	frames, err := framer.FrameCapture(ctx, control, binding.Recovery.Capture.ID)
	if err != nil {
		return result, err
	}
	subject, err := source.ReviewSnapshot(ctx, control, target)
	if err != nil {
		return result, err
	}
	if subject.Target != target || subject.LaunchID != lane.LaunchID || subject.Generation != lane.Generation || subject.Snapshot.ID == "" {
		return result, serviceError(api.CodeIntegrity, "review producer returned another frozen subject")
	}
	required, err := requirements.RequiredReviewChecks(ctx, control, target)
	if err != nil {
		return result, err
	}
	if len(required) == 0 {
		return result, serviceError(api.CodePrerequisite, "protected review checks are empty")
	}
	plan, err := s.deps.Store.LaunchPlan(ctx, control, binding.Recovery.PlanID)
	if err != nil {
		return result, err
	}
	if plan.Inputs == nil {
		return result, serviceError(api.CodeIntegrity, "review base source is absent")
	}
	base := plan.Inputs.Sources.Project.Object
	readTree := func(ref api.BlobRef) (api.ObjectManifest, error) {
		var tree api.ObjectManifest
		raw, err := s.reviewObject(ctx, control, ref)
		if err != nil {
			return tree, err
		}
		if api.DecodeObject(raw, &tree) != nil || manifest.Object(tree) != nil {
			return tree, wire.Invalid("review tree is malformed")
		}
		for _, entry := range tree.Entries {
			for _, content := range manifest.ContentRefs(entry) {
				if _, err := s.dashboardReviewObject(ctx, control, content); err != nil {
					return tree, err
				}
			}
		}
		return tree, nil
	}
	before, err := readTree(base)
	if err != nil {
		return result, err
	}
	after, err := readTree(subject.Snapshot)
	if err != nil {
		return result, err
	}
	capture, err := s.deps.Store.CaptureState(ctx, control, subject.CaptureBindingID)
	if err != nil {
		return result, err
	}
	if capture.Binding.Target != target || capture.Binding.ID != subject.CaptureBindingID || !reflect.DeepEqual(capture.Binding.Streams, subject.Streams) || capture.LastSeq > subject.InventorySeq {
		return result, serviceError(api.CodeIntegrity, "review inventory changed its actual capture")
	}
	retain := func(class string, value any) (api.BlobRef, error) {
		raw, err := json.Marshal(value)
		if err != nil {
			return api.BlobRef{}, err
		}
		raw, err = api.CanonicalJSON(raw)
		if err != nil {
			return api.BlobRef{}, err
		}
		id := api.ID("dash-" + string(digestBytes(append([]byte(class+string(target.LifeID)), raw...))))
		intent := api.InternalIntent{ID: id, Kind: api.InternalObjectRetain, Config: control.Config, Actor: control.Actor,
			RequestedBy: caller.Actor, CauseOperationID: capture.Binding.OperationID, CauseRequestID: capture.Binding.RequestID,
			Target: target, CancellationEpoch: lane.CancellationEpoch}
		ref, err := s.deps.Store.RetainObject(ctx, control, api.RetainObjectRequest{Intent: intent, Object: api.ObjectWrite{
			ObjectKey: id, Class: class, Bytes: raw, SHA256: digestBytes(raw), Origin: "service", InputRefs: []api.BlobRef{},
			ACL: api.ObjectACL{Config: control.Config, Owner: control.Actor, LifeID: target.LifeID, Audience: "owner", Generation: 1}}})
		if err != nil {
			return ref, err
		}
		actual, err := s.reviewObject(ctx, control, ref)
		if err == nil && !reflect.DeepEqual(actual, raw) {
			err = serviceError(api.CodeIntegrity, "prepared review bytes failed read-back")
		}
		return ref, err
	}
	diff, err := retain("diff", dashboardTreeDiff(before, after, base.SHA256, subject.Snapshot.SHA256))
	if err != nil {
		return result, err
	}
	tools, err := retain("manifest", struct {
		Schema  string              `json:"schema"`
		Target  api.LifeRef         `json:"target"`
		Binding api.ID              `json:"binding_id"`
		Through api.Sequence        `json:"through_seq"`
		Records []api.CaptureRecord `json:"records"`
	}{"laneboss.review-tools.v2", target, subject.CaptureBindingID, subject.InventorySeq, frames})
	if err != nil {
		return result, err
	}
	toolCoverage, err := s.dashboardToolCoverage(ctx, control, subject.Target, lane.Session, frames)
	if err != nil {
		return result, err
	}
	inventory := reviewjob.InventoryRecord{Schema: "laneboss.review-inventory.v2", ThroughSeq: subject.InventorySeq,
		Streams: []api.ReviewStreamFact{}, ToolRecords: tools, ToolCoverage: toolCoverage}
	for _, stream := range subject.Streams {
		found := false
		for _, position := range capture.Positions {
			if position.StreamID == stream.ID && position.EOF {
				inventory.Streams = append(inventory.Streams, api.ReviewStreamFact{BindingID: capture.Binding.ID, StreamID: stream.ID,
					EndOffset: position.NextOffset, EOF: true, GapIDs: []api.ID{}})
				found = true
			}
		}
		if !found {
			return result, serviceError(api.CodeIntegrity, "review stream has no measured EOF")
		}
	}
	inventoryRef, err := retain("manifest", inventory)
	if err != nil {
		return result, err
	}
	checks := []api.BlobRef{}
	names := map[string]bool{}
	cursor := ""
	for pageNumber := 0; ; pageNumber++ {
		if pageNumber >= 512 {
			return result, wire.Invalid("review check history exceeds its bound")
		}
		page, err := s.deps.Store.Events(ctx, control, api.EventTailRequest{LifeID: target.LifeID, Run: target.Run, Cursor: cursor})
		if err != nil {
			return result, err
		}
		for _, event := range page.Events {
			if event.Kind != "blob.committed" || event.Origin != "service" {
				continue
			}
			var ref api.BlobRef
			if api.DecodeObject(event.Payload, &ref) != nil || ref.Class != "check" {
				continue
			}
			raw, err := s.reviewObject(ctx, control, ref)
			if err != nil {
				return result, err
			}
			var check reviewjob.CheckRecord
			if api.DecodeObject(raw, &check) != nil || check.Schema != "laneboss.check.v2" || check.Target != target ||
				check.EndSeq != subject.EndSeq || check.SnapshotSHA256 != subject.Snapshot.SHA256 {
				continue
			}
			if names[check.Name] {
				return result, serviceError(api.CodeIntegrity, "review has ambiguous measured check outputs")
			}
			names[check.Name] = true
			checks = append(checks, ref)
		}
		if page.Complete {
			break
		}
		if page.Cursor == "" || page.Cursor == cursor {
			return result, wire.Invalid("review history cursor did not advance")
		}
		cursor = page.Cursor
	}
	missing := []string{}
	for _, name := range required {
		if !names[name] {
			missing = append(missing, name)
		}
	}
	return dashboardReviewInputs{Subject: subject, Required: required, Missing: missing, Request: api.ReviewRequest{
		Target: target, Diff: diff, Checks: checks, RecordInventory: inventoryRef, RefusalResolution: []api.ID{}}}, nil
}

func dashboardTreeDiff(base, current api.ObjectManifest, baseHash, currentHash api.Digest) reviewjob.Diff {
	before, after := map[string]api.ObjectEntry{}, map[string]api.ObjectEntry{}
	for _, entry := range base.Entries {
		before[entry.Path] = entry
	}
	for _, entry := range current.Entries {
		if strings.HasPrefix(entry.Path, "work/") {
			entry.Path = strings.TrimPrefix(entry.Path, "work/")
			after[entry.Path] = entry
		}
	}
	paths := map[string]bool{}
	for path := range before {
		paths[path] = true
	}
	for path := range after {
		paths[path] = true
	}
	names := []string{}
	for path := range paths {
		names = append(names, path)
	}
	sort.Strings(names)
	result := reviewjob.Diff{Schema: "laneboss.review-diff.v2", Base: baseHash, Current: currentHash, Changes: []reviewjob.Change{}}
	for _, path := range names {
		a, aok := before[path]
		b, bok := after[path]
		content := func(e api.ObjectEntry) (api.Digest, int64) {
			if e.Content != nil {
				return e.Content.SHA256, e.Content.Bytes
			}
			if e.Assembly != nil {
				return e.Assembly.SHA256, e.Assembly.Bytes
			}
			return "", 0
		}
		ah, as := content(a)
		bh, bs := content(b)
		if aok && bok && a.Kind == b.Kind && a.Mode == b.Mode && a.LinkTarget == b.LinkTarget && ah == bh && as == bs {
			continue
		}
		change := reviewjob.Change{Path: path}
		if aok {
			change.Before = &a
		}
		if bok {
			change.After = &b
		}
		result.Changes = append(result.Changes, change)
	}
	return result
}

func (s *Server) dashboardReviewObject(ctx context.Context, scope api.Scope, ref api.BlobRef) ([]byte, error) {
	if ref.Bytes != 0 {
		return s.reviewObject(ctx, scope, ref)
	}
	chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Limit: 1})
	if err != nil {
		return nil, err
	}
	if chunk.ObjectID != ref.ID || chunk.Offset != 0 || len(chunk.Data) != 0 || chunk.SHA256 != digestBytes(chunk.Data) || ref.SHA256 != chunk.SHA256 {
		return nil, serviceError(api.CodeIntegrity, "empty review object differs from its retained bytes")
	}
	return chunk.Data, nil
}

// The case emits a deliberately narrow provider grammar. Unsupported shapes
// remain partial; the installed writer/verifier independently rechecks them.
func (s *Server) dashboardToolCoverage(ctx context.Context, scope api.Scope, target api.LifeRef, session api.Session, frames []api.CaptureRecord) (string, error) {
	initialized, ended := false, false
	started, finished := map[string]bool{}, map[string]bool{}
	for _, frame := range frames {
		if frame.Target != target || !frame.Primary || frame.Coverage != "complete" {
			return api.CoveragePartial, nil
		}
		raw, err := s.reviewObject(ctx, scope, frame.Data)
		if err != nil {
			return "", err
		}
		var event struct {
			Type    string `json:"type"`
			Subtype string `json:"subtype"`
			Session string `json:"session_id"`
			CWD     string `json:"cwd"`
			Error   *bool  `json:"is_error"`
			Message struct {
				Content []struct {
					Type  string `json:"type"`
					ID    string `json:"id"`
					Name  string `json:"name"`
					UseID string `json:"tool_use_id"`
				} `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal(raw, &event) != nil || ended || session.VendorID == "" || event.Session != session.VendorID {
			return api.CoveragePartial, nil
		}
		switch event.Type {
		case "system":
			if event.Subtype == "init" {
				if initialized || event.CWD != session.LogicalCWD {
					return api.CoveragePartial, nil
				}
				initialized = true
			} else if event.Subtype != "dashboard-fixture" || !initialized {
				return api.CoveragePartial, nil
			}
		case "assistant", "user":
			if !initialized || event.Message.Content == nil {
				return api.CoveragePartial, nil
			}
			for _, block := range event.Message.Content {
				switch block.Type {
				case "tool_use":
					if event.Type != "assistant" || block.ID == "" || block.Name == "" || started[block.ID] {
						return api.CoveragePartial, nil
					}
					started[block.ID] = true
				case "tool_result":
					id := block.UseID
					if event.Type != "user" || !started[id] || finished[id] {
						return api.CoveragePartial, nil
					}
					finished[id] = true
				case "text", "thinking", "redacted_thinking":
				default:
					return api.CoveragePartial, nil
				}
			}
		case "result":
			if !initialized || event.Error == nil {
				return api.CoveragePartial, nil
			}
			ended = true
		default:
			return api.CoveragePartial, nil
		}
	}
	if !initialized || !ended || len(started) != len(finished) {
		return api.CoveragePartial, nil
	}
	return api.CoverageComplete, nil
}
