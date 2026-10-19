package store

import (
	"context"
	"database/sql"
	"sort"
	"strconv"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/approval"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/orgrender"
)

type renderRecord struct {
	Stage  orgrender.Stage
	Result *api.ChangeRequest
	Native *orgrender.Result
}

func (s *Service) BeginRender(ctx context.Context, scope api.Scope, change api.ChangeRequest) (stage orgrender.Stage, cached *api.ChangeRequest, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return stage, nil, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return stage, nil, err
	}
	if scope.Actor != change.Requester || scope.Actor.Kind != "lane" || scope.Actor.Level != 6 || change.Config != s.deps.Config ||
		scope.Request.Method != "org.change.propose" && scope.Request.Method != "org.change.apply" {
		return stage, nil, fault(api.CodeForbidden, "render requires its original authenticated L6 mutation")
	}
	reserved, err := s.lookupReceipt(ctx, s.db, scope, requestKey(scope.Request))
	if err != nil {
		return stage, nil, err
	}
	id := api.ID("render-" + hash([]byte(reserved.Operation.ID))[:28])
	var prior renderRecord
	err = storedProjection(ctx, s.db, "org_render", id, &prior)
	if err == nil {
		if !sameValue(prior.Stage.Change, change) {
			return stage, nil, fault(api.CodeIdempotencyConflict, "render retry changed its original source inputs")
		}
		if prior.Result != nil {
			return prior.Stage, prior.Result, nil
		}
		if future(prior.Stage.Deadline, s.deps.Clock.Now()) {
			return stage, nil, fault(api.CodeUnavailable, "original render claim is still executing")
		}
		stage = prior.Stage
		stage.Generation++
	} else if !absent(err) {
		return stage, nil, err
	} else {
		var snapshot api.OrgSnapshot
		if err := storedProjection(ctx, s.db, "org", change.OrgID, &snapshot); err != nil {
			return stage, nil, err
		}
		if snapshot.Ref != change.SourceSnapshot || snapshot.Renderer != change.Renderer || snapshot.OwnershipManifest != change.OwnershipManifest {
			return stage, nil, fault(api.CodeConflict, "render base differs from the approved source snapshot")
		}
		if err := changeDeltas(snapshot, change); err != nil {
			return stage, nil, err
		}
		var launch api.LaunchRecord
		if err := storedProjection(ctx, s.db, "launch", scope.LaunchID, &launch); err != nil {
			return stage, nil, err
		}
		stage = orgrender.Stage{ID: id, OperationID: reserved.Operation.ID, Generation: 1, ParentLeaseID: launch.UIDLeaseID, Target: launch.Target, Change: change, Snapshot: snapshot,
			ObservedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano)), Sources: []orgrender.File{}, Derived: []orgrender.File{}}
		groups := [2]map[string]orgrender.File{{}, {}}
		for i, files := range [][]api.ResourceFile{snapshot.Sources, snapshot.Derived} {
			for _, file := range files {
				meta, raw, err := objectRow(ctx, s.db, file.Content.ID)
				if err != nil {
					return stage, nil, err
				}
				if meta.Ref != file.Content {
					return stage, nil, fault(api.CodeIntegrity, "render source differs from its committed object")
				}
				groups[i][file.Source.Path] = orgrender.File{Path: file.Source.Path, Mode: file.Mode, Data: raw}
				if i == 0 {
					stage.Before = append(stage.Before, groups[i][file.Source.Path])
				}
			}
		}
		for _, delta := range change.Files {
			if delta.Action == "delete" {
				delete(groups[0], delta.Path)
				continue
			}
			if delta.After == nil {
				return stage, nil, wire.Invalid("render source delta omitted its after bytes")
			}
			meta, raw, err := objectRow(ctx, s.db, delta.After.ID)
			if err != nil {
				return stage, nil, err
			}
			if meta.Ref != *delta.After {
				return stage, nil, fault(api.CodeIntegrity, "render after bytes differ from their committed object")
			}
			groups[0][delta.Path] = orgrender.File{Path: delta.Path, Mode: delta.Mode, Data: raw}
		}
		for _, file := range groups[0] {
			stage.Sources = append(stage.Sources, file)
		}
		for _, file := range groups[1] {
			stage.Derived = append(stage.Derived, file)
		}
		sort.Slice(stage.Sources, func(i, j int) bool { return stage.Sources[i].Path < stage.Sources[j].Path })
		sort.Slice(stage.Derived, func(i, j int) bool { return stage.Derived[i].Path < stage.Derived[j].Path })
	}
	stage.ClaimID, err = wire.NewID()
	if err != nil {
		return stage, nil, err
	}
	stage.Deadline = api.Timestamp(s.deps.Clock.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return stage, nil, err
	}
	defer finish(tx, &resultErr)
	if err := put(ctx, tx, "org_render", stage.ID, stage.Generation, renderRecord{Stage: stage}); err != nil {
		return stage, nil, err
	}
	if err := tx.Commit(); err != nil {
		return stage, nil, err
	}
	return stage, nil, nil
}

func (s *Service) FinishRender(ctx context.Context, scope api.Scope, stage orgrender.Stage, output orgrender.Result) (change api.ChangeRequest, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return change, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return change, err
	}
	var saved renderRecord
	if err := storedProjection(ctx, s.db, "org_render", stage.ID, &saved); err != nil {
		return change, err
	}
	if !sameValue(saved.Stage, stage) || scope.Actor != stage.Change.Requester || !future(stage.Deadline, s.deps.Clock.Now()) ||
		output.JobID != stage.ID || output.ClaimID != stage.ClaimID || output.Generation != stage.Generation || output.InputSHA256 != orgrender.Digest(stage) || output.Renderer != stage.Change.Renderer || output.PID <= 1 || output.Files == nil {
		return change, fault(api.CodeConflict, "render output lost its original live claim or pinned inputs")
	}
	if saved.Result != nil {
		return *saved.Result, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return change, err
	}
	defer finish(tx, &resultErr)
	change = stage.Change
	change.Derived = []api.ResourceDelta{}
	before := map[string]api.ResourceFile{}
	sources, seen := map[string]bool{}, map[string]bool{}
	for _, file := range stage.Sources {
		sources[file.Path] = true
	}
	for _, file := range stage.Snapshot.Derived {
		before[file.Source.Path] = file
	}
	for _, file := range output.Files {
		if manifest.Relative(file.Path) != nil || file.Path == "." || sources[file.Path] || seen[file.Path] || file.Mode & ^uint32(0777) != 0 {
			return change, wire.Invalid("invalid or overlapping generated render file")
		}
		seen[file.Path] = true
		old, exists := before[file.Path]
		delete(before, file.Path)
		if exists && old.Content.SHA256 == api.Digest(hash(file.Data)) && old.Mode == file.Mode {
			continue
		}
		ref, err := s.renderObject(ctx, tx, scope, stage, file.Data)
		if err != nil {
			return change, err
		}
		delta := api.ResourceDelta{Path: file.Path, Mode: file.Mode, Action: "add", After: &ref}
		if exists {
			delta.Action, delta.BeforeSHA256 = "replace", old.Content.SHA256
		}
		change.Derived = append(change.Derived, delta)
	}
	for name, file := range before {
		change.Derived = append(change.Derived, api.ResourceDelta{Path: name, Action: "delete", Mode: file.Mode, BeforeSHA256: file.Content.SHA256})
	}
	sort.Slice(change.Derived, func(i, j int) bool { return change.Derived[i].Path < change.Derived[j].Path })
	// This review document contains the actual before/after byte inventories,
	// rather than a receipt or renderer claim standing in for the source diff.
	review := renderReview(append(append([]orgrender.File{}, stage.Derived...), stage.Before...), append(append([]orgrender.File{}, stage.Sources...), output.Files...))
	change.Diff, err = s.renderObject(ctx, tx, scope, stage, review)
	if err != nil {
		return change, err
	}
	change.ManifestSHA256, err = approval.ManifestDigest(change)
	if err != nil {
		return change, err
	}
	if err := approval.ValidateRenderedChange(stage.Change, change); err != nil {
		return change, err
	}
	saved.Result, saved.Native = &change, &output
	if err := put(ctx, tx, "org_render", stage.ID, stage.Generation+1, saved); err != nil {
		return change, err
	}
	if err := tx.Commit(); err != nil {
		return change, err
	}
	return change, nil
}

func renderReview(before, after []orgrender.File) []byte {
	var text strings.Builder
	for i, files := range [][]orgrender.File{before, after} {
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		for _, file := range files {
			text.WriteString([]string{"--- before ", "+++ after "}[i] + file.Path + " mode " + strconv.FormatUint(uint64(file.Mode), 8) + "\n")
			text.Write(file.Data)
			text.WriteString("\n")
		}
	}
	return []byte(text.String())
}

func (s *Service) renderObject(ctx context.Context, tx *sql.Tx, scope api.Scope, stage orgrender.Stage, raw []byte) (api.BlobRef, error) {
	id, err := wire.NewID()
	if err != nil {
		return api.BlobRef{}, err
	}
	return s.retain(ctx, tx, api.Scope{Config: scope.Config, Actor: api.Actor{Kind: "service", ID: "lb-v2-grants"}}, api.ObjectWrite{ObjectKey: id, Class: "artifact", Bytes: raw, SHA256: api.Digest(hash(raw)), Origin: "service",
		ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, LifeID: scope.Actor.LifeID, Audience: "config", Generation: 1}}, stage.OperationID, api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano)))
}
