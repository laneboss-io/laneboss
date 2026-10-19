package admin

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This file-backed component writer applies actual supplied writes and a CAS.
// It is not SQLite, a native endpoint or installed-service acceptance evidence.
type initialDisk struct {
	Snapshot  api.OrgSnapshot
	Policy    api.EffectivePolicy
	Objects   map[api.ID][]byte
	Metadata  map[api.ID]api.ObjectMetadata
	Operation api.Operation
	Events    []api.Event
}
type initialTestStore struct {
	api.StateStore
	path  string
	calls int
}

func (s *initialTestStore) load() (initialDisk, error) {
	var disk initialDisk
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return initialDisk{Objects: map[api.ID][]byte{}, Metadata: map[api.ID]api.ObjectMetadata{}, Events: []api.Event{}}, nil
	}
	if err != nil {
		return disk, err
	}
	err = json.Unmarshal(raw, &disk)
	return disk, err
}
func (s *initialTestStore) CommitInitial(ctx context.Context, tx api.Transaction) (api.Commit, error) {
	s.calls++
	if err := VerifyInitialTransaction(ctx, tx); err != nil {
		return api.Commit{}, err
	}
	if err := api.ValidateTransactionShape(tx); err != nil {
		return api.Commit{}, err
	}
	disk, err := s.load()
	if err != nil {
		return api.Commit{}, err
	}
	want := []api.Compare{{Kind: api.CompareOrg, ID: api.ID(tx.Scope.Config), Generation: disk.Snapshot.Ref.Generation}}
	if disk.Snapshot.Ref.Generation != 0 || !reflect.DeepEqual(tx.Compare, want) {
		return api.Commit{}, failure(api.CodeConflict, "component empty-org compare failed")
	}
	if len(tx.Writes.OrgSnapshots) != 1 || tx.Writes.Policy == nil || len(tx.Events) != 1 {
		return api.Commit{}, failure(api.CodeInvalid, "component initial writes missing")
	}
	disk.Snapshot, disk.Policy = tx.Writes.OrgSnapshots[0], *tx.Writes.Policy
	now := api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	for _, write := range tx.Writes.Objects {
		if _, exists := disk.Objects[write.ObjectKey]; exists || digestBytes(write.Bytes) != write.SHA256 {
			return api.Commit{}, failure(api.CodeIntegrity, "component object is not immutable")
		}
		ref := api.BlobRef{ID: write.ObjectKey, Class: write.Class, Bytes: int64(len(write.Bytes)), SHA256: write.SHA256}
		disk.Objects[ref.ID] = append([]byte{}, write.Bytes...)
		disk.Metadata[ref.ID] = api.ObjectMetadata{Ref: ref, ACL: write.ACL, Origin: write.Origin, SourceOperationID: tx.Internal.CauseOperationID, CommittedAt: now}
	}
	for _, event := range tx.Events {
		event.Seq = api.Sequence(len(disk.Events) + 1)
		event.OperationID = tx.Internal.CauseOperationID
		event.RecordedAt = now
		disk.Events = append(disk.Events, event)
	}
	disk.Operation = api.Operation{ID: tx.Internal.CauseOperationID, Status: "succeeded", FirstSeq: disk.Events[0].Seq, LastSeq: disk.Events[len(disk.Events)-1].Seq}
	raw, err := json.Marshal(disk)
	if err != nil {
		return api.Commit{}, err
	}
	file, err := os.CreateTemp(filepath.Dir(s.path), "initial-")
	if err != nil {
		return api.Commit{}, err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return api.Commit{}, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return api.Commit{}, err
	}
	if err := file.Close(); err != nil {
		return api.Commit{}, err
	}
	if err := os.Rename(file.Name(), s.path); err != nil {
		return api.Commit{}, err
	}
	return api.Commit{Operation: disk.Operation, FirstSeq: disk.Operation.FirstSeq, LastSeq: disk.Operation.LastSeq}, nil
}
func (s *initialTestStore) ObjectMetadata(_ context.Context, _ api.Scope, id api.ID) (api.ObjectMetadata, error) {
	disk, err := s.load()
	if err != nil {
		return api.ObjectMetadata{}, err
	}
	m, ok := disk.Metadata[id]
	if !ok {
		return m, failure(api.CodeNotFound, "component object absent")
	}
	return m, nil
}
func (s *initialTestStore) Blob(_ context.Context, _ api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	disk, err := s.load()
	if err != nil {
		return api.BlobChunk{}, err
	}
	raw, ok := disk.Objects[request.ObjectID]
	if !ok || request.Offset < 0 || request.Offset >= int64(len(raw)) || request.Limit <= 0 {
		return api.BlobChunk{}, failure(api.CodeNotFound, "component range absent")
	}
	part := append([]byte{}, raw[request.Offset:min(int64(len(raw)), request.Offset+int64(request.Limit))]...)
	return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: part, SHA256: digestBytes(part)}, nil
}
func (s *initialTestStore) Operation(_ context.Context, _ api.Scope, id api.ID) (api.Operation, error) {
	disk, err := s.load()
	if err == nil && disk.Operation.ID != id {
		err = failure(api.CodeNotFound, "component operation absent")
	}
	return disk.Operation, err
}
func (s *initialTestStore) Events(_ context.Context, _ api.Scope, request api.EventTailRequest) (api.EventPage, error) {
	disk, err := s.load()
	page := api.EventPage{Events: []api.Event{}, Complete: true}
	for _, e := range disk.Events {
		if e.Seq > request.Since {
			page.Events = append(page.Events, e)
		}
	}
	return page, err
}
func (s *initialTestStore) OrgSnapshot(_ context.Context, _ api.Scope, request api.OrgSnapshotRequest) (api.OrgSnapshot, error) {
	disk, err := s.load()
	if err == nil && (disk.Snapshot.Ref.OrgID != request.OrgID || disk.Snapshot.Ref.Generation != request.Generation) {
		err = failure(api.CodeNotFound, "component snapshot absent")
	}
	return disk.Snapshot, err
}
func (s *initialTestStore) Policy(context.Context, api.Scope) (api.EffectivePolicy, error) {
	disk, err := s.load()
	return disk.Policy, err
}

func initialEncode(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func initialFixture(t *testing.T) initialBundle {
	t.Helper()
	objects := map[api.ID][]byte{}
	refs := []api.BlobRef{}
	add := func(id api.ID, class string, raw []byte) api.BlobRef {
		r := api.BlobRef{ID: id, Class: class, Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
		objects[id] = raw
		refs = append(refs, r)
		return r
	}
	l5 := api.RoleContext{Level: 5, Role: "coordinator"}
	executableBytes := []byte("component executable bytes; never executed")
	executableRef := add("binary-content", "artifact", executableBytes)
	executable := api.Executable{ID: "component-tool", SHA256: executableRef.SHA256, Version: "component-v1"}
	runtime := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: executable, Bootstrap: executable, Objects: []api.RuntimeObject{{ID: executable.ID, Role: "artifact", RootID: "runtime", RelativePath: "tool", Content: executableRef, Mode: 0555}}, Bindings: []api.InstalledBinding{}}
	runtimeRef := add("runtime", "manifest", initialEncode(t, runtime))
	project := add("project", "manifest", initialEncode(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}))
	launch := api.LaunchEnrollment{Schema: "laneboss.launch-enrollment.v2", Config: "admin-case", Generation: 1, Projects: []api.ProjectEnrollment{{ID: "project-enrollment", Generation: 1, ProjectID: "demo", Object: project, Base: string(digestBytes([]byte("component base"))), HistoryScope: "tree"}}, Runtimes: []api.LaunchRuntime{{EnrollmentID: "runtime-enrollment", Generation: 1, Backend: "linux-bwrap-landlock", Driver: api.DriverCodex, Executable: executable, Manifest: runtimeRef}}}
	launchRef := add("launch", "manifest", initialEncode(t, launch))
	sources := []api.ResourceFile{}
	entries := []api.ObjectEntry{}
	for _, kind := range []string{"prompt", "drivers", "policy"} {
		r := add(api.ID(kind+"-bytes"), "artifact", []byte("explicit component "+kind+" source"))
		s := api.SourceRef{ID: api.ID(kind + "-source"), Path: kind + ".md", SHA256: r.SHA256, Generation: 1}
		sources = append(sources, api.ResourceFile{Source: s, Content: r, Kind: kind, Mode: 0444, RevisionGeneration: 1})
		copy := r
		entries = append(entries, api.ObjectEntry{Path: s.Path, Kind: "file", Mode: 0444, Content: &copy})
	}
	sourceManifest := add("source-manifest", "manifest", initialEncode(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: entries}))
	ownership := add("ownership", "manifest", initialEncode(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}))
	snapshot := api.OrgSnapshot{Ref: api.OrgSnapshotRef{OrgID: "admin-case", Generation: 1, ManifestSHA256: sourceManifest.SHA256}, Config: "admin-case", Sources: sources, Derived: []api.ResourceFile{}, Renderer: executable, OwnershipManifest: ownership}
	snapshotRef := add("sources", "manifest", initialEncode(t, snapshot))
	policy := api.EffectivePolicy{Generation: 1, Context: l5, Rules: []api.Rule{{ID: "rule-a", Text: "explicit deny", Instead: "retain evidence", Band: "refuse", Scope: api.RuleScope{Levels: []int{5}, Roles: []string{"coordinator"}}, Source: sources[2].Source, Thresholds: api.Thresholds{Match: 0.9, UncertainLow: 0.4, UncertainHigh: 0.8, CalibrationID: "calibration"}}}, Skip: []api.SkipEntry{}, Sources: []api.SourceRef{sources[2].Source}, GuidanceSource: sources[2].Source, GuidanceMinRelevance: 0.5, GuidanceHalfLifeSeconds: 3600, ProfileExclusions: []api.ID{}, Judge: api.JudgeConfig{Provider: api.DefaultJudgeProvider, Model: api.DefaultJudgeModel, DeploymentSHA256: digestBytes([]byte("deployment")), TokenizerSHA256: digestBytes([]byte("tokenizer")), ContextTokens: 1024, MaxBytes: 4096, MaxQuestions: 12, CommandDeadlineMS: 1000, GuidanceDeadlineMS: 1000, CacheTTLMS: 100, OutagePolicy: "critical-only"}}
	policy.SHA256 = digestBytes(initialEncode(t, policy))
	policyRef := add("policy", "manifest", initialEncode(t, policy))
	profiles := api.RootGrantManifest{Schema: "laneboss.root-grants.v2", Resources: []api.ResourceGrant{}, Data: []api.DataGrant{}, Secrets: []api.SecretGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}, Profiles: []api.ProfileGrant{{ProfileID: "profile", Driver: api.DriverCodex, Provider: "component-provider", ExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))}}}
	profileRef := add("profiles", "manifest", initialEncode(t, profiles))
	task := add("task", "task", []byte("explicit L5 task"))
	m := InitialManifest{Schema: "laneboss.initial.v2", Config: "admin-case", ID: "publication", Generation: 1, Runtime: runtimeRef, Launch: launchRef, Policy: policyRef, Sources: snapshotRef, SourceManifest: sourceManifest, Profiles: profileRef, Task: task, L5: l5, L5Sources: api.RoleTemplateSources{Prompt: api.TemplateSource{Source: sources[0].Source, Content: sources[0].Content}, Drivers: api.TemplateSource{Source: sources[1].Source, Content: sources[1].Content}}, Objects: refs}
	raw := initialEncode(t, m)
	ref := api.BlobRef{ID: "initial", Class: "manifest", SHA256: digestBytes(raw), Bytes: int64(len(raw))}
	b, err := validateInitial(ref, raw, objects, "admin-case")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
