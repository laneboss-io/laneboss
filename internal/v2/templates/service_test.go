package templates_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/templates"
)

// These are in-memory dependency fixtures for component tests. They are never
// wired into production, and are not evidence for socket or lifecycle E2E.
// Unexpected methods on the embedded interfaces panic rather than succeed.
type memoryStore struct {
	api.StateStore
	input            templates.RenderInput
	blobs            map[api.ID][]byte
	metadata         map[api.ID]api.ObjectMetadata
	snapshot         api.OrgSnapshot
	selection        api.TemplateSources
	blobError        error
	inputError       error
	orgError         error
	changeSnapshot   func(*api.OrgSnapshot)
	targetError      error
	retainError      error
	changeChunk      func(*api.BlobChunk)
	changeInput      func(*api.BriefingInput)
	changeMeta       func(*api.ObjectMetadata)
	changeSource     func(*api.RetainedSource)
	changeRetain     func(*api.BlobRef)
	changeReceipt    func(*api.MutationReceipt)
	lifecycleService *api.Actor
	plan             api.LaunchPlanRecord
	planning         []api.Effect
	claim            api.EffectRecord
	planCalls        int
	snapshotRequests []api.OrgSnapshotRequest
	laneRequests     []api.LifeRef
	inputRequests    []api.BriefingInputRequest
	orgRequests      []api.OrgSnapshotRequest
	sourceCalls      int
	metadataCalls    int
	receiptCalls     int
	reads            []api.BlobReadRequest
	writes           int
	retained         []api.RetainObjectRequest
	transactions     []api.Transaction
	allowBootstrap   bool
	reservation      api.MutationReceipt
	proof            api.VerifiedHumanProof
	target           api.HumanChallengeRequest
	transactionError error
	changeCommit     func(*api.Commit)
	sequence         api.Sequence
}

func (s *memoryStore) put(ref api.BlobRef, data []byte) {
	s.blobs[ref.ID] = bytes.Clone(data)
	s.metadata[ref.ID] = api.ObjectMetadata{Ref: ref,
		ACL: api.ObjectACL{Config: s.input.Config, Generation: 1, Audience: "config",
			Owner: api.Actor{Kind: "service", ID: "fixture-service"}},
		Origin: "fixture", CommittedAt: "2030-01-01T00:00:00Z"}
}

func (s *memoryStore) ObjectMetadata(_ context.Context, _ api.Scope, id api.ID) (api.ObjectMetadata, error) {
	s.metadataCalls++
	value, ok := s.metadata[id]
	if !ok {
		return api.ObjectMetadata{}, &api.Error{Code: api.CodeNotFound, Message: "fixture metadata absent", Instead: "Use a committed fixture object."}
	}
	if s.changeMeta != nil {
		s.changeMeta(&value)
	}
	return value, nil
}

func (s *memoryStore) OrgSnapshot(_ context.Context, _ api.Scope, request api.OrgSnapshotRequest) (api.OrgSnapshot, error) {
	s.orgRequests = append(s.orgRequests, request)
	s.snapshotRequests = append(s.snapshotRequests, request)
	if s.orgError != nil {
		return api.OrgSnapshot{}, s.orgError
	}
	if request.OrgID != "" && request.OrgID != s.snapshot.Ref.OrgID {
		return api.OrgSnapshot{}, &api.Error{Code: api.CodeNotFound, Message: "fixture org absent", Instead: "Use the fixture org."}
	}
	snapshot := s.snapshot
	if s.changeSnapshot != nil {
		s.changeSnapshot(&snapshot)
	}
	return snapshot, nil
}

func (s *memoryStore) TemplateSources(_ context.Context, _ api.Scope, request api.TemplateSourceRequest) (api.TemplateSources, error) {
	if request.OrgID != s.snapshot.Ref.OrgID || request.Generation != s.snapshot.Ref.Generation || request.Context != s.selection.Context {
		return api.TemplateSources{}, &api.Error{Code: api.CodeConflict, Message: "fixture role selection differs", Instead: "Use the fixture snapshot and role."}
	}
	return s.selection, nil
}

func (s *memoryStore) Source(_ context.Context, _ api.Scope, ref api.SourceRef) (api.RetainedSource, error) {
	s.sourceCalls++
	for _, file := range s.snapshot.Sources {
		if file.Source == ref {
			value := api.RetainedSource{Source: file.Source, Content: file.Content}
			if s.changeSource != nil {
				s.changeSource(&value)
			}
			return value, nil
		}
	}
	return api.RetainedSource{}, &api.Error{Code: api.CodeNotFound, Message: "fixture source absent", Instead: "Use the fixture source identity."}
}

func (s *memoryStore) BriefingInput(_ context.Context, _ api.Scope, request api.BriefingInputRequest) (api.BriefingInput, error) {
	s.inputRequests = append(s.inputRequests, request)
	if s.inputError != nil {
		return api.BriefingInput{}, s.inputError
	}
	if request.LifeID != "" && request.LifeID != s.input.Lane.LifeID ||
		request.GrantSetID != "" && request.GrantSetID != s.input.Grants.ID {
		return api.BriefingInput{}, &api.Error{Code: api.CodeNotFound, Message: "fixture briefing absent", Instead: "Use the fixture life."}
	}
	lane, grants, task := s.input.Lane, s.input.Grants, s.input.Task
	value := api.BriefingInput{Mode: "lane", Lane: &lane, GrantSet: &grants, Task: &task,
		Policy: s.input.Policy, Sources: s.selection,
		Groups: api.LaneGroups{Ended: []api.ID{lane.LifeID}},
		Checks: []api.Capability{{Name: "fixture-inputs", Available: true}}}
	if s.changeInput != nil {
		s.changeInput(&value)
	}
	return value, nil
}

func (s *memoryStore) RetainObject(_ context.Context, _ api.Scope, request api.RetainObjectRequest) (api.BlobRef, error) {
	if s.retainError != nil {
		return api.BlobRef{}, s.retainError
	}
	if request.Object.Class != "prompt" || request.Object.SHA256 != digest(request.Object.Bytes) {
		return api.BlobRef{}, errors.New("invalid fixture retention request")
	}
	ref := api.BlobRef{ID: request.Object.ObjectKey, Class: request.Object.Class,
		Bytes: int64(len(request.Object.Bytes)), SHA256: request.Object.SHA256}
	for _, earlier := range s.retained {
		if earlier.Object.ObjectKey == request.Object.ObjectKey && !reflect.DeepEqual(earlier.Object, request.Object) {
			return api.BlobRef{}, &api.Error{Code: api.CodeIntegrity, Message: "fixture object key conflicts with retained bytes or ACL", Instead: "Use the exact immutable object identity."}
		}
	}
	if metadata, exists := s.metadata[ref.ID]; exists {
		if metadata.Ref != ref || !bytes.Equal(s.blobs[ref.ID], request.Object.Bytes) || !reflect.DeepEqual(metadata.ACL, request.Object.ACL) {
			return api.BlobRef{}, &api.Error{Code: api.CodeIntegrity, Message: "fixture retained key conflicts with an existing object", Instead: "Preserve immutable object bytes and ACL."}
		}
	} else {
		s.put(ref, request.Object.Bytes)
		metadata := s.metadata[ref.ID]
		metadata.ACL, metadata.Origin = request.Object.ACL, request.Object.Origin
		metadata.SourceOperationID = request.Intent.CauseOperationID
		s.metadata[ref.ID] = metadata
	}
	s.retained = append(s.retained, request)
	if s.changeRetain != nil {
		s.changeRetain(&ref)
	}
	return ref, nil
}

func (s *memoryStore) Grants(_ context.Context, id api.ID) (api.GrantSet, error) {
	if id != s.input.Grants.ID {
		return api.GrantSet{}, &api.Error{Code: api.CodeNotFound, Message: "fixture grant absent", Instead: "Use the fixture grant."}
	}
	return s.input.Grants, nil
}

func (s *memoryStore) Lane(_ context.Context, _ api.Scope, target api.LifeRef) (api.Lane, error) {
	s.laneRequests = append(s.laneRequests, target)
	if target.LifeID != s.input.Lane.LifeID {
		return api.Lane{}, &api.Error{Code: api.CodeNotFound, Message: "fixture lane absent", Instead: "Use the fixture life."}
	}
	return s.input.Lane, nil
}

func (s *memoryStore) Blob(_ context.Context, _ api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	s.reads = append(s.reads, request)
	if s.blobError != nil {
		return api.BlobChunk{}, s.blobError
	}
	data, exists := s.blobs[request.ObjectID]
	if !exists || request.Offset < 0 || request.Offset > int64(len(data)) || request.Limit <= 0 || request.Limit > api.MaxChunkBytes {
		return api.BlobChunk{}, &api.Error{Code: api.CodeNotFound, Message: "fixture chunk absent", Instead: "Read a committed fixture object."}
	}
	end := min(int(request.Offset)+request.Limit, len(data))
	row := api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset,
		Data: bytes.Clone(data[int(request.Offset):end]), SHA256: digest(data[int(request.Offset):end])}
	if s.changeChunk != nil {
		s.changeChunk(&row)
	}
	return row, nil
}

func (s *memoryStore) Transact(_ context.Context, transaction api.Transaction) (api.Commit, error) {
	s.writes++
	s.transactions = append(s.transactions, transaction)
	if s.transactionError != nil {
		return api.Commit{}, s.transactionError
	}
	if s.allowBootstrap {
		if err := api.ValidateTransactionShape(transaction); err != nil {
			return api.Commit{}, err
		}
		operation := s.reservation.Operation
		var submitted api.Operation
		if transaction.Reply == nil || json.Unmarshal(transaction.Reply.Result, &submitted) != nil || submitted.ID != operation.ID {
			return api.Commit{}, errors.New("fixture bootstrap omitted its submitted operation")
		}
		operation.SimulatedPresence = submitted.SimulatedPresence
		s.sequence++
		operation.FirstSeq, operation.LastSeq = s.sequence, s.sequence
		reply, err := json.Marshal(operation)
		if err != nil {
			return api.Commit{}, err
		}
		s.reservation.Operation, s.reservation.Reply = operation, &api.RPCReply{Result: reply}
		s.reservation.SimulatedPresence = operation.SimulatedPresence
		commit := api.Commit{Operation: operation, Reply: s.reservation.Reply, FirstSeq: s.sequence, LastSeq: s.sequence}
		if s.changeCommit != nil {
			s.changeCommit(&commit)
		}
		return commit, nil
	}
	return api.Commit{}, &api.Error{Code: api.CodeForbidden, Message: "read-only fixture", Instead: "Do not mutate while briefing."}
}

type memoryPolicy struct {
	api.PolicyAPI
	input      templates.RenderInput
	failure    error
	validation api.OrgValidation
	calls      int
}

func (p *memoryPolicy) PolicyGet(_ context.Context, _ api.Scope, request api.PolicyGetRequest) (api.EffectivePolicy, error) {
	p.calls++
	if p.failure != nil {
		return api.EffectivePolicy{}, p.failure
	}
	if request.LifeID != "" && request.LifeID != p.input.Lane.LifeID {
		return api.EffectivePolicy{}, &api.Error{Code: api.CodeNotFound, Message: "fixture policy absent", Instead: "Use the fixture life."}
	}
	return p.input.Policy, nil
}

func (p *memoryPolicy) ConfigRead(_ context.Context, _ api.Scope, request api.ConfigReadRequest) (api.ConfigView, error) {
	if p.failure != nil {
		return api.ConfigView{}, p.failure
	}
	if request.View != "roles" {
		return api.ConfigView{}, &api.Error{Code: api.CodeInvalid, Message: "wrong fixture view", Instead: "Read roles."}
	}
	return api.ConfigView{Generation: 7}, nil
}

func (p *memoryPolicy) ConfigValidate(_ context.Context, _ api.Scope, _ api.Empty) (api.OrgValidation, error) {
	if p.failure != nil {
		return api.OrgValidation{}, p.failure
	}
	return p.validation, nil
}

func component(t *testing.T) (*templates.Service, *memoryStore, *memoryPolicy, api.Scope, api.TemplateRequest) {
	t.Helper()
	input := fixture(t)
	input.Lane.Task, input.Lane.Run = input.Task, 1
	store := &memoryStore{input: input, blobs: map[api.ID][]byte{}, metadata: map[api.ID]api.ObjectMetadata{}}
	store.put(input.Task, input.TaskBytes)
	pair := layers(t)
	store.snapshot = api.OrgSnapshot{Config: input.Config,
		Ref:      api.OrgSnapshotRef{OrgID: api.ID(input.Config), Generation: 7, ManifestSHA256: digest([]byte("fixture manifest"))},
		Derived:  []api.ResourceFile{},
		Renderer: api.Executable{ID: "renderer-one", SHA256: digest([]byte("renderer")), Version: "fixture-v2"}}
	for _, item := range append(input.Role.RetainedSources(), source("org-workflow", templates.WorkflowPath, asset(t, "org", "workflow.toml"))) {
		ref := api.BlobRef{ID: api.ID("content-" + string(item.Ref.ID)), Class: "policy", Bytes: int64(len(item.Bytes)), SHA256: item.Ref.SHA256}
		store.put(ref, item.Bytes)
		kind := "prompt"
		if item.Ref.Path == templates.WorkflowPath {
			kind = "policy"
		} else if strings.HasSuffix(item.Ref.Path, ".toml") {
			kind = "drivers"
		}
		store.snapshot.Sources = append(store.snapshot.Sources, api.ResourceFile{Source: item.Ref, Content: ref,
			Kind: kind, Mode: 0644, RevisionGeneration: 2})
	}
	generated := []byte("# Generated fixture rules\nRetained generated bytes.\n")
	generatedRef := api.BlobRef{ID: "generated-content", Class: "artifact", Bytes: int64(len(generated)), SHA256: digest(generated)}
	store.put(generatedRef, generated)
	store.snapshot.Derived = []api.ResourceFile{{Source: api.SourceRef{ID: "generated-source", Path: ".laneboss/generated/rules.md", SHA256: generatedRef.SHA256, Generation: 7},
		Content: generatedRef, Kind: "file", Mode: 0644, RevisionGeneration: 2}}
	ownership := []byte("fixture retained ownership inventory")
	derived := []byte("fixture rendered org output")
	derivedRef := api.BlobRef{ID: "derived-content", Class: "artifact", Bytes: int64(len(derived)), SHA256: digest(derived)}
	store.put(derivedRef, derived)
	store.snapshot.Derived = []api.ResourceFile{{Kind: "file", Mode: 0644, RevisionGeneration: 2,
		Source: api.SourceRef{ID: "derived-output", Path: "generated/rules.md", Generation: 7, SHA256: derivedRef.SHA256}, Content: derivedRef}}
	store.snapshot.OwnershipManifest = api.BlobRef{ID: "ownership-one", Class: "manifest", Bytes: int64(len(ownership)), SHA256: digest(ownership)}
	store.put(store.snapshot.OwnershipManifest, ownership)
	selectSource := func(ref api.SourceRef) api.TemplateSource {
		for _, file := range store.snapshot.Sources {
			if file.Source == ref {
				return api.TemplateSource{Source: ref, Content: file.Content}
			}
		}
		t.Fatal("fixture selection has no retained source")
		return api.TemplateSource{}
	}
	store.selection = api.TemplateSources{Snapshot: store.snapshot.Ref, Context: input.Policy.Context, LocalStatus: "present",
		Org:   api.RoleTemplateSources{Prompt: selectSource(pair.Org.Ref), Drivers: selectSource(pair.OrgDrivers.Ref)},
		Local: &api.RoleTemplateSources{Prompt: selectSource(pair.Local.Ref), Drivers: selectSource(pair.Drivers.Ref)}}
	policy := &memoryPolicy{input: input, validation: api.OrgValidation{Valid: true, Problems: []string{}}}
	service, err := templates.New(templates.Dependencies{Store: store, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	scope := api.Scope{Config: input.Config, PolicyGeneration: input.Policy.Generation,
		Actor: api.Actor{Kind: "lane", ID: "actor-one", LifeID: input.Lane.LifeID, Level: input.Lane.Level, Role: input.Lane.Role}}
	request := api.TemplateRequest{Context: input.Policy.Context, Task: input.Task, GrantSetID: input.Grants.ID}
	params, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request, err = client.PrepareRequest(api.Request{Config: scope.Config, Method: "brief.render", Params: params})
	if err != nil {
		t.Fatal(err)
	}
	return service, store, policy, scope, request
}

func TestDependenciesAndReadFailures(t *testing.T) {
	_, err := templates.New(templates.Dependencies{})
	errorCode(t, err, api.CodePrerequisite)
	service, store, _, scope, request := component(t)
	failure := &api.Error{Code: api.CodeUnavailable, Message: "fixture dependency unavailable", Instead: "Repair the fixture dependency.", Owner: "lb-v2-policy"}
	store.inputError = failure
	result, err := service.BriefRender(context.Background(), scope, request)
	if !errors.Is(err, failure) || result.Markdown.ID != "" {
		t.Fatal("policy failure was swallowed or converted into a briefing")
	}
	store.inputError = nil
	store.blobError = failure
	result, err = service.BriefRender(context.Background(), scope, request)
	if !errors.Is(err, failure) || result.Markdown.ID != "" {
		t.Fatal("blob failure was swallowed or converted into a briefing")
	}
	if store.writes != 0 {
		t.Fatal("brief render changed authoritative state")
	}
}

func TestServiceScopesCannotWiden(t *testing.T) {
	for _, row := range []struct {
		name   string
		change func(*api.Scope, *api.TemplateRequest, *memoryStore)
		code   api.ErrorCode
	}{
		{"binding", func(s *api.Scope, _ *api.TemplateRequest, _ *memoryStore) { s.Request.Config = "another-config" }, api.CodeForbidden},
		{"role", func(_ *api.Scope, r *api.TemplateRequest, _ *memoryStore) { r.Context.Role = "supervisor" }, api.CodeForbidden},
		{"level", func(_ *api.Scope, r *api.TemplateRequest, _ *memoryStore) { r.Context.Level = 6 }, api.CodeForbidden},
		{"sibling", func(_ *api.Scope, _ *api.TemplateRequest, s *memoryStore) { s.input.Grants.LifeID = "life-sibling" }, api.CodeForbidden},
	} {
		t.Run(row.name, func(t *testing.T) {
			service, store, _, scope, request := component(t)
			row.change(&scope, &request, store)
			result, err := service.BriefRender(context.Background(), scope, request)
			errorCode(t, err, row.code)
			if result.Markdown.ID != "" || len(store.reads) != 0 || store.writes != 0 {
				t.Fatal("refused scope reached task bytes or mutated state")
			}
		})
	}
}

func TestBlobIntegrityAndNoFakePrompt(t *testing.T) {
	for _, row := range []struct {
		name   string
		change func(*api.BlobChunk)
	}{
		{"offset", func(c *api.BlobChunk) { c.Offset++ }},
		{"object", func(c *api.BlobChunk) { c.ObjectID = "wrong-object" }},
		{"hash", func(c *api.BlobChunk) {
			if len(c.Data) != 0 {
				c.SHA256 = digest([]byte("wrong"))
			}
		}},
		{"empty", func(c *api.BlobChunk) { c.Data = nil }},
	} {
		t.Run(row.name, func(t *testing.T) {
			service, store, _, scope, request := component(t)
			store.changeChunk = row.change
			result, err := service.BriefRender(context.Background(), scope, request)
			errorCode(t, err, api.CodeIntegrity)
			if result.Markdown.ID != "" || store.writes != 0 {
				t.Fatal("corrupt input returned a prompt or changed state")
			}
		})
	}
	service, store, _, scope, request := component(t)
	data := bytes.Repeat([]byte("x"), api.MaxChunkBytes+17)
	request.Task.Bytes, request.Task.SHA256 = int64(len(data)), digest(data)
	store.input.Task, store.input.Lane.Task, store.input.TaskBytes = request.Task, request.Task, data
	store.put(request.Task, data)
	result, err := service.BriefRender(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	var reads []api.BlobReadRequest
	for _, read := range store.reads {
		if read.ObjectID == request.Task.ID && read.Offset < request.Task.Bytes {
			reads = append(reads, read)
		}
	}
	if len(reads) != 2 || reads[1].Offset != api.MaxChunkBytes || reads[1].Limit != 17 {
		t.Fatal("committed task was not read through bounded contiguous chunks")
	}
	if len(store.retained) != 1 || !bytes.Equal(store.blobs[result.Markdown.ID], store.retained[0].Object.Bytes) ||
		!bytes.HasSuffix(store.blobs[result.Markdown.ID], data) || store.writes != 0 {
		t.Fatal("retention did not store the actual rendered prompt and task")
	}
}

func TestBriefStartDoesNotLaunch(t *testing.T) {
	service, store, _, scope, _ := component(t)
	request := api.BriefingRequest{Level: scope.Actor.Level, Role: scope.Actor.Role}
	result, err := service.BriefStart(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Markdown.ID == "" || store.writes != 0 || len(store.retained) != 1 ||
		!bytes.HasSuffix(store.blobs[result.Markdown.ID], store.input.TaskBytes) {
		t.Fatal("briefing lost the retained task or started work")
	}
	request.LifeID = "life-sibling"
	_, err = service.BriefStart(context.Background(), scope, request)
	errorCode(t, err, api.CodeForbidden)
}

func TestOrgValidationNeedsSources(t *testing.T) {
	service, store, policy, scope, _ := component(t)
	_, err := service.OrgValidate(context.Background(), scope, api.OrgValidateRequest{Generation: 6})
	errorCode(t, err, api.CodeConflict)
	policy.validation = api.OrgValidation{Valid: false, Problems: []string{"fixture malformed role"}}
	result, err := service.OrgValidate(context.Background(), scope, api.OrgValidateRequest{Generation: 7})
	if err != nil || result.Valid || len(result.Problems) != 1 {
		t.Fatal("actual policy validation failure was lost")
	}
	policy.validation = api.OrgValidation{Valid: true, Problems: []string{}}
	// A plugin's own roles directory is inert source data, not a level/role
	// prompt layer. Full inventory validation must not mistake it for one.
	data := []byte("ordinary plugin role documentation")
	ref := source("plugin-doc", ".laneboss/plugins/sample/roles/readme.md", data).Ref
	content := api.BlobRef{ID: "plugin-doc-content", Class: "artifact", Bytes: int64(len(data)), SHA256: ref.SHA256}
	store.put(content, data)
	store.snapshot.Sources = append(store.snapshot.Sources, api.ResourceFile{Source: ref, Content: content, Kind: "prompt", Mode: 0644, RevisionGeneration: 7})
	result, err = service.OrgValidate(context.Background(), scope, api.OrgValidateRequest{Generation: 7})
	if err != nil || !result.Valid || store.writes != 0 {
		t.Fatal("complete approved source validation failed or changed state")
	}
	store.changeSource = func(ref *api.RetainedSource) { ref.Content.ID = "unapproved-source" }
	result, err = service.OrgValidate(context.Background(), scope, api.OrgValidateRequest{Generation: 7})
	errorCode(t, err, api.CodeIntegrity)
	if result.Valid || store.writes != 0 {
		t.Fatal("policy-only validation claimed complete org validity")
	}
}

func TestBootstrapRequiresAtomicApply(t *testing.T) {
	service, store, _, scope, _ := component(t)
	data := []byte("{\"schema\":\"laneboss.objects.v2\",\"entries\":[]}")
	ref := api.BlobRef{ID: "bootstrap-input", Class: "manifest", SHA256: digest(data), Bytes: int64(len(data))}
	store.put(ref, data)
	request := api.BootstrapRequest{OrgName: "case-org", SourceManifest: ref}
	_, err := service.OrgBootstrap(context.Background(), scope, request)
	errorCode(t, err, api.CodeForbidden)
	if len(store.reads) != 0 {
		t.Fatal("lane bootstrap reached the manifest")
	}
	scope.Actor = api.Actor{Kind: "human", ID: "human-one"}
	_, err = service.OrgBootstrap(context.Background(), scope, request)
	errorCode(t, err, api.CodeForbidden)
	scope.Request.Proof = &api.ProofRef{ID: "fixture-proof"}
	result, err := service.OrgBootstrap(context.Background(), scope, request)
	errorCode(t, err, api.CodeInvalid)
	if result.ID != "" || store.writes != 0 {
		t.Fatal("a proof label or read manifest became a fake bootstrap receipt")
	}
}

func TestApprovedPromptRetention(t *testing.T) {
	service, store, _, scope, request := component(t)
	briefing, err := service.BriefRender(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.retained) != 1 || len(briefing.Sources) != len(store.snapshot.Sources) ||
		briefing.Template.Generation != 7 || briefing.PolicyGeneration != 9 {
		t.Fatal("approved source and policy generations were conflated or not retained")
	}
	kept := store.retained[0]
	if kept.Intent.Kind != api.InternalObjectRetain || kept.Intent.RequestedBy != scope.Actor ||
		kept.Intent.Target.LifeID != store.input.Lane.LifeID || kept.Object.ACL.LifeID != store.input.Lane.LifeID ||
		len(kept.Object.InputRefs) != len(briefing.Sources)+1 {
		t.Fatal("prompt retention lost its authentic scope or input provenance")
	}
	if err := templates.VerifyTaskPrompt(request.Context, briefing, request.Task, store.input.TaskBytes, store.blobs[briefing.Markdown.ID]); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(briefing.LaneGroups.Ended, []api.ID{store.input.Lane.LifeID}) || store.writes != 0 {
		t.Fatal("briefing dropped authorized groups or changed lifecycle state")
	}
}

type registrar struct {
	handlers map[api.Method]api.Handler
	fail     api.Method
	failure  error
}

func (r *registrar) Register(method api.Method, handler api.Handler) error {
	if method == r.fail {
		return r.failure
	}
	if r.handlers[method] != nil {
		return errors.New("duplicate fixture registration")
	}
	r.handlers[method] = handler
	return nil
}

func (r *registrar) RegisterStream(_ api.Method, _ api.StreamHandler) error {
	return errors.New("templates must not register a stream")
}

func TestRegistrationStopsOnFailure(t *testing.T) {
	service, _, _, scope, _ := component(t)
	registry := &registrar{handlers: map[api.Method]api.Handler{}}
	if err := service.Register(registry); err != nil {
		t.Fatal(err)
	}
	if len(registry.handlers) != 4 {
		t.Fatal("templates registered an unexpected method catalog")
	}
	for _, method := range []api.Method{"brief.render", "brief.start", "org.validate", "org.bootstrap"} {
		if registry.handlers[method] == nil {
			t.Fatal("owned method missing")
		}
	}
	_, err := registry.handlers["brief.start"](context.Background(), scope, []byte(`{"level":3,"role":"executor","life_id":null}`))
	errorCode(t, err, api.CodeInvalid)
	failure := errors.New("fixture registrar unavailable")
	registry = &registrar{handlers: map[api.Method]api.Handler{}, fail: "brief.start", failure: failure}
	if !errors.Is(service.Register(registry), failure) || len(registry.handlers) != 1 {
		t.Fatal("registration continued after failure")
	}
}

func TestDecodeStrictRequestBodies(t *testing.T) {
	for name, data := range map[string]string{
		"duplicate": `{"role":"executor","role":"reviewer","level":3}`,
		"case":      `{"Role":"executor","level":3}`,
		"unknown":   `{"role":"executor","level":3,"grant":"all"}`,
		"missing":   `{"role":"executor"}`,
		"null":      `{"role":"executor","level":3,"life_id":null}`,
		"fraction":  `{"role":"executor","level":3.0}`,
		"range":     `{"role":"executor","level":9007199254740992}`,
		"unicode":   `{"role":"\ud800","level":3}`,
		"trailing":  `{"role":"executor","level":3} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			var result api.BriefingRequest
			errorCode(t, templates.DecodeJSON([]byte(data), &result), api.CodeInvalid)
		})
	}
	var valid api.BriefingRequest
	if err := templates.DecodeJSON([]byte(`{"role":"executor","level":3}`), &valid); err != nil {
		t.Fatal(err)
	}
	if valid.Role != "executor" || valid.Level != 3 || valid.LifeID != "" {
		t.Fatal("valid request lost its values")
	}
}

func TestCLIRejectsAmbiguousInputs(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "request.json")
	if err := os.WriteFile(path, []byte(`{"level":3,"role":"executor","unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"brief", "start", "--request", path},
		{"brief", "start", "--request-file", path},
		{"brief", "start", "--request-file", path, "--request-file", path},
		{"start", "--level", "3", "--role", "executor", "--role", "reviewer"},
		{"brief", "render", "--request", path, "--brief", path},
		{"brief", "start", "--level", "3", "--role", "executor", "--format", "html"},
		{"org", "validate", "--generation", "0"},
		{"org", "bootstrap", "--name", "new-org", "--template", path},
	} {
		var stdout, stderr bytes.Buffer
		command := append(append([]string{}, args...), "--config", "case-templates")
		if exit := cli.Run(command, bytes.NewReader(nil), &stdout, &stderr); exit != 2 {
			t.Fatalf("invalid CLI input returned %d: %s", exit, stderr.String())
		}
		var failure api.Error
		if err := json.Unmarshal(stderr.Bytes(), &failure); err != nil {
			t.Fatal(err)
		}
		if failure.Code != api.CodeInvalid || failure.Instead == "" || stdout.Len() != 0 {
			t.Fatal("invalid CLI input reached transport or produced success output")
		}
	}
}

func TestBootstrapCLICommittedInput(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"schema":"laneboss.objects.v2","entries":[]}`)
	manifestFile, refFile := filepath.Join(directory, "manifest.json"), filepath.Join(directory, "ref.json")
	if err := os.WriteFile(manifestFile, manifest, 0600); err != nil {
		t.Fatal(err)
	}
	ref := api.BlobRef{ID: "committed-manifest", Class: "manifest", Bytes: int64(len(manifest)), SHA256: digest([]byte("different manifest"))}
	data, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(refFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, message string
		args          []string
		code          api.ErrorCode
		exit          int
	}{
		{"proof-needs-committed-ref", "proof-bound bootstrap requires a committed --content-ref or --request-file",
			[]string{"--manifest", manifestFile, "--proof", filepath.Join(directory, "proof.json")}, api.CodeInvalid, 2},
		{"exact-manifest", "--manifest bytes differ from the committed --content-ref",
			[]string{"--manifest", manifestFile, "--content-ref", refFile}, api.CodeIntegrity, 3},
	} {
		t.Run(row.name, func(t *testing.T) {
			args := append([]string{"org", "bootstrap", "--name", "new-org", "--config", "case-templates"}, row.args...)
			var stdout, stderr bytes.Buffer
			if exit := cli.Run(args, bytes.NewReader(nil), &stdout, &stderr); exit != row.exit {
				t.Fatalf("bootstrap committed-input boundary reached transport: exit %d: %s", exit, stderr.String())
			}
			var failure api.Error
			if err := templates.DecodeJSON(stderr.Bytes(), &failure); err != nil {
				t.Fatal(err)
			}
			if failure.Code != row.code || failure.Message != row.message || failure.Instead == "" || stdout.Len() != 0 {
				t.Fatal("bootstrap accepted changed or uncommitted proof-bound input")
			}
		})
	}
}
