// This owned test asset is compiled in package cli through the mutation
// runner's retained Go overlay. It adds no production hook or shared file.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	rendering "laneboss.io/laneboss/internal/v2/templates"
)

type templatesCLIFixture struct {
	call                 Invocation
	wire                 *integrateFixtureClient
	lane                 api.Lane
	grants               api.GrantSet
	activeTask           api.BlobRef
	self                 api.Scope
	briefing             api.Briefing
	objects              map[api.ID][]byte
	taskFile, directory  string
	output               bytes.Buffer
	session, needSession bool
	staged               []byte
	declared             api.BlobBeginRequest
	seq                  api.Sequence
}

func templatesCLINew(t *testing.T) *templatesCLIFixture {
	t.Helper()
	f := &templatesCLIFixture{directory: t.TempDir(), objects: map[api.ID][]byte{}, staged: []byte{}}
	if err := os.Chmod(f.directory, 0700); err != nil {
		t.Fatal(err)
	}
	ctx := api.RoleContext{Level: 3, Role: "executor"}
	source := func(id api.ID, name string) rendering.Source {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "templates", "v2", "org", name))
		if err != nil {
			t.Fatal(err)
		}
		path := rendering.OrgTemplatePath
		if name == "drivers.toml" {
			path = rendering.OrgDriversPath
		}
		return rendering.Source{Ref: api.SourceRef{ID: id, Path: path, Generation: 7, SHA256: templatesHash(data)}, Bytes: data}
	}
	role, err := rendering.Resolve(ctx, rendering.Layers{Generation: 7,
		Org: source("org-body", "default.md"), OrgDrivers: source("org-drivers", "drivers.toml")})
	if err != nil {
		t.Fatal(err)
	}
	task := []byte("# CLI task\r\nExact task bytes: 測試\nlast line")
	ref := api.BlobRef{ID: "task-one", Class: "task", Bytes: int64(len(task)), SHA256: templatesHash(task)}
	f.lane = api.Lane{LifeID: "life-one", RootLifeID: "life-one", StarterChain: []api.ID{},
		Level: 3, Role: "executor", Run: 1, Generation: 2, Task: ref, GrantSetID: "grants-one", PolicyGeneration: 9,
		Workspace: api.Workspace{ID: "work", LogicalCWD: "/work/main", Branch: "branch"}, Session: api.Session{Driver: api.DriverCodex}}
	f.grants = api.GrantSet{ID: f.lane.GrantSetID, LifeID: f.lane.LifeID, Generation: 1, PolicyGeneration: 9,
		SHA256: templatesHash([]byte("grants")), Resources: []api.ResourceGrant{}, Data: []api.DataGrant{}, Secrets: []api.SecretGrant{},
		Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	document, err := rendering.Render(rendering.RenderInput{Config: "case-templates", Role: role, Lane: f.lane,
		Policy: api.EffectivePolicy{Generation: 9, Context: ctx, SHA256: templatesHash([]byte("policy")), Rules: []api.Rule{}, Sources: []api.SourceRef{}},
		Grants: f.grants, Task: ref, TaskBytes: task})
	if err != nil {
		t.Fatal(err)
	}
	prompt := api.BlobRef{ID: "prompt-one", Class: "prompt", Bytes: int64(len(document.Markdown)), SHA256: templatesHash(document.Markdown)}
	f.objects[ref.ID], f.objects[prompt.ID] = task, document.Markdown
	f.briefing = api.Briefing{Markdown: prompt, Template: document.Template, PolicyGeneration: 9, Sources: document.Sources,
		Checks:     []api.Capability{{Name: "fixture", Available: true}},
		LaneGroups: api.LaneGroups{Running: []api.ID{}, Ended: []api.ID{f.lane.LifeID}, Accepted: []api.ID{}, Lost: []api.ID{}, Idle: []api.ID{}, Others: []api.ID{}}}
	f.self = api.Scope{Config: "case-templates", Actor: api.Actor{Kind: "lane", ID: "actor", LifeID: f.lane.LifeID, Level: 3, Role: "executor"}}
	f.wire = &integrateFixtureClient{handle: f.handle}
	key, err := client.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	f.call = Invocation{Config: f.self.Config, Stdout: &f.output, Stderr: &bytes.Buffer{}, IdempotencyKey: key,
		integrateSocket: &integrateSocket{options: client.Options{Config: f.self.Config}, connection: f.wire}}
	f.taskFile = filepath.Join(f.directory, "task.md")
	if err := os.WriteFile(f.taskFile, task, 0600); err != nil {
		t.Fatal(err)
	}
	// Typed subcalls must work without another feature's file-input hook.
	for _, method := range []api.Method{"blob.read", "grants.get", "lane.status", "identity.self"} {
		integrateInputChecks.Lock()
		previous := integrateInputChecks.methods[method]
		delete(integrateInputChecks.methods, method)
		integrateInputChecks.Unlock()
		t.Cleanup(func() {
			integrateInputChecks.Lock()
			if previous != nil {
				integrateInputChecks.methods[method] = previous
			} else {
				delete(integrateInputChecks.methods, method)
			}
			integrateInputChecks.Unlock()
		})
	}
	return f
}

func (f *templatesCLIFixture) handle(request api.Request) (any, error) {
	decode := func(target any) error { return api.DecodeObject(request.Params, target) }
	switch request.Method {
	case "human.session":
		if request.Proof == nil || f.self.Actor.Kind != "human" {
			return nil, errors.New("session lost its proof")
		}
		f.session = true
		return api.HumanSession{ID: api.ID("session-" + string(request.RequestID)), Config: request.Config}, nil
	case "identity.self":
		return f.self, nil
	case "grants.get":
		var input api.GrantGetRequest
		if err := decode(&input); err != nil {
			return nil, err
		}
		if input.GrantSetID != f.grants.ID {
			return nil, errors.New("grant selector changed")
		}
		return f.grants, nil
	case "lane.status":
		var input api.LifeRef
		if err := decode(&input); err != nil {
			return nil, err
		}
		if input.LifeID != f.lane.LifeID {
			return nil, errors.New("life selector changed")
		}
		return f.lane, nil
	case "brief.render":
		var input api.TemplateRequest
		if err := decode(&input); err != nil {
			return nil, err
		}
		assigned := f.activeTask
		if assigned.ID == "" {
			assigned = f.lane.Task
		}
		if input.Task != assigned || input.GrantSetID != f.grants.ID {
			return nil, errors.New("render assignment changed")
		}
		return f.briefing, nil
	case "brief.start":
		var input api.BriefingRequest
		if err := decode(&input); err != nil {
			return nil, err
		}
		if input.Level != f.lane.Level || input.Role != f.lane.Role {
			return nil, errors.New("start context changed")
		}
		return f.briefing, nil
	case "blob.read":
		var input api.BlobReadRequest
		if err := decode(&input); err != nil {
			return nil, err
		}
		data, exists := f.objects[input.ObjectID]
		if !exists || input.Offset < 0 || input.Offset > int64(len(data)) || input.Limit <= 0 {
			return nil, errors.New("invalid blob read")
		}
		chunk := bytes.Clone(data[int(input.Offset):min(int(input.Offset)+input.Limit, len(data))])
		if chunk == nil {
			chunk = []byte{}
		}
		return api.BlobChunk{ObjectID: input.ObjectID, Offset: input.Offset, Data: chunk, SHA256: templatesHash(chunk)}, nil
	case "org.validate":
		var input api.OrgValidateRequest
		if err := decode(&input); err != nil {
			return nil, err
		}
		if input.Generation != f.briefing.Template.Generation {
			return nil, errors.New("org generation changed")
		}
		return api.OrgValidation{Valid: true, Problems: []string{}}, nil
	case "org.bootstrap":
		var input api.BootstrapRequest
		if err := decode(&input); err != nil {
			return nil, err
		}
		if f.self.Actor.Kind != "human" || input.OrgName == "" || input.SourceManifest.SHA256 != templatesHash(f.objects[input.SourceManifest.ID]) || request.Proof == nil {
			return nil, errors.New("bootstrap lost its committed input or operation proof")
		}
		f.seq++
		return api.Operation{ID: api.ID("op-" + string(request.RequestID)), Status: "pending", FirstSeq: f.seq, LastSeq: f.seq}, nil
	case "blob.begin", "blob.chunk", "blob.commit":
		if f.needSession && !f.session || request.Proof != nil {
			return nil, errors.New("blob staging lacks its connection session")
		}
		switch request.Method {
		case "blob.begin":
			if err := decode(&f.declared); err != nil {
				return nil, err
			}
			return api.BlobUpload{ObjectID: "upload", MaxChunkBytes: api.MaxChunkBytes}, nil
		case "blob.chunk":
			var input api.BlobChunk
			if err := decode(&input); err != nil {
				return nil, err
			}
			if input.ObjectID != "upload" || input.Offset != int64(len(f.staged)) || input.SHA256 != templatesHash(input.Data) {
				return nil, errors.New("staging chunk changed")
			}
			f.staged = append(f.staged, input.Data...)
			return api.BlobUpload{ObjectID: input.ObjectID, MaxChunkBytes: api.MaxChunkBytes}, nil
		default:
			var input api.BlobCommitRequest
			if err := decode(&input); err != nil {
				return nil, err
			}
			if input.ObjectID != "upload" || input.SHA256 != templatesHash(f.staged) || int64(len(f.staged)) != f.declared.Bytes {
				return nil, errors.New("committed staging bytes changed")
			}
			return api.BlobRef{ID: input.ObjectID, SHA256: input.SHA256, Bytes: int64(len(f.staged)), Class: f.declared.Class}, nil
		}
	}
	return nil, errors.New("unexpected fixture method")
}

func templatesCLIProof(t *testing.T, f *templatesCLIFixture, method api.Method, params any) string {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	proof := api.ProofRef{ID: "fixture-proof", ExpiresAt: "2030-01-01T00:10:00Z"}
	digest, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.call.Config, Method: method, Params: raw})
	if err != nil {
		t.Fatal(err)
	}
	proof.RequestSHA256 = digest
	return integrateFixtureFile(t, f.directory, "proof.json", proof)
}

func TestTemplatesCLI(t *testing.T) {
	for _, name := range []string{"render", "start", "validate", "bootstrap"} {
		t.Run(name, func(t *testing.T) {
			f := templatesCLINew(t)
			var err error
			switch name {
			case "render":
				f.call.Method, f.call.Args = "brief.render", []string{"--level", "3", "--role", "executor", "--grant-set-id", string(f.grants.ID), "--brief", f.taskFile}
				err = runBriefRender(context.Background(), f.call)
			case "start":
				f.call.Method, f.call.Args = "brief.start", []string{"--level", "3", "--role", "executor"}
				err = runBriefStart(context.Background(), f.call)
			case "validate":
				f.call.Method, f.call.Args = "org.validate", []string{"--generation", "7"}
				err = runOrgValidate(context.Background(), f.call)
			case "bootstrap":
				f.self.Actor = api.Actor{Kind: "human", ID: "human"}
				data := []byte(`{"schema":"laneboss.objects.v2","entries":[]}`)
				ref := api.BlobRef{ID: "manifest", Class: "manifest", Bytes: int64(len(data)), SHA256: templatesHash(data)}
				f.objects[ref.ID] = data
				path := integrateFixtureFile(t, f.directory, "ref.json", ref)
				f.call.Method, f.call.Args = "org.bootstrap", []string{"--name", "new-org", "--content-ref", path}
				f.call.ProofFile = templatesCLIProof(t, f, "org.bootstrap", api.BootstrapRequest{OrgName: "new-org", SourceManifest: ref})
				err = runOrgBootstrap(context.Background(), f.call)
			}
			if err != nil {
				t.Fatalf("template CLI failed its typed transport path: %v", err)
			}
			if f.output.Len() == 0 || f.wire.closed != 0 || len(f.wire.requests) == 0 {
				t.Fatal("template CLI lost output or borrowed connection ownership")
			}
			if name == "render" || name == "start" {
				if !bytes.Equal(f.output.Bytes(), f.objects[f.briefing.Markdown.ID]) {
					t.Fatal("template CLI changed verified prompt bytes")
				}
			}
		})
	}
}

func TestTemplatesIdentity(t *testing.T) {
	for _, field := range []string{"config", "life", "kind"} {
		t.Run(field, func(t *testing.T) {
			f := templatesCLINew(t)
			if field == "config" {
				f.self.Config = "foreign"
			} else if field == "life" {
				f.self.Actor.LifeID = ""
			} else {
				f.self.Actor.Kind, f.self.Actor.LifeID = "service", ""
			}
			f.call.Method, f.call.Args = "brief.start", []string{"--level", "3", "--role", "executor"}
			err := runBriefStart(context.Background(), f.call)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || f.output.Len() != 0 {
				t.Fatal("start skipped its authenticated identity and task boundary")
			}
		})
	}
}

func TestTemplatesStage(t *testing.T) {
	f := templatesCLINew(t)
	f.self.Actor = api.Actor{Kind: "human", ID: "human"}
	f.needSession = true
	f.call.Method = "org.bootstrap"
	options := templatesFlags{socket: f.call.integrateSocket, proofFile: templatesCLIProof(t, f, "human.session", api.Empty{})}
	data := []byte("exact staged manifest bytes")
	ref, err := templatesUpload(context.Background(), f.call, &options, "manifest", data)
	if err != nil || ref.SHA256 != templatesHash(data) || !bytes.Equal(data, f.staged) || !options.sessionReady {
		t.Fatalf("session staging lost its connection-scoped proof: %v", err)
	}
	sessions := 0
	for _, request := range f.wire.requests {
		if request.Method == "human.session" {
			sessions++
		} else if request.Proof != nil {
			t.Fatal("session proof leaked into a staging mutation")
		}
	}
	if sessions != 1 || f.wire.requests[0].Method != "human.session" {
		t.Fatal("session staging did not open exactly one session first")
	}
}

func TestTemplatesFileBytes(t *testing.T) {
	f := templatesCLINew(t)
	f.self.Actor = api.Actor{Kind: "human", ID: "human"}
	request := api.TemplateRequest{Context: api.RoleContext{Level: 3, Role: "executor"}, Task: f.lane.Task, GrantSetID: f.grants.ID}
	raw, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(append([]byte("\n"), raw...), '\n')
	path := filepath.Join(f.directory, "request.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	f.call.Method, f.call.Args = "brief.render", []string{"--request-file", path, "--format", "json"}
	f.call.ProofFile = templatesCLIProof(t, f, "human.session", api.Empty{})
	if err := runBriefRender(context.Background(), f.call); err != nil {
		t.Fatal(err)
	}
	sessions, matched := 0, false
	for _, call := range f.wire.requests {
		if call.Method == "human.session" {
			sessions++
			continue
		}
		if call.Proof != nil {
			t.Fatal("human read carried a session proof as an ambient token")
		}
		if call.Method == "brief.render" {
			matched = bytes.Equal(call.Params, raw)
		}
	}
	if sessions != 1 || !matched || f.wire.requests[0].Method != "human.session" || f.output.Len() == 0 {
		t.Fatal("template file input lost its exact bytes or shared read session")
	}
}

func TestTemplatesFIFO(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "input")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := templatesReadFile(path, api.MaxFrameBytes); result <- err }()
	select {
	case err := <-result:
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeInvalid {
			t.Fatal("non-regular file was accepted")
		}
	case <-time.After(time.Second):
		writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Fatal("blocked FIFO reader did not quiesce")
		}
		t.Fatal("template file reader blocked on a FIFO")
	}
}

func TestTemplatesTurn(t *testing.T) {
	f := templatesCLINew(t)
	data := []byte("# CLI active turn\nRetained follow-up bytes.\n")
	f.activeTask = api.BlobRef{ID: "turn-task", Class: "task", Bytes: int64(len(data)), SHA256: templatesHash(data)}
	f.objects[f.activeTask.ID] = data
	prompt := bytes.Replace(f.objects[f.briefing.Markdown.ID], f.objects[f.lane.Task.ID], data, 1)
	if bytes.Equal(prompt, f.objects[f.briefing.Markdown.ID]) {
		t.Fatal("CLI fixture omitted its actual original task frame")
	}
	f.objects[f.briefing.Markdown.ID] = prompt
	f.briefing.Markdown.Bytes, f.briefing.Markdown.SHA256 = int64(len(prompt)), templatesHash(prompt)
	f.briefing.Template.RenderedSHA256 = templatesHash(prompt)
	f.lane.Run = 2
	if err := os.WriteFile(f.taskFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	ref := integrateFixtureFile(t, f.directory, "task-ref.json", f.activeTask)
	f.call.Method, f.call.Args = "brief.render", []string{"--level", "3", "--role", "executor", "--grant-set-id", string(f.grants.ID), "--brief", f.taskFile, "--task-ref", ref}
	if err := runBriefRender(context.Background(), f.call); err != nil || !bytes.Equal(f.output.Bytes(), prompt) {
		t.Fatalf("CLI refused the committed active turn task: %v", err)
	}
}
