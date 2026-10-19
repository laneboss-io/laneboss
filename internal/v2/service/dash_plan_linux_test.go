//go:build linux

package service

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/policy"
	"laneboss.io/laneboss/internal/v2/store"
	"laneboss.io/laneboss/internal/v2/templates"
)

// The installed org can retain a default L3 projection while approving L6
// sources. Compile the actual source bytes; never relabel the retained policy.
func dashPlanOrg(t *testing.T, state *store.Service, scope api.Scope) api.EffectivePolicy {
	t.Helper()
	objects := []api.ObjectWrite{}
	files := []api.ResourceFile{}
	keep := func(path, kind, class string, raw []byte) api.ResourceFile {
		ref := api.BlobRef{ID: fixtureID(t), Class: class, Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
		objects = append(objects, api.ObjectWrite{ObjectKey: ref.ID, Class: class, Bytes: raw, SHA256: ref.SHA256,
			Origin: "service", ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "config", Generation: 1}})
		file := api.ResourceFile{Source: api.SourceRef{ID: fixtureID(t), Path: path, SHA256: ref.SHA256, Generation: 1},
			Content: ref, Kind: kind, Mode: 0444, RevisionGeneration: 1}
		files = append(files, file)
		return file
	}
	body := []byte("## Scope\nUse the retained task.\n## Responsibilities\nRetain evidence.\n## Deliverable\nReport checks.\n## Must not\nWiden authority.\n")
	keep(templates.OrgTemplatePath, "prompt", "artifact", body)
	keep(templates.OrgDriversPath, "drivers", "artifact", []byte("drivers = [\"codex\"]\n"))
	workflow, err := os.ReadFile(filepath.Join("..", "..", "..", "templates", "v2", "org", "workflow.toml"))
	if err != nil {
		t.Fatal(err)
	}
	keep(templates.WorkflowPath, "policy", "policy", workflow)
	for _, role := range []api.RoleContext{{Level: 3, Role: "executor"}, {Level: 6, Role: "supervisor"}} {
		keep(fmt.Sprintf(".laneboss/L%d/roles/%s.md", role.Level, role.Role), "prompt", "artifact", body)
		keep(fmt.Sprintf(".laneboss/L%d/roles/%s.toml", role.Level, role.Role), "drivers", "artifact", []byte("drivers = [\"codex\"]\n"))
	}
	thresholds := api.Thresholds{Match: .8, UncertainLow: .4, UncertainHigh: .6, CalibrationID: "dash-calibration"}
	judge := api.JudgeConfig{Provider: api.DefaultJudgeProvider, Model: api.DefaultJudgeModel,
		DeploymentSHA256: digestBytes([]byte("unexecuted judge deployment")), TokenizerSHA256: digestBytes([]byte("unexecuted tokenizer")),
		ContextTokens: 32768, MaxBytes: api.MaxJudgeBytes, MaxQuestions: 12, CommandDeadlineMS: 2000,
		GuidanceDeadlineMS: 5000, OutagePolicy: "critical-only"}
	halfLife, relevance, exclusions := int64(3600), .5, []api.ID{}
	doc := policy.CanonicalDocument{Schema: "laneboss.policy-source.v2", Thresholds: thresholds,
		Rules: []api.Rule{}, Skip: []api.SkipEntry{}, Settings: []api.SettingValue{}, Judge: &judge,
		GuidanceHalfLifeSeconds: &halfLife, GuidanceMinRelevance: &relevance, ProfileExclusions: &exclusions}
	source := keep(policy.CanonicalPath, "policy", "policy", fixtureJSON(t, doc))
	localRole := api.RoleContext{Level: 3, Role: "executor"}
	localRules := []api.Rule{{ID: "l3-only-rule", Text: "Executor-only policy marker.", Instead: "Retain the executor policy.",
		Band: "refuse", Scope: api.RuleScope{Levels: []int{3}, Roles: []string{"executor"}}}}
	localDoc := policy.CanonicalDocument{Schema: doc.Schema, Thresholds: thresholds, Rules: localRules,
		Skip: []api.SkipEntry{}, Settings: []api.SettingValue{}}
	local := keep(".laneboss/L3/policy/executor.json", "policy", "policy", fixtureJSON(t, localDoc))
	approved, err := policy.Resolve(1, api.RoleContext{Level: 3, Role: "executor"},
		[]policy.Layer{{Source: source.Source, Thresholds: thresholds, Rules: []api.Rule{}, Skip: []api.SkipEntry{}},
			{Source: local.Source, DefinedAt: &localRole, Thresholds: thresholds, Rules: localRules, Skip: []api.SkipEntry{}}}, judge, halfLife)
	if err != nil {
		t.Fatal(err)
	}
	inventory := fixtureJSON(t, files)
	manifest := api.BlobRef{ID: fixtureID(t), Class: "manifest", Bytes: int64(len(inventory)), SHA256: digestBytes(inventory)}
	objects = append(objects, api.ObjectWrite{ObjectKey: manifest.ID, Class: manifest.Class, Bytes: inventory, SHA256: manifest.SHA256,
		Origin: "service", ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "config", Generation: 1}})
	ownershipBytes := fixtureJSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}})
	ownership := api.BlobRef{ID: fixtureID(t), Class: "manifest", Bytes: int64(len(ownershipBytes)), SHA256: digestBytes(ownershipBytes)}
	objects = append(objects, api.ObjectWrite{ObjectKey: ownership.ID, Class: ownership.Class, Bytes: ownershipBytes, SHA256: ownership.SHA256,
		Origin: "service", ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "config", Generation: 1}})
	org := api.OrgSnapshot{Config: scope.Config, Ref: api.OrgSnapshotRef{OrgID: api.ID(scope.Config), Generation: 1, ManifestSHA256: manifest.SHA256},
		Sources: files, Derived: []api.ResourceFile{}, OwnershipManifest: ownership,
		Renderer:    api.Executable{ID: fixtureID(t), Version: "component-renderer", SHA256: digestBytes(body)},
		PublishedBy: fixtureID(t), PublishedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	cause := api.InternalIntent{ID: fixtureID(t), Kind: api.InternalOrgBootstrap, Config: scope.Config, Actor: scope.Actor, RequestedBy: scope.Actor}
	if _, err := state.Transact(context.Background(), api.Transaction{Scope: scope, Internal: &cause,
		Writes: api.StateWrites{Objects: objects, OrgSnapshots: []api.OrgSnapshot{org}, Policy: &approved}}); err != nil {
		t.Fatal("approved dashboard org fixture did not commit", err)
	}
	return approved
}

// Kernel/helper/runner observations use existing component ports. Admission,
// proofs, role policy, planner, owner and operation completion are real.
func dashPlanComplete(t *testing.T, host *Server, state *store.Service, identities *identity.Service,
	scope api.Scope, directory string, root api.GrantSet, ticket api.Ticket, call func(any, any)) {
	t.Helper()
	ctx := context.Background()
	scope.PolicyGeneration = root.PolicyGeneration
	keep := func(class string, raw []byte) api.BlobRef {
		ref := api.BlobRef{ID: fixtureID(t), Class: class, Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
		cause := api.InternalIntent{ID: fixtureID(t), Kind: api.InternalOrgBootstrap, Config: scope.Config, Actor: scope.Actor, RequestedBy: scope.Actor}
		if _, err := state.Transact(ctx, api.Transaction{Scope: scope, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{{
			ObjectKey: ref.ID, Class: class, Bytes: raw, SHA256: ref.SHA256, Origin: "service",
			ACL: api.ObjectACL{Config: scope.Config, Owner: ticketActor(ticket), Audience: "owner", Generation: 1}}}}}); err != nil {
			t.Fatal(err)
		}
		return ref
	}
	metadata, err := state.ObjectMetadata(ctx, scope, root.Data[0].SourceObjectID)
	if err != nil || metadata.Ref.SHA256 != root.Data[0].SourceSHA256 {
		t.Fatal("prior root source differs from its retained object", err)
	}
	start := api.StartRequest{Lane: "dash-root", ProjectID: fixtureID(t), Level: ticket.Level, Role: ticket.Role,
		Task: keep("task", []byte("# Component launch\nComplete the HTTP root launch.\n")), Driver: api.DriverCodex,
		ProfileGrantID: root.Profiles[0].ID, Model: "fixture-model", Effort: "high", RootTicketID: ticket.ID, ExpectedPolicyGeneration: root.PolicyGeneration,
		Budget: api.Budget{WallMS: 60000, CPUSeconds: 10, MemoryBytes: 1 << 20, Processes: 10, DiskBytes: 1 << 20, Currency: "USD"},
		Grants: api.GrantRequest{Resources: []api.ResourceDelegation{}, Secrets: []api.SecretDelegation{}, Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{},
			Data:     []api.DataGrantRequest{{ParentGrantID: root.Data[0].ID, RelativePath: ".", Access: root.Data[0].Access, Delivery: "copy", Destination: "/work/main", Delegate: root.Data[0].Delegate, ExpiresAt: root.Data[0].ExpiresAt}},
			Profiles: []api.ProfileDelegation{{ParentGrantID: root.Profiles[0].ID, ProfileID: root.Profiles[0].ProfileID, Delegate: root.Profiles[0].Delegate, ExpiresAt: root.Profiles[0].ExpiresAt}}}}
	resolver, err := grants.New(grants.Dependencies{Config: scope.Config, Store: state, Worker: &dataworker.Service{}, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	probe := &healthLauncher{probe: api.IsolationCapabilities{Backend: "linux-bwrap-landlock", Available: true,
		Checks: []api.Capability{{Name: "component-kernel", Available: true}}}}
	admission, err := lifecycle.New(lifecycle.Dependencies{Store: state, Identity: identities, Grants: resolver,
		Launcher: probe, Codex: &successfulPlanPorts{}, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := admission.Register(host); err != nil {
		t.Fatal(err)
	}
	core, err := New(host.deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Register(host); err != nil {
		t.Fatal(err)
	}
	host.verified, host.controller = true, fixtureID(t)
	if err := host.BindRuntime(ctx, api.RuntimeServices{Config: scope.Config, Store: host.deps.Store, Identity: identities,
		Socket: host.deps.Binding.Socket, ArtifactSHA256: host.deps.Binding.ArtifactSHA256, LaunchPlanner: admission,
		Helper: &agentOwnerHelper{}, Worker: &dataworker.Service{}, Launcher: probe}); err != nil {
		t.Fatal(err)
	}
	stopRecovery := dashRecoveryReady(t, host)
	defer stopRecovery()
	var operation api.Operation
	call(requestFor(t, "lane.start", start), &operation)
	stopRecovery()
	if operation.Status != "pending" || operation.ID == "" || operation.Run != 1 {
		t.Fatal("HTTP root launch did not reserve its actual pending operation")
	}
	plan, err := state.LaunchPlanForOperation(ctx, scope, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	effects, err := state.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil || len(effects) != 1 || effects[0].OperationID != operation.ID {
		t.Fatal("HTTP launch lost its sole planning effect", err)
	}
	f := dashLaunchFixture(state, scope, directory, start, root, ticketActor(ticket))
	tracked := &planningPolicyStore{Service: state, effect: effects[0].ID}
	// Prior profile/enrollment installation is independent of this pending
	// launch. The planner subsequently uses only the actual retained claim.
	planner := scopePlanSetup(t, tracked, f, effects[0], nil, func(p *successfulPlanPorts) { p.profileMode = "helper" })
	f.Reservation, f.Record = plan.Reservation, plan
	owner := fixtureServer(t)
	owner.options.Config, owner.deps.Store, owner.deps.Clock = scope.Config, tracked, fixtureClock{}
	owner.verified, owner.bound, owner.controller = true, true, fixtureID(t)
	laneHostFixture(t, owner)
	owner.runtime = api.RuntimeServices{Store: tracked, LaunchPlanner: planner, Helper: &agentOwnerHelper{state: tracked},
		Worker: tracked.sourcePorts, Launcher: &dashPlanLauncher{agentOwnerLauncher: &agentOwnerLauncher{state: tracked}}}
	owner.reconcileEffect(ctx, effects[0], make(effectRetries))
	var completed api.Operation
	call(requestFor(t, "operation.get", api.OperationGetRequest{OperationID: operation.ID}), &completed)
	if owner.fault != nil || completed.ID != operation.ID || completed.Status != "succeeded" || completed.Error != nil || completed.LastSeq == 0 {
		t.Fatalf("HTTP root operation did not complete: status=%s fault=%v", completed.Status, owner.fault)
	}
	retained, err := state.LaunchPlanForOperation(ctx, scope, operation.ID)
	if err != nil || retained.Plan == nil {
		t.Fatal("completed HTTP operation lost its actual plan", err)
	}
	prompt, err := state.Blob(ctx, scope, api.BlobReadRequest{ObjectID: retained.Plan.Runner.Prompt.ID, Limit: api.MaxChunkBytes})
	if err != nil || bytes.Contains(prompt.Data, []byte("Executor-only policy marker.")) || !bytes.Contains(prompt.Data, []byte("Component launch")) {
		t.Fatal("L6 prompt retained the L3 policy or lost its actual task", err)
	}
	approved, err := state.Policy(ctx, scope)
	if err != nil || approved.Context != (api.RoleContext{Level: 3, Role: "executor"}) || len(approved.Rules) != 1 {
		t.Fatal("launch rewrote the approved default instead of resolving its target role", err)
	}
}

func dashRecoveryReady(t *testing.T, host *Server) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); host.launchRecoveryLoop(ctx) }()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("dashboard recovery job did not join")
		}
	}
	t.Cleanup(stop)
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		host.mu.RLock()
		healthy, failure := host.launchJobsActive && host.launchJobsHealthy, host.fault
		host.mu.RUnlock()
		if failure != nil {
			t.Fatal("dashboard recovery job failed", failure)
		}
		if healthy {
			return stop
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("dashboard recovery job did not become healthy")
		}
	}
}

func ticketActor(ticket api.Ticket) api.Actor {
	return api.Actor{Kind: "human", ID: ticket.PrincipalID}
}

type dashPlanLauncher struct{ *agentOwnerLauncher }

func (l *dashPlanLauncher) Prepare(ctx context.Context, spec api.LaunchSpec) (api.PreparedLaunch, error) {
	parent, ok := api.EffectLeaseFromContext(ctx)
	if !ok {
		return api.PreparedLaunch{}, serviceError(api.CodeUnauthenticated, "planning claim is absent")
	}
	scope := api.Scope{Config: l.state.sourcePorts.f.Deps.Config, Actor: api.Actor{Kind: "service", ID: parent.Record.ClaimantID}, Source: "worker"}
	record, err := l.state.LaunchPlan(ctx, scope, spec.PlanID)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	return api.PreparedLaunch{ID: api.ID("prepared-" + string(spec.LaunchID)), SpecSHA256: record.Handoff.SpecSHA256, Target: spec.Target,
		ContainmentID: record.Plan.Lease.ContainmentID, ProcessGeneration: "dash-component", EndpointGeneration: record.Plan.Lease.EndpointGeneration,
		GateID: api.ID("gate-" + string(spec.LaunchID))}, nil
}
