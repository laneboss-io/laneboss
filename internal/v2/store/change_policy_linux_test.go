//go:build linux

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/approval"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/policy"
	"laneboss.io/laneboss/internal/v2/templates"
)

func canonicalApplyFixture(t *testing.T) (*Service, Dependencies, api.Transaction, api.EffectivePolicy) {
	t.Helper()
	s, deps, proposal := changeFixture(t)
	ctx := context.Background()
	var org api.OrgSnapshot
	if err := storedProjection(ctx, s.db, "org", api.ID(deps.Config), &org); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ path, kind, name string }{
		{templates.OrgTemplatePath, "prompt", "default.md"},
		{templates.OrgDriversPath, "drivers", "drivers.toml"},
		{templates.WorkflowPath, "policy", "workflow.toml"},
	} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "templates", "v2", "org", item.name))
		if err != nil {
			t.Fatal(err)
		}
		content := policyObject(t, s, raw)
		org.Sources = append(org.Sources, api.ResourceFile{Source: api.SourceRef{ID: testID(t), Path: item.path, SHA256: content.SHA256, Generation: 1}, Content: content, Kind: item.kind, Mode: 0444, RevisionGeneration: 1})
	}
	judge := policy.DefaultJudgeConfig(testDigest([]byte("deployment")), testDigest([]byte("tokenizer")), 32768)
	half, cutoff, exclusions := int64(3600), .5, []api.ID{}
	rules := []api.Rule{{ID: testID(t), Text: "Keep the current reviewed result.", Instead: "Request review.", Band: "refuse", Scope: api.RuleScope{Levels: []int{}, Roles: []string{}}}}
	thresholds := api.Thresholds{Match: .85, UncertainLow: .4, UncertainHigh: .6, CalibrationID: testID(t)}
	doc := policy.CanonicalDocument{Schema: "laneboss.policy-source.v2", Thresholds: thresholds, Rules: rules, Skip: []api.SkipEntry{}, Settings: []api.SettingValue{}, Judge: &judge, GuidanceHalfLifeSeconds: &half, GuidanceMinRelevance: &cutoff, ProfileExclusions: &exclusions}
	content := policyObject(t, s, enrollmentJSON(t, doc))
	source := api.SourceRef{ID: testID(t), Path: policy.CanonicalPath, SHA256: content.SHA256, Generation: 1}
	org.Sources = append(org.Sources, api.ResourceFile{Source: source, Content: content, Kind: "policy", Mode: 0444, RevisionGeneration: 1})
	before, err := policy.Resolve(4, api.RoleContext{Level: 6, Role: "supervisor"}, []policy.Layer{{Source: source, Thresholds: thresholds, Rules: rules, Skip: []api.SkipEntry{}}}, judge, half)
	if err != nil {
		t.Fatal(err)
	}
	fixtureProjection(t, s, "org", org.Ref.OrgID, 1, org)
	fixtureProjection(t, s, "policy", api.ID(deps.Config), before.Generation, before)
	doc.Rules[0].Text = "Keep the newly reviewed result."
	updated := policyObject(t, s, enrollmentJSON(t, doc))
	derived := policyObject(t, s, []byte("reviewed generated policy output\n"))
	change := proposal.Writes.Changes[0]
	change.SourceSnapshot = org.Ref
	change.Files = []api.ResourceDelta{{Path: policy.CanonicalPath, Action: "replace", BeforeSHA256: source.SHA256, After: &updated, Mode: 0444}}
	change.Derived = []api.ResourceDelta{{Path: "derived/policy.txt", Action: "add", After: &derived, Mode: 0444}}
	change.ManifestSHA256, err = approval.ManifestDigest(change)
	if err != nil {
		t.Fatal(err)
	}
	proposal.Writes.Changes[0] = change
	proposal.Scope.Request = testRequest(t, "org.change.propose", api.ChangeProposeRequest{OrgID: change.OrgID, BaseGeneration: change.BaseGeneration, Files: change.Files, Reason: change.Reason})
	proposal.Events[0].Payload = enrollmentJSON(t, api.ChangeEvent{Change: change, Reason: "exact canonical policy update"})
	proposal.Reply.Result = enrollmentJSON(t, change)
	s, deps, tx := deferredChangeFrom(t, s, deps, proposal)
	return s, deps, tx, before
}

func TestPlanCanonicalPublishedPolicy(t *testing.T) {
	s, deps, tx, before := canonicalApplyFixture(t)
	ctx := context.Background()
	if _, err := s.Transact(ctx, tx); err != nil {
		t.Fatal("approved canonical policy change did not reach publication", err)
	}
	publisher, lease, publication := publicationClaim(t, s, tx)
	receipt, err := s.PublishChange(ctx, publisher, publication)
	if err != nil {
		t.Fatal("canonical source generation was not published", err)
	}
	if _, err := s.CompleteEffect(ctx, publisher, publicationOutcome(t, tx, lease, receipt)); err != nil {
		t.Fatal("canonical policy completion failed", err)
	}
	wantGeneration := before.Generation + 1
	human := cacheHuman(t, s, api.Scope{Config: deps.Config, PolicyGeneration: wantGeneration})
	expiry := api.Timestamp(time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339Nano))
	taskBytes := []byte("# Canonical launch\n")
	taskRef := api.BlobRef{ID: testID(t), Class: "task", SHA256: testDigest(taskBytes), Bytes: int64(len(taskBytes))}
	cause := api.InternalIntent{ID: testID(t), Kind: api.InternalOrgBootstrap, Config: deps.Config, Actor: publisher.Actor, RequestedBy: human.Actor}
	taskWrite := api.ObjectWrite{ObjectKey: taskRef.ID, Class: taskRef.Class, Bytes: taskBytes, SHA256: taskRef.SHA256, Origin: "service",
		ACL: api.ObjectACL{Config: deps.Config, Owner: human.Actor, Audience: "owner", Generation: 1}}
	profile := api.ProfileGrant{ID: testID(t), ProfileID: testID(t), Driver: api.DriverCodex, Provider: "component-provider", Delegate: true, ExpiresAt: expiry}
	ceiling := api.GrantSet{ID: testID(t), LifeID: testID(t), Generation: 1, PolicyGeneration: wantGeneration, ExpiresAt: expiry,
		Resources: []api.ResourceGrant{}, Data: []api.DataGrant{}, Secrets: []api.SecretGrant{},
		Profiles: []api.ProfileGrant{profile}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	sealed, err := api.CanonicalJSON(enrollmentJSON(t, ceiling))
	if err != nil {
		t.Fatal(err)
	}
	ceiling.SHA256 = testDigest(sealed)
	if _, err := s.Transact(ctx, api.Transaction{Scope: publisher, Internal: &cause, Writes: api.StateWrites{Grants: []api.GrantSet{ceiling}, Objects: []api.ObjectWrite{taskWrite}}}); err != nil {
		t.Fatal(err)
	}
	ticket := api.Ticket{ID: testID(t), PrincipalID: human.Actor.ID, Config: deps.Config, EndpointGeneration: human.EndpointGeneration,
		Level: 5, Role: "supervisor", GrantSetID: ceiling.ID, ExpiresAt: expiry}
	fixtureProjection(t, s, "ticket", ticket.ID, 1, ticketRecord{PrincipalID: human.Actor.ID, Config: deps.Config, EndpointGeneration: human.EndpointGeneration, Ticket: ticket})
	start := api.StartRequest{Lane: string(testID(t)), ProjectID: testID(t), Level: 5, Role: "supervisor", Task: taskRef,
		Driver: api.DriverCodex, ProfileGrantID: profile.ID, Model: "fixture-model", Effort: "high",
		RootTicketID: ticket.ID, ExpectedPolicyGeneration: wantGeneration,
		Budget: api.Budget{WallMS: 60000, CPUSeconds: 10, MemoryBytes: 1 << 20, Processes: 10, DiskBytes: 1 << 20, Currency: "USD"},
		Grants: api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{}, Secrets: []api.SecretDelegation{},
			Profiles: []api.ProfileDelegation{{ParentGrantID: profile.ID, ProfileID: profile.ProfileID, Delegate: true, ExpiresAt: expiry}},
			Network:  []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}}
	human.Request = testRequest(t, "lane.start", start)
	human.Frame = &archFrame{raw: enrollmentJSON(t, human.Request)}
	reserved, err := s.ReserveRequest(ctx, api.RequestReservation{Scope: human, RawRequest: human.Frame.Bytes(), Deadline: expiry})
	if err != nil {
		t.Fatal(err)
	}
	guard := api.TransactionGuard{Ticket: &api.TicketUse{TicketID: ticket.ID, PrincipalID: human.Actor.ID, Config: deps.Config,
		EndpointGeneration: human.EndpointGeneration, Level: start.Level, Role: start.Role, GrantSetID: ceiling.ID}}
	request := api.LaunchReservationRequest{OperationID: reserved.Operation.ID, Guards: []api.TransactionGuard{guard}}
	stale := human
	stale.PolicyGeneration = before.Generation
	if _, err := s.ReserveLaunch(ctx, stale, request); err == nil {
		t.Fatal("canonical launch accepted a stale policy generation")
	} else {
		expectCode(t, err, api.CodeConflict)
	}
	launch, err := s.ReserveLaunch(ctx, human, request)
	if err != nil {
		t.Fatal("canonical launch reservation failed", err)
	}
	effects, err := s.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var planEffect api.Effect
	for _, effect := range effects {
		if effect.PlanLaunch != nil && effect.PlanLaunch.ReservationID == launch.ID {
			planEffect = effect
		}
	}
	if planEffect.ID == "" {
		t.Fatal("launch reservation did not enqueue its PlanLaunch effect")
	}
	worker := api.Scope{Config: deps.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}, Source: "worker"}
	claim, err := s.ClaimEffect(ctx, worker, api.EffectClaimRequest{EffectID: planEffect.ID, ExpectedGeneration: 1, ClaimantID: worker.Actor.ID, Deadline: expiry})
	if err != nil {
		t.Fatal(err)
	}
	// This is the service executor's plan_policy boundary in reconcile.go:
	// its fresh internal claim has no caller-selected policy generation.
	current, err := s.Policy(ctx, worker)
	if err != nil {
		t.Fatal("PlanLaunch worker claim could not bind current canonical policy", err)
	}
	worker.PolicyGeneration = current.Generation
	record, err := s.LaunchPlan(ctx, worker, launch.ID)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := api.PolicyGenerationFor(api.PolicyNewLaunch, current.Generation, 0)
	if err != nil || worker.PolicyGeneration != wantGeneration || generation != record.Reservation.PolicyGeneration {
		t.Fatal("bound planner policy generation differed from the canonical launch reservation", err, worker.PolicyGeneration, generation, record.Reservation.PolicyGeneration)
	}
	if err := s.currentLaunch(ctx, s.db, record); err != nil {
		t.Fatal("unchanged canonical launch policy was refused", err)
	}
	planner, err := lifecycle.New(lifecycle.Dependencies{Store: s,
		Identity: &struct{ api.Authenticator }{}, Clock: deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	// Exercise actual PlanLaunch after binding the executor. The deliberately
	// absent grant resolver is the next boundary; no helper or model starts.
	_, err = planner.PlanLaunch(ctx, worker, api.LaunchPlanRequest{Lease: claim})
	var boundary *api.Error
	if !errors.As(err, &boundary) || boundary.Code != api.CodeNotImplemented ||
		boundary.Owner != "lb-v2-grants" {
		t.Fatal("PlanLaunch did not advance past its canonical policy fence", err)
	}
	retained, err := s.LaunchPlan(ctx, worker, launch.ID)
	if err != nil || retained.Phase != "reserved" || retained.Generation != record.Generation {
		t.Fatal("policy read retried or changed the original reservation", err)
	}
	current.Generation++
	current.SHA256 = ""
	current.SHA256 = testDigest(enrollmentJSON(t, current))
	fixtureProjection(t, s, "policy", api.ID(deps.Config), current.Generation, current)
	if err := s.currentLaunch(ctx, s.db, record); err == nil {
		t.Fatal("canonical launch accepted a changed policy generation")
	} else {
		expectCode(t, err, api.CodeConflict)
	}
}

func TestCanonicalD6Publication(t *testing.T) {
	s, deps, tx, before := canonicalApplyFixture(t)
	ctx := context.Background()
	if _, err := s.Transact(ctx, tx); err != nil {
		t.Fatal("approved canonical policy change did not reach publication", err)
	}
	scope, lease, request := publicationClaim(t, s, tx)
	receipt, err := s.PublishChange(ctx, scope, request)
	if err != nil {
		t.Fatal("canonical source generation was not published", err)
	}
	var pending api.EffectivePolicy
	if err := storedProjection(ctx, s.db, "policy", api.ID(deps.Config), &pending); err != nil || !reflect.DeepEqual(pending, before) {
		t.Fatal("publication exposed policy before its atomic completion", err)
	}
	outcome := publicationOutcome(t, tx, lease, receipt)
	if _, err := s.CompleteEffect(ctx, scope, outcome); err != nil {
		t.Fatal("canonical policy completion failed", err)
	}
	scope.PolicyGeneration = before.Generation + 1
	after, err := s.Policy(ctx, scope)
	if err != nil || after.Generation != before.Generation+1 || after.Rules[0].Text != "Keep the newly reviewed result." || after.Sources[0].Generation != 2 || after.SHA256 == before.SHA256 {
		t.Fatal("published sources did not become the working current policy", err)
	}
	human := cacheHuman(t, s, api.Scope{Config: s.deps.Config})
	authority, err := human.Connection.ReadAuthority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	enrolled := enrollmentInput(t).Writes.Enrollments[0].Enrollment
	enrolled.Config, enrolled.PrincipalID = deps.Config, human.Actor.ID
	enrolled.Credentials[0].ID = authority.CredentialID
	fixtureProjection(t, s, "enrollment", human.Actor.ID, 1, enrolled)
	human.PolicyGeneration = after.Generation
	read := api.ConfigReadRequest{View: "show"}
	human.Request = testRequest(t, "config.read", read)
	human.Frame = &archFrame{raw: enrollmentJSON(t, human.Request)}
	service, err := policy.NewInstalled(policy.Dependencies{Store: s, Judge: &struct{ api.ScopedJudge }{}, Clock: s.deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	view, err := service.ConfigRead(ctx, human, read)
	if err != nil || view.Generation != 2 || view.Projection.ID == "" {
		t.Fatal("public config show cannot consume the newly published policy", err)
	}
	if _, err := s.CompleteEffect(ctx, scope, outcome); err != nil {
		t.Fatal("publication replay changed its result", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(deps)
	if err != nil {
		t.Fatal("canonical policy publication did not survive restart", err)
	}
	defer reopened.Close()
	if check, err := reopened.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !check.OK {
		t.Fatal("canonical publication did not verify after restart", err)
	}
}

func policyObject(t *testing.T, s *Service, raw []byte, owners ...api.Actor) api.BlobRef {
	t.Helper()
	actor := api.Actor{Kind: "service", ID: testID(t)}
	owner := actor
	if len(owners) != 0 {
		owner = owners[0]
	}
	scope := api.Scope{Config: s.deps.Config, Actor: actor}
	ref := api.BlobRef{ID: testID(t), Class: "artifact", SHA256: testDigest(raw), Bytes: int64(len(raw))}
	cause := api.InternalIntent{ID: testID(t), Kind: api.InternalOrgBootstrap, Config: scope.Config, Actor: actor, RequestedBy: actor}
	write := api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, Bytes: raw, SHA256: ref.SHA256, Origin: "service", ACL: api.ObjectACL{Config: scope.Config, Owner: owner, Audience: "owner", Generation: 1}}
	if _, err := s.Transact(context.Background(), api.Transaction{Scope: scope, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{write}}}); err != nil {
		t.Fatal(err)
	}
	return ref
}

type policyRenderProbe struct{ api.Launcher }

func (policyRenderProbe) Probe(ctx context.Context) (api.IsolationCapabilities, error) {
	return api.IsolationCapabilities{Available: true, Backend: "linux-bwrap-landlock"}, ctx.Err()
}

func TestCanonicalProposalProducer(t *testing.T) {
	s, _, pending, _ := canonicalApplyFixture(t)
	ctx := context.Background()
	var staged api.ChangeRequest
	if err := storedProjection(ctx, s.db, "change", pending.Effects[0].ApplyChange.ChangeID, &staged); err != nil {
		t.Fatal(err)
	}
	scope := pending.Scope
	_, raw, err := objectRow(ctx, s.db, staged.Files[0].After.ID)
	if err != nil {
		t.Fatal(err)
	}
	after := policyObject(t, s, raw, scope.Actor)
	reason := policyObject(t, s, []byte("review the exact canonical update\n"), scope.Actor)
	request := api.ChangeProposeRequest{OrgID: staged.OrgID, BaseGeneration: staged.BaseGeneration, Reason: reason,
		Files: []api.ResourceDelta{{Path: staged.Files[0].Path, Action: "replace", BeforeSHA256: staged.Files[0].BeforeSHA256, After: &after, Mode: staged.Files[0].Mode}}}
	scope.Request = testRequest(t, "org.change.propose", request)
	scope.Frame = &archFrame{raw: enrollmentJSON(t, scope.Request)}
	reserved, err := s.ReserveRequest(ctx, api.RequestReservation{Scope: scope, RawRequest: scope.Frame.Bytes(), Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := dataworker.New(dataworker.Dependencies{Config: s.deps.Config, Store: s, Helper: &struct{ api.HelperControl }{}, Launcher: policyRenderProbe{}, Clock: s.deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	service, err := approval.New(approval.Dependencies{Store: s, Human: &struct{ api.HumanVerifier }{}, Worker: worker, Publisher: worker, Clock: s.deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.OrgChangePropose(ctx, scope, request)
	if err != nil {
		t.Fatal("canonical proposal did not produce real reviewed effects", err)
	}
	if len(got.Derived) == 0 || got.Diff.ID == "" || got.ManifestSHA256 == "" {
		t.Fatal("proposal omitted its actual effects or diff")
	}
	derived, err := s.Blob(ctx, scope, api.BlobReadRequest{ObjectID: got.Derived[0].After.ID, Limit: api.MaxChunkBytes})
	if err != nil || !bytes.Contains(derived.Data, []byte("Keep the newly reviewed result.")) {
		t.Fatal("derived policy does not reflect changed input", err)
	}
	var document policy.CanonicalDocument
	if err := json.Unmarshal(raw, &document); err != nil || !bytes.Contains(derived.Data, []byte(document.Rules[0].ID)) {
		t.Fatal("derived policy omits the unpredictable source rule identity", err)
	}
	diff, err := s.Blob(ctx, scope, api.BlobReadRequest{ObjectID: got.Diff.ID, Limit: api.MaxChunkBytes})
	if err != nil || !bytes.Contains(diff.Data, []byte("Keep the current reviewed result.")) || !bytes.Contains(diff.Data, []byte("Keep the newly reviewed result.")) {
		t.Fatal("owner diff omits the actual before or after bytes", err)
	}
	meta, err := s.ObjectMetadata(ctx, scope, got.Diff.ID)
	if err != nil || meta.SourceOperationID != reserved.Operation.ID {
		t.Fatal("render lost its original proposal operation", err)
	}
	again, err := service.OrgChangePropose(ctx, scope, request)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatal("proposal replay regenerated effects", err)
	}
	human := cacheHuman(t, s, api.Scope{Config: s.deps.Config})
	authority, err := human.Connection.ReadAuthority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	enrolled := enrollmentInput(t).Writes.Enrollments[0].Enrollment
	enrolled.Config, enrolled.PrincipalID = s.deps.Config, human.Actor.ID
	enrolled.Credentials[0].ID = authority.CredentialID
	fixtureProjection(t, s, "enrollment", human.Actor.ID, 1, enrolled)
	human.Request = testRequest(t, "org.change.get", api.ChangeGetRequest{ChangeID: got.ID})
	human.ReadAuthority = &authority
	human.Frame = &archFrame{raw: enrollmentJSON(t, human.Request)}
	review, err := service.OrgChangeGet(ctx, human, api.ChangeGetRequest{ChangeID: got.ID})
	if err != nil || !reflect.DeepEqual(got, review) {
		t.Fatal("human cannot inspect the actual staged change", err)
	}
	for _, ref := range []api.BlobRef{got.Diff, got.Reason, *got.Files[0].After, *got.Derived[0].After} {
		chunk, err := s.Blob(ctx, human, api.BlobReadRequest{ObjectID: ref.ID, Limit: api.MaxChunkBytes})
		if err != nil || len(chunk.Data) == 0 {
			t.Fatal("human cannot review the exact proposed source or derived bytes", err)
		}
	}
	// This supplies an explicit component approval, not a physical gesture.
	// Propose, render, apply, publication and readback use their real owners.
	approved := api.ChangeApproval{ID: testID(t), ChangeID: got.ID, RequesterLifeID: scope.Actor.LifeID, ApproverKeyID: authority.CredentialID, NonceID: testID(t), ManifestSHA256: got.ManifestSHA256, BaseGeneration: got.BaseGeneration,
		ApprovedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}
	fixtureProjection(t, s, "approval", approved.ID, 1, approved)
	fixtureProjection(t, s, "lane", scope.Actor.LifeID, 1, api.Lane{LifeID: scope.Actor.LifeID, Level: scope.Actor.Level, Role: scope.Actor.Role, Run: 1, Generation: 1, PolicyGeneration: 4, LaunchID: scope.LaunchID, State: "running", CancellationEpoch: 1})
	apply := api.ChangeApplyRequest{ChangeID: got.ID, ApprovalID: approved.ID, ExpectedGeneration: got.BaseGeneration}
	applyScope := scope
	applyScope.Request = testRequest(t, "org.change.apply", apply)
	applyScope.Frame = &archFrame{raw: enrollmentJSON(t, applyScope.Request)}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := s.ReserveRequest(bounded, api.RequestReservation{Scope: applyScope, RawRequest: applyScope.Frame.Bytes(), Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}); err != nil {
		t.Fatal(err)
	}
	type result struct {
		receipt api.ChangeReceipt
		err     error
	}
	done := make(chan result, 1)
	go func() { value, err := service.OrgChangeApply(bounded, applyScope, apply); done <- result{value, err} }()
	var deferred api.MutationReceipt
	for deferred.Deferred == nil {
		s.mu.RLock()
		changed := s.changed
		s.mu.RUnlock()
		deferred, err = s.LookupReceipt(bounded, applyScope, requestKey(applyScope.Request))
		if err != nil {
			t.Fatal(err)
		}
		if deferred.Deferred != nil {
			break
		}
		select {
		case early := <-done:
			t.Fatal("apply returned before its publisher", early.err)
		case <-bounded.Done():
			t.Fatal("public apply did not enqueue its actual publication")
		case <-changed:
		}
	}
	tx := api.Transaction{Scope: applyScope, Deferred: deferred.Deferred}
	publisher, lease, publication := publicationClaim(t, s, tx)
	measured, err := s.PublishChange(bounded, publisher, publication)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteEffect(bounded, publisher, publicationOutcome(t, tx, lease, measured)); err != nil {
		t.Fatal(err)
	}
	completed := <-done
	if completed.err != nil || completed.receipt != measured {
		t.Fatal("public apply lost measured publication", completed.err)
	}
}

func policyApplyFixture(t *testing.T) (*Service, Dependencies, api.Transaction, api.EffectivePolicy) {
	t.Helper()
	s, deps, proposal, p := policyProposal(t)
	s, deps, tx := deferredChangeFrom(t, s, deps, proposal)
	return s, deps, tx, p
}

func policyProposal(t *testing.T) (*Service, Dependencies, api.Transaction, api.EffectivePolicy) {
	t.Helper()
	s, deps, proposal := changeFixture(t)
	var snapshot api.OrgSnapshot
	if err := storedProjection(context.Background(), s.db, "org", api.ID(deps.Config), &snapshot); err != nil {
		t.Fatal(err)
	}
	// This is an already approved component policy, not a renderer or an
	// installer ceremony. The unchanged source is an actual committed object.
	content := policyObject(t, s, []byte("Do not publish unreviewed output.\n"))
	source := api.SourceRef{ID: testID(t), Path: "shared/policy.txt", SHA256: content.SHA256, Generation: 1}
	snapshot.Sources = []api.ResourceFile{{Source: source, Content: content, Kind: "policy", Mode: 0600, RevisionGeneration: 1}}
	snapshot.Ref.ManifestSHA256 = testDigest(enrollmentJSON(t, snapshot.Sources))
	fixtureProjection(t, s, "org", snapshot.Ref.OrgID, 1, snapshot)
	p, err := policy.Resolve(4, api.RoleContext{Level: 6, Role: "supervisor"}, []policy.Layer{{Source: source,
		Thresholds: api.Thresholds{Match: 0.85, UncertainLow: 0.4, UncertainHigh: 0.6, CalibrationID: testID(t)},
		Rules:      []api.Rule{{ID: testID(t), Text: "Do not publish unreviewed output.", Instead: "Request review.", Band: "refuse", Scope: api.RuleScope{Levels: []int{}, Roles: []string{}}}}}},
		policy.DefaultJudgeConfig(testDigest([]byte("deployment")), testDigest([]byte("tokenizer")), 32768), 3600)
	if err != nil {
		t.Fatal(err)
	}
	fixtureProjection(t, s, "policy", api.ID(deps.Config), p.Generation, p)
	change := proposal.Writes.Changes[0]
	change.SourceSnapshot = snapshot.Ref
	derived := policyObject(t, s, []byte("reviewed generated output\n"))
	change.Derived = []api.ResourceDelta{{Path: "derived/settings.txt", Action: "add", Mode: 0600, After: &derived}}
	change.ManifestSHA256, err = approval.ManifestDigest(change)
	if err != nil {
		t.Fatal(err)
	}
	proposal.Writes.Changes[0] = change
	proposal.Events[0].Payload = enrollmentJSON(t, api.ChangeEvent{Change: change, Reason: "retained exact render fixture"})
	proposal.Reply.Result = enrollmentJSON(t, change)
	return s, deps, proposal, p
}

func TestChangePolicyAdvance(t *testing.T) {
	for _, defect := range []string{"publish", "foreign_source", "stale_source", "changed_source", "missing_object", "missing_policy", "changed_policy", "changed_completion", "tampered_compiler", "policy_binding", "channel", "skip", "capture", "replay"} {
		t.Run(defect, func(t *testing.T) {
			s, deps, tx, before := policyApplyFixture(t)
			ctx := context.Background()
			p := before
			p.Sources = append([]api.SourceRef{}, before.Sources...)
			p.Rules = append([]api.Rule{}, before.Rules...)
			switch defect {
			case "foreign_source":
				p.Sources[0].ID = testID(t)
			case "stale_source":
				p.Sources[0].Generation++
			case "changed_source":
				p.Sources[0].SHA256 = testDigest([]byte("unapproved source"))
			case "missing_object":
				var snapshot api.OrgSnapshot
				if err := storedProjection(ctx, s.db, "org", api.ID(deps.Config), &snapshot); err != nil {
					t.Fatal(err)
				}
				snapshot.Sources[0].Content.ID = testID(t)
				fixtureProjection(t, s, "org", snapshot.Ref.OrgID, 1, snapshot)
			case "missing_policy":
				if _, err := s.db.Exec("DELETE FROM projections WHERE kind='policy'"); err != nil {
					t.Fatal(err)
				}
			case "channel":
				channel := api.EnrolledChannel{ID: testID(t), Config: deps.Config, Generation: 1, Source: before.Sources[0]}
				fixtureProjection(t, s, "channel", channel.ID, 1, channel)
			case "skip":
				p.Skip = []api.SkipEntry{{ID: testID(t), Description: "approved exemption", RuleSetSHA256: testDigest([]byte("rules")), ContextSHA256: testDigest([]byte("context")), Source: p.Sources[0]}}
			case "capture":
				p.AllowCaptureRefusal, p.CaptureRefusalApprovalID = true, testID(t)
			}
			if defect == "foreign_source" || defect == "stale_source" || defect == "changed_source" {
				p.GuidanceSource, p.Rules[0].Source = p.Sources[0], p.Sources[0]
			}
			if defect == "foreign_source" || defect == "stale_source" || defect == "changed_source" || defect == "skip" || defect == "capture" {
				p.SHA256 = ""
				p.SHA256 = testDigest(enrollmentJSON(t, p))
				fixtureProjection(t, s, "policy", api.ID(deps.Config), p.Generation, p)
			}
			commit, err := s.Transact(ctx, tx)
			if defect != "publish" && defect != "changed_policy" && defect != "changed_completion" && defect != "tampered_compiler" && defect != "policy_binding" && defect != "replay" {
				if err == nil {
					t.Fatal("publication accepted policy prerequisite defect", defect)
				}
				var effects int
				if err := s.db.QueryRow("SELECT count(*) FROM effects WHERE id=?", string(tx.Deferred.EffectID)).Scan(&effects); err != nil || effects != 0 {
					t.Fatal("policy refusal retained a publication effect", err)
				}
				return
			}
			if err != nil || commit.Deferred == nil {
				t.Fatal("unchanged approved policy prevented unrelated publication", err)
			}
			if defect == "tampered_compiler" || defect == "policy_binding" {
				if check, err := s.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !check.OK {
					t.Fatal("original pending compiler control did not verify", err)
				}
				var job orgApply
				if err := storedProjection(ctx, s.db, "org_apply", tx.Deferred.OperationID, &job); err != nil {
					t.Fatal(err)
				}
				if job.Policy == nil {
					t.Fatal("publication omitted its retained policy compiler inputs")
				}
				if defect == "policy_binding" {
					old := job.Policy.Before
					old.Generation--
					old.SHA256 = ""
					old.SHA256 = testDigest(enrollmentJSON(t, old))
					fixtureProjection(t, s, "policy", api.ID(deps.Config), old.Generation, old)
					job.Policy.Before = old
					next, err := nextOrgSnapshot(job, api.ChangeReceipt{})
					if err != nil {
						t.Fatal(err)
					}
					job.Policy.After, err = policy.RebindOrgSources(old, job.Snapshot, next)
					if err != nil {
						t.Fatal("substituted input was not a valid compiler control", err)
					}
				} else {
					job.Policy.After.GuidanceMinRelevance = 0.6
					job.Policy.After.SHA256 = ""
					job.Policy.After.SHA256 = testDigest(enrollmentJSON(t, job.Policy.After))
				}
				fixtureProjection(t, s, "org_apply", job.Deferred.OperationID, 1, job)
				fixtureProjection(t, s, "org_apply_gate", job.Change.OrgID, job.Change.BaseGeneration, job)
				if check, err := s.Verify(ctx, api.VerifyRequest{Scope: "all"}); err == nil && check.OK {
					t.Fatal("verification accepted substituted policy compiler state", defect)
				}
				return
			}
			scope, lease, request := publicationClaim(t, s, tx)
			if defect == "changed_policy" {
				p.Generation++
				p.GuidanceHalfLifeSeconds++
				p.SHA256 = ""
				p.SHA256 = testDigest(enrollmentJSON(t, p))
				fixtureProjection(t, s, "policy", api.ID(deps.Config), p.Generation, p)
				if _, err := s.PublishChange(ctx, scope, request); err == nil {
					t.Fatal("publication silently recompiled changed policy inputs")
				}
				return
			}
			receipt, err := s.PublishChange(ctx, scope, request)
			if err != nil {
				t.Fatal(err)
			}
			var pending api.EffectivePolicy
			if err := storedProjection(ctx, s.db, "policy", api.ID(deps.Config), &pending); err != nil || !reflect.DeepEqual(pending, before) {
				t.Fatal("filesystem publication changed policy before measured completion", err)
			}
			outcome := publicationOutcome(t, tx, lease, receipt)
			if defect == "changed_completion" {
				p.Generation++
				p.GuidanceHalfLifeSeconds++
				p.SHA256 = ""
				p.SHA256 = testDigest(enrollmentJSON(t, p))
				fixtureProjection(t, s, "policy", api.ID(deps.Config), p.Generation, p)
				if _, err := s.CompleteEffect(ctx, scope, outcome); err == nil {
					t.Fatal("completion accepted changed policy compiler inputs")
				}
				return
			}
			if _, err := s.CompleteEffect(ctx, scope, outcome); err != nil {
				t.Fatal(err)
			}
			if defect == "replay" {
				if replay, err := s.CompleteEffect(ctx, scope, outcome); err != nil || !replay.Replayed {
					t.Fatal("policy publication replay was not exact", err)
				}
			}
			after, err := s.Policy(ctx, scope)
			if err != nil || after.Generation != before.Generation+1 || after.SHA256 == before.SHA256 || after.Sources[0].Generation != 2 || after.GuidanceSource != after.Sources[0] || after.Rules[0].Source != after.Sources[0] {
				t.Fatal("policy and all defining references did not advance atomically", err)
			}
			if after.Rules[0].Text != before.Rules[0].Text || after.Judge != before.Judge || after.Sources[0].SHA256 != before.Sources[0].SHA256 {
				t.Fatal("provenance compilation changed approved policy semantics")
			}
			final, err := s.LookupReceipt(ctx, tx.Scope, tx.Deferred.Key)
			if err != nil || final.PolicyGeneration != before.Generation {
				t.Fatal("publication rewrote its original request policy stamp", err)
			}
			old, err := s.PolicyAt(ctx, scope, before.Generation)
			if err != nil || !reflect.DeepEqual(old, before) {
				t.Fatal("policy compilation rewrote historical approval", err)
			}
			snapshot, err := s.OrgSnapshot(ctx, scope, api.OrgSnapshotRequest{OrgID: api.ID(deps.Config), Generation: 2})
			if err != nil {
				t.Fatal(err)
			}
			if err := api.ValidateOrgKinds(snapshot); err != nil {
				t.Fatal("publication did not retain canonical inventory kinds", err)
			}
			retained, err := s.Source(ctx, scope, after.Sources[0])
			if err != nil || retained.Source != after.Sources[0] || retained.Content.SHA256 != before.Sources[0].SHA256 {
				t.Fatal("current consumer could not read the compiled defining source", err)
			}
			if _, err := s.Source(ctx, scope, before.Sources[0]); err == nil {
				t.Fatal("current source lookup accepted historical policy provenance")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := New(deps)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if check, err := reopened.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !check.OK {
				t.Fatal("compiled policy publication failed independent reopen", err)
			}
		})
	}
}
