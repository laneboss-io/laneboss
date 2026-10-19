//go:build linux

package store_test

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func readRetentionFixture(t *testing.T) (*fx.Fixture, api.RetainObjectRequest) {
	t.Helper()
	f := publicBriefingFixture(t)
	f.Human.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: "brief.start", RequestID: fx.ID(t), Params: fx.JSON(t, api.BriefingRequest{Level: f.Lane.Level, Role: f.Lane.Role})}
	f.Human.Frame = &fx.Frame{Raw: fx.JSON(t, f.Human.Request)}
	body := []byte("Read the full retained task and approved rules.\n")
	intent := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalObjectRetain, Config: f.Deps.Config, Actor: api.Actor{Kind: "service", ID: "lb-v2-templates"}, RequestedBy: f.Human.Actor, CauseRequestID: f.Human.Request.RequestID, Target: f.Reservation.Target, LogicalTurnID: f.Lane.LogicalTurnID, CancellationEpoch: f.Lane.CancellationEpoch}
	return f, api.RetainObjectRequest{Intent: intent, Object: api.ObjectWrite{ObjectKey: fx.ID(t), Class: "prompt", Bytes: body, SHA256: fx.Digest(body), Origin: "service", InputRefs: []api.BlobRef{f.Lane.Task}, ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Human.Actor, LifeID: f.Lane.LifeID, Audience: "life", Generation: 1}}}
}

func TestItem4PublicReadRetention(t *testing.T) {
	f, request := readRetentionFixture(t)
	ref, err := f.State.RetainObject(context.Background(), f.Human, request)
	if err != nil || ref.SHA256 != request.Object.SHA256 {
		t.Fatal("authenticated briefing read could not retain its generated prompt", err)
	}
	metadata, err := f.State.ObjectMetadata(context.Background(), f.Human, ref.ID)
	if err != nil || metadata.SourceOperationID == "" || metadata.ACL.Owner != f.Human.Actor {
		t.Fatal("read projection has no real causal operation or principal", err)
	}
	replay, err := f.State.RetainObject(context.Background(), f.Human, request)
	if err != nil || replay != ref {
		t.Fatal("read retention replay changed immutable bytes", err)
	}
}

func TestItem4PublicReadRetentionFences(t *testing.T) {
	for _, name := range []string{"foreign_life", "foreign_owner", "missing_input", "wrong_method", "wrong_emitter", "stale_frame"} {
		t.Run(name, func(t *testing.T) {
			f, request := readRetentionFixture(t)
			switch name {
			case "foreign_life":
				request.Intent.Target.LifeID = fx.ID(t)
			case "foreign_owner":
				request.Object.ACL.Owner.ID = fx.ID(t)
			case "missing_input":
				request.Object.InputRefs[0].ID = fx.ID(t)
			case "wrong_method":
				f.Human.Request.Method = "judge.list"
			case "wrong_emitter":
				request.Intent.Actor.ID = "lb-v2-policy"
			case "stale_frame":
				f.Human.Frame = &fx.Frame{Raw: []byte("{}")}
			}
			if _, err := f.State.RetainObject(context.Background(), f.Human, request); err == nil {
				t.Fatal("read retention accepted " + name)
			}
		})
	}
}

func policyRetentionFixture(t *testing.T) (*fx.Fixture, api.RetainObjectRequest) {
	t.Helper()
	f, judge := judgeExecutionFixture(t)
	input := api.PolicyEvaluateRequest{Target: f.Reservation.Target, LogicalTurnID: f.Lane.LogicalTurnID, Command: *judge.Request.Command}
	f.Admit(t, "policy.evaluate", input)
	body := fx.JSON(t, input)
	intent := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalObjectRetain, Config: f.Deps.Config, Actor: api.Actor{Kind: "service", ID: "lb-v2-policy"}, RequestedBy: f.Human.Actor, CauseOperationID: f.Receipt.Operation.ID, CauseRequestID: f.Human.Request.RequestID, Target: f.Reservation.Target, LogicalTurnID: f.Lane.LogicalTurnID}
	return f, api.RetainObjectRequest{Intent: intent, Object: api.ObjectWrite{ObjectKey: fx.ID(t), Class: "judge_request", Bytes: body, SHA256: fx.Digest(body), Origin: "service", InputRefs: []api.BlobRef{f.Lane.Task}, ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Human.Actor, LifeID: f.Lane.LifeID, Audience: "owner", Generation: 1}}}
}

func TestItem4PolicyAuditRetention(t *testing.T) {
	f, request := policyRetentionFixture(t)
	ref, err := f.State.RetainObject(context.Background(), f.Human, request)
	if err != nil || ref.SHA256 != request.Object.SHA256 {
		t.Fatal("reserved policy operation could not retain its actual generated audit input", err)
	}
	metadata, err := f.State.ObjectMetadata(context.Background(), f.Human, ref.ID)
	if err != nil || metadata.SourceOperationID != f.Receipt.Operation.ID || metadata.ACL.Owner != f.Human.Actor {
		t.Fatal("policy retention changed its original parent or principal", err)
	}
}

func TestApprovedPolicyAuditInput(t *testing.T) {
	f, request := policyRetentionFixture(t)
	ctx := context.Background()
	raw := []byte("exact approved source from another L6\n")
	ref := api.BlobRef{ID: fx.ID(t), Class: "artifact", SHA256: fx.Digest(raw), Bytes: int64(len(raw))}
	owner := api.Actor{Kind: "lane", ID: fx.ID(t), LifeID: fx.ID(t), Level: 6, Role: "supervisor"}
	cause := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalObjectRetain, Config: f.Deps.Config, Actor: f.Execution.Actor, RequestedBy: owner}
	object := api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, SHA256: ref.SHA256, Bytes: raw, Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: owner, Audience: "owner", Generation: 1}}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{object}}}); err != nil {
		t.Fatal(err)
	}
	org := api.OrgSnapshot{Config: f.Deps.Config, Ref: api.OrgSnapshotRef{OrgID: api.ID(f.Deps.Config), Generation: 1, ManifestSHA256: fx.Digest(raw)},
		Sources: []api.ResourceFile{{Source: api.SourceRef{ID: fx.ID(t), Path: ".laneboss/policy.json", SHA256: ref.SHA256, Generation: 1}, Content: ref, Kind: "policy", Mode: 0444, RevisionGeneration: 1}}}
	f.Replace(t, "org", api.ID(f.Deps.Config), 1, org)
	request.Object.InputRefs = append(request.Object.InputRefs, ref)
	retained, err := f.State.RetainObject(ctx, f.Human, request)
	if err != nil {
		t.Fatal("approved source could be read but not consumed by the policy audit", err)
	}
	metadata, err := f.State.ObjectMetadata(ctx, f.Human, retained.ID)
	if err != nil || metadata.Ref.SHA256 != request.Object.SHA256 || metadata.SourceOperationID != f.Receipt.Operation.ID {
		t.Fatal("audit did not retain its exact approved source and original operation", err)
	}
}

func TestItem4PolicyAuditRetentionFences(t *testing.T) {
	for _, name := range []string{"parent", "requester", "target", "emitter", "class", "input"} {
		t.Run(name, func(t *testing.T) {
			f, request := policyRetentionFixture(t)
			switch name {
			case "parent":
				request.Intent.CauseOperationID = fx.ID(t)
			case "requester":
				request.Intent.RequestedBy.ID = fx.ID(t)
			case "target":
				request.Intent.Target.LifeID = fx.ID(t)
			case "emitter":
				request.Intent.Actor.ID = "lb-v2-templates"
			case "class":
				request.Object.Class = "prompt"
			case "input":
				request.Object.InputRefs[0].ID = fx.ID(t)
			}
			if _, err := f.State.RetainObject(context.Background(), f.Human, request); err == nil {
				t.Fatal("policy retention accepted foreign " + name)
			}
		})
	}
}
