package policy

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func readFixture(f *fixture, method string) error {
	f.scope.Request.Method = api.Method(method)
	switch method {
	case "policy.get":
		_, err := f.service.PolicyGet(context.Background(), f.scope, api.PolicyGetRequest{})
		return err
	case "config.read":
		_, err := f.service.ConfigRead(context.Background(), f.scope, api.ConfigReadRequest{View: "path"})
		return err
	case "config.validate":
		_, err := f.service.ConfigValidate(context.Background(), f.scope, api.Empty{})
		return err
	default:
		return invalid("unknown fixture read")
	}
}

func TestConfiguredInferenceBudget(t *testing.T) {
	f := newFixture(t, sourceRule("ordinary"))
	for _, cost := range []int64{0, -1} {
		service, err := New(Dependencies{Store: f.store, Judge: f.judge, Clock: f.clock, MaxCostMicros: cost})
		wantCode(t, err, api.CodePrerequisite)
		if service != nil || err.(*api.Error).Owner != "lb-v2-integrate" || err.(*api.Error).Instead == "" {
			t.Fatal("missing inference ceiling did not name assembly prerequisite")
		}
	}
	deps := f.service.deps
	deps.MaxCostMicros = 37
	service, err := New(deps)
	if err != nil {
		t.Fatal(err)
	}
	f.service = service
	f.judge.probability = 1
	decision, err := f.evaluateOnce(context.Background())
	if err != nil || len(f.judge.requests) != 1 || f.judge.requests[0].MaxCostMicros != 37 || decision.Result != "refuse" ||
		len(decision.Rules) != 1 || decision.Rules[0].Probability == nil {
		t.Fatalf("approved inference ceiling did not reach the judge: %v", err)
	}
}

func TestLanePolicyGenerationDiagnostic(t *testing.T) {
	for _, method := range []string{"policy.get", "config.read", "config.validate", "policy.evaluate"} {
		t.Run(method, func(t *testing.T) {
			f := newFixture(t, sourceRule("ordinary"))
			// Historical pins are legal; a future live projection still refuses.
			f.scope.PolicyGeneration = 7
			f.store.policy.Generation = 7
			f.store.lane.PolicyGeneration = 9
			f.seal(t)
			var err error
			if method == "policy.evaluate" {
				_, err = f.evaluateOnce(context.Background())
			} else {
				err = readFixture(f, method)
			}
			wantCode(t, err, api.CodeConflict)
			refusal := err.(*api.Error)
			if refusal.Message != "recorded life policy generation 9 differs from current policy generation 7" ||
				refusal.Owner != "lb-v2-policy" || refusal.Instead == "" ||
				len(f.judge.fits) != 0 || f.store.retentions != 0 || len(f.store.events) != 0 {
				t.Fatal("generation refusal lost recorded/current values or reached protected work")
			}
		})
	}
}

func TestHumanReadAuthority(t *testing.T) {
	for _, row := range []struct {
		name string
		edit func(*fixture, *testReadConnection)
	}{
		{"missing", func(f *fixture, _ *testReadConnection) { f.scope.Connection = nil }},
		{"no-session", func(_ *fixture, c *testReadConnection) { c.authority.SessionID = "" }},
		{"closed", func(_ *fixture, c *testReadConnection) { c.closed = true }},
		{"revoked", func(_ *fixture, c *testReadConnection) { c.revoked = true }},
		{"idle", func(f *fixture, _ *testReadConnection) { f.clock.now = f.clock.now.Add(5 * time.Minute) }},
		{"absolute", func(f *fixture, c *testReadConnection) {
			c.authority.ExpiresAt = api.Timestamp(f.clock.now.Format(time.RFC3339Nano))
		}},
		{"connection", func(_ *fixture, c *testReadConnection) { c.authority.ConnectionID = "other-connection" }},
		{"principal", func(_ *fixture, c *testReadConnection) { c.authority.PrincipalID = "other-human" }},
		{"config", func(_ *fixture, c *testReadConnection) { c.authority.Config = "other-config" }},
		{"endpoint", func(_ *fixture, c *testReadConnection) { c.authority.EndpointGeneration++ }},
	} {
		t.Run(row.name, func(t *testing.T) {
			for _, method := range []string{"policy.get", "config.read", "config.validate"} {
				f := newFixture(t)
				f.scope.Actor, f.scope.LaunchID = api.Actor{Kind: "human", ID: "reader"}, ""
				connection, err := newReadConnection(f.scope, f.clock)
				if err != nil {
					t.Fatal(err)
				}
				f.scope.Connection = connection
				row.edit(f, connection)
				err = readFixture(f, method)
				if f.store.policyReads+len(f.store.seenScopes)+f.store.retentions != 0 {
					t.Fatal("invalid human read authority reached protected work")
				}
				wantCode(t, err, api.CodeForbidden)
			}
		})
	}
}

func TestMissingJudgeRefusesEvaluation(t *testing.T) {
	f := newFixture(t, sourceRule("ordinary"))
	f.service.deps.Judge = nil
	decision, err := f.evaluateOnce(context.Background())
	wantCode(t, err, api.CodeNotImplemented)
	if err.(*api.Error).Owner != "lb-v2-judge" || decision.ID != "" || len(f.store.events) != 0 {
		t.Fatal("missing judge became an audited noncritical allow")
	}
}

func TestHumanReadRefresh(t *testing.T) {
	for _, method := range []string{"policy.get", "config.read", "config.validate"} {
		f := newFixture(t)
		f.scope.Actor, f.scope.LaunchID = api.Actor{Kind: "human", ID: "reader"}, ""
		connection, err := newReadConnection(f.scope, f.clock)
		if err != nil {
			t.Fatal(err)
		}
		f.scope.Connection = connection
		if err := readFixture(f, method); err != nil {
			t.Fatal(err)
		}
		actual := f.store.lastRead
		if actual.Actor != f.scope.Actor || actual.ReadAuthority == nil ||
			actual.ReadAuthority.ConnectionID != connection.ID() || actual.ReadAuthority.PrincipalID != f.scope.Actor.ID {
			t.Fatal("human read did not pass refreshed connection authority")
		}
	}
}

func TestLaneReadAuthority(t *testing.T) {
	for _, row := range []struct {
		name string
		edit func(*fixture)
		code api.ErrorCode
	}{
		{"cleaned", func(f *fixture) { f.store.lane.Cleaned = true }, api.CodeForbidden},
		{"policy", func(f *fixture) { f.store.lane.PolicyGeneration++ }, api.CodeConflict},
		{"zero-policy", func(f *fixture) { f.store.lane.PolicyGeneration = 0 }, api.CodeConflict},
		{"future-launch-policy", func(f *fixture) { f.store.launch.PolicyGeneration++ }, api.CodeForbidden},
		{"zero-launch-policy", func(f *fixture) { f.store.launch.PolicyGeneration = 0 }, api.CodeForbidden},
		{"future-grant-policy", func(f *fixture) { f.store.grants.PolicyGeneration++ }, api.CodeForbidden},
		{"zero-grant-policy", func(f *fixture) { f.store.grants.PolicyGeneration = 0 }, api.CodeForbidden},
		{"launch", func(f *fixture) { f.store.launch.Revoked = true }, api.CodeForbidden},
		{"launch-id", func(f *fixture) { f.store.lane.LaunchID = "new-launch" }, api.CodeForbidden},
		{"launch-config", func(f *fixture) { f.store.launch.Config = "foreign" }, api.CodeForbidden},
		{"launch-actor", func(f *fixture) { f.store.launch.Actor.ID = "foreign" }, api.CodeForbidden},
		{"endpoint", func(f *fixture) { f.store.launch.EndpointGeneration++ }, api.CodeForbidden},
		{"run", func(f *fixture) { f.store.launch.Target.Run++ }, api.CodeForbidden},
		{"launch-grants", func(f *fixture) { f.store.launch.GrantSetID = "foreign" }, api.CodeForbidden},
		{"grants", func(f *fixture) { f.store.grants.Revoked = true }, api.CodeForbidden},
		{"grants-life", func(f *fixture) { f.store.grants.LifeID = "foreign" }, api.CodeForbidden},
		{"expiry", func(f *fixture) { f.store.grants.ExpiresAt = api.Timestamp(f.clock.now.Format(time.RFC3339Nano)) }, api.CodeForbidden},
	} {
		t.Run(row.name, func(t *testing.T) {
			for _, method := range []string{"policy.get", "config.read", "config.validate"} {
				f := newFixture(t)
				row.edit(f)
				wantCode(t, readFixture(f, method), row.code)
				if f.store.retentions != 0 {
					t.Fatal("invalid lane read authority retained a projection")
				}
			}
		})
	}
}

func TestReadInstanceTarget(t *testing.T) {
	f := newFixture(t)
	role := f.store.policy.Context
	role.InstanceID = "another-instance"
	_, err := f.service.ConfigRead(context.Background(), f.scope, api.ConfigReadRequest{View: "path", Context: &role})
	wantCode(t, err, api.CodeForbidden)
	if f.store.retentions != 0 {
		t.Fatal("foreign instance retained a projection")
	}
}

func addUnselectedSource(f *fixture) {
	source := testSource("other-role")
	content := api.BlobRef{ID: "source-other-role", SHA256: source.SHA256, Bytes: int64(len(source.ID)), Class: "policy"}
	f.store.inputs[content.ID] = &testUpload{request: api.BlobBeginRequest{Class: content.Class,
		Bytes: content.Bytes, SHA256: content.SHA256}, data: []byte(source.ID)}
	f.store.org.Sources = append(f.store.org.Sources, api.ResourceFile{Source: source, Content: content,
		Mode: 0600, RevisionGeneration: source.Generation, Kind: "policy"})
}

func TestProjectionSourceScope(t *testing.T) {
	for _, actor := range []string{"lane", "human"} {
		for _, view := range []string{"path", "list"} {
			t.Run(actor+"-"+view, func(t *testing.T) {
				f := newFixture(t)
				addUnselectedSource(f)
				f.scope.Request.Method = "config.read"
				expected := append([]api.SourceRef{}, f.store.policy.Sources...)
				life := f.scope.Actor.LifeID
				if actor == "human" {
					f.scope.Actor, f.scope.LaunchID = api.Actor{Kind: "human", ID: "reader"}, ""
					connection, err := newReadConnection(f.scope, f.clock)
					if err != nil {
						t.Fatal(err)
					}
					f.scope.Connection = connection
					expected = append(expected, testSource("other-role"))
					life = ""
				}
				result, err := f.service.ConfigRead(context.Background(), f.scope, api.ConfigReadRequest{View: view})
				if err != nil {
					t.Fatal(err)
				}
				var projection api.ConfigProjection
				if api.DecodeObject(f.store.uploads[result.Projection.ID].data, &projection) != nil ||
					!reflect.DeepEqual(projection.Sources, expected) || !reflect.DeepEqual(result.Sources, expected) {
					t.Fatal("configuration source visibility differs from the authenticated scope")
				}
				acl := f.store.metadata[result.Projection.ID].ACL
				if acl.Owner != f.scope.Actor || acl.LifeID != life {
					t.Fatal("configuration projection lost its principal/life ACL")
				}
			})
		}
	}
}
