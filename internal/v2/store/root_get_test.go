//go:build linux

package store

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/identity"
)

type rootReadWorker struct{ api.DataWorker }
type rootReadOnly struct{ api.StateStore }

// Root issuance IDs and the previously verified assertion are component
// inputs. The ticket request comes from the actual Python producer, and
// session finalization, grants.get, ownership and event guards are real.
func TestPolicyRootRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ticket-row.json")
	source, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("python3", "-I", "-B", filepath.Join(source, "e2e", "v2", "cases", "policy", "prep_probe.py"), "--row", path)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual policy ticket request: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Reads []struct {
			Words   []string            `json:"words"`
			Request api.GrantGetRequest `json:"request"`
		} `json:"reads"`
		Grants api.GrantSet `json:"grants"`
	}
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	if len(input.Reads) != 1 || !reflect.DeepEqual(input.Reads[0].Words, []string{"grants", "get"}) ||
		input.Reads[0].Request.GrantSetID != input.Grants.ID {
		t.Fatal("ticket row changed its exact selected grant request")
	}
	input.Grants.SHA256, err = manifest.HashValue(input.Grants)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.StoredSet(input.Grants); err != nil {
		t.Fatal("actual assembled root metadata is invalid", err)
	}
	for _, mode := range []string{"get", "missing-run", "missing-life", "foreign-owner", "no-session",
		"wrong-selector", "wrong-method", "duplicate", "foreign-template", "immutable-event", "missing-port"} {
		t.Run(mode, func(t *testing.T) {
			s, scope, _, _ := committedSessionFixture(t)
			ctx := context.Background()
			identities, err := identity.New(identity.Dependencies{Peers: &sessionPeerTripwire{}, Registry: &sessionRegistryTripwire{},
				Store: s, Sessions: s, Clock: s.deps.Clock})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := identities.FinalizeHumanSession(ctx, scope); err != nil {
				t.Fatal("actual committed session did not bind its connection", err)
			}
			root := input.Grants
			fixtureProjection(t, s, "grants", root.ID, root.Generation, root)
			event := api.Event{Schema: api.SchemaVersion, ID: testID(t), Config: scope.Config, Kind: "grants.issued",
				LifeID: root.LifeID, Origin: "service", Actor: scope.Actor, RequestedBy: scope.Actor,
				OperationID: testID(t), RequestID: testID(t),
				Payload: archJSON(t, api.GrantEvent{GrantSet: root})}
			if mode == "foreign-owner" {
				event.Actor.ID = testID(t)
				event.RequestedBy = event.Actor
			}
			if mode == "foreign-template" {
				other := root
				other.ID = testID(t)
				other.SHA256, err = manifest.HashValue(other)
				if err != nil {
					t.Fatal(err)
				}
				event.Payload = archJSON(t, api.GrantEvent{GrantSet: other})
			}
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			sequence, err := appendPrivateEvent(ctx, tx, event, archStamp())
			if err != nil {
				tx.Rollback()
				t.Fatal(err)
			}
			if mode == "duplicate" {
				event.ID = testID(t)
				if _, err := appendPrivateEvent(ctx, tx, event, archStamp()); err != nil {
					tx.Rollback()
					t.Fatal(err)
				}
			}
			if mode == "immutable-event" {
				_, err := tx.ExecContext(ctx, "UPDATE events SET data=json_set(data,'$.seq',?) WHERE id=?", uint64(sequence+1), string(event.ID))
				if err == nil || !strings.Contains(err.Error(), "immutable events") {
					tx.Rollback()
					t.Fatal("journal mutation did not reach its unchanged immutable-event refusal", err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			scope.Request = testRequest(t, "grants.get", input.Reads[0].Request)
			scope.Frame = &archFrame{raw: archJSON(t, scope.Request)}
			if mode == "missing-run" || mode == "missing-life" {
				query := api.EventTailRequest{LifeID: root.LifeID}
				if mode == "missing-life" {
					query.LifeID, query.Run = "", 1
				}
				page, err := s.Events(ctx, scope, query)
				expectCode(t, err, api.CodeInvalid)
				if len(page.Events) != 0 || err.Error() != "invalid_request: event read requires selected life and run" {
					t.Fatal("unselected public event read exposed data or changed refusal", err)
				}
				return
			}
			if mode == "wrong-selector" || mode == "wrong-method" {
				selected, code := testID(t), api.CodeInvalid
				if mode == "wrong-method" {
					selected, code = root.ID, api.CodeForbidden
					scope.Request = testRequest(t, "event.tail", api.EventTailRequest{LifeID: root.LifeID, Run: 1})
					scope.Frame = &archFrame{raw: archJSON(t, scope.Request)}
				}
				actual, err := s.RootGrantEvent(ctx, scope, selected)
				expectCode(t, err, code)
				if !reflect.DeepEqual(actual, api.Event{}) {
					t.Fatal("private issuance port exposed another request's event")
				}
				return
			}
			if mode == "no-session" {
				scope.Connection.(*sessionCommitConnection).authority = nil
			}
			var backend api.StateStore = s
			if mode == "missing-port" {
				backend = &rootReadOnly{StateStore: s}
			}
			module, err := grants.New(grants.Dependencies{Config: scope.Config, Store: backend, Clock: s.deps.Clock, Worker: &rootReadWorker{}})
			if err != nil {
				t.Fatal(err)
			}
			actual, err := module.GrantsGet(ctx, scope, input.Reads[0].Request)
			if mode != "get" && mode != "immutable-event" {
				code := api.CodeNotFound
				if mode == "no-session" {
					code = api.CodeUnauthenticated
				}
				if mode == "duplicate" || mode == "foreign-template" {
					code = api.CodeIntegrity
				}
				if mode == "missing-port" {
					code = api.CodeNotImplemented
				}
				expectCode(t, err, code)
				if !reflect.DeepEqual(actual, api.GrantSet{}) {
					t.Fatal("refused root read exposed grant data")
				}
				return
			}
			if err != nil || !reflect.DeepEqual(actual, root) {
				t.Fatal("human.itempolicy.ticket exact grants.get failed", err)
			}
		})
	}
}
