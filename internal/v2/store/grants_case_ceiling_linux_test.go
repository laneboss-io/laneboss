//go:build linux

package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/policy"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The case's real Python producer supplies the data proposals and source bytes.
// Prior root issuance, task enrollment and peers are explicit fixture inputs.
// Admission, reserved grant resolution, issuance and SQLite are real.
func TestGrantsCaseLaunchCeiling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("", "lb-v2-case-grants-ceiling-")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "python3", "-B", filepath.Join(root, "e2e/v2/cases/grants/boot_bundle_input.py"), directory)
	command.Dir = root
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	raw, err := command.Output()
	if err != nil {
		t.Fatal("actual grants case boot failed", err, stderr.String())
	}
	kept, err := os.ReadFile(filepath.Join(directory, "boot-bundle.json"))
	if err != nil || !bytes.Equal(raw, kept) {
		t.Fatal("case ceiling input differs from the retained producer bytes", err)
	}
	var input caseLaunchInput
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	if err := manifest.Root(input.Root, time.Now()); err != nil {
		t.Fatal("case root manifest is not a valid approved proposal", err)
	}
	if len(input.Root.Data) == 0 {
		t.Fatal("case input no longer exercises root data grants")
	}
	t.Logf("retained case ceiling input: %s sha256=%x", directory, sha256.Sum256(raw))
	// The installed bundle assembler adds its main workspace before the case's
	// data rows. Use that actual publication, including all member fields, so
	// the regression crosses the real main-workspace and issuance validators.
	proposal := caseLaunchProposal(t, ctx, root, directory, raw, input.Root.Data[0].ExpiresAt)
	for index, data := range input.Root.Data {
		t.Run(fmt.Sprintf("data-%d", index), func(t *testing.T) {
			if data.Access != "ro" {
				t.Fatal("case data fixture no longer exercises read-only authority")
			}
			for _, mode := range []string{"exact", "foreign-parent", "wider-access", "longer-expiry"} {
				t.Run(mode, func(t *testing.T) {
					f := fx.New(t)
					// Retain the producer's exact source documents, then install its
					// complete approved data row as prior root issuance. Only its
					// service-assigned member identity comes from the fixture.
					var objects []api.ObjectWrite
					for _, document := range proposal.Documents {
						if int64(len(document.Data)) != document.Ref.Bytes || fx.Digest(document.Data) != document.Ref.SHA256 {
							t.Fatal("case document differs from its committed reference")
						}
						objects = append(objects, api.ObjectWrite{ObjectKey: document.Ref.ID, Class: document.Ref.Class,
							Bytes: document.Data, SHA256: document.Ref.SHA256, Origin: "service",
							ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}})
					}
					intent := f.Intent(t, api.InternalOrgBootstrap)
					if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &intent, Writes: api.StateWrites{Objects: objects}}); err != nil {
						t.Fatal("case source retention failed", err)
					}
					f.Ceiling.Data = append([]api.DataGrant{}, proposal.Root.Data...)
					f.Ceiling.Profiles = append([]api.ProfileGrant{}, proposal.Root.Profiles...)
					f.Ceiling.ExpiresAt = ""
					// Root issuance assigns IDs and takes the maximum of the actual
					// member expiries. No fixture-generated expiry is substituted.
					for i := range f.Ceiling.Data {
						f.Ceiling.Data[i].ID = fx.ID(t)
					}
					for i := range f.Ceiling.Profiles {
						f.Ceiling.Profiles[i].ID = fx.ID(t)
					}
					for _, expiry := range manifest.Expiries(f.Ceiling) {
						value, err := manifest.Time(expiry)
						if err != nil {
							t.Fatal(err)
						}
						if f.Ceiling.ExpiresAt == "" {
							f.Ceiling.ExpiresAt = expiry
							continue
						}
						limit, err := manifest.Time(f.Ceiling.ExpiresAt)
						if err != nil {
							t.Fatal(err)
						}
						if value.After(limit) {
							f.Ceiling.ExpiresAt = expiry
						}
					}
					f.Ceiling.SHA256 = ""
					sealed, err := api.CanonicalJSON(fx.JSON(t, f.Ceiling))
					if err != nil {
						t.Fatal(err)
					}
					f.Ceiling.SHA256 = fx.Digest(sealed)
					if err := manifest.Set(f.Ceiling, time.Now()); err != nil {
						t.Fatal("case-issued template is invalid", err)
					}
					f.Replace(t, "grants", f.Ceiling.ID, f.Ceiling.Generation, f.Ceiling)
					f.Start.Grants.Data = []api.DataGrantRequest{}
					for _, member := range f.Ceiling.Data {
						f.Start.Grants.Data = append(f.Start.Grants.Data, api.DataGrantRequest{ParentGrantID: member.ID,
							RelativePath: member.RelativePath, Access: member.Access, Delivery: member.Delivery,
							Destination: member.Destination, Delegate: member.Delegate, ExpiresAt: member.ExpiresAt, PublicationID: member.PublicationID})
					}
					f.Start.Grants.Profiles = []api.ProfileDelegation{}
					for _, member := range f.Ceiling.Profiles {
						if member.Driver == f.Start.Driver {
							f.Start.ProfileGrantID = member.ID
							f.Start.Grants.Profiles = append(f.Start.Grants.Profiles, api.ProfileDelegation{ParentGrantID: member.ID,
								ProfileID: member.ProfileID, Delegate: member.Delegate, ExpiresAt: member.ExpiresAt})
						}
					}
					caseIndex := index + 1
					switch mode {
					case "foreign-parent":
						f.Start.Grants.Data[caseIndex].ParentGrantID = fx.ID(t)
					case "wider-access":
						f.Start.Grants.Data[caseIndex].Access = "rw"
					case "longer-expiry":
						expires, err := time.Parse(time.RFC3339Nano, string(data.ExpiresAt))
						if err != nil {
							t.Fatal(err)
						}
						f.Start.Grants.Data[caseIndex].ExpiresAt = api.Timestamp(expires.Add(time.Second).UTC().Format(time.RFC3339Nano))
					}
					f.Admit(t, "lane.start", f.Start)
					t.Logf("grants.data[%d].destination requested=%q authorised=%q generation=%d expiry=%q ceiling=%q", caseIndex,
						f.Start.Grants.Data[caseIndex].Destination, f.Ceiling.Data[caseIndex].Destination, f.Ceiling.Generation,
						f.Start.Grants.Data[caseIndex].ExpiresAt, f.Ceiling.ExpiresAt)
					reservation, err := f.State.ReserveLaunch(ctx, f.Human, f.ReservationRequest(t))
					if mode == "exact" {
						if err != nil {
							t.Fatal("case-approved data destination was refused", err)
						}
						if reservation.ID == "" || reservation.OperationID != f.Receipt.Operation.ID || reservation.RequestedBy != f.Human.Actor {
							t.Fatal("case launch lost its actual reservation ownership")
						}
						f.Reserve(t)
						resolver, err := grants.New(grants.Dependencies{Config: f.Deps.Config, Store: f.State,
							Worker: &caseCeilingWorker{}, Clock: f.Deps.Clock})
						if err != nil {
							t.Fatal(err)
						}
						issued, err := resolver.Resolve(ctx, f.Execution, api.GrantResolveRequest{ReservationID: reservation.ID})
						if err != nil {
							t.Fatal("case-approved proposal did not resolve", err)
						}
						t.Logf("grants.data[%d].history_scope issued=%q authorised=%q source=%q", caseIndex, issued.Data[caseIndex].HistoryScope,
							f.Ceiling.Data[caseIndex].HistoryScope, issued.Data[caseIndex].SourceObjectID)
						for _, fault := range []string{"foreign-parent", "foreign-source", "source-digest", "reachable-history", "wider-access", "longer-expiry", "destination"} {
							var changed api.GrantSet
							if err := json.Unmarshal(fx.JSON(t, issued), &changed); err != nil {
								t.Fatal(err)
							}
							switch fault {
							case "foreign-parent":
								changed.Data[caseIndex].ParentGrantID = fx.ID(t)
							case "foreign-source":
								changed.Data[caseIndex].SourceObjectID = fx.ID(t)
							case "source-digest":
								changed.Data[caseIndex].SourceSHA256 = fx.Digest([]byte("different source"))
							case "reachable-history":
								changed.Data[caseIndex].HistoryScope = "reachable"
							case "wider-access":
								changed.Data[caseIndex].Access = "rw"
							case "longer-expiry":
								expires, err := time.Parse(time.RFC3339Nano, string(data.ExpiresAt))
								if err != nil {
									t.Fatal(err)
								}
								changed.Data[caseIndex].ExpiresAt = api.Timestamp(expires.Add(time.Second).UTC().Format(time.RFC3339Nano))
							case "destination":
								changed.Data[caseIndex].Destination = "/data/elsewhere"
							}
							_, err := f.State.Transact(ctx, caseIssuance(t, f, changed))
							var typed *api.Error
							if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || typed.Owner != "lb-v2-service" {
								t.Fatal("case issuance escaped "+fault, err)
							}
							current, err := f.State.LaunchPlan(ctx, f.Execution, reservation.ID)
							if err != nil || current.Phase != "reserved" || current.Inputs != nil || current.Generation != 1 {
								t.Fatal("refused case issuance partially committed its plan", err)
							}
							if _, err := f.State.Grants(ctx, reservation.GrantSetID); err == nil {
								t.Fatal("refused case issuance retained grants")
							} else {
								launchCode(t, err, api.CodeNotFound)
							}
						}
						if _, err := f.State.Transact(ctx, caseIssuance(t, f, issued)); err != nil {
							t.Fatal("case-approved resolved grants were refused at issuance", err)
						}
						stored, err := f.State.Grants(ctx, reservation.GrantSetID)
						if err != nil || !reflect.DeepEqual(stored, issued) {
							t.Fatal("case issuance changed the real resolver output", err)
						}
						caseMaterialization(t, ctx, f, issued)
					} else {
						var typed *api.Error
						if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || typed.Owner != "lb-v2-service" ||
							typed.Message != "launch request exceeds its current grant ceiling" {
							t.Fatal("case destination widened its grant ceiling", err)
						}
						effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
						if err != nil || len(effects) != 0 {
							t.Fatal("refused case launch created a planning effect", err)
						}
					}
					held, err := f.State.Grants(ctx, f.Ceiling.ID)
					if err != nil || !reflect.DeepEqual(held, f.Ceiling) {
						t.Fatal("case admission changed the issued ceiling or generation", err)
					}
				})
			}
		})
	}
}

type caseLaunchDocument struct {
	Ref  api.BlobRef `json:"ref"`
	Data []byte      `json:"data"`
}

type caseLaunchInput struct {
	Root      api.RootGrantManifest `json:"root_grants"`
	Documents []caseLaunchDocument  `json:"documents"`
}

// Run the same bundle assembler as provision.fixture_initial. Only runtime,
// task and template intake are component fixtures; the case's root proposal
// crosses the assembler unchanged, and its published members supply the test.
func caseLaunchProposal(t *testing.T, ctx context.Context, root, directory string, raw []byte, expiry api.Timestamp) caseLaunchInput {
	t.Helper()
	var full map[string]json.RawMessage
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatal(err)
	}
	var additional []json.RawMessage
	if err := json.Unmarshal(full["sources"], &additional); err != nil {
		t.Fatal(err)
	}
	var sources []json.RawMessage
	for _, source := range []struct{ id, path, logical, kind string }{
		{"org-prompt", "org/default.md", ".laneboss/shared/templates/default.md", "prompt"},
		{"org-drivers", "org/drivers.toml", ".laneboss/shared/templates/drivers.toml", "drivers"},
		{"workflow", "org/workflow.toml", ".laneboss/shared/workflow.toml", "policy"},
		{"l5-prompt", "roles/L5/supervisor.md", ".laneboss/L5/roles/supervisor.md", "prompt"},
		{"l5-drivers", "roles/L5/supervisor.toml", ".laneboss/L5/roles/supervisor.toml", "drivers"},
	} {
		data, err := os.ReadFile(filepath.Join(root, "templates", "v2", source.path))
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, fx.JSON(t, map[string]any{"id": source.id, "path": source.logical, "kind": source.kind, "data": data}))
	}
	full["sources"] = fx.JSON(t, append(sources, additional...))
	asset := []byte("unexecuted component runtime bytes")
	executable := api.Executable{ID: "case-agent", SHA256: fx.Digest(asset), Version: "fixture-model"}
	runtime := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: executable, Bootstrap: executable,
		Bindings: []api.InstalledBinding{}, Objects: []api.RuntimeObject{{ID: executable.ID, Role: "serve-fixture-agent", RootID: "runtime",
			RelativePath: "agent", Mode: 0555, Content: api.BlobRef{ID: executable.ID, Class: "artifact", Bytes: int64(len(asset)), SHA256: executable.SHA256}}}}
	runtimeRaw := fx.JSON(t, runtime)
	project, err := os.ReadFile(filepath.Join(root, "scripts", "v2-serve", "fixtures", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{
		"config": "launch-fixture", "runtime_ref": api.BlobRef{ID: "case-runtime", Class: "manifest", Bytes: int64(len(runtimeRaw)), SHA256: fx.Digest(runtimeRaw)},
		"runtime": runtimeRaw, "project": project, "task": []byte("component task"), "model": executable.Version, "expires_at": expiry,
		"judge": policy.DefaultJudgeConfig(fx.Digest([]byte("component deployment")), fx.Digest([]byte("component tokenizer")), 32768),
	} {
		full[name] = fx.JSON(t, value)
	}
	path := filepath.Join(directory, "bundle-input.json")
	if err := os.WriteFile(path, fx.JSON(t, full), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "go", "run", "-mod=readonly", "./scripts/v2-serve/bundle", "--input", path)
	command.Dir = root
	var stderr bytes.Buffer
	command.Stderr = &stderr
	assembled, err := command.Output()
	if writeErr := os.WriteFile(filepath.Join(directory, "bundle-assembly.stderr"), stderr.Bytes(), 0600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if err != nil {
		t.Fatal("actual case bundle assembly failed", err, stderr.String())
	}
	if err := os.WriteFile(filepath.Join(directory, "bundle-assembly.json"), assembled, 0600); err != nil {
		t.Fatal(err)
	}
	var output struct {
		Documents []caseLaunchDocument `json:"documents"`
		Root      api.RootGrantRequest `json:"root_request"`
	}
	if err := json.Unmarshal(assembled, &output); err != nil {
		t.Fatal(err)
	}
	proposal := caseLaunchInput{Documents: output.Documents}
	for _, document := range output.Documents {
		if document.Ref == output.Root.Manifest {
			if err := api.DecodeObject(document.Data, &proposal.Root); err != nil {
				t.Fatal(err)
			}
		}
	}
	var original caseLaunchInput
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	if len(proposal.Root.Data) != len(original.Root.Data)+1 || proposal.Root.Data[0].Destination != "/work/main" {
		t.Fatal("case publication lost its actual baseline workspace")
	}
	withoutMain := proposal.Root
	withoutMain.Data = withoutMain.Data[1:]
	if !reflect.DeepEqual(withoutMain, original.Root) {
		t.Fatal("case assembly changed the producer's approved member fields")
	}
	t.Logf("retained assembled case proposal: %s sha256=%x", directory, sha256.Sum256(assembled))
	return proposal
}

// Resolve does not use a worker; this dependency cannot supply grant results.
type caseCeilingWorker struct{ api.DataWorker }

func caseMaterialization(t *testing.T, ctx context.Context, f *fx.Fixture, issued api.GrantSet) {
	t.Helper()
	var err error
	f.Record, err = f.State.LaunchPlan(ctx, f.Execution, f.Reservation.ID)
	if err != nil {
		t.Fatal(err)
	}
	allocate := f.Intent(t, api.InternalHelperAllocate)
	allocate.EffectID = fx.ID(t)
	effect := api.Effect{ID: allocate.EffectID, OperationID: f.Reservation.OperationID, Context: &allocate,
		HelperAllocate: &api.HelperLeaseRequest{ReservationID: f.Reservation.ID, Cause: allocate, Config: f.Deps.Config,
			LifeID: f.Reservation.Target.LifeID, Backend: f.Record.Inputs.Sources.Runtime.Backend, Budget: f.Start.Budget,
			RuntimeManifestID: f.Record.Inputs.Sources.Runtime.Manifest.ID}}
	parent := f.Intent(t, api.InternalLaunchPlan)
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &parent, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal("case materialization allocation reservation failed", err)
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1,
		ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	agent := api.HelperLease{ID: fx.ID(t), UID: uint32(os.Geteuid()) + 1000, GID: uint32(os.Getegid()) + 1000,
		ContainmentID: fx.ID(t), EndpointGeneration: 1}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, api.EffectOutcome{EffectID: effect.ID, ClaimID: claim.ClaimID,
		ExpectedGeneration: claim.Record.Generation, Status: "succeeded", HelperLease: &agent}); err != nil {
		t.Fatal(err)
	}
	request := api.LaunchDataRequest{ReservationID: f.Reservation.ID, GrantSetID: issued.ID, LeaseID: agent.ID,
		Claim: api.PlanningClaim(f.Reservation.ID, f.Claim)}
	// Adversarial protected projections exercise the real execution boundary,
	// while the issued set remains unchanged. None is a positive grant fixture.
	for _, field := range []string{"id", "source", "digest", "path", "access", "delivery", "destination", "expiry", "expired", "duplicate-project", "project-path", "project-delivery"} {
		var changed api.LaunchPlanRecord
		if err := json.Unmarshal(fx.JSON(t, f.Record), &changed); err != nil {
			t.Fatal(err)
		}
		member := &changed.Inputs.Grants.Data[1]
		switch field {
		case "id":
			member.ID = fx.ID(t)
		case "source":
			member.SourceObjectID = fx.ID(t)
		case "digest":
			member.SourceSHA256 = fx.Digest([]byte("unissued source"))
		case "path":
			member.RelativePath = "child"
		case "access":
			member.Access = "rw"
		case "delivery":
			member.Delivery = "mount"
		case "destination":
			member.Destination = "/data/unissued"
		case "expiry":
			member.ExpiresAt = fx.Expiry()
		case "expired":
			member.ExpiresAt = api.Timestamp(time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano))
		case "duplicate-project":
			member.ID = changed.Inputs.Sources.Project.GrantID
		case "project-path":
			changed.Inputs.Grants.Data[0].RelativePath = "README.md"
		case "project-delivery":
			changed.Inputs.Grants.Data[0].Delivery = "mount"
		}
		f.Replace(t, "launch_plan", changed.Reservation.ID, changed.Generation, changed)
		_, err := f.State.LaunchDataStage(ctx, f.Execution, request)
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Owner != "lb-v2-service" || typed.Code != api.CodeForbidden && typed.Code != api.CodeUnsupported {
			t.Fatal("materialization passed a data entry outside issuance: "+field, err)
		}
		retained, err := f.State.LaunchPlan(ctx, f.Execution, f.Reservation.ID)
		if err != nil || retained.DataStageID != "" {
			t.Fatal("refused materialization retained a worker stage", field, err)
		}
		f.Replace(t, "launch_plan", f.Record.Reservation.ID, f.Record.Generation, f.Record)
	}
	stage, err := f.State.LaunchDataStage(ctx, f.Execution, request)
	if err != nil {
		t.Fatal("case three-grant materialization failed", err)
	}
	if len(issued.Data) != 3 || !reflect.DeepEqual(stage.Inputs.Grants, issued) {
		t.Fatal("case materialization dropped or changed an issued data delivery")
	}
	project := stage.Inputs.Sources.Project
	if len(stage.Grants.Data) != 1 || stage.Grants.Data[0].ParentGrantID != project.GrantID ||
		stage.Grants.Data[0].SourceObjectID != project.Object.ID || stage.Grants.Data[0].Destination != "/job/source" {
		t.Fatal("case materialization did not select its unique project source")
	}
	delivery := fx.DataForLaunch(t, f, request)
	sealed, err := f.State.SealDataStage(ctx, f.Execution, stage.ID, delivery.Projection, delivery.Allocation)
	if err != nil {
		t.Fatal("case materialization sealing failed", err)
	}
	if !reflect.DeepEqual(sealed.Inputs.Grants, issued) {
		t.Fatal("sealed materialization dropped or changed an issued data delivery")
	}
	for _, grant := range issued.Data {
		t.Logf("materialization retained grant source=%q path=%q access=%q delivery=%q destination=%q expiry=%q",
			grant.SourceObjectID, grant.RelativePath, grant.Access, grant.Delivery, grant.Destination, grant.ExpiresAt)
	}
}

func caseIssuance(t *testing.T, f *fx.Fixture, issued api.GrantSet) api.Transaction {
	t.Helper()
	issued.SHA256 = ""
	sealed, err := api.CanonicalJSON(fx.JSON(t, issued))
	if err != nil {
		t.Fatal(err)
	}
	issued.SHA256 = fx.Digest(sealed)
	transaction := f.SourceTransaction(t)
	transaction.Writes.Grants = []api.GrantSet{issued}
	transaction.Writes.LaunchPlans[0].Inputs.Grants = issued
	transaction.Writes.LaunchPlans[0].Inputs.Sources.Project.GrantID = issued.Data[0].ID
	transaction.Events[0].Payload = fx.JSON(t, api.GrantEvent{GrantSet: issued})
	return transaction
}
