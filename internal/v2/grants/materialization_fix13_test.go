package grants_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func resealWorkerInput(t *testing.T, f *materializationFixture, change func(*dataworker.MaterializationInput)) {
	t.Helper()
	var input dataworker.MaterializationInput
	if err := api.DecodeObject(f.blobs[f.stage.Worker.Input.ID], &input); err != nil {
		t.Fatal(err)
	}
	change(&input)
	launchSeal(t, &input.Grants)
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := api.CanonicalJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	f.stage.Worker.Input = f.object(f.stage.Worker.Input.ID, "materialize_input", canonical, f.stage.Reservation.OperationID)
	f.stage.Plan.Input = f.stage.Worker.Input
	f.stage.Claim.Record.Effect.Worker.Input = f.stage.Worker.Input
	f.principal.Lease.Input = f.stage.Worker.Input
	f.principal.Claim.Record.Effect.Worker.Input = f.stage.Worker.Input
	f.principal.Record.GrantsSHA256 = input.Grants.SHA256
}

func TestMaterializationWorkerGrantLimits(t *testing.T) {
	for _, group := range []struct {
		name   string
		faults []string
	}{{"expiry", []string{"set-expired", "data-expired"}}, {"ceilings", []string{"set-ceiling", "lease-ceiling"}}, {"identities", []string{"parent", "generation", "data-id", "source-id"}}} {
		t.Run(group.name, func(t *testing.T) {
			for _, fault := range group.faults {
				t.Run(fault, func(t *testing.T) {
					f := newMaterializationFixture(t)
					resealWorkerInput(t, f, func(input *dataworker.MaterializationInput) {
						switch fault {
						case "set-expired":
							input.Grants.ExpiresAt = "2029-01-01T00:00:00Z"
							input.Grants.Data[0].ExpiresAt = input.Grants.ExpiresAt
						case "data-expired":
							input.Grants.Data[0].ExpiresAt = "2029-01-01T00:00:00Z"
						case "set-ceiling":
							input.Grants.Data[0].ExpiresAt = "2030-01-01T00:06:00Z"
						case "lease-ceiling":
							input.Grants.ExpiresAt = "2030-01-01T00:06:00Z"
						case "parent":
							input.Grants.ParentLifeID = "other-life"
						case "generation":
							input.Grants.Generation = 2
						case "data-id":
							input.Grants.Data[0].ID = ""
						case "source-id":
							input.Grants.Data[0].ID = input.Source.GrantID
						}
					})
					receipt, err := dataworker.RunMaterialization(context.Background(), f.job())
					var typed *api.Error
					if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || receipt.LeaseID != "" || f.objectReads != 0 || f.resultCalls != 0 {
						t.Fatal("worker grant limits accepted an unauthorized job", err)
					}
					for _, path := range []string{f.workspacePath, f.homePath} {
						entries, err := os.ReadDir(path)
						if err != nil || len(entries) != 0 {
							t.Fatal("worker grant refusal changed a destination", err)
						}
					}
				})
			}
		})
	}
}
func TestLaunchSnapshotAuthority(t *testing.T) {
	for _, group := range []struct {
		name   string
		faults []string
	}{{"tree", []string{"extra", "mode", "digest", "link"}}, {"metadata", []string{"metadata-config", "metadata-digest", "metadata-class"}}} {
		t.Run(group.name, func(t *testing.T) {
			for _, fault := range group.faults {
				t.Run(fault, func(t *testing.T) {
					g := newLaunchGraph(t)
					r := g.completed()
					request := launchRequestFor(r)
					if _, err := g.worker.MaterializeLaunch(context.Background(), request); err != nil {
						t.Fatal("snapshot positive replay failed", err)
					}
					var object api.ObjectManifest
					ref := r.Plan.Data.Workspace.Snapshot
					if err := api.DecodeObject(g.blobs[ref.ID], &object); err != nil {
						t.Fatal(err)
					}
					switch fault {
					case "extra":
						extra := object.Entries[0]
						extra.Path = "ungranted.txt"
						object.Entries = append(object.Entries, extra)
					case "mode":
						object.Entries[0].Mode = 0644
					case "digest":
						changed := g.object("changed-workspace-file", "artifact", []byte("substituted bytes"), r.Reservation.OperationID)
						object.Entries[0].Content = &changed
					case "link":
						object.Entries = append(object.Entries, api.ObjectEntry{Path: "ungranted-link", Kind: "symlink", LinkTarget: "main.txt"})
					default:
						metadata := g.metadata["workspace-file"]
						switch fault {
						case "metadata-config":
							metadata.ACL.Config = "other"
						case "metadata-digest":
							metadata.Ref.SHA256 = manifest.Hash([]byte("other bytes"))
						case "metadata-class":
							metadata.Ref.Class = "policy"
						}
						g.metadata["workspace-file"] = metadata
					}
					if err := manifest.Object(object); err != nil {
						t.Fatal("snapshot adversarial manifest is malformed", err)
					}
					r.Plan.Data.Workspace.Snapshot = g.encoded("changed-workspace-snapshot", "manifest", object, r.Reservation.OperationID)
					r.Plan.Data.Materialization.Objects[0].SnapshotSHA256 = r.Plan.Data.Workspace.Snapshot.SHA256
					g.plans[r.Reservation.ID] = r
					if err := api.ValidateLaunchPlanRecord(r); err != nil {
						t.Fatal("snapshot replay fixture lost its valid retained plan", err)
					}
					result, err := g.worker.MaterializeLaunch(context.Background(), request)
					var typed *api.Error
					if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || result.ReservationID != "" {
						t.Fatal("launch accepted a snapshot outside its granted source", err)
					}
				})
			}
		})
	}
}

func TestMaterializationSpecialFiles(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink-fifo", "symlink-file"} {
		t.Run(kind, func(t *testing.T) {
			f := newMaterializationFixture(t)
			name := filepath.Join(f.sourcePath, "main.txt")
			if err := os.Rename(name, filepath.Join(f.sourcePath, "kept")); err != nil {
				t.Fatal(err)
			}
			if kind == "fifo" {
				if err := unix.Mkfifo(name, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				target := "kept"
				if kind == "symlink-fifo" {
					target = "pipe"
					if err := unix.Mkfifo(filepath.Join(f.sourcePath, target), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(target, name); err != nil {
					t.Fatal(err)
				}
			}
			receipt, err := dataworker.RunMaterialization(context.Background(), f.job())
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "materialization source is not a single regular file before open" || receipt.LeaseID != "" || f.resultCalls != 0 {
				t.Fatal("special source file reached the kernel data open", err)
			}
		})
	}
}

type materializationMovingClock struct{ now time.Time }

func (c *materializationMovingClock) Now() time.Time { return c.now }

func TestMaterializationGrantRelease(t *testing.T) {
	f := newMaterializationFixture(t)
	resealWorkerInput(t, f, func(input *dataworker.MaterializationInput) {
		input.Grants.ExpiresAt = "2030-01-01T00:02:00Z"
		input.Grants.Data[0].ExpiresAt = input.Grants.ExpiresAt
	})
	clock := &materializationMovingClock{now: launchClock{}.Now()}
	f.onObject = func(api.ID) { clock.now = launchClock{}.Now().Add(3 * time.Minute) }
	job := f.job()
	job.Clock = clock
	receipt, err := dataworker.RunMaterialization(context.Background(), job)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || receipt.LeaseID != "" || f.resultCalls != 0 {
		t.Fatal("materialization acknowledged grants that expired during copy", err)
	}
}

func TestLaunchOutputManifest(t *testing.T) {
	g := newLaunchGraph(t)
	r := g.completed()
	request := launchRequestFor(r)
	if _, err := g.worker.MaterializeLaunch(context.Background(), request); err != nil {
		t.Fatal("materialization manifest positive replay failed", err)
	}
	var object api.ObjectManifest
	if err := api.DecodeObject(g.blobs[r.Plan.Data.Materialization.Manifest.ID], &object); err != nil {
		t.Fatal(err)
	}
	extra := object.Entries[0]
	extra.Path = "ungranted.txt"
	object.Entries = append(object.Entries, extra)
	if err := manifest.Object(object); err != nil {
		t.Fatal(err)
	}
	r.Plan.Data.Materialization.Manifest = g.encoded("changed-materialization", "manifest", object, r.Reservation.OperationID)
	g.plans[r.Reservation.ID] = r
	if err := api.ValidateLaunchPlanRecord(r); err != nil {
		t.Fatal("output manifest fixture lost its valid plan", err)
	}
	result, err := g.worker.MaterializeLaunch(context.Background(), request)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || result.ReservationID != "" {
		t.Fatal("launch accepted ungranted materialization manifest", err)
	}
}
