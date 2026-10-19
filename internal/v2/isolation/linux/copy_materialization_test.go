package linux

import (
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Match the installed grants item's issued shape: the main project plus two
// independent read-only copies at /data/parent and /data/fixed. Build copy
// receipts with the production builder and seal the same fields as PlanLaunch.
func installedGrantCopySpec(t *testing.T, driver api.Driver) (api.LaunchSpec, api.LaunchPlan, []api.DataCopyProjection) {
	t.Helper()
	record, _ := planMetaForDriver(t, driver)
	plan := *record.Plan
	plan.Inputs.Sources.Project.HistoryScope = "tree"
	plan.Inputs.Sources.Project.Base = string(plan.Inputs.Sources.Project.Object.SHA256)
	plan.Inputs.Grants.Data[0].HistoryScope = "tree"
	plan.Data.Source = plan.Inputs.Sources.Project
	plan.Data.Workspace.Base = plan.Data.Source.Base
	input, canary, fixed := metaBlob("grants-input", "artifact"), metaBlob("grants-canary", "artifact"), metaBlob("grants-fixed", "artifact")
	trees := []api.ObjectManifest{
		{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
			{Path: "child/input.txt", Kind: "file", Mode: 0444, Content: &input},
			{Path: "private/canary", Kind: "file", Mode: 0444, Content: &canary},
			{Path: "alias", Kind: "symlink", Mode: 0777, LinkTarget: "private/canary"},
		}},
		{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "fixed.txt", Kind: "file", Mode: 0444, Content: &fixed}}},
	}
	var copies []api.DataCopyProjection
	for i, name := range []string{"parent", "fixed"} {
		raw := metaJSON(t, trees[i])
		source := api.BlobRef{ID: api.ID("grants-" + name + "-tree"), Class: "manifest", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
		grant := api.DataGrant{ID: api.ID(name + "-data"), SourceObjectID: source.ID, SourceSHA256: source.SHA256,
			RelativePath: ".", Access: "ro", Delivery: "copy", Destination: "/data/" + name,
			ExpiresAt: plan.Inputs.Grants.ExpiresAt, HistoryScope: "tree"}
		copy := api.DataCopyProjection{Grant: grant, Source: source, Manifest: trees[i], WorkspaceID: api.ID("copy-" + name),
			SourceIdentity: name + "-source-inode", DestinationIdentity: name + "-destination-inode"}
		receipt, err := copy.Receipt(plan.Data.Workspace.ID)
		if err != nil {
			t.Fatal(err)
		}
		if copy.WorkspaceID == plan.Data.Workspace.ID || receipt.SourceIdentity != copy.SourceIdentity ||
			receipt.DestinationIdentity != copy.DestinationIdentity || !validDigest(receipt.SnapshotSHA256) {
			t.Fatal("copy fixture lost its independent held root or measured receipt fields")
		}
		plan.Inputs.Grants.Data = append(plan.Inputs.Grants.Data, grant)
		plan.Data.Materialization.Objects = append(plan.Data.Materialization.Objects, receipt)
		copies = append(copies, copy)
	}
	r := plan.Reservation
	spec := api.LaunchSpec{Kind: "agent", PlanID: r.ID, ID: r.SpecID, LaunchID: r.LaunchID, Target: r.Target,
		Backend: plan.Inputs.Sources.Runtime.Backend, UIDLeaseID: plan.Lease.ID, Workspace: plan.Data.Workspace,
		Materialization: plan.Data.Materialization, Grants: plan.Inputs.Grants, Runner: &plan.Runner, Injection: plan.Injection,
		Budget: plan.Budget, Capture: &plan.Capture, EndpointGeneration: plan.Lease.EndpointGeneration,
		PolicyGeneration: r.PolicyGeneration, RuntimeManifest: plan.Inputs.Sources.Runtime.Manifest}
	if err := api.ValidateAgentLaunchSpec(spec, plan); err != nil {
		t.Fatal("installed-shape spec must match the complete PlanLaunch fields", err)
	}
	return spec, plan, copies
}

func TestInstalledGrantCopySpec(t *testing.T) {
	for _, driver := range []api.Driver{api.DriverClaudock, api.DriverCodex} {
		t.Run(string(driver), func(t *testing.T) {
			spec, _, copies := installedGrantCopySpec(t, driver)
			if err := validateSpec(spec, spec.RuntimeManifest, time.Now()); err != nil {
				for _, object := range spec.Materialization.Objects {
					t.Logf("receipt fields: workspace_matches=%t source_present=%t destination_present=%t snapshot_valid=%t",
						object.WorkspaceID == spec.Workspace.ID, object.SourceIdentity != "", object.DestinationIdentity != "", validDigest(object.SnapshotSHA256))
				}
				t.Fatal("PlanLaunch installed grant shape failed Linux spec validation", err)
			}
			for index := range spec.Materialization.Objects {
				for _, fault := range []string{"foreign-workspace", "empty-source", "empty-destination", "invalid-snapshot", "unknown-grant", "duplicate-grant"} {
					changed := spec
					changed.Materialization.Objects = append([]api.MaterializedObject{}, spec.Materialization.Objects...)
					object := &changed.Materialization.Objects[index]
					switch fault {
					case "foreign-workspace":
						object.WorkspaceID = "foreign-workspace"
					case "empty-source":
						object.SourceIdentity = ""
					case "empty-destination":
						object.DestinationIdentity = ""
					case "invalid-snapshot":
						object.SnapshotSHA256 = "invalid"
					case "unknown-grant":
						object.GrantID = "ungranted"
					case "duplicate-grant":
						changed.Materialization.Objects = append(changed.Materialization.Objects, *object)
					}
					var typed *api.Error
					err := validateSpec(changed, changed.RuntimeManifest, time.Now())
					if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "materialization identities are incomplete or mismatched" {
						t.Fatal("mismatched materialization identity escaped the strict Linux check", fault, index, err)
					}
				}
			}
			for i, copy := range copies {
				changed := spec
				changed.Materialization.Objects = append([]api.MaterializedObject{}, spec.Materialization.Objects...)
				changed.Materialization.Objects[i+1].WorkspaceID = copy.WorkspaceID
				if err := validateSpec(changed, changed.RuntimeManifest, time.Now()); err == nil {
					t.Fatal("private copy-root ID was accepted as the launch workspace")
				}
			}
		})
	}
}
