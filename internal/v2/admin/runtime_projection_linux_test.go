//go:build linux

package admin

import (
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func TestLaneRuntimeProjection(t *testing.T) {
	base := testBinding()
	installed := api.InstalledBinding{Schema: "laneboss.binding.v2", Config: base.Config, Protocol: api.Protocol,
		APISchema: api.SchemaVersion, ContractRevision: api.ContractRevision, Class: api.EndpointHuman,
		InstallationGeneration: 1, EndpointGeneration: 1, ServiceVersion: base.Release.Version,
		ServiceUID: base.Service.UID, ServiceGID: base.Service.GID, Socket: "/run/laneboss-v2/" + "runtime-projection/service.sock",
		ArtifactSHA256: base.Artifact.SHA256, Backend: "linux-bwrap-landlock"}
	lease := api.HelperLease{ID: "projection-lease", ContainmentID: "projection-containment", UID: base.Lanes[0].UID, GID: base.Lanes[0].GID, EndpointGeneration: 1}
	home := api.PrivateHome{ID: "projection-home", WorkspaceID: "projection-workspace", VendorDirectory: ".codex", HistoryID: "projection-history"}
	workspace := api.Workspace{ID: home.WorkspaceID, ProjectID: "projection-project", Base: "fixture-base", Branch: "lane/projection-life", LogicalCWD: "/work/main",
		Snapshot: api.BlobRef{ID: "projection-snapshot", Class: "manifest", Bytes: 1, SHA256: testDigest("snapshot")}}
	runtimeRef := api.BlobRef{ID: "projection-runtime", Class: "manifest", Bytes: 1, SHA256: testDigest("runtime")}
	spec := api.LaunchSpec{ID: "projection-spec", Kind: "agent", LaunchID: "projection-launch", Target: api.LifeRef{LifeID: "projection-life", Run: 2},
		UIDLeaseID: lease.ID, EndpointGeneration: 1, Backend: installed.Backend, RuntimeManifest: runtimeRef,
		Workspace: workspace, Runner: &api.RunnerPlan{Driver: api.DriverCodex, Home: home}}
	raw := api.ResolvedRuntime{Manifest: api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1,
		Artifact:  api.Executable{ID: "projection-artifact", SHA256: installed.ArtifactSHA256, Version: installed.ServiceVersion},
		Bootstrap: api.Executable{ID: "projection-bootstrap", SHA256: installed.ArtifactSHA256, Version: installed.ServiceVersion},
		Objects:   []api.RuntimeObject{}, Bindings: []api.InstalledBinding{}},
		SpecReceipt: api.PreparedSpecReceipt{SpecID: spec.ID, Config: installed.Config, Target: spec.Target, LeaseID: lease.ID,
			SpecSHA256: testDigest("projection-spec"), RuntimeManifest: runtimeRef, OperationID: "projection-operation"},
		Home: home, Workspace: workspace,
		Network: api.NetworkLease{ID: "private-network", NamespaceID: "private-namespace", GrantSetID: "retained-grants",
			Generation: 1, EndpointIDs: []api.ID{}, PolicySHA256: testDigest("offline-network"), ExpiresAt: "2100-01-01T00:00:00Z"}}
	t.Run("granted-egress", func(t *testing.T) {
		input, selected := raw, spec
		selected.Grants.ID, selected.PolicyGeneration, selected.Grants.ExpiresAt = raw.Network.GrantSetID, raw.Network.Generation, raw.Network.ExpiresAt
		selected.Grants.Network = []api.NetworkGrant{{ID: "network-grant", EndpointID: "service-endpoint", Mode: "service", ExpiresAt: raw.Network.ExpiresAt}}
		policy, err := json.Marshal(selected.Grants.Network)
		if err != nil {
			t.Fatal(err)
		}
		input.Network.EndpointIDs, input.Network.PolicySHA256 = []api.ID{selected.Grants.Network[0].EndpointID}, digestBytes(policy)
		actual, err := laneRuntimeProjection(installed, selected, lease, input)
		if err != nil || !reflect.DeepEqual(actual.Network, input.Network) {
			t.Fatal("enrolled egress lost its measured namespace lease before Linux preparation", err)
		}
		data, err := json.Marshal(actual)
		if err != nil {
			t.Fatal(err)
		}
		var read api.ResolvedRuntime
		if err := wire.Decode(data, &read); err != nil || !reflect.DeepEqual(read, actual) {
			t.Fatal("enrolled egress cannot cross the strict runtime reply", err)
		}
		for _, fault := range []string{"endpoint", "generation", "policy", "expiry"} {
			t.Run(fault, func(t *testing.T) {
				changed := input
				switch fault {
				case "endpoint":
					changed.Network.EndpointIDs = []api.ID{"foreign-endpoint"}
				case "generation":
					changed.Network.Generation++
				case "policy":
					changed.Network.PolicySHA256 = testDigest("foreign-policy")
				case "expiry":
					changed.Network.ExpiresAt = "2000-01-01T00:00:00Z"
				}
				if _, err := laneRuntimeProjection(installed, selected, lease, changed); err == nil {
					t.Fatal("enrolled egress accepted a foreign namespace lease")
				}
			})
		}
	})
	for _, fault := range []string{"valid", "binding", "artifact", "bootstrap", "egress", "target", "lease"} {
		t.Run(fault, func(t *testing.T) {
			input, selected := raw, spec
			switch fault {
			case "binding":
				input.Manifest.Bindings = []api.InstalledBinding{installed}
			case "artifact":
				input.Manifest.Artifact.SHA256 = testDigest("other-artifact")
			case "bootstrap":
				input.Manifest.Bootstrap.SHA256 = testDigest("other-bootstrap")
			case "egress":
				selected.Grants.Network = []api.NetworkGrant{{ID: "unowned-egress"}}
			case "target":
				selected.Target.Run = 0
			case "lease":
				selected.UIDLeaseID = "foreign-lease"
			}
			actual, err := laneRuntimeProjection(installed, selected, lease, input)
			if fault != "valid" {
				if err == nil {
					t.Fatal("acceptance: lane runtime accepted an unrelated artifact, binding or authority")
				}
				return
			}
			if err != nil || len(actual.Manifest.Bindings) != 1 {
				t.Fatal("acceptance: lane runtime omitted its exact run endpoint", err)
			}
			expected, err := wire.LaneEndpointBinding(installed, spec, lease)
			if err != nil || !reflect.DeepEqual(actual.Manifest.Bindings[0], expected) || len(raw.Manifest.Bindings) != 0 {
				t.Fatal("acceptance: lane runtime changed the protected manifest or endpoint identity", err)
			}
			if actual.Network.ID != "" || actual.Network.NamespaceID != "" || actual.Network.GrantSetID != "" || actual.Network.Generation != 0 ||
				actual.Network.PolicySHA256 != "" || actual.Network.ExpiresAt != "" || actual.Network.EndpointIDs == nil || len(actual.Network.EndpointIDs) != 0 || raw.Network.ID == "" {
				t.Fatal("acceptance: offline runtime leaked its private namespace as egress authority")
			}
			data, err := json.Marshal(actual)
			if err != nil {
				t.Fatal(err)
			}
			var apiRead, wireRead api.ResolvedRuntime
			if err := api.DecodeObject(data, &apiRead); err != nil {
				t.Fatal("acceptance: lane runtime producer disagrees with the API strict reader", err)
			}
			if err := wire.Decode(data, &wireRead); err != nil || !reflect.DeepEqual(apiRead, actual) || !reflect.DeepEqual(wireRead, actual) {
				t.Fatal("acceptance: lane runtime producer disagrees with the wire strict reader", err)
			}
			for _, malformed := range []string{"id", "grant", "namespace", "generation", "digest", "expiry", "null", "missing", "extra"} {
				t.Run("m-"+malformed, func(t *testing.T) {
					var object map[string]json.RawMessage
					if err := json.Unmarshal(data, &object); err != nil {
						t.Fatal(err)
					}
					var network map[string]json.RawMessage
					if err := json.Unmarshal(object["Network"], &network); err != nil {
						t.Fatal(err)
					}
					switch malformed {
					case "id":
						network["ID"] = json.RawMessage(`"foreign-network"`)
					case "grant":
						network["GrantSetID"] = json.RawMessage(`"foreign-grants"`)
					case "namespace":
						network["NamespaceID"] = json.RawMessage(`"foreign-namespace"`)
					case "generation":
						network["Generation"] = json.RawMessage(`1`)
					case "digest":
						network["PolicySHA256"] = json.RawMessage(`"nonempty"`)
					case "expiry":
						network["ExpiresAt"] = json.RawMessage(`"2100-01-01T00:00:00Z"`)
					case "null":
						network["EndpointIDs"] = json.RawMessage(`null`)
					case "missing":
						delete(network, "EndpointIDs")
					case "extra":
						network["unexpected"] = json.RawMessage(`true`)
					}
					changedNetwork, err := json.Marshal(network)
					if err != nil {
						t.Fatal(err)
					}
					object["Network"] = changedNetwork
					changed, err := json.Marshal(object)
					if err != nil {
						t.Fatal(err)
					}
					var refused api.ResolvedRuntime
					if err := wire.Decode(changed, &refused); err == nil || !reflect.DeepEqual(refused, api.ResolvedRuntime{}) {
						t.Fatal("acceptance: offline runtime shape accepted partial network authority", err)
					}
				})
			}
			networkBytes, err := json.Marshal(actual.Network)
			if err != nil {
				t.Fatal(err)
			}
			var standalone api.NetworkLease
			if err := wire.Decode(networkBytes, &standalone); err == nil {
				t.Fatal("acceptance: offline runtime exception escaped its enclosing DTO")
			}
		})
	}
}
