package secrets

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestInjectionSelectionReplay(t *testing.T) {
	c := newLaunchCase(t, "helper")
	grant, _ := c.addSecret(t, "retry-canary", "env", "RETRY_TOKEN")
	if _, err := c.acquire(context.Background(), c.target, c.grant); err != nil {
		t.Fatal("cannot prepare exact injection selection")
	}
	one, err := c.inject(context.Background(), c.target, []api.SecretGrant{grant})
	if err != nil {
		t.Fatal("cannot prepare exact selected injection")
	}
	again, err := c.inject(context.Background(), c.target, []api.SecretGrant{grant})
	if err != nil || !reflect.DeepEqual(one, again) {
		t.Fatal("unchanged injection selection did not replay its exact slots")
	}
	_, err = c.inject(context.Background(), c.target, []api.SecretGrant{})
	stageCode(t, err, api.CodeConflict)
}

func TestPreparedAgentMaterialGuards(t *testing.T) {
	for _, fault := range []string{"foreign", "executable", "phase", "policy", "grants", "expiry", "history", "runtime", "runtime-file", "handoff", "revoked-source"} {
		t.Run(fault, func(t *testing.T) {
			c := newLaunchCase(t, "headless_token")
			slot, err := c.acquire(context.Background(), c.target, c.grant)
			if err != nil {
				t.Fatal("cannot acquire agent delivery refusal control")
			}
			injection, err := c.inject(context.Background(), c.target, []api.SecretGrant{})
			if err != nil {
				t.Fatal("cannot prepare agent delivery refusal control")
			}
			c.beforeBind = func(t *testing.T, spec api.LaunchSpec) {
				code := api.CodeForbidden
				switch fault {
				case "foreign":
					spec.Target.LifeID = "foreign-life"
				case "executable":
					copy := *spec.Runner
					copy.Executable.ID = "/caller/executable"
					spec.Runner = &copy
					code = api.CodeInvalid
				case "phase":
					record := c.plan(t)
					record.Plan, record.Handoff, record.Phase, record.Generation = nil, nil, "sourced", 2
					c.setPlan(t, record)
					code = api.CodeConflict
				case "policy":
					c.store.policy.Generation++
					code = api.CodeConflict
				case "grants":
					c.store.grants.Revoked = true
				case "expiry":
					c.clock.now = c.clock.now.Add(4 * time.Minute)
				case "history":
					var storage api.LaunchStorage
					if err := c.store.read("storage.json", &storage); err != nil {
						t.Fatal("cannot read private storage control")
					}
					storage.Home.Home.HistoryID = slot.ID
					if err := c.store.save("storage.json", storage); err != nil {
						t.Fatal("cannot retain history alias control")
					}
					code = api.CodeConflict
				case "runtime":
					c.helper.fail["runtime"] = api.NotImplemented("lb-v2-admin", "admin.ResolveRuntime")
					code = api.CodeNotImplemented
				case "runtime-file":
					if err := os.WriteFile(filepath.Join(c.helper.root, "runtime.bin"), syntheticBytes(t, 97), 0600); err != nil {
						t.Fatal("cannot change actual runtime-file control")
					}
					code = api.CodeIntegrity
				case "handoff":
					c.helper.fail["handoff"] = api.NotImplemented("lb-v2-service", "service.Handoff")
					code = api.CodeNotImplemented
				case "revoked-source":
					if err := c.backend.Revoke(context.Background(), api.SecretInfo{Name: c.profile.Source.Name, Version: c.profile.Source.Version, SourceHandle: c.profile.Source.SourceHandle, KeyID: "key-a"}); err != nil {
						t.Fatal("cannot revoke the actual enrolled delivery source")
					}
				}
				material, err := c.service.PreparedSlotMaterial(context.Background(), spec, slot.ID)
				stageCode(t, err, code)
				if len(material.Bytes) != 0 || c.helper.process != nil {
					t.Fatal("refused prepared delivery returned bytes or executed an agent")
				}
			}
			c.bind(t, slot, injection)
		})
	}
}

func TestBoundMaterialSourceRevocation(t *testing.T) {
	c := newLaunchCase(t, "helper")
	slot, err := c.acquire(context.Background(), c.target, c.grant)
	if err != nil {
		t.Fatal("cannot acquire bound revocation control")
	}
	injection, err := c.inject(context.Background(), c.target, []api.SecretGrant{})
	if err != nil {
		t.Fatal("cannot prepare bound revocation control")
	}
	c.bind(t, slot, injection)
	if err := c.backend.Revoke(context.Background(), api.SecretInfo{Name: c.profile.Source.Name, Version: c.profile.Source.Version, SourceHandle: c.profile.Source.SourceHandle, KeyID: "key-a"}); err != nil {
		t.Fatal("cannot revoke actual bound source")
	}
	material, err := c.service.SlotMaterial(context.Background(), "launch-a", slot.ID)
	stageCode(t, err, api.CodeForbidden)
	if len(material.Bytes) != 0 {
		t.Fatal("revoked bound source still delivered credential material")
	}
}

func TestInjectionCleanupSelection(t *testing.T) {
	c := newLaunchCase(t, "helper")
	grant, _ := c.addSecret(t, "cleanup-canary", "env", "CLEANUP_TOKEN")
	slot, err := c.acquire(context.Background(), c.target, c.grant)
	if err != nil {
		t.Fatal("cannot prepare injection cleanup selection control")
	}
	injection, err := c.inject(context.Background(), c.target, []api.SecretGrant{grant})
	if err != nil {
		t.Fatal("cannot prepare injection cleanup selection")
	}
	observation := c.bind(t, slot, injection)
	observation = c.finish(t, observation)
	injection.GrantIDs = []api.ID{}
	stageCode(t, c.service.RevokeInjection(context.Background(), injection, observation), api.CodeForbidden)
}

func TestCleanupReplayBinding(t *testing.T) {
	c := newLaunchCase(t, "helper")
	slot, err := c.acquire(context.Background(), c.target, c.grant)
	if err != nil {
		t.Fatal("cannot prepare cleanup replay control")
	}
	injection, err := c.inject(context.Background(), c.target, []api.SecretGrant{})
	if err != nil {
		t.Fatal("cannot prepare cleanup replay injection")
	}
	observation := c.bind(t, slot, injection)
	observation = c.finish(t, observation)
	if err := c.service.Release(context.Background(), slot, observation); err != nil {
		t.Fatal("cannot establish original measured cleanup")
	}
	if err := c.service.Release(context.Background(), slot, observation); err != nil {
		t.Fatal("identical measured cleanup did not replay")
	}
	if c.helper.releases != 1 {
		t.Fatal("cleanup replay released a second helper lease")
	}
	observation.Handle.Generation = "changed-generation"
	stageCode(t, c.service.Release(context.Background(), slot, observation), api.CodeContainmentUnknown)
}
