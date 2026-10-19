//go:build linux

package secrets

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/native"
	"laneboss.io/laneboss/internal/v2/secrets/private"
)

// These are synthetic executable bytes in the installed vendor manifest shape:
// each vendor is a separately pinned file, not an object-store payload or the
// gate bootstrap. No vendor or model request executes in this component test.
func vendorProjectionManifest(t *testing.T, manifest *api.RuntimeManifest, executable *api.Executable) {
	t.Helper()
	for _, name := range []string{"claudock", "claude"} {
		data := syntheticBytes(t, 97+len(name))
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, data, 0555); err != nil {
			t.Fatal(err)
		}
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, data) {
			t.Fatal("cannot read the actual vendor fixture executable bytes", err)
		}
		pin := api.Executable{ID: api.ID(name), SHA256: digestFixture(string(actual)), Version: claudock.ClaudeVersion}
		if name == "claudock" {
			pin.Version = claudock.ClaudockVersion
			*executable = pin
		}
		manifest.Objects = append(manifest.Objects, api.RuntimeObject{ID: pin.ID, Role: name, RootID: "serve_assets", RelativePath: name, Mode: 0555,
			Content: api.BlobRef{ID: pin.ID, Class: "artifact", Bytes: int64(len(actual)), SHA256: pin.SHA256}})
	}
}

type vendorProjectionControl struct {
	api.HelperControl
	change func(*api.RuntimeManifest)
}

func (h vendorProjectionControl) ResolveRuntime(ctx context.Context, handoff api.PreparedSpecHandoff) (api.ResolvedRuntime, error) {
	runtime, err := h.HelperControl.ResolveRuntime(ctx, handoff)
	if err == nil {
		h.change(&runtime.Manifest)
	}
	return runtime, err
}

// Observe actual encrypted-file reads without retaining selectors or contents.
// The native service still performs every read, lock and authentication check.
type vendorProjectionStorage struct {
	*private.Directory
	missing map[string]int
}

func (s *vendorProjectionStorage) AcquireRefreshLease(id api.ID) (bstate.RefreshLease, error) {
	return s.Directory.AcquireRefreshLease(id)
}

func (s *vendorProjectionStorage) Read(name string, limit int64) ([]byte, error) {
	data, err := s.Directory.Read(name, limit)
	if hasCode(err, api.CodeNotFound) {
		kind := "source"
		for _, candidate := range []string{"projection", "slot", "profile", "login"} {
			if strings.HasPrefix(name, ".broker-"+candidate+"-") {
				kind = candidate
				break
			}
		}
		if strings.HasPrefix(name, ".key-") {
			kind = "key-check"
		}
		s.missing[kind]++
	}
	return data, err
}

func traceVendorProjectionStorage(t *testing.T, c *launchCase) *vendorProjectionStorage {
	t.Helper()
	if err := c.backend.Close(); err != nil {
		t.Fatal("cannot close native backend before observing encrypted storage")
	}
	directory, err := private.Open(c.directory)
	if err != nil {
		t.Fatal("cannot reopen actual encrypted storage", err)
	}
	storage := &vendorProjectionStorage{Directory: directory, missing: map[string]int{}}
	backend, err := native.NewWithStorage(native.Dependencies{Config: "service-case", KeyHandle: "key-a", Clock: c.clock}, storage)
	if err != nil {
		t.Fatal("cannot install observed native storage", err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Error("cannot close observed native storage", err)
		}
	})
	if err := backend.Unlock(context.Background(), "key-a", bytes.NewReader(c.key)); err != nil {
		t.Fatal("cannot authenticate actual encrypted records after reopening", err)
	}
	c.backend.Service = backend
	return storage
}

func TestVendorProjectionRuntime(t *testing.T) {
	for _, mode := range []string{"claude-api-key", "claudock-headless"} {
		t.Run(mode, func(t *testing.T) {
			m, peer := projectionCaseRuntime(t, func(manifest *api.RuntimeManifest, executable *api.Executable) {
				vendorProjectionManifest(t, manifest, executable)
			}, mode)
			storage := traceVendorProjectionStorage(t, m.c)
			s := m.c.service
			plan := m.c.plan(t)
			plan.Phase = "spec_retained"
			m.c.setPlan(t, plan)
			material, preparedErr := s.PreparedSlotMaterial(context.Background(), m.a.Request.Handoff.Spec, m.a.Request.Handoff.Spec.Runner.Slot.ID)
			if preparedErr != nil || !bytes.Equal(material.Bytes, m.c.material) {
				clear(material.Bytes)
				t.Error("installed vendor shape was refused by prepared credential material", preparedErr)
			}
			clear(material.Bytes)
			if len(storage.missing) != 0 {
				t.Fatal("prepared material unexpectedly needed an absent record")
			}
			transfer, err := s.TransferCredentials(context.Background(), peer, m.a.Request)
			if err != nil || len(transfer.Files) != len(m.a.Targets) {
				t.Fatal("installed vendor shape was refused by credential transfer", err)
			}
			if preparedErr != nil {
				t.Fatal("prepared credential material failed before transfer")
			}
			if len(storage.missing) != 1 || storage.missing["projection"] != 2 {
				t.Fatal("first transfer did not handle its actual projection lookup and generation probes", storage.missing)
			}
			replay, err := s.TransferCredentials(context.Background(), peer, m.a.Request)
			if err != nil || len(replay.Files) != len(transfer.Files) || storage.missing["projection"] != 2 {
				t.Fatal("retained projection replay repeated an absent-record probe or failed", err)
			}
			for i := range replay.Files {
				if replay.Files[i] != transfer.Files[i] {
					t.Fatal("retained projection replay exported another descriptor")
				}
			}
			for i, file := range transfer.Files {
				fact, err := credentialFact(file)
				if err != nil || !fact.Regular || !fact.ReadOnly || !fact.CloseOnExec || fact.Links != 0 || fact.WritableHandles == nil || *fact.WritableHandles != 0 || fact.Size <= 0 {
					t.Fatal("vendor projection exported an unprotected credential descriptor", i, err)
				}
			}
			record, err := s.AcknowledgeCredentials(context.Background(), m.hold(t, transfer))
			if err != nil || record.State != "held" || record.Receipt == nil {
				t.Fatal("vendor projection did not commit its actual descriptor acknowledgement", err)
			}
			t.Logf("vendor projection: mode=%s prepared_material=true transfer=true acknowledged=true projection_first_use_not_found=%d replay_additional_not_found=0", mode, storage.missing["projection"])
		})
	}
}

func TestVendorProjectionPins(t *testing.T) {
	changes := []struct {
		name   string
		change func(*api.RuntimeObject)
	}{
		{"generic-role", func(o *api.RuntimeObject) { o.Role = "agent" }},
		{"stand-in-role", func(o *api.RuntimeObject) { o.Role = "serve-fixture-agent" }},
		{"wrong-vendor-role", func(o *api.RuntimeObject) { o.Role = "claude" }},
		{"id", func(o *api.RuntimeObject) { o.ID = "foreign-vendor" }},
		{"digest", func(o *api.RuntimeObject) { o.Content.SHA256 = digestFixture("different vendor bytes") }},
		{"not-executable", func(o *api.RuntimeObject) { o.Mode = 0444 }},
		{"writable", func(o *api.RuntimeObject) { o.Mode = 0755 }},
		{"setuid", func(o *api.RuntimeObject) { o.Mode = 04555 }},
		{"root", func(o *api.RuntimeObject) { o.RootID = "foreign-root" }},
		{"path", func(o *api.RuntimeObject) { o.RelativePath = "foreign-vendor" }},
		{"content-id", func(o *api.RuntimeObject) { o.Content.ID = "foreign-content" }},
		{"content-class", func(o *api.RuntimeObject) { o.Content.Class = "manifest" }},
		{"content-size", func(o *api.RuntimeObject) { o.Content.Bytes++ }},
	}
	for _, side := range []string{"observed", "installed"} {
		for _, test := range changes {
			t.Run(side+"/"+test.name, func(t *testing.T) {
				var original api.RuntimeObject
				m, peer := projectionCaseRuntime(t, func(manifest *api.RuntimeManifest, executable *api.Executable) {
					vendorProjectionManifest(t, manifest, executable)
					original = manifest.Objects[0]
					if side == "installed" {
						test.change(&manifest.Objects[0])
					}
				}, "claude-api-key")
				s := m.c.service
				s.deps.Helper = vendorProjectionControl{HelperControl: s.deps.Helper, change: func(manifest *api.RuntimeManifest) {
					if side == "installed" {
						manifest.Objects[0] = original
					} else {
						test.change(&manifest.Objects[0])
					}
				}}
				vendorProjectionRefused(t, m, peer)
			})
		}
	}
	for _, side := range []string{"observed", "installed"} {
		for _, invalid := range []bool{false, true} {
			name := side + "/duplicate"
			if invalid {
				name += "-invalid"
			}
			t.Run(name, func(t *testing.T) {
				duplicate := func(manifest *api.RuntimeManifest) {
					object := manifest.Objects[0]
					if invalid {
						object.Role = "unrelated"
					}
					manifest.Objects = append(manifest.Objects, object)
				}
				m, peer := projectionCaseRuntime(t, func(manifest *api.RuntimeManifest, executable *api.Executable) {
					vendorProjectionManifest(t, manifest, executable)
					if side == "installed" {
						duplicate(manifest)
					}
				}, "claude-api-key")
				s := m.c.service
				s.deps.Helper = vendorProjectionControl{HelperControl: s.deps.Helper, change: func(manifest *api.RuntimeManifest) {
					if side == "installed" {
						manifest.Objects = manifest.Objects[:2]
					} else {
						duplicate(manifest)
					}
				}}
				vendorProjectionRefused(t, m, peer)
			})
		}
	}
	// Agreement alone cannot authorize a noncanonical vendor role, a digest
	// different from the selected executable, or a mutable executable mode.
	for _, test := range []struct {
		name   string
		change func(*api.RuntimeObject)
	}{
		{"generic-role", func(o *api.RuntimeObject) { o.Role = "agent" }},
		{"stand-in-role", func(o *api.RuntimeObject) { o.Role = "serve-fixture-agent" }},
		{"digest", func(o *api.RuntimeObject) { o.Content.SHA256 = digestFixture("different installed vendor bytes") }},
		{"writable", func(o *api.RuntimeObject) { o.Mode = 0755 }},
		{"setuid", func(o *api.RuntimeObject) { o.Mode = 04555 }},
	} {
		t.Run("both/"+test.name, func(t *testing.T) {
			m, peer := projectionCaseRuntime(t, func(manifest *api.RuntimeManifest, executable *api.Executable) {
				vendorProjectionManifest(t, manifest, executable)
				test.change(&manifest.Objects[0])
			}, "claude-api-key")
			vendorProjectionRefused(t, m, peer)
		})
	}
	t.Run("foreign-gate", func(t *testing.T) {
		m, peer := projectionCaseRuntime(t, func(manifest *api.RuntimeManifest, executable *api.Executable) {
			vendorProjectionManifest(t, manifest, executable)
		}, "claude-api-key")
		m.c.service.deps.Helper = vendorProjectionControl{HelperControl: m.c.service.deps.Helper, change: func(manifest *api.RuntimeManifest) {
			manifest.Bootstrap.ID = "foreign-bootstrap"
		}}
		vendorProjectionRefused(t, m, peer)
	})
	t.Run("missing-required-source", func(t *testing.T) {
		m, peer := projectionCaseRuntime(t, func(manifest *api.RuntimeManifest, executable *api.Executable) {
			vendorProjectionManifest(t, manifest, executable)
		}, "claude-api-key")
		storage := traceVendorProjectionStorage(t, m.c)
		plan := m.c.plan(t)
		plan.Phase = "spec_retained"
		m.c.setPlan(t, plan)
		original := filepath.Join(m.c.directory, string(m.c.profile.Source.SourceHandle)+".json")
		retained := filepath.Join(t.TempDir(), "retained-encrypted-source")
		if err := os.Rename(original, retained); err != nil {
			t.Fatal("cannot withdraw actual encrypted source for absence control", err)
		}
		defer func() {
			if err := os.Rename(retained, original); err != nil {
				t.Error("cannot restore encrypted source after absence control", err)
			}
		}()
		material, preparedErr := m.c.service.PreparedSlotMaterial(context.Background(), m.a.Request.Handoff.Spec, m.a.Request.Handoff.Spec.Runner.Slot.ID)
		defer clear(material.Bytes)
		transfer, transferErr := m.c.service.TransferCredentials(context.Background(), peer, m.a.Request)
		if !hasCode(preparedErr, api.CodeNotFound) || !hasCode(transferErr, api.CodeNotFound) || len(material.Bytes) != 0 || len(transfer.Files) != 0 || storage.missing["source"] != 2 {
			t.Fatal("required-source absence was swallowed or another refusal masked it", preparedErr, transferErr, storage.missing)
		}
		t.Log("missing required source: prepared and transfer both refused not_found; no credential returned")
	})
}

func vendorProjectionRefused(t *testing.T, m *projectionModel, peer api.VerifiedPeer) {
	t.Helper()
	s := m.c.service
	storage := traceVendorProjectionStorage(t, m.c)
	plan := m.c.plan(t)
	plan.Phase = "spec_retained"
	m.c.setPlan(t, plan)
	material, preparedErr := s.PreparedSlotMaterial(context.Background(), m.a.Request.Handoff.Spec, m.a.Request.Handoff.Spec.Runner.Slot.ID)
	defer clear(material.Bytes)
	transfer, transferErr := s.TransferCredentials(context.Background(), peer, m.a.Request)
	for _, result := range []struct {
		name string
		err  error
	}{{"prepared", preparedErr}, {"transfer", transferErr}} {
		var refusal *api.Error
		if !errors.As(result.err, &refusal) || refusal.Code != api.CodeForbidden || !strings.Contains(refusal.Message, "credential agent or gate bootstrap differs") {
			t.Error("credential projection accepted a changed vendor or failed for another reason", result.name, result.err)
		}
	}
	if len(material.Bytes) != 0 || len(transfer.Files) != 0 {
		t.Error("refused vendor projection returned credential material")
	}
	if len(storage.missing) != 1 || storage.missing["projection"] != 1 {
		t.Error("vendor refusal did not preserve its cause through the absent projection cleanup probe", storage.missing)
	}
}
