//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

type copyViewExpectation struct {
	SHA256   api.Digest
	ReadOnly bool
}

type copyViewExpectations struct {
	UID   uint32
	Files map[string]copyViewExpectation
	Links map[string]string
}

func TestMaterializationCopyViews(t *testing.T) {
	if os.Args[len(os.Args)-1] != "copy-view" {
		t.Fatal("copy view observer requires its sealed native canary input")
	}
	raw, err := os.ReadFile("/runtime/views.json")
	if err != nil {
		t.Fatal(err)
	}
	var input copyViewExpectations
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	if uint32(os.Geteuid()) != input.UID || input.UID == 0 || len(input.Files) < 3 || len(input.Links) == 0 {
		t.Fatal("copy view observer lost its allocated lane UID or rich data views")
	}
	writes := 0
	for name, expected := range input.Files {
		raw, err := os.ReadFile(name)
		if err != nil || digestBytes(raw) != expected.SHA256 {
			t.Fatal("lane destination does not contain the exact granted bytes", name, err)
		}
		if expected.ReadOnly {
			file, err := os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0)
			if file != nil {
				file.Close()
			}
			if !errors.Is(err, unix.EROFS) && !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
				t.Fatal("read-only granted copy accepted a write", name, err)
			}
		} else {
			file, err := os.OpenFile(name, os.O_RDWR, 0)
			if err != nil || len(raw) == 0 {
				t.Fatal("writable grant refused its actual file", name, err)
			}
			changed := []byte{raw[0] ^ 0xff}
			_, writeErr := file.WriteAt(changed, 0)
			observed := make([]byte, 1)
			_, readErr := file.ReadAt(observed, 0)
			_, restoreErr := file.WriteAt(raw[:1], 0)
			err = errors.Join(writeErr, readErr, restoreErr, file.Sync(), file.Close())
			if err != nil || !bytes.Equal(observed, changed) {
				t.Fatal("writable copy did not change and restore actual bytes", name, err)
			}
			writes++
		}
	}
	for name, target := range input.Links {
		actual, err := os.Readlink(name)
		if err != nil || actual != target {
			t.Fatal("copied symlink changed its granted target", name, err)
		}
		raw, err := os.ReadFile(name)
		if err != nil || digestBytes(raw) != input.Files[path.Join(path.Dir(name), target)].SHA256 {
			t.Fatal("copied symlink did not resolve to granted assembly bytes", name, err)
		}
	}
	if writes == 0 {
		t.Fatal("copy observer did not exercise a writable grant")
	}
	t.Log("lane UID verified nested assembly, symlink and bound file; rw bytes changed/restored, ro writes refused")
}

func materializationCopyViews(t *testing.T, ctx context.Context, m *leaseManager, lease, stage api.ID) error {
	t.Helper()
	parent, err := m.find(lease)
	if err != nil {
		return err
	}
	for _, job := range parent.DataJobs {
		if job.Reg.Request.StageID != stage {
			continue
		}
		if job.State != "measured" || job.Result == nil || len(job.Reg.Inputs.Grants.Data) != 3 {
			return failure(api.CodeIntegrity, "copy observer lacks three actually measured grant deliveries")
		}
		pins := m.dataPins[job.Projection.OpenToken]
		if pins == nil {
			return failure(api.CodeContainmentUnknown, "copy observer lost native helper descriptors")
		}
		if err := verifyDataCopies(ctx, parent, job, pins, job.Result.Data.Materialization.Objects); err != nil {
			return err
		}
		if err := materializationCopyOverlapNegative(job); err != nil {
			return err
		}
		t.Log("sibling copy selections validated; overlapping rw subtree and ro file refused with the exact grant error")
		if err := materializationCopyNegatives(ctx, m, job, pins); err != nil {
			return err
		}
		t.Log("helper refused changed source SHA, outside destination, expired grant and ro-to-rw; live baseline matched")
		parent.Spec = &specRegistration{Handoff: api.PreparedSpecHandoff{Cause: api.InternalIntent{EffectID: job.Reg.ParentEffect},
			Spec: api.LaunchSpec{Target: job.Reg.Reservation.Target, Grants: job.Reg.Inputs.Grants, RuntimeManifest: job.Reg.Inputs.Sources.Runtime.Manifest}}}
		priorResolver := m.exportResolver
		liveCalls := 0
		m.exportResolver = func(context.Context, leaseRecord, api.DataGrant) (registeredExport, error) {
			liveCalls++
			return registeredExport{}, failure(api.CodeIntegrity, "native copy reached the live mount owner")
		}
		defer func() { m.exportResolver = priorResolver }()
		if err := m.registerGateExports(ctx, &parent); err != nil {
			return err
		}
		if liveCalls != 0 {
			return failure(api.CodeIntegrity, "native copied exports called the live mount resolver")
		}
		defer m.collectGateExports(parent.Lease.ID)
		_, mounts, err := m.gateMounts(ctx, parent)
		if err != nil {
			return err
		}
		defer func() {
			for _, mount := range mounts {
				mount.file.Close()
			}
		}()
		withExports, err := m.appendGateExports(parent, mounts)
		if err != nil {
			return err
		}
		mounts = withExports
		expected := copyViewExpectations{UID: parent.Lease.UID, Files: map[string]copyViewExpectation{}, Links: map[string]string{}}
		var main api.ObjectManifest
		if err := json.Unmarshal(pins.manifest, &main); err != nil {
			return err
		}
		for _, entry := range main.Entries {
			if entry.Content != nil {
				expected.Files[path.Join("/work/main", entry.Path)] = copyViewExpectation{SHA256: entry.Content.SHA256,
					ReadOnly: job.Reg.Inputs.Grants.Data[0].Access == "ro"}
			}
		}
		for _, copy := range pins.copies {
			for _, entry := range copy.Projection.Manifest.Entries {
				name := path.Join(copy.Projection.Grant.Destination, entry.Path)
				if copy.Projection.File != "" {
					if copy.Projection.File != "file" {
						return failure(api.CodeIntegrity, "copy file view lost its fixed bound leaf")
					}
					name = copy.Projection.Grant.Destination
				}
				if entry.Kind == "symlink" {
					expected.Links[name] = entry.LinkTarget
				}
				if entry.Kind == "file" {
					var sha api.Digest
					if entry.Content != nil {
						sha = entry.Content.SHA256
					} else if entry.Assembly != nil {
						sha = entry.Assembly.SHA256
					}
					expected.Files[name] = copyViewExpectation{SHA256: sha, ReadOnly: copy.Projection.Grant.Access == "ro"}
				}
			}
		}
		metadata, err := sealedBootstrap(expected)
		if err != nil {
			return err
		}
		defer metadata.Close()
		if err := metadata.Chmod(0444); err != nil {
			return err
		}
		mounts = append(mounts, &nativeMount{file: metadata, target: "/runtime/views.json", sealed: true})
		// Exercise the production lane mount builder and descriptor grammar.
		// Only the final fixed executable entry changes to this test observer.
		observe := func() ([]byte, error) {
			args, files := nativeGateArgs(m.binding.Config, "copy-view", nil, mounts, true)
			boundary := slices.Index(args, "--")
			if boundary < 0 {
				return nil, failure(api.CodeIntegrity, "native gate lost its executable boundary")
			}
			args = append(args[:boundary+1], fixedBootstrapPath, "-test.run=^TestMaterializationCopyViews$", "-test.v", "--", "copy-view")
			command := exec.CommandContext(ctx, "/usr/bin/bwrap", args...)
			command.Dir = "/"
			command.Env, command.ExtraFiles = []string{}, files
			command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: parent.Lease.UID, Gid: parent.Lease.GID, Groups: []uint32{}}}
			return command.CombinedOutput()
		}
		output, err := observe()
		if err != nil {
			return fmt.Errorf("native copied-view observer failed: %w; %s", err, output)
		}
		t.Log(string(output))
		// A writable project bind must make the same observer fail from a real
		// successful write-open. No bytes are changed by that negative control.
		var project *nativeMount
		for _, mount := range mounts {
			if mount.target == "/work/main" {
				project = mount
			}
		}
		if project == nil || project.writable {
			return failure(api.CodeIntegrity, "native lane builder did not retain the read-only project bind")
		}
		project.writable = true
		control, controlErr := observe()
		project.writable = false
		if controlErr == nil || !bytes.Contains(control, []byte("read-only granted copy accepted a write /work/main/")) {
			return fmt.Errorf("copy observer did not reject the actual writable project control: %w; %s", controlErr, control)
		}
		t.Log("observer rejected the actual writable project mount control")
		return nil
	}
	return failure(api.CodeNotFound, "copy observer selected an unknown stage")
}

func materializationCopyOverlapNegative(job dataJob) error {
	grants := job.Reg.Inputs.Grants
	if err := manifest.StoredSet(grants); err != nil {
		return fmt.Errorf("actual sibling copy grant baseline failed: %w", err)
	}
	grants.Data = append([]api.DataGrant{}, grants.Data...)
	var writable, file int = -1, -1
	for i, grant := range grants.Data {
		if grant.Destination == "/data/parent" && grant.Access == "rw" {
			writable = i
		}
		if grant.Destination == "/data/fixed" && grant.Access == "ro" {
			file = i
		}
	}
	if writable < 0 || file < 0 {
		return failure(api.CodeIntegrity, "overlap control lost its actual rw and ro grants")
	}
	// Select the same immutable source as well as an overlapping path, so
	// this control pins the original same-source ambiguity rule explicitly.
	grants.Data[file].SourceObjectID = grants.Data[writable].SourceObjectID
	grants.Data[file].SourceSHA256 = grants.Data[writable].SourceSHA256
	grants.Data[file].RelativePath = path.Join(grants.Data[writable].RelativePath, "nested/input.bin")
	err := manifest.StoredSet(grants)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || typed.Message != "data source grants have ambiguous overlapping rights" {
		return fmt.Errorf("overlapping copy grants escaped their original refusal: %v", err)
	}
	return nil
}

func materializationCopyNegatives(ctx context.Context, m *leaseManager, job dataJob, pins *dataPins) error {
	payloads := make([]dataCopyPayload, 0, len(pins.copies))
	for _, copy := range pins.copies {
		payloads = append(payloads, copy.Payload)
	}
	if _, err := validateCopyPayloads(job.Reg.Inputs, payloads); err != nil {
		return fmt.Errorf("actual copied-source baseline failed: %w", err)
	}
	for _, name := range []string{"source-sha", "destination", "ro-to-rw", "expired"} {
		raw, err := json.Marshal(payloads)
		if err != nil {
			return err
		}
		var changed []dataCopyPayload
		if err := json.Unmarshal(raw, &changed); err != nil {
			return err
		}
		switch name {
		case "source-sha":
			changed[0].Source.Ref.SHA256 = digestBytes([]byte("different ceiling source"))
		case "destination":
			changed[0].Grant.Destination = "/runtime/ungranted"
		case "ro-to-rw":
			for i := range changed {
				if changed[i].Grant.Access == "ro" {
					changed[i].Grant.Access = "rw"
					break
				}
			}
		case "expired":
			changed[0].Grant.ExpiresAt = api.Timestamp(time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano))
		}
		_, err = m.openData(ctx, job.Reg, changed)
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeForbidden {
			return fmt.Errorf("copied-source %s escaped its original helper ceiling: %v", name, err)
		}
	}
	// Match the trusted grant input as well, so these controls reach each
	// independent predicate rather than the complete-grant equality check.
	for _, control := range []struct {
		name, message string
		code          api.ErrorCode
	}{
		{"destination", "destination must be /work/ID or /data/ID", api.CodeInvalid},
		{"access", "copy preparation has an invalid extra destination or access", api.CodeForbidden},
		{"source-pin", "copy preparation substituted its issued source or grant", api.CodeForbidden},
		{"expired", "grant has expired", api.CodeForbidden},
		{"delivery", "materialization delivery mode \"mount\" is not implemented", api.CodeUnsupported},
	} {
		inputRaw, err := json.Marshal(job.Reg.Inputs)
		if err != nil {
			return err
		}
		payloadRaw, err := json.Marshal(payloads)
		if err != nil {
			return err
		}
		var inputs api.LaunchInputs
		var changed []dataCopyPayload
		if err := errors.Join(json.Unmarshal(inputRaw, &inputs), json.Unmarshal(payloadRaw, &changed)); err != nil {
			return err
		}
		switch control.name {
		case "destination":
			changed[0].Grant.Destination = "/runtime/ungranted"
		case "access":
			changed[0].Grant.Access = "invalid"
		case "source-pin":
			changed[0].Grant.SourceSHA256 = digestBytes([]byte("different trusted source"))
		case "expired":
			changed[0].Grant.ExpiresAt = api.Timestamp(time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano))
		case "delivery":
			changed[0].Grant.Delivery = "mount"
		}
		for i := range inputs.Grants.Data {
			if inputs.Grants.Data[i].ID == changed[0].Grant.ID {
				inputs.Grants.Data[i] = changed[0].Grant
			}
		}
		_, err = validateCopyPayloads(inputs, changed)
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != control.code || typed.Message != control.message {
			return fmt.Errorf("copy %s predicate did not produce its own refusal: %v", control.name, err)
		}
	}
	return nil
}

func materializationCopyCollection(t *testing.T, ctx context.Context, m *leaseManager, lease, stage api.ID) error {
	t.Helper()
	parent, err := m.find(lease)
	if err != nil {
		return err
	}
	for _, job := range parent.DataJobs {
		if job.Reg.Request.StageID != stage {
			continue
		}
		copies, err := api.ValidateDataCopyProjections(job.Reg.Inputs, job.Projection)
		if err != nil || len(copies) != 2 {
			return failure(api.CodeIntegrity, "copy collection lacks its original projections")
		}
		root, err := openStorageRoot(storageBase(m.binding, parent))
		if err != nil {
			return err
		}
		inventory, inventoryErr := inventoryStorage(ctx, root, parent)
		if err := errors.Join(inventoryErr, root.Close()); err != nil {
			return err
		}
		for _, copy := range copies {
			found := false
			for _, item := range inventory {
				found = found || fmt.Sprintf("%d:%d", item.Device, item.Inode) == copy.DestinationIdentity
			}
			if !found {
				return failure(api.CodeIntegrity, "copy destination is missing from actual private collection inventory")
			}
		}
		if matched, err := m.collectData(ctx, stage); err != nil || !matched {
			return fmt.Errorf("native copied-source collection failed: matched=%t: %w", matched, err)
		}
		for _, name := range append([]string{"source"}, copySourceNames(copies)...) {
			if _, err := os.Lstat(filepath.Join(laneStagePath(m.binding, stage), name)); !errors.Is(err, os.ErrNotExist) {
				return failure(api.CodeIntegrity, "native source collection left a copied source root")
			}
		}
		parent, err = m.find(lease)
		if err != nil {
			return err
		}
		if err := m.collectPrivateStorage(ctx, &parent); err != nil {
			return err
		}
		for _, copy := range copies {
			if _, err := os.Lstat(filepath.Join(storageBase(m.binding, parent), string(copy.WorkspaceID))); !errors.Is(err, os.ErrNotExist) {
				return failure(api.CodeIntegrity, "private collection left a copied destination root")
			}
		}
		t.Log("native collection removed every additional source and destination root")
		return nil
	}
	return failure(api.CodeNotFound, "copy collection selected an unknown stage")
}

func copySourceNames(copies []api.DataCopyProjection) []string {
	names := make([]string, 0, len(copies))
	for _, copy := range copies {
		names = append(names, "source-"+string(copy.WorkspaceID))
	}
	return names
}
