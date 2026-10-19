//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

type dataCacheCanaryObject struct {
	Ref  api.BlobRef `json:"ref"`
	Data []byte      `json:"data"`
}

// The cgroup effect boundary uses the existing component recorder. The
// journal, installer, seccomp, paths, contents, UID/GID and inode checks are
// real; this test does not claim installed cgroup provisioning.
type dataOpenFixtureOptions struct {
	Config  string
	Service account
	Lanes   []account
}

func dataOpenNativeFixture(t *testing.T, options ...dataOpenFixtureOptions) (*leaseManager, dataReg, string) {
	t.Helper()
	parent, job, binding := dataTestReg(t)
	id, err := randomID("")
	if err != nil {
		t.Fatal(err)
	}
	binding.Config = "data-" + string(id[:16])
	if len(options) > 1 || len(options) == 1 && (!validConfig(options[0].Config) || len(options[0].Lanes) < 2) {
		t.Fatal("native data fixture requires one valid explicit configuration")
	}
	if len(options) == 1 {
		binding.Config, binding.Service, binding.Lanes = options[0].Config, options[0].Service, options[0].Lanes
		parent.Lease.UID, parent.Lease.GID = binding.Lanes[0].UID, binding.Lanes[0].GID
	}
	parent.Request.Config, parent.Request.Cause.Config = binding.Config, binding.Config
	parent.IssuedAt = gateTimestamp()
	allocation := &parent.LaunchAllocations[0]
	allocation.Request, allocation.Reservation.Config = parent.Request, binding.Config
	content := []byte("retained native source cache bytes\n")
	file := api.BlobRef{ID: "native-source-file", Class: "artifact", SHA256: digestBytes(content), Bytes: int64(len(content))}
	manifest, err := canonicalValue(api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
		{Path: "README.md", Kind: "file", Mode: 0444, Content: &file},
		{Path: "nested", Kind: "directory", Mode: 0500},
		{Path: "nested/copy", Kind: "file", Mode: 0444, Content: &file},
		{Path: "link", Kind: "symlink", Mode: 0777, LinkTarget: "README.md"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	source := &allocation.Inputs.Sources.Project
	source.Object = api.BlobRef{ID: "native-project", Class: "manifest", SHA256: digestBytes(manifest), Bytes: int64(len(manifest))}
	source.Base = string(source.Object.SHA256)
	grant := &allocation.Inputs.Grants.Data[0]
	grant.SourceObjectID, grant.SourceSHA256 = source.Object.ID, source.Object.SHA256
	job.Reg.Reservation, job.Reg.Inputs = allocation.Reservation, allocation.Inputs
	job.Reg.Grants.Data[0].SourceObjectID, job.Reg.Grants.Data[0].SourceSHA256 = source.Object.ID, source.Object.SHA256
	job.Reg.Grants.SHA256 = ""
	encoded, err := canonicalValue(job.Reg.Grants)
	if err != nil {
		t.Fatal(err)
	}
	job.Reg.Grants.SHA256 = digestBytes(encoded)
	if err := validateDataReg(job.Reg, binding.Config); err != nil {
		t.Fatal("native data registration is invalid", err)
	}
	state, lanes := binding.statePath(), filepath.Dir(laneStagePath(binding, parent.Lease.ID))
	for _, directory := range []string{state, lanes} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(directory); err != nil {
				t.Error(err)
			}
		})
	}
	if err := createLaneStage(laneStagePath(binding, parent.Lease.ID), parent.Lease.GID); err != nil {
		t.Fatal(err)
	}
	root, err := openStorageRoot(laneStagePath(binding, parent.Lease.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(syncStorageDirectories(context.Background(), root, &parent, 0, true), root.Close()); err != nil {
		t.Fatal(err)
	}
	journal, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	})
	m := newLeaseManager(binding, parent.BootID, &fileLeaseStore{root: journal}, &observedResources{})
	if err := m.save(parent); err != nil {
		t.Fatal(err)
	}
	enrollment, err := json.Marshal(api.LaunchEnrollment{Schema: "laneboss.launch-enrollment.v2", Config: binding.Config, Generation: 1,
		Projects: []api.ProjectEnrollment{{ID: "native-project-enrollment", ProjectID: source.ProjectID, Generation: 1, Object: source.Object, Base: source.Base, HistoryScope: "tree"}},
		Runtimes: []api.LaunchRuntime{allocation.Inputs.Sources.Runtime}})
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(struct {
		Enrollment []byte                  `json:"enrollment"`
		Objects    []dataCacheCanaryObject `json:"objects"`
	}{enrollment, []dataCacheCanaryObject{{source.Object, manifest}, {file, content}}})
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(privateTestDir(t), "cache-input.json")
	if err := os.WriteFile(inputPath, input, 0600); err != nil {
		t.Fatal(err)
	}
	return m, job.Reg, inputPath
}

func TestDataOpenReservedRetry(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("data open canary requires disposable Linux root")
	}
	if os.Args[len(os.Args)-1] != "admin-data-open-seccomp" {
		executable, err := os.Open("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		defer executable.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "/proc/self/fd/3", "-test.run=^TestDataOpenReservedRetry$", "-test.v", "--", "admin-data-open-seccomp")
		command.Env, command.ExtraFiles = []string{}, []*os.File{executable}
		output, err := command.CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte("--- PASS: TestDataOpenReservedRetry ")) {
			t.Fatalf("restricted native data-open child did not pass: %v\n%s", err, output)
		}
		return
	}
	m, request, input := dataOpenNativeFixture(t)
	ctx := context.Background()
	if err := denyOpenat2(); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, m.binding.statePath(), &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC})
	if fd >= 0 {
		unix.Close(fd)
	}
	if !errors.Is(err, unix.EPERM) {
		t.Fatal("native openat2 denial was not active")
	}
	_, err = m.openData(ctx, request)
	if err == nil || api.HelperReason(err) != "storage_directory" {
		t.Fatal("missing protected source cache did not reproduce the installed refusal", err)
	}
	records, err := m.records()
	if err != nil || len(records) != 1 || len(records[0].DataJobs) != 1 || records[0].DataJobs[0].State != "reserved" {
		t.Fatal("failed open did not retain its actual reservation", err)
	}
	original := records[0].DataJobs[0].Lease
	if _, err := os.Lstat(laneStagePath(m.binding, request.Request.StageID)); !os.IsNotExist(err) {
		t.Fatal("pre-source failure unexpectedly created a data stage", err)
	}
	install := func(mode string) ([]byte, error) {
		args := []string{"-I", "-B", "testdata/source_cache_canary.py", input, m.binding.statePath()}
		if mode != "" {
			args = append(args, mode)
		}
		command := exec.CommandContext(ctx, "/usr/bin/python3", args...)
		command.Env = []string{}
		return command.CombinedOutput()
	}
	for _, mode := range []string{"changed_blob", "escape", "duplicate", "linked_parent"} {
		if _, err := install(mode); err == nil {
			t.Fatal("source-cache installer admitted changed or escaping input")
		}
		if _, err := os.Lstat(filepath.Join(m.binding.statePath(), "sources")); !os.IsNotExist(err) {
			t.Fatal("invalid source input caused cache publication", err)
		}
	}
	for _, expected := range []string{"source-cache:changed\n", "source-cache:verified\n"} {
		if output, err := install(""); err != nil || string(output) != expected {
			t.Fatalf("actual installer source step or exact replay failed: %v\n%s", err, output)
		}
	}
	foreign := request
	foreign.Reservation.OperationID, foreign.Worker.OperationID = "foreign-open-operation", "foreign-open-operation"
	if _, err := m.openData(ctx, foreign); err == nil {
		t.Fatal("data retry adopted a foreign operation")
	}
	concurrent := request
	concurrent.ClaimID = "concurrent-open-attempt"
	var typed *api.Error
	if _, err := m.openData(ctx, concurrent); !errors.As(err, &typed) || typed.Code != api.CodeConflict {
		t.Fatal("same-generation foreign attempt borrowed the reserved operation", err)
	}
	stage := laneStagePath(m.binding, request.Request.StageID)
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	var before, after unix.Stat_t
	if unix.Lstat(stage, &before) != nil {
		t.Fatal("could not observe the conflicting native stage")
	}
	if _, err := m.openData(ctx, request); err == nil || api.HelperReason(err) != "data_retry" {
		t.Fatal("data retry adopted an unjournaled native stage", err)
	}
	if unix.Lstat(stage, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode {
		t.Fatal("refused retry changed the conflicting stage")
	}
	if err := os.Remove(stage); err != nil {
		t.Fatal(err)
	}
	request.ClaimID, request.ClaimGeneration = "renewed-open-attempt", request.ClaimGeneration+1
	projection, err := m.openData(ctx, request)
	if err != nil || projection.OpenToken == "" {
		t.Fatal("same data open could not recover after its prerequisite was installed", err)
	}
	pins := m.dataPins[projection.OpenToken]
	if pins == nil {
		t.Fatal("successful retry did not retain native descriptors")
	}
	t.Cleanup(func() {
		if err := pins.close(); err != nil {
			t.Error(err)
		}
	})
	records, err = m.records()
	if err != nil || len(records[0].DataJobs) != 1 || records[0].DataJobs[0].Lease != original || records[0].DataJobs[0].State != "open" {
		t.Fatal("retry replaced its reserved UID or appended another operation", err)
	}
	replayed, err := m.openData(ctx, request)
	if err != nil || !reflect.DeepEqual(replayed, projection) {
		t.Fatal("successful data-open replay changed its held token or native roots", err)
	}
	for _, file := range pins.roots {
		var info unix.Stat_t
		if unix.Fstat(int(file.Fd()), &info) != nil || info.Uid != original.UID || info.Gid != original.GID || info.Mode&07777 != 0700 {
			t.Fatal("retry did not perform the actual confined-worker ownership transfer")
		}
	}
	cacheFile := filepath.Join(m.binding.statePath(), "sources", string(request.Inputs.Sources.Project.Object.SHA256), "tree", "README.md")
	changed := []byte("changed protected cache control\n")
	if err := os.WriteFile(cacheFile, changed, 0444); err != nil {
		t.Fatal(err)
	}
	if _, err := install(""); err == nil {
		t.Fatal("installer accepted or silently overwrote a changed source cache")
	}
	if retained, err := os.ReadFile(cacheFile); err != nil || !bytes.Equal(retained, changed) {
		t.Fatal("refused source-cache replay changed the retained bytes", err)
	}
}
