//go:build linux

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/orgrender"
)

func (m *leaseManager) renderOrg(ctx context.Context, stage orgrender.Stage) (orgrender.Result, error) {
	var zero orgrender.Result
	parent, err := m.find(stage.ParentLeaseID)
	if err != nil {
		return zero, err
	}
	if parent.Spec == nil || parent.Request.LifeID != stage.Target.LifeID || stage.Change.Config != m.binding.Config {
		return zero, failure(api.CodeConflict, "render has no original installed L6 allocation")
	}
	parent.Storage = nil // Render projects the retained org, not the lane's home.
	runtime, mounts, err := m.gateMounts(ctx, parent)
	if err != nil {
		return zero, err
	}
	defer func() {
		for _, mount := range mounts {
			mount.file.Close()
		}
	}()
	executable := ""
	for _, object := range runtime.Objects {
		if object.ID == stage.Change.Renderer.ID && object.Content.SHA256 == stage.Change.Renderer.SHA256 && object.Mode == 0555 {
			executable = nativeRuntimeTarget(object)
		}
	}
	if executable == "" {
		return zero, failure(api.CodeVersion, "render executable is absent from the pinned installed runtime")
	}
	records, err := m.records()
	if err != nil {
		return zero, err
	}
	used := map[uint32]bool{m.binding.Service.UID: true}
	reserveArchiveUIDs(records, used)
	for _, record := range records {
		if record.Phase != "released" && record.Phase != "aborted" {
			used[record.Lease.UID] = true
		}
		for _, job := range record.DataJobs {
			if job.State != "collected" {
				used[job.Lease.UID] = true
			}
		}
		for _, capture := range record.Captures {
			if captureReservesUID(capture) {
				used[capture.Native.Lease.UID] = true
			}
		}
	}
	for _, candidate := range m.binding.Lanes {
		if candidate.UID != 0 && !used[candidate.UID] {
			return runOrgRender(ctx, stage, candidate.UID, candidate.GID, executable, mounts)
		}
	}
	return zero, failure(api.CodeUnavailable, "render is waiting for a free installed worker UID")
}

// The helper's enclosing operation lock owns the selected UID for this one-shot
// job. The child has a new PID/mount/network namespace and only the opened
// enrolled runtime plus its private staged org. It receives no service socket.
func runOrgRender(ctx context.Context, stage orgrender.Stage, uid, gid uint32, executable string, mounts []*nativeMount) (result orgrender.Result, resultErr error) {
	if uid == 0 || gid == 0 || stage.ClaimID == "" || executable == "" {
		return result, failure(api.CodeInvalid, "native render needs its worker identity, claim and executable")
	}
	directory, err := os.MkdirTemp("", "lb-org-render-")
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(directory)) }()
	if err := os.Chmod(directory, 0711); err != nil {
		return result, err
	}
	root := filepath.Join(directory, "tree")
	if err := os.Mkdir(root, 0700); err != nil {
		return result, err
	}
	for _, file := range append(append([]orgrender.File{}, stage.Sources...), stage.Derived...) {
		if manifest.Relative(file.Path) != nil || file.Path == "." {
			return result, failure(api.CodeInvalid, "render input has an invalid org-relative path")
		}
		name := filepath.Join(root, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			return result, err
		}
		if err := os.WriteFile(name, file.Data, os.FileMode(file.Mode)); err != nil {
			return result, err
		}
	}
	if err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(name, int(uid), int(gid))
	}); err != nil {
		return result, err
	}
	input := orgrender.Input{Sources: []string{}}
	for _, file := range stage.Sources {
		input.Sources = append(input.Sources, file.Path)
	}
	for _, file := range stage.Derived {
		input.Derived = append(input.Derived, file.Path)
	}
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return result, err
	}
	inputPath := filepath.Join(directory, "input.json")
	if err := os.WriteFile(inputPath, inputBytes, 0444); err != nil {
		return result, err
	}
	args := []string{"--unshare-all", "--die-with-parent", "--new-session", "--clearenv", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--dir", "/job", "--bind", root, "/job/tree", "--chdir", "/job/tree",
		"--setenv", "HOME", "/tmp", "--setenv", "PATH", "/usr/bin:/bin:/runtime", "--setenv", "LANEBOSS_RENDER_TIME", string(stage.ObservedAt)}
	args = append(args, "--ro-bind", inputPath, "/job/input.json")
	files := []*os.File{}
	for i, mount := range mounts {
		reader, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(mount.file.Fd())))
		if err != nil {
			return result, err
		}
		defer reader.Close()
		files = append(files, reader)
		mode := "0444"
		if mount.executable {
			mode = "0555"
		}
		args = append(args, "--perms", mode, "--ro-bind-data", strconv.Itoa(3+i), mount.target)
	}
	args = append(args, "--", executable, "internal", "worker", "--config", stage.Change.Config, "org-render")
	command := exec.CommandContext(ctx, "/usr/bin/bwrap", args...)
	command.Env, command.Dir, command.ExtraFiles = []string{}, "/", files
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: false}, Pdeathsig: syscall.SIGKILL}
	var diagnostic renderDiagnostic
	command.Stdout, command.Stderr = &diagnostic, &diagnostic
	if err := command.Start(); err != nil {
		return result, err
	}
	pid := command.Process.Pid
	if err := command.Wait(); err != nil {
		return result, fmt.Errorf("native renderer failed: %w: %s", err, diagnostic.Bytes())
	}
	sources := map[string]orgrender.File{}
	for _, file := range stage.Sources {
		sources[file.Path] = file
	}
	result = orgrender.Result{JobID: stage.ID, ClaimID: stage.ClaimID, Generation: stage.Generation, InputSHA256: orgrender.Digest(stage), Renderer: stage.Change.Renderer, UID: uid, PID: pid, Files: []orgrender.File{}}
	err = filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return failure(api.CodeInvalid, "renderer output must contain regular files")
		}
		relative, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		stream, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		info, statErr := stream.Stat()
		data, readErr := io.ReadAll(io.LimitReader(stream, api.MaxObjectBytes+1))
		if err := errors.Join(statErr, readErr, stream.Close()); err != nil {
			return err
		}
		if len(data) > api.MaxObjectBytes {
			return failure(api.CodeBudget, "generated render file exceeds the object bound")
		}
		if source, found := sources[relative]; found {
			if !bytes.Equal(source.Data, data) || uint32(info.Mode().Perm()) != source.Mode {
				return failure(api.CodeConflict, "renderer changed a staged source instead of generating output")
			}
			delete(sources, relative)
			return nil
		}
		result.Files = append(result.Files, orgrender.File{Path: relative, Mode: uint32(info.Mode().Perm()), Data: data})
		return nil
	})
	if err != nil {
		return result, err
	}
	if len(sources) != 0 {
		return result, failure(api.CodeConflict, "renderer removed a staged source")
	}
	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].Path < result.Files[j].Path })
	return result, nil
}

type renderDiagnostic struct{ bytes.Buffer }

func (b *renderDiagnostic) Write(data []byte) (int, error) {
	n := len(data)
	if remaining := 16*1024 - b.Len(); remaining > 0 {
		b.Buffer.Write(data[:min(remaining, n)])
	}
	return n, nil
}
