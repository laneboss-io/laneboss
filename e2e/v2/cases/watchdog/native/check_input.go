//go:build linux

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

func (f *fixture) upload(class string, raw []byte) (api.BlobRef, error) {
	var ref api.BlobRef
	begun, err := f.call("blob.begin", api.BlobBeginRequest{Class: class, Bytes: int64(len(raw)), SHA256: api.Digest(digest(raw))}, false)
	if err != nil {
		return ref, err
	}
	data, err := json.Marshal(begun)
	if err != nil {
		return ref, err
	}
	var upload api.BlobUpload
	if json.Unmarshal(data, &upload) != nil || upload.ObjectID == "" || upload.MaxChunkBytes < 1 {
		return ref, errors.New("check input upload has no actual bounded lease")
	}
	for offset := 0; offset < len(raw); {
		end := min(len(raw), offset+min(upload.MaxChunkBytes, api.MaxChunkBytes))
		if _, err := f.call("blob.chunk", api.BlobChunk{ObjectID: upload.ObjectID, Offset: int64(offset), Data: raw[offset:end], SHA256: api.Digest(digest(raw[offset:end]))}, false); err != nil {
			return ref, err
		}
		offset = end
	}
	committed, err := f.call("blob.commit", api.BlobCommitRequest{ObjectID: upload.ObjectID, SHA256: api.Digest(digest(raw))}, false)
	if err != nil {
		return ref, err
	}
	data, err = json.Marshal(committed)
	if err != nil {
		return ref, err
	}
	if json.Unmarshal(data, &ref) != nil || ref.ID != upload.ObjectID || ref.Class != class || ref.Bytes != int64(len(raw)) || ref.SHA256 != api.Digest(digest(raw)) {
		return ref, errors.New("check input upload changed exact bytes")
	}
	return ref, nil
}

// Candidate bytes originate in the actual child workspace. Only the inert
// tree/plan are uploaded; no check verdict, exit or review receipt is supplied.
func (f *fixture) prepareCheckInput(runtime api.Executable) (api.TestChildRequest, error) {
	var request api.TestChildRequest
	tree := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}
	cwd, err := os.Getwd()
	if err != nil {
		return request, err
	}
	total := int64(0)
	err = filepath.WalkDir(cwd, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == cwd {
			return nil
		}
		relative, err := filepath.Rel(cwd, path)
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if len(tree.Entries) >= 4096 {
			return errors.New("child candidate exceeds its entry bound")
		}
		value := api.ObjectEntry{Path: filepath.ToSlash(relative), Mode: uint32(info.Mode().Perm())}
		switch {
		case info.IsDir():
			value.Kind = "directory"
		case info.Mode().IsRegular():
			if info.Size() < 0 || info.Size() > 1<<20 || total+info.Size() > 4<<20 {
				return errors.New("child candidate exceeds its byte bound")
			}
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			raw, readErr := io.ReadAll(io.LimitReader(file, info.Size()+1))
			closeErr := file.Close()
			if err := errors.Join(readErr, closeErr); err != nil {
				return err
			}
			if int64(len(raw)) != info.Size() {
				return errors.New("child candidate changed while reading")
			}
			total += int64(len(raw))
			ref, err := f.upload("artifact", raw)
			if err != nil {
				return err
			}
			value.Kind, value.Content = "file", &ref
		default:
			return errors.New("child checker candidate has unsupported special filesystem entries")
		}
		tree.Entries = append(tree.Entries, value)
		return nil
	})
	if err != nil {
		return request, err
	}
	raw, err := api.CanonicalJSON(encode(tree))
	if err != nil {
		return request, err
	}
	candidate, err := f.upload("manifest", raw)
	if err != nil {
		return request, err
	}
	lane, err := f.call("lane.status", api.LifeRef{LifeID: api.ID(f.Life), Run: api.RunNumber(f.Run)}, false)
	if err != nil {
		return request, err
	}
	grant, ok := lane["grant_set_id"].(string)
	if !ok || grant == "" {
		return request, errors.New("check input has no exact child grants")
	}
	budget := api.Budget{WallMS: 60000, CPUSeconds: 10, MemoryBytes: 256 << 20, Processes: 16, DiskBytes: 4 << 20, Currency: "USD"}
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "test", Executable: runtime, Argv: []string{"laneboss", "check", reviewjob.SnapshotIntegrity}, Input: candidate, GrantSetID: api.ID(grant), Budget: budget}
	raw, err = api.CanonicalJSON(encode(plan))
	if err != nil {
		return request, err
	}
	declared, err := f.upload("manifest", raw)
	if err != nil {
		return request, err
	}
	request = api.TestChildRequest{Child: api.LifeRef{LifeID: api.ID(f.Life), Run: api.RunNumber(f.Run)}, Candidate: candidate, TestPlan: declared, Budget: budget}
	return request, nil
}

func (f *fixture) emitCheckInput() error {
	if f.Client == "" {
		return nil
	}
	info, err := os.Stat(f.Client)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 || info.Size() < 1 || info.Size() > 128<<20 {
		return errors.New("checker bootstrap is not the held installed runtime")
	}
	file, err := os.Open(f.Client)
	if err != nil {
		return err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, 128<<20+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, f.Client, "--version")
	command.Env = []string{}
	versionRaw, err := command.Output()
	if err != nil {
		return err
	}
	var version struct {
		Program string `json:"program"`
		Version string `json:"version"`
	}
	if json.Unmarshal(versionRaw, &version) != nil || version.Program != "laneboss" || version.Version == "" {
		return errors.New("checker bootstrap has no measured installed version")
	}
	runtime, err := f.checkBootstrap()
	if err != nil {
		return err
	}
	if runtime.SHA256 != api.Digest(digest(raw)) || runtime.Version != version.Version {
		return errors.New("checker runtime differs from actual installed bootstrap bytes or version")
	}
	request, err := f.prepareCheckInput(runtime)
	if err != nil {
		return err
	}
	payload := base64.StdEncoding.EncodeToString(encode(request))
	return emit(map[string]any{"type": "assistant", "session_id": f.VendorSession, "message": map[string]any{"content": []any{map[string]any{"type": "text", "text": "WD-CHECK-INPUT " + payload}}}})
}

func (f *fixture) checkBootstrap() (api.Executable, error) {
	var empty api.Executable
	fd, err := syscall.Open("/runtime/serve-agent_json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return empty, err
	}
	file := os.NewFile(uintptr(fd), "protected-fixture-runtime")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 || info.Size() < 1 || info.Size() > api.MaxFrameBytes {
		return empty, errors.New("checker runtime declaration is not protected")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	mapped, _, mapErr := wire.NamespaceServiceIDs()
	if !ok || stat.Nlink != 1 || stat.Uid != 0 && (mapErr != nil || stat.Uid != mapped) {
		return empty, errors.New("checker runtime declaration has a foreign owner")
	}
	raw, err := io.ReadAll(io.LimitReader(file, api.MaxFrameBytes+1))
	if err != nil {
		return empty, err
	}
	var declared struct {
		Schema string         `json:"schema"`
		Config string         `json:"config"`
		Vendor bool           `json:"vendor_stood_in"`
		Client api.Executable `json:"client"`
	}
	if json.Unmarshal(raw, &declared) != nil || declared.Schema != "laneboss.serve-agent.v1" || declared.Config != f.Config || !declared.Vendor || declared.Client.ID == "" {
		return empty, errors.New("checker runtime differs from the installed fixture enrollment")
	}
	return declared.Client, nil
}
