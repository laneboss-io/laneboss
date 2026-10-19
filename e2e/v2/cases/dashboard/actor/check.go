package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"laneboss.io/laneboss/internal/v2/api"
)

func checkWorkspace(path string, expected api.Digest) (result map[string]any, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > api.MaxFrameBytes {
		return nil, errors.New("candidate check requires a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, api.MaxFrameBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != info.Size() || hash(raw) != expected {
		return nil, errors.New("candidate content differs from its exact expected bytes")
	}
	return map[string]any{"path": path, "sha256": hash(raw), "bytes": len(raw)}, nil
}

func uploadObject(ctx context.Context, opt options, kind string, raw []byte) (api.BlobRef, error) {
	var begun api.BlobUpload
	if err := internal(ctx, opt, "blob begin", api.BlobBeginRequest{Class: kind, Bytes: int64(len(raw)), SHA256: hash(raw)}, &begun); err != nil {
		return api.BlobRef{}, err
	}
	if begun.ObjectID == "" || begun.MaxChunkBytes < 1 || begun.MaxChunkBytes > api.MaxChunkBytes {
		return api.BlobRef{}, errors.New("candidate upload has no bounded actual staging object")
	}
	for offset := 0; offset < len(raw); {
		end := min(offset+begun.MaxChunkBytes, len(raw))
		var chunk api.BlobUpload
		if err := internal(ctx, opt, "blob chunk", api.BlobChunk{ObjectID: begun.ObjectID, Offset: int64(offset), Data: raw[offset:end], SHA256: hash(raw[offset:end])}, &chunk); err != nil {
			return api.BlobRef{}, err
		}
		if chunk.ObjectID != begun.ObjectID {
			return api.BlobRef{}, errors.New("candidate upload chunk selected another staging object")
		}
		offset = end
	}
	var ref api.BlobRef
	if err := internal(ctx, opt, "blob commit", api.BlobCommitRequest{ObjectID: begun.ObjectID, SHA256: hash(raw)}, &ref); err != nil {
		return ref, err
	}
	if ref != (api.BlobRef{ID: begun.ObjectID, Class: kind, SHA256: hash(raw), Bytes: int64(len(raw))}) {
		return api.BlobRef{}, errors.New("candidate upload changed exact bytes")
	}
	return ref, nil
}

func snapshotCandidate(ctx context.Context, opt options, raw json.RawMessage) (api.TestChildRequest, error) {
	var request struct {
		Executable api.Executable `json:"executable"`
		Budget     api.Budget     `json:"budget"`
	}
	if err := api.DecodeObject(raw, &request); err != nil {
		return api.TestChildRequest{}, err
	}
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil || hash(self) != request.Executable.SHA256 {
		return api.TestChildRequest{}, errors.New("test plan executable differs from the actual fixture binary")
	}
	content, err := os.ReadFile("README.md")
	if err != nil || len(content) > api.MaxFrameBytes {
		return api.TestChildRequest{}, errors.New("actual candidate workspace file is unavailable or exceeds its bound")
	}
	info, err := os.Stat("README.md")
	if err != nil || !info.Mode().IsRegular() {
		return api.TestChildRequest{}, errors.New("actual candidate workspace file is not regular")
	}
	ref, err := uploadObject(ctx, opt, "artifact", content)
	if err != nil {
		return api.TestChildRequest{}, err
	}
	body, err := json.Marshal(api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "README.md", Kind: "file", Mode: uint32(info.Mode().Perm()), Content: &ref}}})
	if err != nil {
		return api.TestChildRequest{}, err
	}
	candidate, err := uploadObject(ctx, opt, "manifest", body)
	if err != nil {
		return api.TestChildRequest{}, err
	}
	target := api.LifeRef{LifeID: api.ID(opt.Life), Run: api.RunNumber(opt.Run)}
	var lane api.Lane
	if err := internal(ctx, opt, "lane status", target, &lane); err != nil {
		return api.TestChildRequest{}, err
	}
	if lane.LifeID != target.LifeID || lane.Run != target.Run || lane.GrantSetID == "" {
		return api.TestChildRequest{}, errors.New("test plan lost its actual child grants")
	}
	body, err = json.Marshal(workspaceCheckPlan(candidate, request.Executable, lane.GrantSetID, request.Budget, ref.SHA256))
	if err != nil {
		return api.TestChildRequest{}, err
	}
	plan, err := uploadObject(ctx, opt, "manifest", body)
	if err != nil {
		return api.TestChildRequest{}, err
	}
	return api.TestChildRequest{Child: target, Candidate: candidate, TestPlan: plan, Budget: request.Budget}, nil
}

func workspaceCheckPlan(candidate api.BlobRef, executable api.Executable, grants api.ID, budget api.Budget, expected api.Digest) api.WorkerPlan {
	return api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "test", Executable: executable,
		Argv:  []string{string(executable.ID), "--dashboard-check", "README.md", string(expected)},
		Input: candidate, GrantSetID: grants, Budget: budget}
}
