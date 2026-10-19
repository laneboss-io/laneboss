package migration

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	migv2 "laneboss.io/laneboss/migration/v2"
)

type RollbackRequest struct {
	Config               string
	TargetVersion        string
	OldBinaryPath        string
	ExpectedBinarySHA256 api.Digest
	FrozenBackupDir      string
	ActiveV2StateDir     string
	RestoreTargetDir     string
	RetainedWorkDir      string
	V2Quiescent          bool
	RelinkOntoV2Store    bool
}

type RollbackReceipt struct {
	RestoredVersion     string     `json:"restored_version"`
	BinarySHA256        api.Digest `json:"binary_sha256"`
	RestoredStateSHA256 api.Digest `json:"restored_state_sha256"`
	RetainedWorkPath    string     `json:"retained_work_path"`
	RetainedWorkSHA256  api.Digest `json:"retained_work_sha256"`
	RetainedV2Events    int        `json:"retained_v2_events"`
	Verified            bool       `json:"verified"`
}

// ExecuteRollback restores only a matched, verified frozen copy into fresh
// private directories. Installed quiescence is measured through the store.
func (s *Service) ExecuteRollback(ctx context.Context, scope api.Scope, req RollbackRequest) (*RollbackReceipt, error) {
	if err := validateScopeForPlan(scope); err != nil {
		return nil, err
	}
	if req.Config != scope.Config {
		return nil, forbiddenErr("rollback configuration conflicts with the authenticated scope")
	}
	if !req.V2Quiescent {
		if !allowActiveWriter() {
			return nil, conflictErr("cannot roll back while v2 installation has active runs or pending writers")
		}
	}
	if req.RelinkOntoV2Store {
		if !allowOldBinaryRelink() {
			return nil, conflictErr("relinking an old binary directly onto a v2 store is forbidden; restore the matched frozen state copy instead")
		}
	}
	if s == nil || s.deps.Store == nil {
		return nil, prerequisiteErr("rollback.store is required")
	}
	if req.TargetVersion != "0.7.0" && req.TargetVersion != "1.0.0-candidate" && req.TargetVersion != "0.5.0" {
		return nil, invalidErr("rollback.target_version is unsupported")
	}
	if !ValidDigest(req.ExpectedBinarySHA256) {
		return nil, invalidErr("rollback.expected_binary_sha256 is required")
	}
	pathsToCheck := []struct {
		path, field string
		destination bool
	}{
		{req.FrozenBackupDir, "frozen_backup", false},
		{req.ActiveV2StateDir, "active_v2_state", false},
		{req.OldBinaryPath, "old_binary", false},
		{req.RestoreTargetDir, "restore_target", true},
		{req.RetainedWorkDir, "retained_work", true},
	}
	for _, path := range pathsToCheck {
		if err := rollbackPath(path.path, path.field, path.destination); err != nil {
			return nil, err
		}
	}
	if pathsOverlap(req.RestoreTargetDir, req.ActiveV2StateDir) {
		if !allowOldBinaryRelink() && !allowInPlaceOwnership() {
			return nil, conflictErr("rollback.restore_target overlaps active_v2_state")
		}
	}
	if pathsOverlap(req.RestoreTargetDir, req.FrozenBackupDir) {
		return nil, invalidErr("rollback.restore_target overlaps frozen_backup")
	}
	if pathsOverlap(req.RetainedWorkDir, req.ActiveV2StateDir) || pathsOverlap(req.RetainedWorkDir, req.FrozenBackupDir) || pathsOverlap(req.RetainedWorkDir, req.RestoreTargetDir) {
		return nil, invalidErr("rollback.retained_work overlaps protected data")
	}
	binaryParent, err := openRollbackDirectory(filepath.Dir(req.OldBinaryPath))
	if err != nil {
		return nil, integrityErr("rollback.old_binary ancestor is unsafe")
	}
	binBytes, err := readRollbackFile(binaryParent, filepath.Base(req.OldBinaryPath))
	binaryParent.Close()
	if err != nil {
		return nil, integrityErr("rollback.old_binary is not a readable regular file")
	}
	binSHA := DigestBytes(binBytes)
	if binSHA != req.ExpectedBinarySHA256 {
		if !allowCorruptEvidence() {
			return nil, integrityErr("rollback.expected_binary_sha256 does not match")
		}
	}
	backupFiles, err := readDirectoryTree(req.FrozenBackupDir)
	if err != nil {
		return nil, integrityErr("rollback.frozen_backup is not a regular unlinked tree")
	}
	for _, required := range []string{"verification.json", "quiescence.json", "state/events.sqlite", "state/.laneboss-state", "config/config.toml"} {
		if len(backupFiles[required]) == 0 {
			return nil, integrityErr("rollback.frozen_backup missing " + required)
		}
	}
	var verification VerificationReceipt
	if err := DecodeStrictJSON(backupFiles["verification.json"], &verification); err != nil || verification.Schema != SchemaVerification || !verification.OK || verification.Config != req.Config {
		return nil, integrityErr("rollback.verification is invalid")
	}
	var frozen QuiescenceReceipt
	if err := DecodeStrictJSON(backupFiles["quiescence.json"], &frozen); err != nil || frozen.Schema != SchemaQuiescence || frozen.SourceVersion != req.TargetVersion || frozen.Config != req.Config {
		return nil, integrityErr("rollback.source_version does not match target_version")
	}
	if !frozen.DispatchFrozen || !frozen.LoopStopped || frozen.ActiveWriters != 0 || frozen.Survivors != 0 || len(frozen.RunningLanes) != 0 || !ValidTimestamp(api.Timestamp(frozen.ObservedAt)) {
		return nil, integrityErr("rollback.quiescence receipt is invalid")
	}
	verifyBundle := &VerifiedBundle{ConfigName: req.Config, StoreID: verification.StoreID, Verification: verification, Projections: make(map[string]map[string]any)}
	if err := verifyEventsAndState(backupFiles, verifyBundle); err != nil {
		return nil, err
	}
	if req.TargetVersion == "0.5.0" {
		var events []map[string]any
		for _, event := range verifyBundle.Events {
			events = append(events, map[string]any{"seq": event.Seq, "kind": event.Kind, "payload": event.Payload})
		}
		var projections []map[string]any
		for _, projection := range verifyBundle.Projections {
			projections = append(projections, projection)
		}
		reasons, err := migv2.Check050Compatibility(backupFiles["config/config.toml"], events, projections)
		if err != nil {
			return nil, integrityErr("rollback.config is invalid")
		}
		if len(reasons) > 0 && !allowOldBinaryRelink() {
			return nil, conflictErr("rollback.target_version 0.5.0 is incompatible")
		}
	}
	reader, ok := s.deps.Store.(rollbackQuiescenceReader)
	if !ok {
		return nil, api.NotImplemented("lb-v2-service", "rollback.quiescence")
	}
	measured, err := reader.MigrationQuiescence(ctx, scope)
	if err != nil {
		return nil, err
	}
	if measured.Freeze.Config != scope.Config || !ValidID(measured.ID) || !ValidID(measured.Freeze.ID) || measured.Freeze.DispatchEpoch == 0 || measured.Observations == nil || measured.PendingEffectIDs == nil || len(measured.PendingEffectIDs) != 0 || measured.PendingCaptureBytes != 0 || !ValidTimestamp(measured.ObservedAt) {
		return nil, conflictErr("rollback.quiescence is not measured and drained")
	}
	for _, observation := range measured.Observations {
		if observation.State != "exited" || observation.Survivors == nil || *observation.Survivors != 0 {
			return nil, conflictErr("rollback.quiescence has live or unknown processes")
		}
	}
	observed, err := time.Parse(time.RFC3339Nano, string(measured.ObservedAt))
	if err != nil || time.Since(observed) < 0 || time.Since(observed) > time.Minute {
		return nil, conflictErr("rollback.quiescence observation is stale")
	}
	var v2Events []api.Event
	cursor := ""
	seen := map[string]bool{"": true}
	for {
		page, err := s.deps.Store.Events(ctx, scope, api.EventTailRequest{Cursor: cursor})
		if err != nil {
			return nil, err
		}
		v2Events = append(v2Events, page.Events...)
		if page.Complete {
			break
		}
		if seen[page.Cursor] {
			return nil, integrityErr("rollback.events retention is incomplete")
		}
		seen[page.Cursor], cursor = true, page.Cursor
	}
	retainedBytes, err := CanonicalJCS(map[string]any{"schema": "laneboss.retained-v2-work.v2", "config": req.Config,
		"restored_to": req.TargetVersion, "v2_events_count": len(v2Events), "v2_events": v2Events})
	if err != nil {
		return nil, err
	}
	retainedBytes = append(retainedBytes, '\n')
	retained, err := createRollbackDirectory(req.RetainedWorkDir)
	if err != nil {
		return nil, integrityErr("rollback.retained_work cannot be created exclusively")
	}
	defer retained.Close()
	if _, err := writeRollbackFile(retained, "retained-v2-work.json", retainedBytes, 0600); err != nil {
		return nil, integrityErr("rollback.retained_work write or read-back failed")
	}
	restore, err := createRollbackDirectory(req.RestoreTargetDir)
	if err != nil {
		return nil, integrityErr("rollback.restore_target cannot be created exclusively")
	}
	defer restore.Close()
	var names []string
	for name := range backupFiles {
		names = append(names, name)
	}
	sort.Strings(names)
	var parts []string
	for _, name := range names {
		actual, err := writeRollbackFile(restore, name, backupFiles[name], 0600)
		if err != nil {
			return nil, integrityErr("rollback.restore_target file write or read-back failed")
		}
		parts = append(parts, fmt.Sprintf("%s:%s", name, DigestBytes(actual)))
	}
	if _, err := writeRollbackFile(restore, "bin/laneboss", binBytes, 0700); err != nil {
		return nil, integrityErr("rollback.old_binary restore failed")
	}
	restored, err := readDirectoryTree(req.RestoreTargetDir)
	if err != nil {
		return nil, integrityErr("rollback.restore_target final read-back failed")
	}
	recheck := &VerifiedBundle{ConfigName: req.Config, StoreID: verification.StoreID, Verification: verification, Projections: make(map[string]map[string]any)}
	if err := verifyEventsAndState(restored, recheck); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(verifyBundle.Events, recheck.Events) {
		return nil, integrityErr("rollback.events changed after restore")
	}
	return &RollbackReceipt{RestoredVersion: req.TargetVersion, BinarySHA256: binSHA,
		RestoredStateSHA256: DigestBytes([]byte(strings.Join(parts, "\n"))), RetainedWorkPath: filepath.Join(req.RetainedWorkDir, "retained-v2-work.json"),
		RetainedWorkSHA256: DigestBytes(retainedBytes), RetainedV2Events: len(v2Events), Verified: true}, nil
}

func prerequisiteErr(message string) *api.Error {
	return &api.Error{Code: api.CodePrerequisite, Message: message, Instead: "Supply the installed migration dependency.", Owner: "lb-v2-migration"}
}
