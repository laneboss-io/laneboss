package lane

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"laneboss.io/laneboss/internal/faults"
)

type archiveAttempt struct {
	directory   string
	receiptPath string
	receipt     object
}

func (s *session) openArchiveDestination(destination string, create bool) (*os.Root, error) {
	if err := s.c.checkPath(destination, "the archive destination", false); err != nil {
		return nil, err
	}
	if inside(destination, s.c.state) {
		relative, err := filepath.Rel(s.c.state, destination)
		if err != nil {
			return nil, err
		}
		return rootChild(s.root, relative, create)
	}
	if create {
		if err := os.MkdirAll(destination, 0700); err != nil {
			return nil, refuse("cannot create archive destination")
		}
	}
	return rootDirectory(destination)
}

// reuseArchive is called under the lifecycle lock. Only a verified attempt for
// this life of the lane, with no later completion and identical input manifest,
// can proceed without writing another tar, uploading or ingesting again.
func (s *session) reuseArchive(lane string, plan *archivePlan, manifest *archiveManifest, hash, destination string) (*archiveAttempt, error) {
	verified, err := s.last(lane, "archive.verified")
	if err != nil || verified == nil {
		return nil, err
	}
	started, err := s.last(lane, "lane.started")
	if err != nil {
		return nil, err
	}
	completed, err := s.last(lane, "archive.completed")
	if err != nil {
		return nil, err
	}
	if integer(verified["seq"]) <= integer(started["seq"]) || completed != nil && integer(completed["seq"]) > integer(verified["seq"]) {
		return nil, nil
	}
	// The target cannot legitimately verify its own archive while its caller
	// process is running. Such an event is not evidence for later collection.
	if verified["actor"] == "lane:"+lane {
		return nil, nil
	}
	payload := obj(verified["payload"])
	if payload["manifest_sha256"] != hash {
		return nil, nil
	}
	// An explicit different destination is the recovery route for unavailable
	// old artifacts. Retain them and perform a complete new verified attempt.
	if destination != "" && filepath.Dir(str(payload["receipt"])) != destination {
		return nil, nil
	}
	if len(stringsOf(s.c.data["archive_command"])) != 0 && payload["remote_sha256"] == nil {
		return nil, nil
	}
	if faults.Get("archive-repeat-verified-attempt").Point != "" {
		if err = faults.Reach("archive-repeat-verified-attempt"); err != nil {
			return nil, err
		}
		return nil, nil
	}
	path, tarName, manifestName := str(payload["receipt"]), str(payload["tar"]), str(payload["manifest"])
	stem := strings.TrimSuffix(tarName, ".tar")
	if !filepath.IsAbs(path) || !strings.HasSuffix(tarName, ".tar") || filepath.Base(tarName) != tarName || !strings.HasPrefix(stem, lane+"-") || !match(`[0-9a-f]{32}`, strings.TrimPrefix(stem, lane+"-")) || manifestName != stem+".manifest.json" || filepath.Base(path) != stem+".receipt.json" {
		return nil, integrity("the verified archive attempt has invalid artifact names; nothing was collected")
	}
	if payload["lane"] != lane || integer(payload["run"]) != integer(plan.row["run"]) || payload["read_back"] != true || payload["remove_paths_sha256"] != digest(canonical(plan.remove)) || integer(payload["remove_count"]) != len(plan.remove) || !match(`[0-9a-f]{64}`, str(payload["sha256"])) {
		return nil, integrity("the verified archive attempt does not match this removal plan; nothing was collected")
	}
	if remote := payload["remote_sha256"]; remote != nil && remote != payload["sha256"] {
		return nil, integrity("the verified archive upload receipt does not match; nothing was collected")
	}
	directory := filepath.Dir(path)
	if inside(directory, filepath.Join(s.c.state, "lanes")) || inside(directory, s.c.directory) || str(plan.row["worktree"]) != "" && inside(directory, str(plan.row["worktree"])) {
		return nil, integrity("the verified archive destination overlaps retained lane inputs; nothing was collected")
	}
	root, err := s.openArchiveDestination(directory, false)
	if err != nil {
		return nil, archiveReuseRefusal("destination cannot be read")
	}
	defer root.Close()
	if err = verifyLaneTar(root, tarName, manifestName, str(payload["sha256"]), manifest); err != nil {
		return nil, archiveReuseRefusal("tar or manifest is missing, unreadable or changed")
	}
	data, err := rootRead(root, filepath.Base(path), 1024*1024)
	if err != nil || digest(data) != str(payload["receipt_sha256"]) {
		return nil, archiveReuseRefusal("receipt is missing, unreadable or changed")
	}
	receipt := clone(payload)
	delete(receipt, "receipt")
	delete(receipt, "receipt_sha256")
	if !bytes.Equal(data, append(canonical(receipt), '\n')) {
		return nil, archiveReuseRefusal("receipt read-back does not match")
	}
	if err = s.checkArchiveIngest(lane, plan, receipt, path, integer(verified["seq"])); err != nil {
		return nil, err
	}
	return &archiveAttempt{directory: directory, receiptPath: path, receipt: receipt}, nil
}

// Only a previous attempt's artifact/ingest problem is lane-local. Store reads,
// invalid stored receipt metadata, current uploads and lifecycle locks still
// propagate their batch-halting errors.
func archiveReuseRefusal(reason string) error {
	return refuse("the previous verified archive %s; nothing was collected; restore its artifacts/indexed inputs, or make a fresh attempt with a changed input or a different --to directory", reason)
}

// A stored verification can precede an interrupted ingest. Do not silently
// collect that case just because the backup is sound: the indexed inputs must
// also exist. This is read-only and appends no duplicate records or board rows.
func (s *session) checkArchiveIngest(lane string, plan *archivePlan, receipt object, receiptPath string, since int) error {
	documents, err := s.archiveDocuments(lane, plan, receipt, receiptPath)
	if err != nil {
		return err
	}
	events, err := s.laneEvents(lane, "store.record")
	if err != nil {
		return err
	}
	stored := map[string]bool{}
	for _, event := range events {
		if integer(event["seq"]) > since {
			stored[digest(canonical(event["payload"]))] = true
		}
	}
	for _, document := range documents {
		if !stored[digest(canonical(document.payload))] {
			return archiveReuseRefusal("has incomplete indexed inputs")
		}
	}
	return nil
}

func archiveAttemptResult(result object, attempt *archiveAttempt) {
	result["destination"] = attempt.directory
	result["archive"] = filepath.Join(attempt.directory, str(attempt.receipt["tar"]))
	result["manifest"] = filepath.Join(attempt.directory, str(attempt.receipt["manifest"]))
	result["receipt"], result["sha256"], result["verified"] = attempt.receiptPath, attempt.receipt["sha256"], true
}

func (s *session) collectArchive(a arguments, actor string, plan *archivePlan, attempt *archiveAttempt, result object) (any, error) {
	// Re-hash after read-back and any first-attempt store writes. The lifecycle
	// lock excludes launcher changes; external edits still fail the comparison.
	current, err := s.planArchivePending(a.get("lane"), plan.pending, plan.preserveLogs)
	if err != nil {
		return nil, err
	}
	if plan.worktree != current.worktree || !reflect.DeepEqual(plan.entries, current.entries) || !reflect.DeepEqual(plan.remove, current.remove) || !reflect.DeepEqual(plan.keep, current.keep) || !reflect.DeepEqual(plan.report, current.report) {
		return nil, refuse("archive inputs changed after read-back; nothing was removed")
	}
	if !flag(plan.row["cleaned"]) {
		cleaned, err := s.cleanLocked(a, plan)
		if err != nil {
			return nil, err
		}
		if obj(cleaned)["pending"] != false && !plan.deferReadOnly {
			return nil, integrity("lane clean has no stored receipt; logs were retained")
		}
		result["clean"] = cleaned
	}
	if plan.worktree != "" {
		if _, err = os.Lstat(plan.worktree); !os.IsNotExist(err) {
			return nil, integrity("lane clean did not remove the planned worktree; logs were retained")
		}
	}
	for _, log := range plan.logs {
		relative, err := filepath.Rel(s.c.state, log.source)
		if err != nil {
			return nil, err
		}
		current, err := archiveFile(log.source, log.Path)
		if err != nil || !reflect.DeepEqual(current, log) {
			return nil, integrity("an archived log changed before collection; the log was retained")
		}
		if err = s.root.Remove(relative); err != nil {
			return nil, integrity("an archived log could not be collected; retain the receipt and inspect the removal plan")
		}
	}
	completed, stored, err := s.recordArchive(envelope(a.get("lane"), "archive.completed", archiveEventReceipt(attempt.receipt, attempt.receiptPath), actor), plan)
	if err != nil {
		return nil, err
	}
	result["event"] = nil
	if stored {
		result["event"] = eventPointer(completed)
	}
	result["pending"] = !stored || flag(obj(result["clean"])["pending"])
	archiveAttemptResult(result, attempt)
	return result, nil
}
