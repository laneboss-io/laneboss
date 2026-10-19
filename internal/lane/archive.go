package lane

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/faults"
)

type archivePlan struct {
	row           object
	entries       []archiveEntry
	remove        []string
	keep          []string
	logs          []archiveEntry
	report        object
	worktree      string
	deferReadOnly bool
	preserveLogs  bool
	pending       []string
}

func (s *session) archiveReport(lane string, root *os.Root) (object, error) {
	if _, err := root.Lstat("report.md"); err == nil {
		data, err := rootRead(root, "report.md", 512*1024)
		if err != nil {
			return nil, err
		}
		p, err := archiveReportPayload(s.lanePath(lane, "report.md"), data)
		if err != nil {
			return nil, s.archiveReportRemedy(lane, err)
		}
		return p, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	started, err := s.last(lane, "lane.started")
	if err != nil {
		return nil, err
	}
	since := integer(started["seq"])
	events, err := s.laneEvents(lane, "store.record")
	if err != nil {
		return nil, err
	}
	for i := len(events) - 1; i >= 0; i-- {
		if integer(events[i]["seq"]) <= since {
			continue
		}
		p := obj(events[i]["payload"])
		if p["kind"] == "lane-report" && p["private"] == false && str(p["text"]) != "" && !strings.HasPrefix(filepath.Base(str(p["source"])), "archive-log-summary-") {
			if strings.HasPrefix(str(p["source"]), "archive:no-report:") {
				continue
			}
			if err = eventstore.ValidateRecord(p); err != nil {
				return nil, s.archiveReportRemedy(lane, err)
			}
			return p, nil
		}
	}
	// Upward reports are configuration-wide events; their authenticated sender
	// supplies the lane association, rather than a guessed filename.
	rows, err := s.db.Query("SELECT " + eventColumns + " FROM events WHERE kind='report.sent' ORDER BY seq DESC")
	if err != nil {
		return nil, integrity("the report history cannot be read")
	}
	defer rows.Close()
	for rows.Next() {
		e, err := readEvent(rows)
		if err != nil {
			return nil, err
		}
		p := obj(e["payload"])
		if integer(e["seq"]) > since && p["from"] == "lane:"+lane {
			value, err := archiveReportPayload("event:"+str(e["id"]), []byte(str(p["text"])))
			if err != nil {
				return nil, s.archiveReportRemedy(lane, err)
			}
			return value, nil
		}
	}
	if err = rows.Err(); err != nil {
		return nil, integrity("the report history cannot be read")
	}
	if err = rows.Close(); err != nil {
		return nil, integrity("the report history cannot be closed")
	}
	return s.archiveRunReport(lane, root)
}

func (s *session) planArchive(lane string) (*archivePlan, error) {
	return s.planArchivePending(lane, nil, false)
}

func (s *session) planArchivePending(lane string, pending []string, preserveLogs bool) (*archivePlan, error) {
	row, err := s.known(lane)
	if err != nil {
		return nil, err
	}
	if flag(row["running"]) || !contains([]string{"merged", "abandoned"}, str(row["state"])) {
		return nil, refuse("lane archive takes a lane marked merged or abandoned that is not running; lane %s is %s", lane, str(row["state"]))
	}
	if err = s.refuseLive(lane); err != nil {
		return nil, err
	}
	if err = s.checkArchivePending(lane, pending); err != nil {
		return nil, err
	}
	n, err := s.refusedCount(lane)
	if err != nil {
		return nil, err
	}
	if n != 0 {
		return nil, refuse("lane %s has pending or refused events; nothing was archived or removed", lane)
	}
	plan := &archivePlan{row: row, remove: []string{}, keep: []string{}, entries: []archiveEntry{}, logs: []archiveEntry{}, preserveLogs: preserveLogs}
	event, err := s.last(lane, "lane.started")
	if err != nil {
		return nil, err
	}
	if event != nil && !flag(row["cleaned"]) {
		p := obj(event["payload"])
		path := str(p["worktree"])
		worktree, err := s.worktreeForCollection(lane, p)
		if err != nil {
			return nil, err
		}
		if worktree.why != "" {
			plan.keep = append(plan.keep, path)
		} else {
			if str(p["repository"]) != "" {
				code, changes, _, err := gitRun(path, "status", "--porcelain", "--untracked-files=all")
				if err != nil {
					return nil, err
				}
				if code != 0 || changes != "" {
					return nil, refuse("lane %s's worktree has uncommitted or untracked work, so nothing was removed", lane)
				}
				plan.worktree = path
			}
			entries, err := archiveTree(path, "worktree")
			if err != nil {
				return nil, err
			}
			plan.entries = append(plan.entries, entries...)
			if plan.worktree != "" {
				for _, entry := range entries {
					plan.remove = append(plan.remove, entry.source)
				}
			}
		}
	}
	root, err := s.laneRoot(lane, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	plan.report, err = s.archiveReport(lane, root)
	if absent, ok := err.(*noRunReport); ok {
		if !preserveLogs {
			return nil, s.archiveReportRemedy(lane, absent)
		}
		plan.report, err = absent.payload(lane)
		if err == nil {
			// This is launcher metadata about the absent report, not runner
			// output. Keep its exact bytes in the verified tar as well as the
			// normal searchable report record and manifest hash.
			data := []byte(str(plan.report["text"]))
			plan.entries = append(plan.entries, archiveEntry{Path: "archive/no-report.md", Type: "file", Size: int64(len(data)), Mode: 0600, SHA256: digest(data), data: data})
		}
	}
	if err != nil {
		return nil, err
	}
	// Raw records, ledgers, inputs and event history stay in place. Diagnostic
	// .log files can be collected by explicit archive after their exact bytes
	// are kept in the tar. Plain clean preserves the original lane inventory.
	entries, err := archiveLogs(s.lanePath(lane))
	if err != nil {
		return nil, err
	}
	kept, err := s.archiveRawRecords(lane, entries)
	if err != nil {
		return nil, err
	}
	if faults.Get("archive-drop-raw-logs").Point != "" {
		if err = faults.Reach("archive-drop-raw-logs"); err != nil {
			return nil, err
		}
		kept = map[string]bool{}
	}
	for _, entry := range entries {
		if entry.Type == "file" && strings.HasSuffix(entry.Path, ".log") {
			plan.entries = append(plan.entries, entry)
			if preserveLogs || kept[entry.source] {
				plan.keep = append(plan.keep, entry.source)
			} else {
				plan.logs = append(plan.logs, entry)
				plan.remove = append(plan.remove, entry.source)
			}
		} else if entry.Path == "lane/report.md" {
			plan.entries = append(plan.entries, entry)
		}
	}
	for _, path := range plan.remove {
		if rule, _ := credential(path); rule != "" {
			return nil, refuse("an archive removal path looks like a credential; nothing was removed")
		}
	}
	sort.Strings(plan.remove)
	sort.Strings(plan.keep)
	sortArchive(plan.entries)
	return plan, nil
}

func (s *session) archive(a arguments) (any, error) {
	s.authority = true
	principal, err := s.c.caller()
	if err != nil {
		return nil, err
	}
	if err = caller.RequireIdentity(principal); err != nil {
		return nil, refuse("%s", err)
	}
	if err = s.c.archivePermission(principal, a.get("lane")); err != nil {
		return nil, err
	}
	unlock, err := s.lanesLock()
	if err != nil {
		return nil, haltArchive("archive cannot hold the lifecycle lock: %s", err)
	}
	defer unlock()
	if err = s.refresh(); err != nil {
		return nil, err
	}
	if a.action == "clean" {
		row, err := s.known(a.get("lane"))
		if err != nil {
			return nil, err
		}
		if flag(row["cleaned"]) {
			return nil, refuse("lane %s was already cleaned", a.get("lane"))
		}
	}
	already, err := s.alreadyArchived(a.get("lane"))
	if err != nil {
		return nil, err
	}
	if already {
		row, err := s.known(a.get("lane"))
		if err != nil {
			return nil, err
		}
		return object{"lane": a.get("lane"), "run": row["run"], "status": "already-archived", "dry_run": a.has("dry-run"), "remove_paths": []string{}}, nil
	}
	plan, err := s.planArchivePending(a.get("lane"), nil, a.action == "clean")
	if err != nil {
		return nil, err
	}
	plan.deferReadOnly = a.action == "clean"
	destination := a.get("to")
	if destination == "" {
		destination = filepath.Join(s.c.state, "archives")
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return nil, refuse("archive destination must be a valid path")
	}
	if err = s.c.checkPath(destination, "the archive destination", false); err != nil {
		return nil, err
	}
	if inside(destination, filepath.Join(s.c.state, "lanes")) || str(plan.row["worktree"]) != "" && inside(destination, str(plan.row["worktree"])) || inside(destination, s.c.directory) {
		return nil, refuse("archive destination must be outside the lane, worktree and configuration files")
	}
	base := a.get("lane") + "-" + newID()
	tarName, manifestName := base+".tar", base+".manifest.json"
	manifest := &archiveManifest{Format: 1, Entries: plan.entries, RemovePaths: plan.remove, RemoveHash: digest(canonical(plan.remove)), ReportHash: digest(canonical(plan.report))}
	manifestData, err := manifestBytes(manifest)
	if err != nil {
		return nil, err
	}
	result := object{"lane": a.get("lane"), "run": plan.row["run"], "dry_run": a.has("dry-run"), "remove_paths": plan.remove, "keep_paths": plan.keep, "destination": destination, "report_private": plan.report["private"], "reused": false}
	reuseDestination := ""
	if a.get("to") != "" {
		reuseDestination = destination
	}
	attempt, err := s.reuseArchive(a.get("lane"), plan, manifest, digest(manifestData), reuseDestination)
	if err != nil {
		return nil, err
	}
	if attempt != nil {
		result["reused"] = true
		if a.has("dry-run") {
			archiveAttemptResult(result, attempt)
			return result, nil
		}
		return s.collectArchive(a, principal.ID, plan, attempt, result)
	}
	if err = s.preflightArchive(a.get("lane"), principal.ID, plan, base, destination, manifestData); err != nil {
		return nil, err
	}
	if a.has("dry-run") {
		return result, nil
	}
	root, err := s.openArchiveDestination(destination, true)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err = rootWrite(root, manifestName, manifestData, false, 0600); err != nil {
		return nil, err
	}
	tarHash, err := writeLaneTar(root, tarName, plan.entries)
	if err != nil {
		return nil, err
	}
	// The mutant performs the real destructive operation at the wrong boundary.
	// The same read-back-failure row must detect that the inputs disappeared.
	if faults.Get("archive-clean-before-readback").Point != "" {
		if err = faults.Reach("archive-clean-before-readback"); err != nil {
			return nil, err
		}
		if _, err = s.cleanLocked(a, plan); err != nil {
			return nil, err
		}
	}
	if err = verifyLaneTar(root, tarName, manifestName, tarHash, manifest); err != nil {
		return nil, err
	}
	remoteHash, err := s.uploadArchive(filepath.Join(destination, tarName), filepath.Join(destination, manifestName), tarHash, a.get("lane"))
	if err != nil {
		return nil, err
	}
	// An uploader may have changed or removed its local inputs. Verify them again
	// before recording a receipt or entering the existing clean operation.
	if err = verifyLaneTar(root, tarName, manifestName, tarHash, manifest); err != nil {
		return nil, err
	}
	receipt, err := archiveReceipt(plan, a.get("lane"), base, digest(manifestData), tarHash, remoteHash)
	if err != nil {
		return nil, err
	}
	receiptName := base + ".receipt.json"
	receiptBytes := append(canonical(receipt), '\n')
	if err = rootWrite(root, receiptName, receiptBytes, false, 0600); err != nil {
		return nil, err
	}
	readBack, err := rootRead(root, receiptName, 32*1024*1024)
	if err != nil || !bytes.Equal(readBack, receiptBytes) {
		return nil, integrity("archive receipt is missing or does not match; nothing was removed")
	}
	if err = s.ingestArchive(a.get("lane"), principal.ID, plan, receipt, filepath.Join(destination, receiptName)); err != nil {
		return nil, err
	}
	attempt = &archiveAttempt{directory: destination, receiptPath: filepath.Join(destination, receiptName), receipt: receipt}
	return s.collectArchive(a, principal.ID, plan, attempt, result)
}

type archiveOutput struct{ bytes.Buffer }

func (b *archiveOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 4096 {
		return 0, fmt.Errorf("archive receipt exceeds output limit")
	}
	return b.Buffer.Write(p)
}

func (s *session) uploadArchive(path, manifest, hash, lane string) (string, error) {
	command := stringsOf(s.c.data["archive_command"])
	if len(command) == 0 {
		return "", nil
	}
	command = append(command, path, manifest, hash, lane)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	var output archiveOutput
	cmd.Stdout, cmd.Stderr, cmd.Dir = &output, io.Discard, s.c.state
	if err := cmd.Run(); err != nil {
		return "", archiveUploadFailure("archive_command failed; no read-back receipt, nothing was removed")
	}
	if strings.TrimSpace(output.String()) != hash {
		return "", archiveUploadFailure("archive_command read-back hash is missing or does not match; nothing was removed")
	}
	return hash, nil
}

func archiveUploadFailure(message string) error {
	if faults.Get("archive-upload-keeps-batch-going").Point != "" {
		if err := faults.Reach("archive-upload-keeps-batch-going"); err != nil {
			return err
		}
		return refuse("%s", message)
	}
	return haltArchive("%s", message)
}
