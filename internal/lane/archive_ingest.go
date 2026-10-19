package lane

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/faults"
)

type archiveDocument struct {
	name    string
	data    []byte
	payload object
}

func archiveReceipt(plan *archivePlan, lane, base, manifestHash, tarHash, remoteHash string) (object, error) {
	receipt := object{"lane": lane, "run": plan.row["run"], "tar": base + ".tar", "sha256": tarHash,
		"manifest": base + ".manifest.json", "manifest_sha256": manifestHash, "read_back": true,
		"remote_sha256": nullable(remoteHash), "remove_paths_sha256": digest(canonical(plan.remove)), "remove_count": len(plan.remove)}
	if faults.Get("archive-list-in-events").Point != "" {
		if err := faults.Reach("archive-list-in-events"); err != nil {
			return nil, err
		}
		receipt["remove_paths"] = plan.remove
	}
	return receipt, nil
}

func archiveEventReceipt(receipt object, path string) object {
	payload := clone(receipt)
	payload["receipt"], payload["receipt_sha256"] = path, digest(append(canonical(receipt), '\n'))
	return payload
}

// Generated source documents belong to the verified attempt, outside the
// retained lane directory and beside its tar, manifest and receipt.
func archiveRecordDirectory(receiptPath string) string {
	return strings.TrimSuffix(receiptPath, ".receipt.json") + ".records"
}

// Build all source files and payloads in memory before the first store append.
// This is shared by dry-run preflight and the real receipt's ingestion.
func (s *session) archiveDocuments(lane string, plan *archivePlan, receipt object, receiptPath string) ([]archiveDocument, error) {
	documents := []archiveDocument{{payload: plan.report}}
	var summary strings.Builder
	fmt.Fprintf(&summary, "# Archived logs for %s\n\n", lane)
	for _, entry := range plan.entries {
		if strings.HasPrefix(entry.Path, "lane/") && strings.HasSuffix(entry.Path, ".log") {
			fmt.Fprintf(&summary, "%s: %d bytes; sha256 %s\n", entry.Path, entry.Size, entry.SHA256)
		}
	}
	ledger := fmt.Sprintf("Lane %s, run %d, state %s. Archive verified; event and ledger rows retained.\n", lane, integer(plan.row["run"]), str(plan.row["state"]))
	text := fmt.Sprintf("Lane %s archive read-back verified. Tar sha256 %s. Manifest sha256 %s. Receipt sha256 %s.\n", lane, str(receipt["sha256"]), str(receipt["manifest_sha256"]), digest(append(canonical(receipt), '\n')))
	for _, source := range []struct{ prefix, kind, text string }{
		{"archive-log-summary-", "lane-report", summary.String()},
		{"archive-receipt-", "receipt", text},
		{"archive-ledger-", "ledger-row", ledger},
	} {
		data := []byte(source.text)
		name := source.prefix + digest(data) + ".md"
		payload, err := eventstore.RecordPayload(source.kind, filepath.Join(archiveRecordDirectory(receiptPath), name), data, false)
		if err != nil {
			return nil, refuse("archive preflight: %s", err)
		}
		documents = append(documents, archiveDocument{name: name, data: data, payload: payload})
	}
	return documents, nil
}

func validateArchivePayloads(lane, actor string, documents []archiveDocument, receipt object) error {
	for _, document := range documents {
		if _, err := normalizeEnvelope(envelope(lane, "store.record", document.payload, actor)); err != nil {
			return refuse("archive preflight: %s", err)
		}
	}
	for _, kind := range []string{"archive.verified", "archive.completed"} {
		if _, err := normalizeEnvelope(envelope(lane, kind, receipt, actor)); err != nil {
			return refuse("archive preflight: %s", err)
		}
	}
	return nil
}

func (s *session) preflightArchive(lane, actor string, plan *archivePlan, base, destination string, manifest []byte) error {
	if len(manifest) > archiveManifestLimit {
		return refuse("archive preflight: manifest exceeds the 32 MiB read-back limit; nothing was ingested or removed")
	}
	// The tar hash does not exist yet. Use the actual manifest's SHA-256 only
	// for sizing these in-memory payloads: every eventual hash has the same
	// 64-byte, unescaped hexadecimal width. No prospective receipt is stored.
	hash := digest(manifest)
	remote := ""
	if len(stringsOf(s.c.data["archive_command"])) != 0 {
		remote = hash
	}
	receipt, err := archiveReceipt(plan, lane, base, hash, hash, remote)
	if err != nil {
		return err
	}
	receiptPath := filepath.Join(destination, base+".receipt.json")
	documents, err := s.archiveDocuments(lane, plan, receipt, receiptPath)
	if err != nil {
		return err
	}
	payload := archiveEventReceipt(receipt, receiptPath)
	if err = validateArchivePayloads(lane, actor, documents, payload); err != nil {
		return err
	}
	info, err := s.root.Lstat("archive-ledger.md")
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if info != nil && !info.Mode().IsRegular() {
		return refuse("archive preflight: the archive ledger must be a regular file")
	}
	return nil
}

func (s *session) ingestArchive(lane, actor string, plan *archivePlan, receipt object, receiptPath string) error {
	documents, err := s.archiveDocuments(lane, plan, receipt, receiptPath)
	if err != nil {
		return err
	}
	payload := archiveEventReceipt(receipt, receiptPath)
	if err = validateArchivePayloads(lane, actor, documents, payload); err != nil {
		return err
	}
	// The artifact passed read-back. Persist verification in SQLite or, for a
	// read-only plain clean, its durable pending queue before any indexed/board row.
	if _, _, err = s.recordArchive(envelope(lane, "archive.verified", payload, actor), plan); err != nil {
		return err
	}
	root, err := s.openArchiveDestination(archiveRecordDirectory(receiptPath), true)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, document := range documents {
		if document.name != "" {
			if err = rootWrite(root, document.name, document.data, true, 0600); err != nil {
				return err
			}
		}
		if _, _, err = s.recordArchive(envelope(lane, "store.record", document.payload, actor), plan); err != nil {
			return err
		}
	}
	ledger := documents[len(documents)-1]
	return s.appendArchiveLedger(fmt.Sprintf("- %s Receipt: %s\n", strings.TrimSpace(string(ledger.data)), receiptPath))
}

// The ledger grows by appending one bounded row, not reading/re-writing its
// entire history. No total-file size cap can strand subsequent archives.
func (s *session) appendArchiveLedger(row string) error {
	file, err := childOpen(s.root, "archive-ledger.md", os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return refuse("the archive ledger must be a regular file")
	}
	if info.Size() == 0 {
		row = "# Lane ledger\n\n## Archive\n\n" + row
	}
	n, err := io.WriteString(file, row)
	if err != nil {
		return err
	}
	if n != len(row) {
		return io.ErrShortWrite
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return s.dir.Sync()
}
