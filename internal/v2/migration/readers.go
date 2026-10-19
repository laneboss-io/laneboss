package migration

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/credentialtext"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/v2/api"
	migv2 "laneboss.io/laneboss/migration/v2"
	_ "modernc.org/sqlite"
)

type QuiescenceReceipt struct {
	Schema           string   `json:"schema"`
	Config           string   `json:"config"`
	SourceVersion    string   `json:"source_version"`
	DispatchFrozen   bool     `json:"dispatch_frozen"`
	LoopStopped      bool     `json:"loop_stopped"`
	ActiveWriters    int      `json:"active_writers"`
	Survivors        int      `json:"survivors"`
	RunningLanes     []string `json:"running_lanes"`
	UnfinishedLanes  []string `json:"unfinished_lanes,omitempty"`
	ObservedAt       string   `json:"observed_at"`
	InPlaceOwnership bool     `json:"in_place_ownership,omitempty"`
	SharedStore      bool     `json:"shared_store,omitempty"`
	DeriveParent     bool     `json:"derive_parent_from_labels,omitempty"`
}

type VerificationReceipt struct {
	Schema            string `json:"schema"`
	OK                bool   `json:"ok"`
	Config            string `json:"config"`
	StoreID           string `json:"store_id"`
	Events            int    `json:"events"`
	Lanes             int    `json:"lanes"`
	EventsChainSHA256 string `json:"events_chain_sha256"`
	DecisionsSHA256   string `json:"decisions_sha256,omitempty"`
}

type LegacyEventRecord struct {
	Seq             int64          `json:"seq"`
	ID              string         `json:"id"`
	Kind            string         `json:"kind"`
	Lane            string         `json:"lane,omitempty"`
	Actor           string         `json:"actor"`
	OccurredAt      string         `json:"occurred_at,omitempty"`
	ProtocolVersion string         `json:"protocol_version"`
	RecordedAt      string         `json:"recorded_at"`
	SHA256          string         `json:"sha256"`
	Payload         map[string]any `json:"payload"`
	RawCanonical    []byte         `json:"-"`
}

type LegacyMailItem struct {
	Lane       string
	Sequence   int64
	Sender     string
	SHA256     string
	Bytes      int64
	Content    []byte
	Delivered  bool
	Returned   bool
	LegacyRel  bool
	QueuedSeq  int64
	RecordedAt string
}

type LegacyDecisionItem struct {
	ID              string
	RecordJSON      []byte
	RecordSHA256    string
	FirstWrittenSHA string
	Authoritative   bool
	RecordedBy      string
	AnsweredAt      string
}

type LegacyVectorItem struct {
	RecordID     string
	WhichText    string
	Model        string
	Dimension    int
	TextSHA256   string
	VectorSHA256 string
	EntrySHA256  string
	CreatedAt    string
	RawJSON      []byte
}

type LegacyEgressItem struct {
	ID          int64
	RecordID    string
	WhichText   string
	Model       string
	TextSHA256  string
	PrevSHA256  string
	EntrySHA256 string
	At          string
	RawJSON     []byte
}

type LegacyArchiveItem struct {
	Stem           string
	Lane           string
	Run            int64
	TarSHA256      string
	ManifestSHA256 string
	ReceiptSHA256  string
	ManifestBytes  []byte
	ReceiptBytes   []byte
}

type LegacyUnfinishedSession struct {
	Lane           string
	Runner         string
	Driver         api.Driver
	Model          string
	Effort         string
	SessionID      string
	Branch         string
	Base           string
	WorktreeFiles  map[string][]byte
	SessionHistory []byte
}

type VerifiedBundle struct {
	Manifest           api.MigrationManifest
	Quiescence         QuiescenceReceipt
	Verification       VerificationReceipt
	ConfigName         string
	StoreID            string
	Events             []LegacyEventRecord
	Projections        map[string]map[string]any
	Mail               []LegacyMailItem
	Decisions          []LegacyDecisionItem
	Vectors            []LegacyVectorItem
	Egress             []LegacyEgressItem
	Archives           []LegacyArchiveItem
	OwnerQueue         [][]byte
	BoxLedger          [][]byte
	Adversarial        *migv2.AdversarialInventory
	Unfinished         []LegacyUnfinishedSession
	RequiresRelaunch   []api.ID
	Incompatibilities0 []string
}

func readBlobFull(ctx context.Context, store api.Store, scope api.Scope, ref api.BlobRef) ([]byte, error) {
	if err := ValidateBlobRef(ref, ""); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	offset := int64(0)
	for offset < ref.Bytes || (ref.Bytes == 0 && offset == 0) {
		limit := api.MaxChunkBytes
		if rem := ref.Bytes - offset; rem > 0 && rem < int64(limit) {
			limit = int(rem)
		}
		if limit == 0 {
			limit = 1
		}
		chunk, err := store.Blob(ctx, scope, api.BlobReadRequest{
			ObjectID: ref.ID,
			Offset:   offset,
			Limit:    limit,
		})
		if err != nil {
			var typed *api.Error
			if errors.As(err, &typed) && typed.Code != api.CodeNotFound {
				return nil, err
			}
			if allowCorruptEvidence() {
				return []byte{}, nil
			}
			return nil, integrityErr(fmt.Sprintf("missing or unreadable blob %s: %v", ref.ID, err))
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != offset || len(chunk.Data) > limit {
			if !allowCorruptEvidence() {
				return nil, integrityErr(fmt.Sprintf("blob %s chunk offset mismatch", ref.ID))
			}
		}
		if len(chunk.Data) > 0 && DigestBytes(chunk.Data) != chunk.SHA256 {
			if !allowCorruptEvidence() {
				return nil, integrityErr(fmt.Sprintf("blob %s chunk sha256 mismatch", ref.ID))
			}
		}
		out.Write(chunk.Data)
		offset += int64(len(chunk.Data))
		if ref.Bytes == 0 || len(chunk.Data) == 0 {
			break
		}
	}
	data := out.Bytes()
	if int64(len(data)) != ref.Bytes || DigestBytes(data) != ref.SHA256 {
		if !allowCorruptEvidence() {
			return nil, integrityErr(fmt.Sprintf("blob %s content size or sha256 mismatch", ref.ID))
		}
	}
	// A caller's declared prefix is not a complete object. The exact-end read
	// must return the actual empty-byte hash, not hide additional stored bytes.
	end, err := store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: ref.Bytes, Limit: 1})
	if err != nil {
		return nil, err
	}
	if end.ObjectID != ref.ID || end.Offset != ref.Bytes || len(end.Data) != 0 || end.SHA256 != DigestBytes(nil) {
		return nil, integrityErr("source blob reference is a prefix or has an invalid end receipt")
	}
	return data, nil
}

func inspectAndVerifyBundle(ctx context.Context, store api.Store, scope api.Scope, req api.MigrationPlanRequest) (*VerifiedBundle, error) {
	if !migv2.SupportedSourceVersion(req.SourceVersion) {
		return nil, &api.Error{
			Code:    api.CodeUnsupported,
			Message: fmt.Sprintf("unsupported migration source_version %q (supported: 0.7.0, 1.0.0-candidate)", req.SourceVersion),
			Instead: "Supply a frozen 0.7.0 or 1.0.0-candidate migration manifest.",
			Owner:   "lb-v2-migration",
		}
	}
	if err := ValidateBlobRef(req.SourceManifest, "manifest"); err != nil {
		return nil, err
	}
	manifestBytes, err := readBlobFull(ctx, store, scope, req.SourceManifest)
	if err != nil {
		return nil, err
	}
	var manifest api.MigrationManifest
	if err := DecodeStrictJSON(manifestBytes, &manifest); err != nil {
		return nil, err
	}
	if manifest.Schema != SchemaMigrationManifest {
		return nil, invalidErr("manifest schema must be laneboss.migration.v2")
	}
	if manifest.SourceVersion != req.SourceVersion {
		return nil, invalidErr("manifest.source_version does not match request.source_version")
	}
	if !migv2.SupportedSourceProtocol(manifest.SourceProtocol) {
		return nil, &api.Error{
			Code:    api.CodeUnsupported,
			Message: fmt.Sprintf("unsupported migration source_protocol %q", manifest.SourceProtocol),
			Instead: "Use a store written with protocol 1.1.0, 1.2.0 or 1.3.0.",
			Owner:   "lb-v2-migration",
		}
	}
	if strings.TrimSpace(manifest.SourceRevision) == "" {
		return nil, invalidErr("manifest.source_revision is required")
	}
	if err := ValidateObjectManifest(manifest.Inventory); err != nil {
		return nil, err
	}
	if err := ValidateBlobRef(manifest.Quiescence, "manifest"); err != nil {
		return nil, invalidErr("manifest.quiescence: " + err.Error())
	}
	if err := ValidateBlobRef(manifest.Verification, "manifest"); err != nil {
		return nil, invalidErr("manifest.verification: " + err.Error())
	}

	quiescenceBytes, err := readBlobFull(ctx, store, scope, manifest.Quiescence)
	if err != nil {
		return nil, err
	}
	var quiescence QuiescenceReceipt
	if err := DecodeStrictJSON(quiescenceBytes, &quiescence); err != nil {
		return nil, integrityErr("invalid quiescence receipt: " + err.Error())
	}
	if quiescence.Schema != SchemaQuiescence {
		return nil, integrityErr("quiescence receipt schema must be laneboss.quiescence.v2")
	}
	if quiescence.SourceVersion != req.SourceVersion || !ValidTimestamp(api.Timestamp(quiescence.ObservedAt)) {
		return nil, integrityErr("quiescence receipt has a mismatched source version or invalid observation time")
	}
	if quiescence.InPlaceOwnership || quiescence.SharedStore {
		if !allowInPlaceOwnership() {
			return nil, conflictErr("in-place ownership changes and shared stores between old and new writers are forbidden")
		}
	}
	if quiescence.DeriveParent {
		if !allowLabelParent() {
			return nil, forbiddenErr("deriving active parent authority from legacy labels is forbidden")
		}
	}
	if !quiescence.DispatchFrozen || !quiescence.LoopStopped || quiescence.ActiveWriters != 0 || quiescence.Survivors != 0 || len(quiescence.RunningLanes) != 0 {
		if !allowActiveWriter() {
			return nil, conflictErr("legacy installation has active writers, running lanes, or unstopped dispatch/loop")
		}
	}

	verificationBytes, err := readBlobFull(ctx, store, scope, manifest.Verification)
	if err != nil {
		return nil, err
	}
	var verification VerificationReceipt
	if err := DecodeStrictJSON(verificationBytes, &verification); err != nil {
		return nil, integrityErr("invalid verification receipt: " + err.Error())
	}
	if verification.Schema != SchemaVerification || !verification.OK {
		if !allowCorruptEvidence() {
			return nil, integrityErr("source verification receipt is missing or not ok")
		}
	}
	if quiescence.Config != verification.Config {
		return nil, integrityErr("quiescence and verification receipts name different configurations")
	}
	if scope.Config == "" || scope.Config != verification.Config {
		return nil, conflictErr(fmt.Sprintf("source belongs to configuration %q, not %q", verification.Config, scope.Config))
	}

	files := make(map[string][]byte, len(manifest.Inventory.Entries))
	for _, entry := range manifest.Inventory.Entries {
		base := filepath.Base(entry.Path)
		if base == "events.sqlite-wal" || base == "events.sqlite-shm" || base == "events.sqlite-journal" ||
			base == "decisions.sqlite-wal" || base == "decisions.sqlite-shm" || base == "decisions.sqlite-journal" ||
			base == ".lock" || base == "loop.lock" || base == "identityd.lock" {
			if !allowActiveWriter() {
				return nil, conflictErr(fmt.Sprintf("active writer sidecar or lock file present in inventory: %s", entry.Path))
			}
		}
		if entry.Kind == "file" {
			var fileBytes int64
			if entry.Content != nil {
				fileBytes = entry.Content.Bytes
			} else if entry.Assembly != nil {
				fileBytes = entry.Assembly.Bytes
			}
			if (base == "pending.jsonl" || (strings.HasPrefix(base, "pending-") && strings.HasSuffix(base, ".jsonl"))) && fileBytes > 0 {
				if !allowActiveWriter() {
					return nil, conflictErr(fmt.Sprintf("unflushed pending events file present in inventory: %s", entry.Path))
				}
			}
			if entry.Content != nil {
				data, err := readBlobFull(ctx, store, scope, *entry.Content)
				if err != nil {
					return nil, err
				}
				files[entry.Path] = data
			} else if entry.Assembly != nil {
				var assembled bytes.Buffer
				for _, part := range entry.Assembly.Parts {
					pData, err := readBlobFull(ctx, store, scope, part)
					if err != nil {
						return nil, err
					}
					assembled.Write(pData)
				}
				data := assembled.Bytes()
				if int64(len(data)) != entry.Assembly.Bytes || DigestBytes(data) != entry.Assembly.SHA256 {
					if !allowCorruptEvidence() {
						return nil, integrityErr(fmt.Sprintf("assembled file %s size or sha256 mismatch", entry.Path))
					}
				}
				files[entry.Path] = data
			}
		}
	}

	bundle := &VerifiedBundle{
		Manifest:     manifest,
		Quiescence:   quiescence,
		Verification: verification,
		ConfigName:   verification.Config,
		StoreID:      verification.StoreID,
		Projections:  make(map[string]map[string]any),
	}

	if err := verifyEventsAndState(files, bundle); err != nil {
		return nil, err
	}
	if err := verifyIdentityJournal(files, bundle); err != nil {
		return nil, err
	}
	if err := verifyDecisionsAndVectors(files, bundle); err != nil {
		return nil, err
	}
	if err := verifyArchives(files, bundle); err != nil {
		return nil, err
	}
	if err := verifyOwnerQueueAndLedgers(files, bundle); err != nil {
		return nil, err
	}
	if err := collectUnfinishedSessions(files, bundle); err != nil {
		return nil, err
	}

	var rawEventsMap []map[string]any
	for _, ev := range bundle.Events {
		rawEventsMap = append(rawEventsMap, map[string]any{
			"seq":     ev.Seq,
			"kind":    ev.Kind,
			"payload": ev.Payload,
		})
	}
	var projList []map[string]any
	laneNames := make([]string, 0, len(bundle.Projections))
	for k := range bundle.Projections {
		laneNames = append(laneNames, k)
	}
	sort.Strings(laneNames)
	for _, k := range laneNames {
		projList = append(projList, bundle.Projections[k])
	}
	incompat, err := migv2.Check050Compatibility(files["config/config.toml"], rawEventsMap, projList)
	if err != nil && !allowCorruptEvidence() {
		return nil, integrityErr("invalid config.toml in inventory: " + err.Error())
	}
	bundle.Incompatibilities0 = incompat

	return bundle, nil
}

func verifyEventsAndState(files map[string][]byte, bundle *VerifiedBundle) error {
	dbBytes, hasDB := files["state/events.sqlite"]
	markerBytes, hasMarker := files["state/.laneboss-state"]
	if !hasDB {
		if bundle.Verification.Events > 0 && !allowCorruptEvidence() {
			return integrityErr("state/events.sqlite is missing from inventory")
		}
		return nil
	}
	if !hasMarker && !allowCorruptEvidence() {
		return integrityErr("state/.laneboss-state ownership marker is missing from inventory")
	}

	var marker map[string]any
	if hasMarker {
		parsed, err := eventstore.Parse(markerBytes, "the ownership marker")
		if err != nil {
			if !allowCorruptEvidence() {
				return integrityErr("state/.laneboss-state is invalid JSON")
			}
		} else {
			marker, _ = parsed.(map[string]any)
		}
	}

	tmpDir, err := os.MkdirTemp("", "lb-mig-events-*")
	if err != nil {
		return integrityErr("cannot allocate temporary directory for read-only verification")
	}
	defer os.RemoveAll(tmpDir)
	_ = os.Chmod(tmpDir, 0o700)

	dbPath := filepath.Join(tmpDir, "events.sqlite")
	if err := os.WriteFile(dbPath, dbBytes, 0o400); err != nil {
		return integrityErr("cannot stage read-only events.sqlite")
	}
	uri := url.URL{Scheme: "file", Path: dbPath, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		if !allowCorruptEvidence() {
			return integrityErr("cannot open events.sqlite")
		}
		return nil
	}
	defer db.Close()

	var integrityStatus string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&integrityStatus); err != nil || integrityStatus != "ok" {
		if !allowCorruptEvidence() {
			return integrityErr("events.sqlite failed PRAGMA integrity_check")
		}
	}
	var userVersion int
	if err := db.QueryRow("PRAGMA user_version").Scan(&userVersion); err != nil || userVersion != 1 {
		if !allowCorruptEvidence() {
			return integrityErr("events.sqlite user_version must be 1")
		}
	}

	meta := make(map[string]string)
	metaRows, err := db.Query("SELECT key, value FROM meta")
	if err != nil {
		if !allowCorruptEvidence() {
			return integrityErr("events.sqlite meta table is unreadable")
		}
		return nil
	}
	for metaRows.Next() {
		var k, v string
		if err := metaRows.Scan(&k, &v); err != nil {
			metaRows.Close()
			return integrityErr("events.sqlite meta scan failed")
		}
		meta[k] = v
	}
	metaRows.Close()

	if meta["format"] != "event-store" || meta["store_id"] == "" || meta["config"] == "" {
		if !allowCorruptEvidence() {
			return integrityErr("events.sqlite metadata is invalid")
		}
	}
	if meta["config"] != bundle.ConfigName {
		return integrityErr("events.config disagrees with the source configuration")
	}
	if bundle.Verification.StoreID != "" && meta["store_id"] != bundle.Verification.StoreID {
		if !allowRehashedHistory() && !allowCorruptEvidence() {
			return integrityErr("events.sqlite store_id disagrees with verification receipt")
		}
	}
	if marker != nil {
		storeObj, _ := marker["store"].(map[string]any)
		if marker["config"] != meta["config"] || storeObj == nil || storeObj["id"] != meta["store_id"] {
			if !allowCorruptEvidence() {
				return integrityErr("ownership marker .laneboss-state disagrees with events.sqlite meta")
			}
		}
	}

	rows, err := db.Query("SELECT seq, id, kind, lane, actor, occurred_at, payload, protocol_version, recorded_at, sha256 FROM events ORDER BY seq")
	if err != nil {
		if !allowCorruptEvidence() {
			return integrityErr("cannot query events from events.sqlite")
		}
		return nil
	}
	defer rows.Close()

	var events []LegacyEventRecord
	var chainParts []string
	seenIDs := make(map[string]bool)
	prevSeq := int64(0)

	for rows.Next() {
		var seq int64
		var id, kind, actor, payloadTxt, proto, recordedAt, sha string
		var lane, occurredAt sql.NullString
		if err := rows.Scan(&seq, &id, &kind, &lane, &actor, &occurredAt, &payloadTxt, &proto, &recordedAt, &sha); err != nil {
			if !allowCorruptEvidence() {
				return integrityErr("unreadable event row in events.sqlite")
			}
			continue
		}
		if seq != prevSeq+1 {
			if !allowCorruptEvidence() && !allowRehashedHistory() {
				return integrityErr(fmt.Sprintf("event sequence gap at seq %d (previous %d)", seq, prevSeq))
			}
		}
		prevSeq = seq
		if seenIDs[id] {
			if !allowCorruptEvidence() {
				return integrityErr(fmt.Sprintf("duplicate event id %s", id))
			}
		}
		seenIDs[id] = true

		if !migv2.SupportedSourceProtocol(proto) {
			if !allowCorruptEvidence() {
				return integrityErr(fmt.Sprintf("event seq %d has unsupported protocol_version %q", seq, proto))
			}
		}
		parsedPayload, err := eventstore.Parse([]byte(payloadTxt), "stored event payload")
		if err != nil {
			if !allowCorruptEvidence() {
				return integrityErr(fmt.Sprintf("event seq %d payload is invalid JSON: %v", seq, err))
			}
			continue
		}
		payloadObj, ok := parsedPayload.(map[string]any)
		if !ok || eventstore.Canonical(payloadObj) != payloadTxt {
			if !allowCorruptEvidence() && !allowRehashedHistory() {
				return integrityErr(fmt.Sprintf("event seq %d payload is not canonical JSON", seq))
			}
		}

		var laneVal any
		if lane.Valid {
			laneVal = lane.String
		}
		var occurredVal any
		if occurredAt.Valid {
			occurredVal = occurredAt.String
		}
		envForValidate := map[string]any{
			"id":               id,
			"kind":             kind,
			"lane":             laneVal,
			"actor":            actor,
			"occurred_at":      occurredVal,
			"payload":          payloadObj,
			"protocol_version": proto,
		}
		if _, err := eventstore.Validate(envForValidate); err != nil {
			if !allowCorruptEvidence() && !allowRehashedHistory() {
				return integrityErr(fmt.Sprintf("event seq %d failed schema validation: %v", seq, err))
			}
		}

		envForHash := map[string]any{
			"id":               id,
			"kind":             kind,
			"lane":             laneVal,
			"actor":            actor,
			"occurred_at":      occurredVal,
			"payload":          payloadObj,
			"protocol_version": proto,
			"seq":              seq,
			"recorded_at":      recordedAt,
		}
		computedHash := string(DigestBytes([]byte(eventstore.Canonical(envForHash))))
		if computedHash != sha {
			if !allowCorruptEvidence() && !allowRehashedHistory() {
				return integrityErr(fmt.Sprintf("event seq %d sha256 mismatch", seq))
			}
		}

		chainParts = append(chainParts, fmt.Sprintf("%d:%s:%s", seq, id, sha))
		events = append(events, LegacyEventRecord{
			Seq:             seq,
			ID:              id,
			Kind:            kind,
			Lane:            lane.String,
			Actor:           actor,
			OccurredAt:      occurredAt.String,
			ProtocolVersion: proto,
			RecordedAt:      recordedAt,
			SHA256:          sha,
			Payload:         payloadObj,
			RawCanonical:    []byte(eventstore.Canonical(envForHash)),
		})
	}
	if err := rows.Err(); err != nil && !allowCorruptEvidence() {
		return integrityErr("error iterating events.sqlite")
	}

	var seqTableVal int64
	if err := db.QueryRow("SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'events'), 0)").Scan(&seqTableVal); err == nil {
		if seqTableVal != prevSeq && !allowCorruptEvidence() && !allowRehashedHistory() {
			return integrityErr(fmt.Sprintf("sqlite_sequence (%d) != last seq (%d): tail events were removed", seqTableVal, prevSeq))
		}
	}

	if len(events) != bundle.Verification.Events {
		if !allowCorruptEvidence() && !allowRehashedHistory() {
			return integrityErr(fmt.Sprintf("event count %d disagrees with verification receipt (%d)", len(events), bundle.Verification.Events))
		}
	}
	chainDigest := string(DigestBytes([]byte(strings.Join(chainParts, "\n"))))
	if bundle.Verification.EventsChainSHA256 != "" && chainDigest != bundle.Verification.EventsChainSHA256 {
		if !allowRehashedHistory() {
			return integrityErr("events chain digest disagrees with verification receipt: rehashed or modified history detected")
		}
	}

	// Read stored lane projections and verify they match the events.
	pRows, err := db.Query("SELECT lane, projection FROM lanes ORDER BY lane")
	if err != nil {
		if !allowCorruptEvidence() {
			return integrityErr("cannot query lanes projection table")
		}
		return nil
	}
	defer pRows.Close()

	for pRows.Next() {
		var laneName, projTxt string
		if err := pRows.Scan(&laneName, &projTxt); err != nil {
			return integrityErr("cannot scan lane projection")
		}
		parsed, err := eventstore.Parse([]byte(projTxt), "lane projection")
		if err != nil {
			if !allowCorruptEvidence() {
				return integrityErr(fmt.Sprintf("lane %s projection is invalid JSON", laneName))
			}
			continue
		}
		projObj, ok := parsed.(map[string]any)
		if !ok || eventstore.Canonical(projObj) != projTxt {
			if !allowCorruptEvidence() && !allowRehashedHistory() {
				return integrityErr(fmt.Sprintf("lane %s projection is not canonical", laneName))
			}
		}
		if running, _ := projObj["running"].(bool); running {
			if !allowActiveWriter() {
				return conflictErr(fmt.Sprintf("lane %s projection is still marked running in events.sqlite", laneName))
			}
		}
		bundle.Projections[laneName] = projObj
	}

	if bundle.Verification.Lanes != len(bundle.Projections) {
		return integrityErr("verification.lanes disagrees with the projection inventory")
	}
	if err := crossCheckEventsAndFiles(events, bundle.Projections, files); err != nil {
		return err
	}
	bundle.Events = events
	bundle.Mail = extractMailItems(events, bundle.Projections, files)
	return nil
}

func crossCheckEventsAndFiles(events []LegacyEventRecord, projections map[string]map[string]any, files map[string][]byte) error {
	eventCountsByLane := make(map[string]int64)
	lastSeqByLane := make(map[string]int64)
	runByLane := make(map[string]int64)

	for _, ev := range events {
		if strings.HasPrefix(ev.Kind, "lane.") {
			eventCountsByLane[ev.Lane]++
			lastSeqByLane[ev.Lane] = ev.Seq
		}
		switch ev.Kind {
		case "brief.rendered":
			inputs, _ := ev.Payload["inputs"].([]any)
			for _, inItem := range inputs {
				m, _ := inItem.(map[string]any)
				copyRel, _ := m["copy"].(string)
				wantSHA, _ := m["sha256"].(string)
				data, ok := files["state/"+copyRel]
				if !ok {
					if !allowCorruptEvidence() {
						return integrityErr(fmt.Sprintf("missing kept input %s referenced by event seq %d", copyRel, ev.Seq))
					}
					continue
				}
				if string(DigestBytes(data)) != wantSHA {
					if !allowCorruptEvidence() && !allowRehashedHistory() {
						return integrityErr(fmt.Sprintf("kept input %s sha256 mismatch", copyRel))
					}
				}
			}
		case "lane.started", "lane.adopted":
			if ev.Kind == "lane.started" {
				r, _ := int64FromAny(ev.Payload["run"])
				if r != runByLane[ev.Lane]+1 {
					if !allowRehashedHistory() && !allowCorruptEvidence() {
						return integrityErr(fmt.Sprintf("event seq %d run number %d does not follow %d", ev.Seq, r, runByLane[ev.Lane]))
					}
				}
				runByLane[ev.Lane] = r
			} else {
				runByLane[ev.Lane] = 1
			}
			if briefObj, ok := ev.Payload["brief"].(map[string]any); ok {
				wantSHA, _ := briefObj["sha256"].(string)
				rel := fmt.Sprintf("state/lanes/%s/rendered/%s.md", ev.Lane, wantSHA)
				data, exists := files[rel]
				if !exists {
					if !allowCorruptEvidence() {
						return integrityErr(fmt.Sprintf("missing rendered brief %s for event seq %d", rel, ev.Seq))
					}
				} else if string(DigestBytes(data)) != wantSHA {
					if !allowCorruptEvidence() && !allowRehashedHistory() {
						return integrityErr(fmt.Sprintf("rendered brief %s sha256 mismatch", rel))
					}
				}
			}
		case "lane.mailed":
			seqNum, _ := int64FromAny(ev.Payload["sequence"])
			wantSHA, _ := ev.Payload["sha256"].(string)
			wantBytes, _ := int64FromAny(ev.Payload["bytes"])
			rel := fmt.Sprintf("state/lanes/%s/mail/%09d-%s", ev.Lane, seqNum, wantSHA)
			data, exists := files[rel]
			if !exists {
				if !allowCorruptEvidence() {
					return integrityErr(fmt.Sprintf("missing mail file %s for event seq %d", rel, ev.Seq))
				}
			} else if int64(len(data)) != wantBytes || string(DigestBytes(data)) != wantSHA || !utf8.Valid(data) {
				if !allowCorruptEvidence() && !allowRehashedHistory() {
					return integrityErr(fmt.Sprintf("mail file %s content or size mismatch", rel))
				}
			}
		}
	}

	for laneName := range eventCountsByLane {
		if projections[laneName] == nil {
			return integrityErr("events.lane is missing its projection")
		}
	}
	for laneName, proj := range projections {
		evCount, _ := int64FromAny(proj["events"])
		lastSeq, _ := int64FromAny(proj["last_seq"])
		runNum, _ := int64FromAny(proj["run"])
		if evCount != eventCountsByLane[laneName] || lastSeq != lastSeqByLane[laneName] || runNum != runByLane[laneName] {
			if !allowRehashedHistory() && !allowCorruptEvidence() {
				return integrityErr(fmt.Sprintf("lane %s projection disagrees with event stream", laneName))
			}
		}
	}
	return nil
}

func extractMailItems(events []LegacyEventRecord, projections map[string]map[string]any, files map[string][]byte) []LegacyMailItem {
	deliveredByLane := make(map[string]map[int64]bool)
	returnedByLane := make(map[string]map[int64]bool)
	for _, ev := range events {
		if ev.Kind == "lane.delivered" {
			if deliveredByLane[ev.Lane] == nil {
				deliveredByLane[ev.Lane] = make(map[int64]bool)
			}
			seqs, _ := ev.Payload["sequences"].([]any)
			for _, s := range seqs {
				if n, ok := int64FromAny(s); ok {
					deliveredByLane[ev.Lane][n] = true
					if returnedByLane[ev.Lane] != nil {
						delete(returnedByLane[ev.Lane], n)
					}
				}
			}
		} else if ev.Kind == "lane.returned" {
			if returnedByLane[ev.Lane] == nil {
				returnedByLane[ev.Lane] = make(map[int64]bool)
			}
			seqs, _ := ev.Payload["sequences"].([]any)
			for _, s := range seqs {
				if n, ok := int64FromAny(s); ok && !deliveredByLane[ev.Lane][n] {
					returnedByLane[ev.Lane][n] = true
				}
			}
		}
	}
	for laneName, proj := range projections {
		mailObj, _ := proj["mail"].(map[string]any)
		if mailObj == nil {
			continue
		}
		if settled, _ := mailObj["settled"].(map[string]any); settled != nil && settled["outcome"] == "delivered" {
			if deliveredByLane[laneName] == nil {
				deliveredByLane[laneName] = make(map[int64]bool)
			}
			seqs, _ := settled["sequences"].([]any)
			for _, s := range seqs {
				if n, ok := int64FromAny(s); ok {
					deliveredByLane[laneName][n] = true
				}
			}
		}
	}

	var items []LegacyMailItem
	for _, ev := range events {
		if ev.Kind != "lane.mailed" {
			continue
		}
		seqNum, _ := int64FromAny(ev.Payload["sequence"])
		sha, _ := ev.Payload["sha256"].(string)
		sz, _ := int64FromAny(ev.Payload["bytes"])
		sender, _ := ev.Payload["sender"].(string)
		legacyRel, _ := ev.Payload["legacy_relationship"].(bool)
		rel := fmt.Sprintf("state/lanes/%s/mail/%09d-%s", ev.Lane, seqNum, sha)
		content := files[rel]
		isDelivered := deliveredByLane[ev.Lane][seqNum]
		isReturned := returnedByLane[ev.Lane][seqNum]
		items = append(items, LegacyMailItem{
			Lane:       ev.Lane,
			Sequence:   seqNum,
			Sender:     sender,
			SHA256:     sha,
			Bytes:      sz,
			Content:    content,
			Delivered:  isDelivered,
			Returned:   isReturned,
			LegacyRel:  legacyRel,
			QueuedSeq:  ev.Seq,
			RecordedAt: ev.RecordedAt,
		})
	}
	return items
}

func verifyIdentityJournal(files map[string][]byte, bundle *VerifiedBundle) error {
	raw, ok := files["state/records.jsonl"]
	if !ok || len(raw) == 0 {
		return nil
	}
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	prevSeq := int64(0)
	for i, line := range lines {
		if len(line) == 0 {
			continue
		}
		parsed, err := eventstore.Parse(line, "identity journal record")
		if err != nil {
			if !allowCorruptEvidence() {
				return integrityErr(fmt.Sprintf("records.jsonl line %d is invalid JSON", i+1))
			}
			continue
		}
		m, ok := parsed.(map[string]any)
		if !ok {
			if !allowCorruptEvidence() {
				return integrityErr(fmt.Sprintf("records.jsonl line %d is not a JSON object", i+1))
			}
			continue
		}
		ver, _ := int64FromAny(m["laneboss_service"])
		seq, _ := int64FromAny(m["seq"])
		cfg, _ := m["config"].(string)
		op, _ := m["op"].(string)
		if ver != 1 || seq != prevSeq+1 || (bundle.ConfigName != "" && cfg != bundle.ConfigName) {
			if !allowCorruptEvidence() && !allowRehashedHistory() {
				return integrityErr(fmt.Sprintf("records.jsonl line %d has invalid version, seq or config", i+1))
			}
		}
		prevSeq = seq
		if op != "register" && op != "lane-started" && op != "append" {
			if !allowCorruptEvidence() {
				return integrityErr(fmt.Sprintf("records.jsonl line %d has unknown op %q", i+1, op))
			}
		}
	}
	return nil
}

func verifyDecisionsAndVectors(files map[string][]byte, bundle *VerifiedBundle) error {
	if _, sqlite := files["state/decisions.sqlite"]; sqlite {
		if _, jsonl := files["state/decisions.jsonl"]; jsonl {
			return integrityErr("decisions.source is ambiguous: both sqlite and jsonl exist")
		}
	}
	if sqliteBytes, hasSQLite := files["state/decisions.sqlite"]; hasSQLite {
		if err := verifyDecisionsSQLite(sqliteBytes, bundle); err != nil {
			return err
		}
	}
	raw, ok := files["state/decisions.jsonl"]
	if !ok {
		if _, hasSQLite := files["state/decisions.sqlite"]; hasSQLite {
			return nil
		}
		if bundle.Verification.DecisionsSHA256 != "" && !allowCorruptEvidence() {
			return integrityErr("state/decisions.jsonl is missing from inventory")
		}
		return nil
	}
	if bundle.Verification.DecisionsSHA256 != "" && string(DigestBytes(raw)) != bundle.Verification.DecisionsSHA256 {
		if !allowCorruptEvidence() && !allowRehashedHistory() {
			return integrityErr("state/decisions.jsonl sha256 disagrees with verification receipt")
		}
	}

	lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	if len(lines) == 0 {
		return integrityErr("decisions.jsonl is empty")
	}
	manifestAny, err := eventstore.Parse(lines[0], "decisions manifest")
	if err != nil {
		if !allowCorruptEvidence() {
			return integrityErr("decisions.jsonl manifest is invalid JSON")
		}
		return nil
	}
	manifestObj, _ := manifestAny.(map[string]any)
	format, _ := manifestObj["format"].(string)
	if manifestObj["type"] != "manifest" || (format != "laneboss-decisions-jsonl" && format != "sup-decisions-jsonl") {
		if !allowCorruptEvidence() {
			return integrityErr("decisions.jsonl has invalid manifest header")
		}
	}
	countsObj, _ := manifestObj["counts"].(map[string]any)
	wantRecords, _ := int64FromAny(countsObj["records"])
	wantModels, _ := int64FromAny(countsObj["models"])
	wantVectors, _ := int64FromAny(countsObj["vectors"])
	wantEgress, _ := int64FromAny(countsObj["egress"])

	models := make(map[string]int)
	recordQSHA := make(map[string]string)
	recordDSHA := make(map[string]string)
	prevEgressSHA := ""
	var gotModels int64

	for idx, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		entryAny, err := eventstore.Parse(line, "decisions entry")
		if err != nil {
			if !allowCorruptEvidence() {
				return integrityErr(fmt.Sprintf("decisions.jsonl line %d is invalid JSON", idx+2))
			}
			continue
		}
		entry, _ := entryAny.(map[string]any)
		typ, _ := entry["type"].(string)
		switch typ {
		case "record":
			rec, _ := entry["record"].(map[string]any)
			if rec == nil {
				return integrityErr("decision record entry missing record object")
			}
			id, _ := rec["id"].(string)
			ans, _ := rec["answer"].(map[string]any)
			verbatim, _ := ans["verbatim"].(string)
			ansSHA, _ := ans["sha256"].(string)
			if id == "" || verbatim == "" || string(DigestBytes([]byte(verbatim))) != ansSHA {
				if !allowCorruptEvidence() && !allowRehashedHistory() {
					return integrityErr(fmt.Sprintf("decision record %q answer.sha256 mismatch", id))
				}
			}
			recCanon := []byte(eventstore.Canonical(rec))
			recSHA := string(DigestBytes(recCanon))
			firstSHA, _ := entry["first_written_sha256"].(string)
			_, isSuperseded := rec["supersedes"].(string)
			if firstSHA != "" && !isSuperseded && rec["outcome"] != nil {
				if outMap, _ := rec["outcome"].(map[string]any); len(outMap) == 0 && rec["status"] == "in_force" && firstSHA != recSHA {
					if !allowRehashedHistory() {
						return integrityErr(fmt.Sprintf("decision record %q disagrees with first_written_sha256 (rehashed record)", id))
					}
				}
			}
			prov, _ := rec["provenance"].(map[string]any)
			recBy, _ := prov["recorded_by"].(string)
			ansAt, _ := rec["answered_at"].(string)
			q, _ := rec["question"].(map[string]any)
			qText := decisionQuestionProjection(q, rec["topics"])
			dText := decisionAnswerProjection(ans, rec["scope"], rec["outcome"])
			recordQSHA[id] = string(DigestBytes([]byte(qText)))
			recordDSHA[id] = string(DigestBytes([]byte(dText)))

			bundle.Decisions = append(bundle.Decisions, LegacyDecisionItem{
				ID:              id,
				RecordJSON:      recCanon,
				RecordSHA256:    recSHA,
				FirstWrittenSHA: firstSHA,
				Authoritative:   recBy == "human" || recBy == "owner" || strings.HasPrefix(recBy, "d6:"),
				RecordedBy:      recBy,
				AnsweredAt:      ansAt,
			})
		case "model":
			mObj, _ := entry["model"].(map[string]any)
			name, _ := mObj["model"].(string)
			dim, _ := int64FromAny(mObj["dimension"])
			if name == "" || dim < 1 || dim > 4096 {
				if !allowCorruptEvidence() {
					return integrityErr("invalid decision embedding model metadata")
				}
			}
			models[name] = int(dim)
			gotModels++
		case "vector":
			vObj, _ := entry["vector"].(map[string]any)
			recID, _ := vObj["record_id"].(string)
			which, _ := vObj["which_text"].(string)
			modelName, _ := vObj["model"].(string)
			dim, _ := int64FromAny(vObj["dimension"])
			txt, _ := vObj["text"].(string)
			txtSHA, _ := vObj["text_sha256"].(string)
			vecB64, _ := vObj["vector"].(string)
			vecSHA, _ := vObj["vector_sha256"].(string)
			entSHA, _ := vObj["entry_sha256"].(string)
			createdAt, _ := vObj["created_at"].(string)

			vecBytes, err := base64.StdEncoding.DecodeString(vecB64)
			if err != nil || len(vecBytes) != int(dim)*4 || models[modelName] != int(dim) {
				if !allowCorruptEvidence() {
					return integrityErr(fmt.Sprintf("vector %s/%s has invalid float32 bytes or dimension", recID, which))
				}
			}
			if !validFloat32Vector(vecBytes) {
				if !allowCorruptEvidence() {
					return integrityErr(fmt.Sprintf("vector %s/%s contains non-finite or all-zero float32 values", recID, which))
				}
			}
			if string(DigestBytes([]byte(txt))) != txtSHA || string(DigestBytes(vecBytes)) != vecSHA {
				if !allowCorruptEvidence() && !allowRehashedHistory() {
					return integrityErr(fmt.Sprintf("vector %s/%s text or vector sha256 mismatch", recID, which))
				}
			}
			if (which == "q_text" && recordQSHA[recID] != "" && recordQSHA[recID] != txtSHA) ||
				(which == "d_text" && recordDSHA[recID] != "" && recordDSHA[recID] != txtSHA) {
				if !allowRehashedHistory() && !allowCorruptEvidence() {
					return integrityErr(fmt.Sprintf("vector %s/%s text_sha256 does not match decision record", recID, which))
				}
			}
			bundle.Vectors = append(bundle.Vectors, LegacyVectorItem{
				RecordID:     recID,
				WhichText:    which,
				Model:        modelName,
				Dimension:    int(dim),
				TextSHA256:   txtSHA,
				VectorSHA256: vecSHA,
				EntrySHA256:  entSHA,
				CreatedAt:    createdAt,
				RawJSON:      []byte(eventstore.Canonical(vObj)),
			})
		case "egress":
			eObj, _ := entry["egress"].(map[string]any)
			idNum, _ := int64FromAny(eObj["id"])
			recID, _ := eObj["record_id"].(string)
			which, _ := eObj["which_text"].(string)
			modelName, _ := eObj["model"].(string)
			txt, _ := eObj["text"].(string)
			txtSHA, _ := eObj["text_sha256"].(string)
			prevSHA, hasPrev := eObj["previous_entry_sha256"].(string)
			entSHA, _ := eObj["entry_sha256"].(string)
			at, _ := eObj["at"].(string)

			if !hasPrev || prevSHA != prevEgressSHA || string(DigestBytes([]byte(txt))) != txtSHA {
				if !allowCorruptEvidence() && !allowRehashedHistory() {
					return integrityErr(fmt.Sprintf("egress entry %d hash chain mismatch", idNum))
				}
			}
			prevEgressSHA = entSHA
			bundle.Egress = append(bundle.Egress, LegacyEgressItem{
				ID:          idNum,
				RecordID:    recID,
				WhichText:   which,
				Model:       modelName,
				TextSHA256:  txtSHA,
				PrevSHA256:  prevSHA,
				EntrySHA256: entSHA,
				At:          at,
				RawJSON:     []byte(eventstore.Canonical(eObj)),
			})
		}
	}

	if int64(len(bundle.Decisions)) != wantRecords || gotModels != wantModels ||
		int64(len(bundle.Vectors)) != wantVectors || int64(len(bundle.Egress)) != wantEgress {
		if !allowCorruptEvidence() {
			return integrityErr("decisions.jsonl manifest counts mismatch actual entries")
		}
	}
	return nil
}

func verifyDecisionsSQLite(dbBytes []byte, bundle *VerifiedBundle) error {
	if bundle.Verification.DecisionsSHA256 != "" && string(DigestBytes(dbBytes)) != bundle.Verification.DecisionsSHA256 {
		if !allowCorruptEvidence() && !allowRehashedHistory() {
			return integrityErr("state/decisions.sqlite sha256 disagrees with verification receipt")
		}
	}
	tmpDir, err := os.MkdirTemp("", "lb-mig-dec-*")
	if err != nil {
		return integrityErr("cannot allocate temporary directory for decisions.sqlite verification")
	}
	defer os.RemoveAll(tmpDir)
	_ = os.Chmod(tmpDir, 0o700)

	dbPath := filepath.Join(tmpDir, "decisions.sqlite")
	if err := os.WriteFile(dbPath, dbBytes, 0o400); err != nil {
		return integrityErr("cannot stage read-only decisions.sqlite")
	}
	uri := url.URL{Scheme: "file", Path: dbPath, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		if !allowCorruptEvidence() {
			return integrityErr("cannot open decisions.sqlite")
		}
		return nil
	}
	defer db.Close()

	var status string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&status); err != nil || status != "ok" {
		if !allowCorruptEvidence() {
			return integrityErr("decisions.sqlite failed PRAGMA integrity_check")
		}
	}
	var userVersion int
	if err := db.QueryRow("PRAGMA user_version").Scan(&userVersion); err != nil || userVersion < 1 || userVersion > 4 {
		if !allowCorruptEvidence() {
			return integrityErr(fmt.Sprintf("decisions.sqlite has unsupported user_version %d", userVersion))
		}
	}

	firstWritten := make(map[string]string)
	if userVersion >= 2 {
		fwRows, err := db.Query("SELECT record_id, record_sha256 FROM first_written")
		if err == nil {
			for fwRows.Next() {
				var rid, rsha string
				if fwRows.Scan(&rid, &rsha) == nil {
					firstWritten[rid] = rsha
				}
			}
			fwRows.Close()
		}
	}

	rRows, err := db.Query("SELECT id, record_json, record_sha256, verbatim, verbatim_sha256, q_sha256, d_sha256 FROM records ORDER BY id")
	if err != nil {
		if !allowCorruptEvidence() {
			return integrityErr("decisions.sqlite records table is unreadable")
		}
		return nil
	}
	defer rRows.Close()

	recordQSHA := make(map[string]string)
	recordDSHA := make(map[string]string)
	for rRows.Next() {
		var id, recJSON, recSHA, verbSHA, qSHA, dSHA string
		var verbBytes []byte
		if err := rRows.Scan(&id, &recJSON, &recSHA, &verbBytes, &verbSHA, &qSHA, &dSHA); err != nil {
			return integrityErr("cannot scan decisions.sqlite record row")
		}
		if string(DigestBytes([]byte(recJSON))) != recSHA || string(DigestBytes(verbBytes)) != verbSHA {
			if !allowCorruptEvidence() && !allowRehashedHistory() {
				return integrityErr(fmt.Sprintf("decisions.sqlite record %s hash mismatch", id))
			}
		}
		parsed, err := eventstore.Parse([]byte(recJSON), "decision record")
		if err != nil {
			if !allowCorruptEvidence() {
				return integrityErr(fmt.Sprintf("decisions.sqlite record %s is invalid JSON", id))
			}
			continue
		}
		recObj, _ := parsed.(map[string]any)
		if fw, ok := firstWritten[id]; ok {
			_, isSup := recObj["supersedes"].(string)
			outMap, _ := recObj["outcome"].(map[string]any)
			if !isSup && len(outMap) == 0 && recObj["status"] == "in_force" && fw != recSHA {
				if !allowRehashedHistory() {
					return integrityErr(fmt.Sprintf("decisions.sqlite record %s disagrees with first_written", id))
				}
			}
		}
		recordQSHA[id] = qSHA
		recordDSHA[id] = dSHA
		prov, _ := recObj["provenance"].(map[string]any)
		recBy, _ := prov["recorded_by"].(string)
		ansAt, _ := recObj["answered_at"].(string)
		bundle.Decisions = append(bundle.Decisions, LegacyDecisionItem{
			ID:              id,
			RecordJSON:      []byte(recJSON),
			RecordSHA256:    recSHA,
			FirstWrittenSHA: firstWritten[id],
			Authoritative:   recBy == "human" || recBy == "owner" || strings.HasPrefix(recBy, "d6:"),
			RecordedBy:      recBy,
			AnsweredAt:      ansAt,
		})
	}
	if err := rRows.Err(); err != nil {
		return integrityErr("error iterating decisions.sqlite records")
	}

	models := make(map[string]int)
	mRows, err := db.Query("SELECT model, provider, dimension, entry_sha256 FROM models ORDER BY model")
	if err == nil {
		defer mRows.Close()
		for mRows.Next() {
			var modelName, prov, entSHA string
			var dim int
			if err := mRows.Scan(&modelName, &prov, &dim, &entSHA); err != nil || modelName == "" || dim < 1 || dim > 4096 {
				if !allowCorruptEvidence() {
					return integrityErr("invalid model row in decisions.sqlite")
				}
				continue
			}
			models[modelName] = dim
		}
	}

	prevEgressSHA := ""
	eRows, err := db.Query("SELECT id, coalesce(record_id, ''), which_text, text, text_sha256, model, at, previous_entry_sha256, entry_sha256 FROM egress_log ORDER BY id")
	if err == nil {
		defer eRows.Close()
		var expectedID int64 = 1
		for eRows.Next() {
			var idNum int64
			var recID, which, txt, txtSHA, modelName, at, prevSHA, entSHA string
			if err := eRows.Scan(&idNum, &recID, &which, &txt, &txtSHA, &modelName, &at, &prevSHA, &entSHA); err != nil {
				return integrityErr("cannot scan egress_log row in decisions.sqlite")
			}
			if idNum != expectedID || prevSHA != prevEgressSHA || string(DigestBytes([]byte(txt))) != txtSHA {
				if !allowCorruptEvidence() && !allowRehashedHistory() {
					return integrityErr(fmt.Sprintf("decisions.sqlite egress_log entry %d hash chain mismatch", idNum))
				}
			}
			expectedID++
			prevEgressSHA = entSHA
			rawMap := map[string]any{
				"id":                    idNum,
				"record_id":             recID,
				"which_text":            which,
				"text_sha256":           txtSHA,
				"model":                 modelName,
				"at":                    at,
				"previous_entry_sha256": prevSHA,
				"entry_sha256":          entSHA,
			}
			bundle.Egress = append(bundle.Egress, LegacyEgressItem{
				ID:          idNum,
				RecordID:    recID,
				WhichText:   which,
				Model:       modelName,
				TextSHA256:  txtSHA,
				PrevSHA256:  prevSHA,
				EntrySHA256: entSHA,
				At:          at,
				RawJSON:     []byte(eventstore.Canonical(rawMap)),
			})
		}
	}

	vRows, err := db.Query("SELECT record_id, which_text, model, dimension, text, text_sha256, vector, vector_sha256, created_at, entry_sha256 FROM vectors ORDER BY record_id, which_text, model")
	if err == nil {
		defer vRows.Close()
		for vRows.Next() {
			var recID, which, modelName, txt, txtSHA, vecSHA, createdAt, entSHA string
			var dim int
			var vecBlob []byte
			if err := vRows.Scan(&recID, &which, &modelName, &dim, &txt, &txtSHA, &vecBlob, &vecSHA, &createdAt, &entSHA); err != nil {
				return integrityErr("cannot scan vectors row in decisions.sqlite")
			}
			if len(vecBlob) != dim*4 || models[modelName] != dim || !validFloat32Vector(vecBlob) {
				if !allowCorruptEvidence() {
					return integrityErr(fmt.Sprintf("decisions.sqlite vector %s/%s invalid float32 blob or dimension", recID, which))
				}
			}
			if string(DigestBytes([]byte(txt))) != txtSHA || string(DigestBytes(vecBlob)) != vecSHA {
				if !allowCorruptEvidence() && !allowRehashedHistory() {
					return integrityErr(fmt.Sprintf("decisions.sqlite vector %s/%s hash mismatch", recID, which))
				}
			}
			if (which == "q_text" && recordQSHA[recID] != "" && recordQSHA[recID] != txtSHA) ||
				(which == "d_text" && recordDSHA[recID] != "" && recordDSHA[recID] != txtSHA) {
				if !allowRehashedHistory() && !allowCorruptEvidence() {
					return integrityErr(fmt.Sprintf("decisions.sqlite vector %s/%s text_sha256 disagrees with record", recID, which))
				}
			}
			rawMap := map[string]any{
				"record_id":     recID,
				"which_text":    which,
				"model":         modelName,
				"dimension":     dim,
				"text_sha256":   txtSHA,
				"vector_sha256": vecSHA,
				"created_at":    createdAt,
				"entry_sha256":  entSHA,
			}
			bundle.Vectors = append(bundle.Vectors, LegacyVectorItem{
				RecordID:     recID,
				WhichText:    which,
				Model:        modelName,
				Dimension:    dim,
				TextSHA256:   txtSHA,
				VectorSHA256: vecSHA,
				EntrySHA256:  entSHA,
				CreatedAt:    createdAt,
				RawJSON:      []byte(eventstore.Canonical(rawMap)),
			})
		}
	}
	return nil
}

func decisionQuestionProjection(q map[string]any, topics any) string {
	if q == nil {
		return ""
	}
	return strings.Join([]string{
		flattenAny(q["text"]),
		flattenAny(q["background"]),
		flattenAny(q["options"]),
		flattenAny(q["recommendation"]),
		flattenAny(topics),
	}, "\n")
}

func decisionAnswerProjection(a map[string]any, scope, outcome any) string {
	if a == nil {
		return ""
	}
	return strings.Join([]string{
		flattenAny(a["verbatim"]),
		flattenAny(a["interpreted_as"]),
		flattenAny(scope),
		flattenAny(outcome),
	}, "\n")
}

func flattenAny(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			out = append(out, flattenAny(item))
		}
		return strings.Join(out, "\n")
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]string, 0, len(keys))
		for _, k := range keys {
			out = append(out, flattenAny(x[k]))
		}
		return strings.Join(out, "\n")
	case bool:
		if x {
			return "True"
		}
		return "False"
	default:
		return fmt.Sprint(x)
	}
}

func validFloat32Vector(blob []byte) bool {
	if len(blob) == 0 || len(blob)%4 != 0 {
		return false
	}
	nonZero := false
	for i := 0; i < len(blob); i += 4 {
		bits := binary.LittleEndian.Uint32(blob[i : i+4])
		f := float64(math.Float32frombits(bits))
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return false
		}
		if f != 0 {
			nonZero = true
		}
	}
	return nonZero
}

func verifyArchives(files map[string][]byte, bundle *VerifiedBundle) error {
	var receiptPaths []string
	for p := range files {
		if strings.HasPrefix(p, "state/archives/") && strings.HasSuffix(p, ".receipt.json") {
			receiptPaths = append(receiptPaths, p)
		}
	}
	sort.Strings(receiptPaths)

	for _, rPath := range receiptPaths {
		rBytes := files[rPath]
		stem := strings.TrimSuffix(filepath.Base(rPath), ".receipt.json")
		tarPath := "state/archives/" + stem + ".tar"
		manPath := "state/archives/" + stem + ".manifest.json"
		tarBytes, hasTar := files[tarPath]
		manBytes, hasMan := files[manPath]
		if !hasTar || !hasMan {
			if !allowCorruptEvidence() {
				return integrityErr(fmt.Sprintf("archive %s is missing its .tar or .manifest.json", stem))
			}
			continue
		}
		var receipt map[string]any
		if err := json.Unmarshal(rBytes, &receipt); err != nil {
			if !allowCorruptEvidence() {
				return integrityErr(fmt.Sprintf("archive receipt %s is invalid JSON", rPath))
			}
			continue
		}
		wantTarSHA, _ := receipt["sha256"].(string)
		wantManSHA, _ := receipt["manifest_sha256"].(string)
		if string(DigestBytes(tarBytes)) != wantTarSHA || string(DigestBytes(manBytes)) != wantManSHA {
			if !allowCorruptEvidence() && !allowRehashedHistory() {
				return integrityErr(fmt.Sprintf("archive %s tar or manifest sha256 disagrees with receipt", stem))
			}
		}

		var man struct {
			Format  int `json:"format"`
			Entries []struct {
				Path   string `json:"path"`
				Type   string `json:"type"`
				Size   int64  `json:"size"`
				Mode   int64  `json:"mode"`
				SHA256 string `json:"sha256"`
				Link   string `json:"link,omitempty"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(manBytes, &man); err != nil || man.Format != 1 {
			if !allowCorruptEvidence() {
				return integrityErr(fmt.Sprintf("archive %s manifest is invalid", stem))
			}
			continue
		}

		tr := tar.NewReader(bytes.NewReader(tarBytes))
		idx := 0
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil || idx >= len(man.Entries) {
				if !allowCorruptEvidence() {
					return integrityErr(fmt.Sprintf("archive %s tar read-back mismatch", stem))
				}
				break
			}
			expected := man.Entries[idx]
			idx++
			if validateRelativePath(strings.TrimSuffix(hdr.Name, "/")) != nil || hdr.Mode&0o7000 != 0 || expected.Mode&0o7000 != 0 || hdr.Mode&0o777 != expected.Mode&0o777 {
				return integrityErr("archive.member path or mode is unsafe")
			}
			if hdr.Typeflag == tar.TypeSymlink {
				if hdr.Linkname != expected.Link || validateInternalSymlink(hdr.Name, hdr.Linkname) != nil || expected.Type != "symlink" {
					return integrityErr("archive.member symlink is unsafe")
				}
			} else if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA && hdr.Typeflag != tar.TypeDir {
				return integrityErr("archive.member type is unsafe")
			}
			h := sha256.New()
			n, err := io.Copy(h, tr)
			if err != nil || hdr.Name != expected.Path || n != expected.Size || hex.EncodeToString(h.Sum(nil)) != expected.SHA256 {
				if !allowCorruptEvidence() {
					return integrityErr(fmt.Sprintf("archive %s member %s failed read-back verification", stem, hdr.Name))
				}
			}
		}
		if idx != len(man.Entries) && !allowCorruptEvidence() {
			return integrityErr(fmt.Sprintf("archive %s member count mismatch", stem))
		}

		laneName, _ := receipt["lane"].(string)
		runNum, _ := int64FromAny(receipt["run"])
		bundle.Archives = append(bundle.Archives, LegacyArchiveItem{
			Stem:           stem,
			Lane:           laneName,
			Run:            runNum,
			TarSHA256:      wantTarSHA,
			ManifestSHA256: wantManSHA,
			ReceiptSHA256:  string(DigestBytes(rBytes)),
			ManifestBytes:  manBytes,
			ReceiptBytes:   rBytes,
		})
	}
	return nil
}

func verifyOwnerQueueAndLedgers(files map[string][]byte, bundle *VerifiedBundle) error {
	if qBytes, ok := files["state/owner/queue.jsonl"]; ok && len(qBytes) > 0 {
		lines := bytes.Split(bytes.TrimSuffix(qBytes, []byte{'\n'}), []byte{'\n'})
		for i, line := range lines {
			if len(line) == 0 {
				continue
			}
			parsed, err := eventstore.Parse(line, "owner queue entry")
			if err != nil {
				if !allowCorruptEvidence() {
					return integrityErr(fmt.Sprintf("owner/queue.jsonl line %d is invalid JSON", i+1))
				}
				continue
			}
			m, ok := parsed.(map[string]any)
			if !ok || m["to"] != "human" {
				if !allowCorruptEvidence() {
					return integrityErr(fmt.Sprintf("owner/queue.jsonl line %d is not a human owner report", i+1))
				}
			}
			bundle.OwnerQueue = append(bundle.OwnerQueue, []byte(eventstore.Canonical(m)))
		}
	}

	if lBytes, ok := files["state/box-ledger.jsonl"]; ok && len(lBytes) > 0 {
		lines := bytes.Split(bytes.TrimSuffix(lBytes, []byte{'\n'}), []byte{'\n'})
		for i, line := range lines {
			if len(line) == 0 {
				continue
			}
			parsed, err := eventstore.Parse(line, "box ledger entry")
			if err != nil {
				if !allowCorruptEvidence() {
					return integrityErr(fmt.Sprintf("box-ledger.jsonl line %d is invalid JSON", i+1))
				}
				continue
			}
			bundle.BoxLedger = append(bundle.BoxLedger, []byte(eventstore.Canonical(parsed)))
		}
	}

	if advBytes, ok := files["e2e-rows/adversarial-additions.json"]; ok {
		inv, err := migv2.VerifyAdversarialAdditions(advBytes)
		if err != nil && !allowCorruptEvidence() {
			return integrityErr("adversarial-additions.json verification failed: " + err.Error())
		}
		bundle.Adversarial = &inv
	}
	return nil
}

func collectUnfinishedSessions(files map[string][]byte, bundle *VerifiedBundle) error {
	unfinishedSet := make(map[string]bool)
	for _, name := range bundle.Quiescence.UnfinishedLanes {
		if name != "" {
			unfinishedSet[name] = true
		}
	}
	for laneName, proj := range bundle.Projections {
		cleaned, _ := proj["cleaned"].(bool)
		st, _ := proj["state"].(string)
		if !cleaned && (st == "waiting" || st == "verifying" || st == "queued") {
			unfinishedSet[laneName] = true
		}
	}
	for p := range files {
		if strings.HasPrefix(p, "state/lanes/") {
			rest := strings.TrimPrefix(p, "state/lanes/")
			parts := strings.SplitN(rest, "/", 3)
			if len(parts) >= 2 && (parts[1] == "worktree" || parts[1] == "session") {
				proj := bundle.Projections[parts[0]]
				cleaned := false
				st := ""
				if proj != nil {
					cleaned, _ = proj["cleaned"].(bool)
					st, _ = proj["state"].(string)
				}
				if !cleaned && st != "merged" && st != "abandoned" {
					unfinishedSet[parts[0]] = true
				}
			}
		}
	}

	var names []string
	for name := range unfinishedSet {
		names = append(names, name)
	}
	sort.Strings(names)

	lastStarted := make(map[string]map[string]any)
	for _, ev := range bundle.Events {
		if ev.Kind == "lane.started" || ev.Kind == "lane.adopted" {
			lastStarted[ev.Lane] = ev.Payload
		}
	}

	relaunchIDs := make([]api.ID, 0, len(names))
	for _, laneName := range names {
		startPayload := lastStarted[laneName]
		for _, field := range []string{"runner", "model", "effort", "session_id", "branch", "base"} {
			if value := startPayload[field]; value != nil {
				if _, ok := value.(string); !ok {
					return invalidErr(fmt.Sprintf("lane %q: legacy.%s is invalid", laneName, field))
				}
			}
		}
		runnerName, _ := startPayload["runner"].(string)
		driver := mapLegacyDriver(runnerName)
		model, _ := startPayload["model"].(string)
		effort, _ := startPayload["effort"].(string)
		sessID, _ := startPayload["session_id"].(string)
		branch, _ := startPayload["branch"].(string)
		base, _ := startPayload["base"].(string)
		candidate := LegacyUnfinishedSession{Lane: laneName, Runner: runnerName, Driver: driver,
			Model: model, Effort: effort, SessionID: sessID, Branch: branch, Base: base}
		if err := validateLegacyRelaunch(candidate); err != nil {
			var detail *api.Error
			if errors.As(err, &detail) {
				withLane := *detail
				withLane.Message = fmt.Sprintf("lane %q: %s", laneName, detail.Message)
				return &withLane
			}
			return fmt.Errorf("lane %q: %w", laneName, err)
		}

		wtFiles := make(map[string][]byte)
		wtPrefix := "state/lanes/" + laneName + "/worktree/"
		var histBytes []byte
		sessPrefix := "state/lanes/" + laneName + "/session/"

		fileNames := make([]string, 0, len(files))
		for p := range files {
			fileNames = append(fileNames, p)
		}
		sort.Strings(fileNames)
		for _, p := range fileNames {
			data := files[p]
			if strings.HasPrefix(p, wtPrefix) {
				rel := strings.TrimPrefix(p, wtPrefix)
				if isForbiddenAuthPath(rel) || credentialtext.HasCredential(string(data)) {
					return integrityErr("legacy.worktree contains forbidden credential material")
				}
				wtFiles[rel] = data
			} else if strings.HasPrefix(p, sessPrefix) {
				rel := strings.TrimPrefix(p, sessPrefix)
				if isForbiddenAuthPath(rel) || credentialtext.HasCredential(string(data)) {
					if !allowCorruptEvidence() {
						return integrityErr(fmt.Sprintf("session history for lane %s contains forbidden credential file %s", laneName, rel))
					}
					continue
				}
				histBytes = append(histBytes, data...)
			}
		}

		bundle.Unfinished = append(bundle.Unfinished, LegacyUnfinishedSession{
			Lane:           laneName,
			Runner:         runnerName,
			Driver:         driver,
			Model:          model,
			Effort:         effort,
			SessionID:      sessID,
			Branch:         branch,
			Base:           base,
			WorktreeFiles:  wtFiles,
			SessionHistory: histBytes,
		})
		relaunchIDs = append(relaunchIDs, sanitizeRecordID("relaunch-", laneName))
	}
	bundle.RequiresRelaunch = relaunchIDs
	return nil
}

func mapLegacyDriver(runner string) api.Driver {
	if runner == "codex" {
		return api.DriverCodex
	}
	if runner == "claudock" || runner == "claudock-cli" {
		return api.DriverClaudock
	}
	return ""
}

func isForbiddenAuthPath(rel string) bool {
	lower := strings.ToLower(filepath.Base(rel))
	full := "/" + strings.ToLower(filepath.ToSlash(rel))
	if strings.Contains(full, "/.aws/") || strings.Contains(full, "/.docker/") || strings.Contains(full, "/gh/") || strings.Contains(full, "/.ssh/") {
		return true
	}
	switch lower {
	case "auth.json", ".credentials", "credentials", "credentials.json", "id_rsa", "id_ed25519", "id_ecdsa", "keychain.db", ".netrc", ".git-credentials", ".npmrc", ".pypirc":
		return true
	}
	return strings.HasPrefix(lower, ".env") || strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".key") || strings.HasSuffix(lower, ".p12") || strings.HasSuffix(lower, ".pfx") || strings.HasSuffix(lower, ".jks")
}

func int64FromAny(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case float64:
		return int64(x), true
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	}
	return 0, false
}

func asAPIError(err error, target **api.Error) bool {
	if e, ok := err.(*api.Error); ok {
		*target = e
		return true
	}
	return false
}
