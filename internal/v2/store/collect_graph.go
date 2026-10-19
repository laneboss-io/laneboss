package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Only complete BlobRefs become edges. IDs by themselves (including deletion
// journals and workspace handles) are not object retention decisions.
func blobEdges(raw []byte) []api.BlobRef {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	refs := []api.BlobRef{}
	var visit func(any)
	visit = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			if id, ok := v["id"].(string); ok {
				if digest, ok := v["sha256"].(string); ok {
					class, _ := v["class"].(string)
					size, hasSize := v["bytes"].(float64)
					if hasSize && size >= 0 && size <= 1<<53-1 && float64(int64(size)) == size && wire.ValidID(id) && wire.ValidDigest(digest) && class != "" {
						refs = append(refs, api.BlobRef{ID: api.ID(id), Class: class, Bytes: int64(size), SHA256: api.Digest(digest)})
					}
				}
			}
			for _, child := range v {
				visit(child)
			}
		case []any:
			for _, child := range v {
				visit(child)
			}
		}
	}
	visit(value)
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].ID != refs[j].ID {
			return refs[i].ID < refs[j].ID
		}
		if refs[i].SHA256 != refs[j].SHA256 {
			return refs[i].SHA256 < refs[j].SHA256
		}
		return refs[i].Class < refs[j].Class
	})
	return refs
}

type graphObject struct {
	Metadata api.ObjectMetadata
	Outbound []api.BlobRef
	Runtime  *api.CleanupObject `json:",omitempty"`
}

// One writer owns both the SQL namespace and all reference sources. Enumerate
// its complete graph; do not use a worker's candidate IDs. Historical projections
// and immutable requests/events remain roots, including archive transitive refs.
func (s *Service) collectionGraph(ctx context.Context, job api.CleanupJob, inventory *api.CleanupInventory) ([]api.CleanupObject, api.Digest, api.Generation, error) {
	op := job.Intent.Cause.CauseOperationID
	objects := map[api.ID]graphObject{}
	rows, err := s.db.QueryContext(ctx, "SELECT metadata,data FROM objects WHERE json_extract(metadata,'$.SourceOperationID')<>? ORDER BY id", string(op))
	if err != nil {
		return nil, "", 0, err
	}
	for rows.Next() {
		var metadata, raw []byte
		var meta api.ObjectMetadata
		if err := rows.Scan(&metadata, &raw); err != nil {
			rows.Close()
			return nil, "", 0, err
		}
		if err := decodeStored(metadata, &meta); err != nil {
			rows.Close()
			return nil, "", 0, err
		}
		if meta.Ref.Bytes != int64(len(raw)) || meta.Ref.SHA256 != api.Digest(hash(raw)) || meta.ACL.Config != s.deps.Config {
			rows.Close()
			return nil, "", 0, fault(api.CodeIntegrity, "cleanup graph contains corrupt or foreign stored bytes")
		}
		objects[meta.Ref.ID] = graphObject{Metadata: meta, Outbound: blobEdges(raw)}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, "", 0, err
	}
	if err := rows.Close(); err != nil {
		return nil, "", 0, err
	}
	// Reconstruct only this intent's atomic deletions. Missing objects without
	// these journals cannot disappear from the graph or acquire invented bytes.
	rows, err = s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='collection_delete' AND json_extract(data,'$.IntentID')=? ORDER BY id", string(job.Intent.ID))
	if err != nil {
		return nil, "", 0, err
	}
	for rows.Next() {
		var raw []byte
		var deleted collectionDeletion
		var meta api.ObjectMetadata
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, "", 0, err
		}
		if decodeStored(raw, &deleted) != nil || decodeStored([]byte(deleted.Metadata), &meta) != nil || deleted.Result.Action != "remove" || deleted.Result.After.State != "absent" || objects[meta.Ref.ID].Metadata.Ref.ID != "" {
			rows.Close()
			return nil, "", 0, fault(api.CodeIntegrity, "cleanup deletion journal does not match the protected namespace")
		}
		objects[meta.Ref.ID] = graphObject{Metadata: meta, Outbound: deleted.Outbound}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, "", 0, err
	}
	if err := rows.Close(); err != nil {
		return nil, "", 0, err
	}
	refs, selected := map[api.ID]uint64{}, map[api.ID]bool{}
	queries := []string{
		"SELECT data FROM events WHERE json_extract(data,'$.operation_id')<>? ORDER BY seq",
		"SELECT data FROM projection_history WHERE kind<>'collection' AND substr(kind,1,11)<>'collection_' ORDER BY seq",
		"SELECT request FROM receipts WHERE json_extract(operation,'$.id')<>? ORDER BY principal,method,key",
		"SELECT data FROM replies WHERE json_extract(data,'$.Receipt.Operation.id')<>? ORDER BY principal,method,key",
		"SELECT request FROM reservations WHERE operation_id<>? ORDER BY principal,method,key",
		"SELECT data FROM operations WHERE id<>? ORDER BY id",
		"SELECT data FROM effects WHERE operation_id<>? ORDER BY seq",
		"SELECT lease FROM uploads ORDER BY id",
		"SELECT effect_states.data FROM effects JOIN effect_states USING(id) WHERE operation_id<>? ORDER BY effects.seq",
	}
	for _, query := range queries {
		var args []any
		if query != queries[1] && query != queries[7] {
			args = []any{string(op)}
		}
		rows, err := s.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, "", 0, err
		}
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return nil, "", 0, err
			}
			if !json.Valid(raw) {
				rows.Close()
				return nil, "", 0, fault(api.CodeIntegrity, "cleanup reference source is not readable JSON")
			}
			for _, ref := range blobEdges(raw) {
				refs[ref.ID]++
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, "", 0, err
		}
		if err := rows.Close(); err != nil {
			return nil, "", 0, err
		}
	}
	// Required archive closure remains a retention root even if a public
	// receipt does not enumerate its parts, input, result or frozen sources.
	var archiveRaw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='archive_job' AND json_extract(data,'$.Input.receipt_id')=?", string(job.Intent.Archive.ID)).Scan(&archiveRaw); err != nil {
		return nil, "", 0, err
	}
	var archived archiveRecord
	if err := decodeStored(archiveRaw, &archived); err != nil {
		return nil, "", 0, err
	}
	archiveRefs, _, err := s.archiveRefs(ctx, s.db, archived)
	if err != nil {
		return nil, "", 0, err
	}
	if archived.Ack != nil {
		archiveRefs[archived.Ack.Receipt.Result.ID] = archived.Ack.Receipt.Result
	}
	for id := range archiveRefs {
		selected[id] = true
	}
	for id, object := range objects {
		if object.Metadata.ACL.LifeID == job.Intent.Cause.Target.LifeID {
			selected[id] = true
		}
		for _, ref := range object.Outbound {
			refs[ref.ID]++
		}
	}
	// Include foreign and unknown objects reached from the target's own objects.
	skipped := map[[2]api.ID]bool{}
	for changed := true; changed; {
		changed = false
		for id := range selected {
			for _, ref := range objects[id].Outbound {
				if helperRootsEvidence(objects, objects[id], ref) {
					skipped[[2]api.ID{id, ref.ID}] = true
					continue
				}
				if !selected[ref.ID] {
					selected[ref.ID], changed = true, true
				}
			}
		}
	}
	for edge := range skipped {
		journalSkippedRef(job.Intent.Cause.Target.LifeID, edge[0], edge[1])
	}
	limits := archived.Limits
	if limits == (ArchiveLimits{}) {
		limits = s.deps.ArchiveLimits
	}
	limits = limits.resolved(archived.Job.Plan.Budget)
	if len(selected) == 0 || uint64(len(selected)) > limits.CollectionObjects {
		return nil, "", 0, fault(api.CodeBudget, "cleanup requires the complete bounded ownership graph without truncation")
	}
	// Vendor executables are immutable installation files, not SQLite blobs.
	// Keep their edges and include independently measured file identities in
	// the same complete graph. An absent/unrecognized file still fails below.
	if err := s.collectionRuntimeObjects(ctx, objects, selected, archiveRefs, job.Intent.Archive.ID, refs, inventory); err != nil {
		return nil, "", 0, err
	}
	ids := make([]api.ID, 0, len(objects))
	for id := range objects {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	graph := make([]graphObject, 0, len(selected))
	for _, id := range ids {
		if selected[id] {
			graph = append(graph, objects[id])
		}
	}
	rootIdentity := hash([]byte("sqlite-object-root\x00" + string(s.storeID)))
	// Older writers checked InputRefs but did not retain them. Missing historic
	// reference provenance is uncertainty, never evidence of zero references.
	knownInputs := map[api.ID]bool{}
	rows, err = s.db.QueryContext(ctx, "SELECT id FROM projections WHERE kind='object_inputs'")
	if err != nil {
		return nil, "", 0, err
	}
	for rows.Next() {
		var id api.ID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, "", 0, err
		}
		knownInputs[id] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, "", 0, err
	}
	if err := rows.Close(); err != nil {
		return nil, "", 0, err
	}
	result := make([]api.CleanupObject, 0, len(selected))
	for _, id := range ids {
		if !selected[id] {
			continue
		}
		if runtime := objects[id].Runtime; runtime != nil {
			object := *runtime
			result = append(result, object)
			continue
		}
		meta := objects[id].Metadata
		role := "unknown"
		switch meta.Ref.Class {
		case "artifact":
			if knownInputs[id] {
				role = "transient"
			}
		case "task", "prompt", "launch_request", "archive_input", "materialize_input", "launch_spec":
			role = "input"
		case "capture", "transcript":
			role = "capture"
		case "report":
			role = "report"
		case "record":
			role = "event"
		case "manifest", "archive", "worker_result", "policy", "judge_raw", "judge_request":
			role = "history"
		}
		if _, pinned := archiveRefs[id]; pinned && (meta.Ref.Class != "artifact" || knownInputs[id]) {
			role = "archive"
		}
		generation := meta.ACL.Generation
		if meta.ACL.LifeID == "" {
			generation = 0
		}
		result = append(result, api.CleanupObject{Ref: meta.Ref, RootID: s.storeID, RootIdentity: rootIdentity, Identity: objectIdentity(meta), OwnerLifeID: meta.ACL.LifeID, OwnershipGeneration: generation, Role: role, References: refs[id]})
	}
	if len(result) != len(selected) {
		return nil, "", 0, missingCollectionReferences(objects, selected, archiveRefs, job.Intent.Archive.ID)
	}
	// Only selected identities, outgoing edges and their actual global reference
	// counts fence collection. Unrelated lane/capture/history writes remain live.
	encoded, err := collectionJSON(struct {
		Objects   []graphObject
		Inventory []api.CleanupObject
	}{graph, result})
	if err != nil {
		return nil, "", 0, err
	}
	digest := api.Digest(hash(encoded))
	// A content-addressed generation names this exact subgraph, not the global
	// history head. The full digest remains the deciding collision-resistant CAS.
	version, err := strconv.ParseUint(string(digest[:13]), 16, 64)
	if err != nil {
		return nil, "", 0, err
	}
	return result, digest, api.Generation(version + 1), nil
}

// Report only reference classes and opaque IDs, never the containing document
// or missing payload. Sorting keeps the same damaged graph's diagnosis stable.
func missingCollectionReferences(objects map[api.ID]graphObject, selected map[api.ID]bool, archiveRefs map[api.ID]api.BlobRef, archive api.ID) *api.Error {
	edges := map[string]bool{}
	for id := range selected {
		if _, present := objects[id]; present {
			continue
		}
		if ref, archived := archiveRefs[id]; archived {
			edges[fmt.Sprintf("archive:%s -> %s:%s", archive, ref.Class, ref.ID)] = true
		}
	}
	for fromID, from := range objects {
		if !selected[fromID] {
			continue
		}
		for _, ref := range from.Outbound {
			if _, present := objects[ref.ID]; selected[ref.ID] && !present {
				edges[fmt.Sprintf("%s:%s -> %s:%s", from.Metadata.Ref.Class, fromID, ref.Class, ref.ID)] = true
			}
		}
	}
	details := make([]string, 0, len(edges))
	for edge := range edges {
		details = append(details, edge)
	}
	sort.Strings(details)
	return fault(api.CodeIntegrity, fmt.Sprintf("cleanup graph contains a missing referenced object (%s)", strings.Join(details, "; ")))
}

func (s *Service) checkCollectionGraph(ctx context.Context, job api.CleanupJob, r collectionRecord) error {
	objects, graph, generation, err := s.collectionGraph(ctx, job, r.Inventory)
	if err != nil {
		return err
	}
	if r.Inventory == nil || graph != r.Graph || generation != r.Inventory.GraphGeneration || !sameValue(objects, r.Inventory.Objects) {
		return fault(api.CodeConflict, "cleanup complete ownership or reference graph changed")
	}
	return nil
}

// helperRootsEvidence reports a reference to the helper's data-roots evidence (admin data_linux.go: class
// manifest, ID "roots-..."): the helper keeps those bytes and only its reference is embedded in the
// materialize input and launch spec, so it is never a store object to collect. Box 102-103: lane clean
// refused every lane with a workspace on that one external edge. Any other absent reference still refuses.
func helperRootsEvidence(objects map[api.ID]graphObject, from graphObject, ref api.BlobRef) bool {
	_, stored := objects[ref.ID]
	return from.Metadata.Origin == "service" && (from.Metadata.Ref.Class == "materialize_input" || from.Metadata.Ref.Class == "launch_spec") &&
		!stored && ref.Class == "manifest" && strings.HasPrefix(string(ref.ID), "roots-")
}

// journalSkippedRef logs each distinct source/reference edge once per graph
// read, even when two embedding objects share the same helper reference.
func journalSkippedRef(life, from, ref api.ID) {
	data, err := json.Marshal(struct {
		Event string `json:"event"`
		Life  api.ID `json:"life"`
		From  api.ID `json:"from"`
		Ref   api.ID `json:"ref"`
	}{"cleanup_graph_skipped_helper_ref", life, from, ref})
	if err == nil {
		_, _ = os.Stderr.Write(append(data, '\n'))
	}
}
