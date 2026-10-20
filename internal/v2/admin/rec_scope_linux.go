//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"

	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) restoreRoots(ctx context.Context, raw json.RawMessage) ([]string, error) {
	var q restoreRootQuery
	if err := decodeStrict(raw, &q); err != nil {
		return nil, err
	}
	if q.Actor.Kind != "human" && q.Actor.Kind != "lane" || !validID(q.Actor.ID) || q.Actor.Kind == "lane" && (!validID(q.Actor.LifeID) || !validID(q.LaunchID)) {
		return nil, failure(api.CodeForbidden, "restore_target_scope")
	}
	records, err := m.records()
	if err != nil {
		return nil, err
	}
	roots := []string{}
	for _, r := range records {
		if q.Actor.Kind == "lane" && (r.Request.LifeID != q.Actor.LifeID || len(r.LaunchAllocations) == 0 || r.LaunchAllocations[len(r.LaunchAllocations)-1].Reservation.LaunchID != q.LaunchID) {
			continue
		}
		// Only currently writable lane workspaces qualify. A retained archive
		// cannot become a destination, and no withdrawal gate is bypassed.
		if r.Revoked || r.BootID != m.bootID || r.Phase != "active" || r.Archive != nil || r.Storage == nil || !r.Storage.Ready || r.Storage.Withdrawn || r.Storage.Withdrawing || r.Storage.Collecting || r.Storage.Collected || r.Storage.Workspace == nil || r.Storage.Workspace.Phase != "published" {
			continue
		}
		if err := m.requireActive(r, storageReady); err != nil {
			return nil, err
		}
		name := filepath.Join(storageBase(m.binding, r), string(r.Storage.Binding.WorkspaceID))
		root, err := archiveRoot(name)
		if err != nil {
			return nil, err
		}
		identity, _, err := dataIdentity(root)
		closeErr := root.Close()
		if err != nil || closeErr != nil || identity != r.Storage.Workspace.Enrollment.Workspace.DirectoryIdentity {
			return nil, failure(api.CodeIntegrity, "restore workspace root identity changed")
		}
		roots = append(roots, name)
	}
	sort.Strings(roots)
	return roots, nil
}
