//go:build !linux

package admin

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

func (m *leaseManager) dispatchArchiveStorage(context.Context, string, json.RawMessage) (any, error) {
	return nil, failure(api.CodeUnsupported, "native archive storage requires Linux")
}
func (m *leaseManager) dispatchCleanup(context.Context, string, json.RawMessage) (any, error) {
	return nil, failure(api.CodeUnsupported, "native workspace and Git collection requires Linux")
}
func (m *leaseManager) retainPrivateStorage(context.Context, *leaseRecord) error {
	return failure(api.CodeUnsupported, "retained storage withdrawal requires Linux")
}
func (m *leaseManager) archiveParent(archivejob.Intent) (leaseRecord, error) {
	return leaseRecord{}, failure(api.CodeUnsupported, "native archive journal requires Linux")
}
func (m *leaseManager) checkArchive(context.Context, archiveQuery) (archiveHeader, error) {
	return archiveHeader{}, failure(api.CodeUnsupported, "native archive fence requires Linux")
}
func (m *leaseManager) startArchiveGate(context.Context, leaseRecord, archiveWorker) (ownedGate, error) {
	return nil, failure(api.CodeUnsupported, "native archive worker gate requires Linux")
}
func (s *Service) bindArchiveContainment(context.Context, archiveReg) error {
	return failure(api.CodeUnsupported, "native archive containment requires Linux")
}

func (m *leaseManager) retireArchive(context.Context, archiveRetireQuery) (archivejob.Retirement, error) {
	return archivejob.Retirement{}, failure(api.CodeUnsupported, "native archive retirement requires Linux")
}
