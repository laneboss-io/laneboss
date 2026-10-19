package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// The file store can identify a journal generation without decoding its JSON.
// Other stores retain full validation on every request. No time-based lifetime
// is involved, and neither a helper restart nor recovery can reuse this view.
type containmentGenerationStore interface {
	ContainmentGeneration() ([32]byte, error)
}

type containmentRecordSnapshot struct {
	generation [32]byte
	records    []leaseRecord
}

// Only containmentRecord may consume this immutable view under operationMu.
// Normal records/find/save paths always decode their own objects, so mutating
// a nested pointer or slice there cannot change a previously validated view.
// This caches journal decoding only: containment still pins the live cgroup,
// and the service/verifier still check UID, pidfd, generation and membership.
func (m *leaseManager) containmentRecords(ctx context.Context) (_ []leaseRecord, resultErr error) {
	defer helperCheck(&resultErr, "lease_records")
	store, ok := m.store.(containmentGenerationStore)
	if !ok || m.recovery != nil {
		m.containmentSnapshot = nil
		return m.recordsContext(ctx)
	}
	generation := func() ([32]byte, error) {
		defer helperStage(ctx, "journal_generation")()
		return store.ContainmentGeneration()
	}
	before, err := generation()
	if err != nil {
		m.containmentSnapshot = nil
		return nil, err
	}
	if snapshot := m.containmentSnapshot; snapshot != nil && snapshot.generation == before {
		return snapshot.records, nil
	}
	m.containmentSnapshot = nil
	records, err := m.recordsContext(ctx)
	if err != nil {
		return nil, err
	}
	after, err := generation()
	if err != nil {
		return nil, err
	}
	if before != after {
		return nil, failure(api.CodeIntegrity, "helper journal changed during containment validation")
	}
	m.containmentSnapshot = &containmentRecordSnapshot{generation: after, records: records}
	return records, nil
}
