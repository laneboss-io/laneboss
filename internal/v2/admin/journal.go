package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

type recordReadiness uint8

const (
	storageReady recordReadiness = iota
	storageInitializing
)

// Only allocation/storage initialization may use storageInitializing. Every
// acquisition of existing launch resources uses the default ready requirement.
func (m *leaseManager) findActive(id api.ID, readiness recordReadiness) (leaseRecord, error) {
	record, err := m.find(id)
	if err != nil {
		return leaseRecord{}, err
	}
	if err := m.requireActive(record, readiness); err != nil {
		return leaseRecord{}, err
	}
	return record, nil
}

func (m *leaseManager) requireActive(record leaseRecord, readiness recordReadiness) (resultErr error) {
	defer helperCheck(&resultErr, "active_lease")
	if m.recovery != nil {
		return failure(api.CodeForbidden, "recovery cannot acquire launch resources")
	}
	if record.Revoked || record.BootID != m.bootID || record.Phase != "active" {
		return failure(api.CodeContainmentUnknown, "launch mutation requires a current active unrevoked lease")
	}
	if record.Storage != nil && (record.Storage.Withdrawing || record.Storage.Withdrawn) || record.Archive != nil {
		return failure(api.CodeForbidden, "retained archive storage cannot reacquire writable access")
	}
	if readiness != storageReady && readiness != storageInitializing {
		return failure(api.CodeIntegrity, "unknown storage readiness requirement")
	}
	if record.Storage != nil && (record.Storage.Collecting || record.Storage.Collected) ||
		readiness == storageReady && (record.Storage == nil || !record.Storage.Ready) {
		return failure(api.CodeContainmentUnknown, "launch mutation requires ready uncollected private storage")
	}
	return nil
}

func (m *leaseManager) requireAllocation(record leaseRecord) error {
	if record.Phase == "reserved" {
		record.Phase = "active"
	}
	return m.requireActive(record, storageInitializing)
}

// Every helper-journal write uses this path. Validation sees the complete
// would-be snapshot before the storage backend can publish any bytes.
func (m *leaseManager) save(record leaseRecord) (resultErr error) {
	// Invalidate before any publication attempt, including one which fails
	// after changing storage. All callers own the same operation lock as reads.
	m.containmentSnapshot = nil
	check := "lease_read"
	defer func() { helperCheck(&resultErr, check) }()
	var records []leaseRecord
	var err error
	if m.recovery == nil {
		records, err = m.store.Records()
	} else {
		records = append([]leaseRecord{}, m.recovery.records...)
	}
	if err != nil {
		return err
	}
	found := false
	check = "lease_duplicate"
	for index := range records {
		if records[index].Lease.ID == record.Lease.ID {
			check = "lease_duplicate"
			if found {
				return failure(api.CodeIntegrity, "write selects duplicate lease records")
			}
			if m.recovery != nil {
				check = "lease_recovery_transition"
				if err := recoveryTransition(records[index], record); err != nil {
					return err
				}
			}
			records[index], found = record, true
		}
	}
	if !found {
		records = append(records, record)
	}
	if m.recovery == nil {
		check = "lease_save"
		if _, err := m.validateRecords(records); err != nil {
			return err
		}
	} else {
		check = "lease_recovery_owner"
		if !found || !m.recovery.allowed[record.Lease.ID] {
			return failure(api.CodeIntegrity, "recovery write selects an invalid or ambiguous owner")
		}
		if _, err := m.validateRecords([]leaseRecord{record}); err != nil {
			return err
		}
		check = "lease_recovery_identity"
		if err := validateIdentityScope(records, record.Lease.ID); err != nil {
			return err
		}
	}
	check = "lease_write"
	if err := m.store.Save(record); err != nil {
		return err
	}
	if m.recovery != nil {
		m.recovery.records = records
	}
	return nil
}

type journalRecovery struct {
	records []leaseRecord
	allowed map[api.ID]bool
	issues  []error
}

type recoveryLeaseStore interface {
	Inventory() ([]leaseRecord, []error, error)
}

// The outer stop/revoke reports retained damage after operating on disjoint,
// validated owners. Acquisition and collection never use this scoped view.
func (m *leaseManager) beginRecovery() (func(error) error, error) {
	if m.recovery != nil {
		return func(err error) error { return err }, nil
	}
	var records []leaseRecord
	var issues []error
	var err error
	if store, ok := m.store.(recoveryLeaseStore); ok {
		records, issues, err = store.Inventory()
	} else {
		records, err = m.store.Records()
	}
	if err != nil {
		return nil, err
	}
	state := &journalRecovery{records: records, allowed: map[api.ID]bool{}, issues: issues}
	for _, record := range records {
		if _, err := m.validateRecords([]leaseRecord{record}); err != nil {
			state.issues = append(state.issues, fmt.Errorf("retained invalid helper owner %s: %w", record.Lease.ID, err))
		} else {
			state.allowed[record.Lease.ID] = true
		}
	}
	for _, issue := range dataIdentityIssues(records) {
		state.issues = append(state.issues, failure(api.CodeIntegrity, issue.detail))
		for _, id := range issue.owners {
			delete(state.allowed, id)
		}
	}
	m.recovery = state
	return func(operationErr error) error {
		m.recovery = nil
		if len(state.issues) == 0 {
			return operationErr
		}
		message := fmt.Sprintf("recovery retained %d journal problems; acquisition remains blocked", len(state.issues))
		if operationErr != nil {
			message += "; selected operation: " + operationErr.Error()
		}
		for _, issue := range state.issues {
			if len(message)+len(issue.Error()) > 8192 {
				message += "; additional problems retained in journal"
				break
			}
			message += "; " + issue.Error()
		}
		// The helper transport serializes the first typed error. Keep the
		// bounded damage report first so an operation error cannot hide it.
		return errors.Join(failure(api.CodeIntegrity, message), operationErr, errors.Join(state.issues...))
	}, nil
}

func (m *leaseManager) recoveryRecords() ([]leaseRecord, error) {
	var records []leaseRecord
	for _, record := range m.recovery.records {
		if m.recovery.allowed[record.Lease.ID] {
			data, err := json.Marshal(record)
			if err != nil {
				return nil, failure(api.CodeIntegrity, "cannot retain recovery record comparison")
			}
			var copy leaseRecord
			if err := decodeStrict(data, &copy); err != nil {
				return nil, err
			}
			records = append(records, copy)
		}
	}
	return records, nil
}

func recoveryTransition(before, after leaseRecord) error {
	if len(before.Reviews) != len(after.Reviews) {
		return failure(api.CodeIntegrity, "recovery cannot replace the native review inventory")
	}
	for i := range before.Reviews {
		if err := archiveRecoveryTransition(before.Reviews[i], after.Reviews[i]); err != nil {
			return err
		}
	}
	before.Reviews = after.Reviews
	if err := archiveRecoveryTransition(before.Archive, after.Archive); err != nil {
		return err
	}
	before.Archive = after.Archive
	if err := credentialRecoveryTransition(before.Credentials, after.Credentials); err != nil {
		return err
	}
	before.Credentials = after.Credentials
	if before.Revoked && !after.Revoked || len(before.DataJobs) != len(after.DataJobs) || (before.Gate == nil) != (after.Gate == nil) {
		return failure(api.CodeIntegrity, "recovery cannot restore authority or replace native identity")
	}
	before.Revoked = after.Revoked
	if before.DataJobs != nil {
		before.DataJobs = append([]dataJob{}, before.DataJobs...)
	}
	for index := range before.DataJobs {
		if before.DataJobs[index].State != after.DataJobs[index].State && after.DataJobs[index].State != "revoked" {
			return failure(api.CodeIntegrity, "recovery may only invalidate an existing data job")
		}
		before.DataJobs[index].State = after.DataJobs[index].State
	}
	if before.Gate != nil {
		gate := *before.Gate
		before.Gate = &gate
		if gate.Stop != nil && !reflect.DeepEqual(gate.Stop, after.Gate.Stop) {
			return failure(api.CodeIntegrity, "recovery cannot replace a committed native stop fence")
		}
		before.Gate.Stop = after.Gate.Stop
		if gate.State != after.Gate.State && !(gate.State == "opened" && after.Gate.State == "ended") {
			return failure(api.CodeIntegrity, "recovery may only observe a terminal gate")
		}
		before.Gate.State, before.Gate.Observation = after.Gate.State, after.Gate.Observation
	}
	if !reflect.DeepEqual(before, after) {
		return failure(api.CodeIntegrity, "recovery write changed retained launch identity or inputs")
	}
	return nil
}
