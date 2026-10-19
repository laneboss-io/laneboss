//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/rscan"
)

func (m *leaseManager) prepareCredentials(ctx context.Context, input credentialPrepare, prepared api.PreparedLaunch) error {
	record, err := m.findActive(input.Request.LeaseID, storageReady)
	if err != nil {
		return err
	}
	if record.Spec == nil || !credentialRequired(record.Spec.Handoff.Spec) {
		return nil
	}
	if m.credentials == nil {
		return failure(api.CodeUnavailable, "native credential projection receiver is not bound")
	}
	if record.Gate == nil || record.Gate.Prepared != prepared || record.Storage == nil {
		return failure(api.CodeIntegrity, "credential preparation lost its exact native gate or home")
	}
	if record.Credentials != nil {
		if record.Credentials.Record == nil {
			return failure(api.CodeContainmentUnknown, "credential transfer is uncertain; replacement export is forbidden")
		}
		held := m.credentials.held[record.Credentials.Record.Authority.ID]
		if held == nil || held.record.Receipt == nil {
			return failure(api.CodeContainmentUnknown, "credential ownership was lost; retain the original projection")
		}
		if _, err := m.credentials.observe(ctx, held.record.Authority.ID); err != nil {
			return err
		}
		if record.Credentials.State == "held" {
			return nil
		}
		if record.Credentials.State != "receiving" {
			return failure(api.CodeForbidden, "credential projection is fenced")
		}
		return m.acknowledgeCredentials(ctx, &record, held)
	}
	q := api.CredentialProjectionRequest{Cause: input.Request.Cause, Claim: input.Claim, Handoff: record.Spec.Handoff, Prepared: prepared, Lease: record.Lease, Home: record.Storage.Binding.Home}
	if q.Handoff.Spec.Kind == "worker" {
		selector, ok := m.credentials.identity.(api.CredentialWorkerSelector)
		if !ok || !nonnilCredentialClient(selector) {
			return failure(api.CodePrerequisite, "credential worker requires its protected native job selector")
		}
		selected, err := selector.SelectCredentialWorker(ctx, q.Handoff)
		if err != nil {
			return err
		}
		q.Worker, q.WorkerCredentials = &selected.Lease, selected.Credentials
	}
	if err := api.ValidateCredentialProjectionRequest(q, time.Now()); err != nil {
		return err
	}
	record.Credentials = &credentialJournal{State: "receiving", Request: &q}
	if err := m.save(record); err != nil {
		return err
	}
	reserver, canReserve := m.credentials.broker.(api.CredentialProjectionReservationBroker)
	if canReserve {
		reserved, err := reserver.ReserveCredentials(ctx, m.credentials.peer, q)
		if err != nil {
			return err
		}
		if reserved.State != "reserved" || reserved.Receipt != nil || reserved.Fence != nil || !reflect.DeepEqual(reserved.Authority.Request, q) {
			return failure(api.CodeIntegrity, "credential reservation changed the original native request")
		}
		record.Credentials.Record = &reserved
		if err := m.save(record); err != nil {
			return err
		}
	}
	authority, err := m.credentials.identity.AuthorizeCredentialProjection(ctx, m.credentials.peer, q)
	if err != nil {
		return err
	}
	if !canReserve {
		return failure(api.CodePrerequisite, "credential prepare requires its native reservation port")
	}
	if !reflect.DeepEqual(authority.Request, q) || record.Credentials.Record == nil || !reflect.DeepEqual(record.Credentials.Record.Authority, authority) {
		return failure(api.CodeUnauthenticated, "credential authorizer changed the retained request or reservation")
	}
	reserved := api.CredentialProjectionRecord{State: "reserved", Authority: authority, Generation: authority.Generation}
	record.Credentials.Record = &reserved
	if err := m.save(record); err != nil {
		return err
	}
	transfer, err := m.credentials.broker.TransferCredentials(ctx, m.credentials.peer, q)
	if err != nil {
		return errors.Join(err, closeCredentialFiles(transfer.Files))
	}
	if !reflect.DeepEqual(authority, transfer.Authority) {
		return errors.Join(failure(api.CodeUnauthenticated, "credential transfer differs from independent identity authority"), closeCredentialFiles(transfer.Files))
	}
	if _, err := m.credentials.project(ctx, transfer); err != nil {
		return err
	}
	held := m.credentials.held[authority.ID]
	record.Credentials.Record = &held.record
	if err := m.save(record); err != nil {
		return err
	}
	return m.acknowledgeCredentials(ctx, &record, held)
}

func (m *leaseManager) acknowledgeCredentials(ctx context.Context, record *leaseRecord, held *heldCredentials) error {
	if held.record.Receipt == nil {
		return failure(api.CodeIntegrity, "credential acknowledgement precedes holding")
	}
	observed, err := m.credentials.observe(ctx, held.record.Authority.ID)
	if err != nil {
		return err
	}
	if err := credentialAcknowledgementReady(held, observed); err != nil {
		return err
	}
	committed, err := m.credentials.broker.AcknowledgeCredentials(ctx, *held.record.Receipt)
	if err != nil {
		return err
	}
	if committed.State != "held" || committed.Generation != held.record.Authority.Generation+1 || !reflect.DeepEqual(committed.Authority, held.record.Authority) || !reflect.DeepEqual(committed.Receipt, held.record.Receipt) || committed.Fence != nil || committed.Withdrawal != nil {
		return failure(api.CodeIntegrity, "credential acknowledgement changed the exact held receipt")
	}
	held.record = committed
	record.Credentials = &credentialJournal{State: "held", Record: &committed, Request: record.Credentials.Request, Stop: record.Credentials.Stop}
	return m.save(*record)
}

func credentialAcknowledgementReady(held *heldCredentials, observed api.CredentialProjectionReceipt) error {
	if held.record.Receipt == nil || !reflect.DeepEqual(observed.Targets, held.record.Receipt.Targets) || observed.HeldDescriptors == nil || *observed.HeldDescriptors != uint64(len(held.files)) || observed.InheritedSources == nil || *observed.InheritedSources != 0 {
		return failure(api.CodeIntegrity, "credential acknowledgement lost its measured objects")
	}
	return nil
}

func (m *leaseManager) lockCredentials(ctx context.Context, registration gateOpenRegistration) (api.CredentialGateGuard, error) {
	record, err := m.findActive(registration.Binding.Record.UIDLeaseID, storageReady)
	if err != nil {
		return nil, err
	}
	if record.Spec == nil || !credentialRequired(record.Spec.Handoff.Spec) {
		return nil, nil
	}
	if m.credentials == nil || record.Credentials == nil || record.Credentials.State != "held" || record.Credentials.Record == nil {
		return nil, failure(api.CodeContainmentUnknown, "open has no acknowledged native credential projection")
	}
	projection := *record.Credentials.Record
	guard, err := m.credentials.broker.LockCredentialProjection(ctx, api.CredentialGateRequest{ProjectionID: projection.Authority.ID, ExpectedGeneration: projection.Generation, Open: registration.Request})
	if err != nil {
		return nil, err
	}
	if guard == nil {
		return nil, failure(api.CodeIntegrity, "credential broker returned no live guard")
	}
	if !reflect.DeepEqual(guard.Projection(), projection) {
		guard.Close()
		return nil, failure(api.CodeForbidden, "credential guard selected a different protected record")
	}
	if err := api.ValidateCredentialGateRequest(projection, api.CredentialGateRequest{ProjectionID: projection.Authority.ID, ExpectedGeneration: projection.Generation, Open: registration.Request}, registration.Binding, time.Now()); err != nil {
		guard.Close()
		return nil, err
	}
	if err := guard.Check(ctx); err != nil {
		guard.Close()
		return nil, err
	}
	if _, err := m.credentials.observe(ctx, projection.Authority.ID); err != nil {
		guard.Close()
		return nil, err
	}
	return guard, nil
}

func (r *credentialRuntime) stopped(ctx context.Context, record leaseRecord) (api.ProcessObservation, error) {
	if record.Gate == nil || record.Spec == nil {
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "credential withdrawal lost its original gate")
	}
	live := r.manager.gates[record.Lease.ID]
	if live == nil {
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "credential withdrawal lost native wait ownership")
	}
	if err := r.manager.killContainment(ctx, record); err != nil {
		return api.ProcessObservation{}, err
	}
	if err := live.Close(); err != nil {
		return api.ProcessObservation{}, err
	}
	if err := stopAndWait(ctx, live, gateHandle(record), func() error { return r.manager.waitContainmentEmpty(ctx, record) }); err != nil {
		return api.ProcessObservation{}, err
	}
	observation, err := live.Observe(ctx, gateHandle(record))
	if err != nil {
		return observation, err
	}
	if observation.State != "exited" {
		return observation, failure(api.CodeContainmentUnknown, "credential withdrawal still has a running process")
	}
	if err := r.manager.resources.Quiescent(ctx, record); err != nil {
		return observation, err
	}
	zero := uint64(0)
	observation.Survivors = &zero
	return observation, nil
}

func (r *credentialRuntime) collectRefresh(ctx context.Context, p api.CredentialProjectionRecord) (api.CredentialRefresh, error) {
	held := r.held[p.Authority.ID]
	if held == nil {
		return api.CredentialRefresh{}, failure(api.CodeContainmentUnknown, "credential refresh lost original held objects")
	}
	q := p.Authority.Request
	if p.State != "withdrawing" || p.Fence == nil || p.Fence.Reason != "release" || q.Handoff.Spec.Runner == nil || q.Handoff.Spec.Runner.Slot.Mode != "codex-file" {
		return api.CredentialRefresh{}, failure(api.CodeForbidden, "only normal fenced Codex release may return refresh")
	}
	record, err := r.manager.find(q.Lease.ID)
	if err != nil {
		return api.CredentialRefresh{}, err
	}
	if record.Revoked {
		return api.CredentialRefresh{}, failure(api.CodeForbidden, "revoked containment requires credential rotation, not canonical refresh")
	}
	if held.refresh != nil {
		return *held.refresh, nil
	}
	observation, err := r.stopped(ctx, record)
	if err != nil {
		return api.CredentialRefresh{}, err
	}
	for i, target := range p.Authority.Targets {
		if target.SlotID != q.Handoff.Spec.Runner.Slot.ID {
			continue
		}
		parent, base, err := dataEntryParent(held.home, target.RelativePath)
		if err != nil {
			return api.CredentialRefresh{}, err
		}
		_, st, err := credentialObject(held.files[i])
		var actual unix.Stat_t
		statErr := unix.Fstatat(int(parent.Fd()), base, &actual, unix.AT_SYMLINK_NOFOLLOW)
		parent.Close()
		if err != nil || statErr != nil || st.Dev != actual.Dev || st.Ino != actual.Ino || st.Nlink != 1 || st.Uid != q.Lease.UID || st.Mode&07777 != 0600 || st.Size <= 0 || st.Size > api.MaxFrameBytes {
			return api.CredentialRefresh{}, failure(api.CodeContainmentUnknown, "Codex refresh object was replaced or aliased; rotation is required")
		}
		export, err := anonymousCredential(ctx, held.files[i], st.Size)
		if err != nil {
			return api.CredentialRefresh{}, err
		}
		fact, err := credentialDescriptor(export, true)
		if err != nil {
			export.Close()
			return api.CredentialRefresh{}, err
		}
		refresh := api.CredentialRefresh{ProjectionID: p.Authority.ID, ExpectedGeneration: p.Generation, SlotID: target.SlotID, Observation: observation, Fact: fact, File: export}
		for _, source := range p.Authority.Sources {
			if source.Key == target.SlotID {
				refresh.ExpectedSourceGeneration = source.Generation
			}
		}
		if err := api.ValidateCredentialRefresh(p, refresh, time.Now()); err != nil {
			export.Close()
			return refresh, err
		}
		held.export, held.refresh = export, &refresh
		return refresh, nil
	}
	return api.CredentialRefresh{}, failure(api.CodeIntegrity, "Codex projection has no held slot object")
}

func (r *credentialRuntime) withdraw(ctx context.Context, p api.CredentialProjectionRecord) (api.CredentialWithdrawalReceipt, error) {
	held := r.held[p.Authority.ID]
	if held == nil || p.State != "withdrawing" || p.Fence == nil || !reflect.DeepEqual(held.record.Authority, p.Authority) {
		return api.CredentialWithdrawalReceipt{}, failure(api.CodeContainmentUnknown, "credential withdrawal has no exact fenced native holding")
	}
	if len(held.files) != len(p.Authority.Targets) || len(held.destinations) != len(p.Authority.Targets) {
		return api.CredentialWithdrawalReceipt{}, failure(api.CodeContainmentUnknown, "partial credential projection requires owner reconciliation")
	}
	record, err := r.manager.find(p.Authority.Request.Lease.ID)
	if err != nil {
		return api.CredentialWithdrawalReceipt{}, err
	}
	observation, err := r.stopped(ctx, record)
	if err != nil {
		return api.CredentialWithdrawalReceipt{}, err
	}
	executed := record.Gate.Permit != nil || record.Gate.Open != nil
	receipt := api.CredentialWithdrawalReceipt{ProjectionID: p.Authority.ID, Generation: p.Generation + 1, Cause: p.Fence.Cause, Prepared: p.Authority.Request.Prepared, HelperLeaseID: record.Lease.ID, Home: p.Authority.Request.Home, Observation: observation,
		AgentExecuted: &executed, RotationRequired: executed && (p.Fence.Reason != "release" || record.Revoked), ObservedAt: gateTimestamp()}
	if held.cleanup != nil && reflect.DeepEqual(held.record, p) {
		return *held.cleanup, nil
	}
	key, err := releaseAPIKeyMaterial(held, p)
	if err != nil {
		return receipt, err
	}
	defer clear(key)
	for _, file := range held.files {
		if file == nil {
			continue
		}
		_, st, err := credentialObject(file)
		if err != nil {
			return receipt, err
		}
		if st.Nlink > 1 {
			return receipt, failure(api.CodeContainmentUnknown, "projected credential has unresolved aliases; rotate and retain ownership")
		}
		held.inventory = append(held.inventory, storageInode{Device: uint64(st.Dev), Inode: st.Ino})
	}
	if held.export != nil {
		return receipt, failure(api.CodeContainmentUnknown, "credential refresh export has not been acknowledged")
	}
	var projected uint64
	for i, target := range p.Authority.Targets {
		if target.Delivery != "file" {
			continue
		}
		parent, base, err := dataEntryParent(held.home, target.RelativePath)
		if err != nil {
			return receipt, err
		}
		var st unix.Stat_t
		err = unix.Fstatat(int(parent.Fd()), base, &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || uint64(st.Dev) != held.destinations[i].Device || st.Ino != held.destinations[i].Inode {
				parent.Close()
				return receipt, failure(api.CodeContainmentUnknown, "credential replacement cannot be safely collected; rotate and retain ownership")
			}
			if err := unix.Unlinkat(int(parent.Fd()), base, 0); err != nil {
				parent.Close()
				return receipt, failure(api.CodeContainmentUnknown, "credential name removal is uncertain")
			}
		} else if !errors.Is(err, unix.ENOENT) {
			parent.Close()
			return receipt, failure(api.CodeContainmentUnknown, "credential name is unreadable during withdrawal")
		}
		if held.files[i] != nil {
			_, actual, e := credentialObject(held.files[i])
			if e != nil || actual.Nlink != 0 {
				parent.Close()
				return receipt, failure(api.CodeContainmentUnknown, "credential inode has a renamed or unresolved alias; rotation is required")
			}
		}
		if err := unix.Fstatat(int(parent.Fd()), base, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			projected++
		} else if !errors.Is(err, unix.ENOENT) {
			parent.Close()
			return receipt, failure(api.CodeContainmentUnknown, "credential removal read-back failed")
		}
		parent.Close()
	}
	for i, file := range held.files {
		if file != nil {
			if err := file.Close(); err != nil {
				return receipt, failure(api.CodeContainmentUnknown, "credential descriptor close is uncertain")
			}
			held.files[i] = nil
		}
	}
	references, err := scanStorageReferences(ctx, storageBase(r.manager.binding, record), held.inventory)
	if err != nil || references != 0 {
		if err != nil {
			return receipt, err
		}
		return receipt, failure(api.CodeContainmentUnknown, "credential objects still have native references")
	}
	var descriptors, buffers uint64
	inherited, err := inheritedCredentialSources(held.sourceHandles)
	if err != nil || inherited != 0 {
		return receipt, errors.Join(err, failure(api.CodeContainmentUnknown, "credential cleanup retained source descriptors"))
	}
	for i, file := range held.files {
		if file != nil {
			descriptors++
			if p.Authority.Targets[i].Delivery == "env" {
				buffers++
			}
		}
	}
	native, ok := r.manager.gates[record.Lease.ID].(*nativeGate)
	if !ok {
		return receipt, failure(api.CodeContainmentUnknown, "credential cleanup has no native gate inventory")
	}
	native.mu.Lock()
	open := uint64(0)
	if native.release != nil {
		open++
	}
	native.mu.Unlock()
	receipt.HelperDescriptors = &descriptors
	receipt.ProjectedFiles = &projected
	receipt.EnvironmentBuffers = &buffers
	receipt.OpenGates = &open
	if descriptors != 0 || projected != 0 || buffers != 0 || open != 0 {
		return receipt, failure(api.CodeContainmentUnknown, "credential withdrawal retained helper material")
	}
	if len(key) != 0 {
		scan, err := r.manager.scanReleaseAPIKey(ctx, record, p, key)
		if err != nil {
			return receipt, err
		}
		held.releaseScan = &rscan.NativeReleaseScan{Authority: p.Authority, Cause: p.Fence.Cause, Scan: scan}
	}
	held.record = p
	held.cleanup = &receipt
	return receipt, nil
}

func (m *leaseManager) withdrawProjection(ctx context.Context, record *leaseRecord, cause api.InternalIntent, reason string) error {
	m.credentialLeaseMu.Lock()
	defer m.credentialLeaseMu.Unlock()
	if record.Credentials == nil {
		return nil
	}
	if record.Credentials.State == "withdrawn" {
		return journalCredentialRotation(ctx, record.Credentials.Record)
	}
	if m.credentials == nil || record.Credentials.Record == nil {
		return failure(api.CodeContainmentUnknown, "uncertain credential transfer requires protected owner reconciliation and rotation")
	}
	if reason == "revoked" {
		if err := m.fenceStopped(record, cause, reason); err != nil {
			return err
		}
	}
	if stop := record.Credentials.Stop; stop != nil {
		cause, reason = stop.Cause, stop.Reason
	}
	p := *record.Credentials.Record
	revoked := p.Revoked || p.Authority.Revoked || p.Fence != nil && p.Fence.Reason == "revoked"
	if p.State != "withdrawing" || reason == "revoked" && !revoked {
		if p.Fence != nil {
			cause = p.Fence.Cause
		}
		q := api.CredentialWithdrawalRequest{ProjectionID: p.Authority.ID, ExpectedGeneration: p.Generation, Cause: cause, Reason: reason}
		if err := api.ValidateCredentialWithdrawalRequest(p, q); err != nil {
			return err
		}
		fenced, err := m.credentials.broker.BeginCredentialWithdrawal(ctx, q)
		if err != nil {
			return err
		}
		prior := p.PriorFence
		if p.State == "withdrawing" {
			prior = p.Fence
		}
		if fenced.State != "withdrawing" || fenced.Generation != p.Generation+1 || fenced.Fence == nil || *fenced.Fence != q || fenced.Revoked != (p.Revoked || reason == "revoked") || !reflect.DeepEqual(fenced.PriorFence, prior) || !reflect.DeepEqual(fenced.Authority, p.Authority) || !reflect.DeepEqual(fenced.Receipt, p.Receipt) || fenced.Withdrawal != nil {
			return failure(api.CodeIntegrity, "credential owner changed its withdrawal fence")
		}
		p = fenced
		record.Credentials = &credentialJournal{State: "withdrawing", Record: &p, Request: record.Credentials.Request, Stop: record.Credentials.Stop}
		if err := m.save(*record); err != nil {
			return err
		}
	}
	held := m.credentials.held[p.Authority.ID]
	if held == nil {
		return failure(api.CodeContainmentUnknown, "withdrawal lost its original native objects")
	}
	if p.Fence.Reason == "release" && !record.Revoked && p.Authority.Request.Handoff.Spec.Runner != nil && p.Authority.Request.Handoff.Spec.Runner.Slot.Mode == "codex-file" && record.Credentials.Refresh == nil {
		refresh, err := m.credentials.collectRefresh(ctx, p)
		if err != nil {
			return err
		}
		version, err := m.credentials.acceptCredentialRefresh(ctx, refresh)
		if err != nil {
			return err
		}
		journal := *record.Credentials
		journal.Refresh = &version
		record.Credentials = &journal
		if err := m.save(*record); err != nil {
			return err
		}
		if err := held.export.Close(); err != nil {
			return failure(api.CodeContainmentUnknown, "refresh export close is uncertain")
		}
		held.export = nil
	}
	if record.Credentials.Refresh != nil && held.export != nil {
		if err := held.export.Close(); err != nil {
			return failure(api.CodeContainmentUnknown, "refresh export close is uncertain")
		}
		held.export = nil
	}
	receipt, err := m.credentials.withdraw(ctx, p)
	if err != nil {
		return err
	}
	completed, err := m.credentials.broker.FinishCredentialWithdrawal(rscan.WithNativeReleaseScan(ctx, held.releaseScan), p, receipt)
	if err != nil {
		return err
	}
	if completed.State != "withdrawn" || completed.Generation != receipt.Generation || completed.Revoked != p.Revoked || !reflect.DeepEqual(completed.PriorFence, p.PriorFence) || !reflect.DeepEqual(completed.Authority, p.Authority) || !reflect.DeepEqual(completed.Receipt, p.Receipt) || !reflect.DeepEqual(completed.Fence, p.Fence) || completed.Withdrawal == nil {
		return failure(api.CodeIntegrity, "credential withdrawal completion changed its protected record")
	}
	if err := api.ValidateCredentialWithdrawal(p, *completed.Withdrawal); err != nil {
		return err
	}
	if !sameHelperWithdrawal(*completed.Withdrawal, receipt) {
		return failure(api.CodeIntegrity, "credential owner replaced helper cleanup observations")
	}
	record.Credentials = &credentialJournal{State: "withdrawn", Record: &completed, Refresh: record.Credentials.Refresh, Request: record.Credentials.Request, Stop: record.Credentials.Stop}
	if err := m.save(*record); err != nil {
		return err
	}
	if err := held.home.Close(); err != nil {
		return failure(api.CodeContainmentUnknown, "credential holding root close failed")
	}
	delete(m.credentials.held, p.Authority.ID)
	return journalCredentialRotation(ctx, &completed)
}

// Publish the durable rotation requirement to the installed helper journal.
// Values and private selectors never enter this notice. A journal failure can
// retry from the same withdrawn record without repeating native collection.
func journalCredentialRotation(ctx context.Context, record *api.CredentialProjectionRecord) error {
	if record == nil || record.State != "withdrawn" || record.Withdrawal == nil || !record.Withdrawal.RotationRequired {
		return nil
	}
	var writer io.Writer = os.Stderr
	if trace, _ := ctx.Value(helperTimingKey{}).(*helperRequestTrace); trace != nil && trace.timing != nil {
		writer = trace.timing
	}
	data, err := json.Marshal(struct {
		Event            string `json:"event"`
		State            string `json:"state"`
		RotationRequired bool   `json:"rotation_required"`
	}{"credential_withdrawn", record.State, record.Withdrawal.RotationRequired})
	if err != nil {
		return errors.Join(errHelperJournal, err)
	}
	data = append(data, '\n')
	n, err := writer.Write(data)
	if err != nil || n != len(data) {
		return errors.Join(errHelperJournal, err)
	}
	return nil
}

func sameHelperWithdrawal(completed, measured api.CredentialWithdrawalReceipt) bool {
	completed.BrokerDescriptors = nil
	completed.RefreshLeases = nil
	measured.BrokerDescriptors = nil
	measured.RefreshLeases = nil
	return reflect.DeepEqual(completed, measured)
}

func (r *credentialRuntime) acceptCredentialRefresh(ctx context.Context, refresh api.CredentialRefresh) (api.CredentialSourceVersion, error) {
	version, err := r.broker.AcceptCredentialRefresh(ctx, r.peer, refresh)
	if err != nil {
		return version, err
	}
	if version.Key != refresh.SlotID || version.Revoked || version.Generation <= refresh.ExpectedSourceGeneration || version.Version == "" {
		return api.CredentialSourceVersion{}, failure(api.CodeIntegrity, "credential owner returned an invalid canonical refresh receipt")
	}
	return version, nil
}
