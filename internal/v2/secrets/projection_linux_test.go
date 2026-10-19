//go:build linux

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
	"laneboss.io/laneboss/internal/v2/runner/codex"
)

// This is a post-authentication consumer model. Kernel export/seal/SCM bytes
// are real; helper ownership/holding observations are typed correlation facts.
// It does not prove an authenticated root helper or actual lane projection.
type projectionModel struct {
	c *launchCase
	api.CredentialProjectionIdentity
	a           api.CredentialProjectionAuthority
	held        api.CredentialProjectionReceipt
	withdrawal  api.CredentialWithdrawalReceipt
	effects     map[api.ID]api.EffectRecord
	open        api.HelperOpenRequest
	omitCommit  bool
	identityErr error
}
type projectionStore struct {
	*launchCaseStore
	m *projectionModel
}
type projectionHelper struct {
	*launchCaseHelper
	m *projectionModel
}
type projectionControl struct {
	*launchCaseControl
	m *projectionModel
}

func (m *projectionModel) AuthorizeCredentialProjection(_ context.Context, _ api.VerifiedPeer, r api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error) {
	if m.identityErr != nil {
		return api.CredentialProjectionAuthority{}, m.identityErr
	}
	if !reflect.DeepEqual(m.a.Request, r) {
		return api.CredentialProjectionAuthority{}, api.NotImplemented("lb-v2-identity", "fixture request is not the retained native projection")
	}
	return m.a, nil
}
func (m *projectionModel) CheckLaunchCredentials(context.Context, api.LaunchBindingRequest) (api.CredentialProjectionRecord, error) {
	return api.CredentialProjectionRecord{}, api.NotImplemented("lb-v2-identity", "fixture has no identity permit producer")
}
func (s *projectionStore) CurrentApprovedPolicy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	return s.Policy(ctx, scope)
}
func (s *projectionStore) Effect(ctx context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	if value, ok := s.m.effects[id]; ok {
		return value, nil
	}
	return s.launchCaseStore.Effect(ctx, scope, id)
}
func (s *projectionStore) CredentialProjection(_ context.Context, config string, prepared api.ID) (api.CredentialProjectionRecord, error) {
	var r api.CredentialProjectionRecord
	if config != s.m.a.Request.Handoff.Config || prepared != s.m.a.Request.Prepared.ID {
		return r, &api.Error{Code: api.CodeNotFound}
	}
	err := s.read("projection-record.json", &r)
	return r, err
}
func (s *projectionStore) ReserveCredentialProjection(ctx context.Context, _ api.Scope, request api.CredentialProjectionRequest) (api.CredentialProjectionRecord, error) {
	if err := api.ValidateCredentialProjectionRequest(request, s.m.c.clock.Now()); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	prior, err := s.CredentialProjection(ctx, s.m.a.Request.Handoff.Config, request.Prepared.ID)
	if err == nil {
		if !reflect.DeepEqual(prior.Authority.Request, request) {
			return prior, &api.Error{Code: api.CodeConflict}
		}
		return prior, nil
	}
	if !hasCode(err, api.CodeNotFound) {
		return prior, err
	}
	if !reflect.DeepEqual(request, s.m.a.Request) {
		return prior, &api.Error{Code: api.CodeForbidden}
	}
	r := api.CredentialProjectionRecord{Authority: s.m.a, Generation: s.m.a.Generation, State: "reserved"}
	return r, s.save("projection-record.json", r)
}
func (s *projectionStore) CommitCredentialProjection(ctx context.Context, _ api.Scope, receipt api.CredentialProjectionReceipt) (api.CredentialProjectionRecord, error) {
	r, err := s.CredentialProjection(ctx, s.m.a.Request.Handoff.Config, receipt.Prepared.ID)
	if err != nil {
		return r, err
	}
	if r.State != "reserved" || receipt.ProjectionID != r.Authority.ID || receipt.Generation != r.Generation+1 {
		return r, &api.Error{Code: api.CodeConflict}
	}
	r.State, r.Generation, r.Receipt = "held", receipt.Generation, &receipt
	if s.m.omitCommit {
		return r, nil
	}
	return r, s.save("projection-record.json", r)
}
func (s *projectionStore) FenceCredentialProjection(ctx context.Context, _ api.Scope, request api.CredentialWithdrawalRequest) (api.CredentialProjectionRecord, error) {
	r, err := s.CredentialProjection(ctx, s.m.a.Request.Handoff.Config, s.m.a.Request.Prepared.ID)
	if err != nil {
		return r, err
	}
	if err := api.ValidateCredentialWithdrawalRequest(r, request); err != nil {
		return r, err
	}
	if r.State == "withdrawing" {
		r.PriorFence = r.Fence
	}
	r.State, r.Generation, r.Fence = "withdrawing", r.Generation+1, &request
	r.Revoked = r.Revoked || request.Reason == "revoked"
	return r, s.save("projection-record.json", r)
}
func (s *projectionStore) CompleteCredentialWithdrawal(ctx context.Context, _ api.Scope, receipt api.CredentialWithdrawalReceipt) (api.CredentialProjectionRecord, error) {
	r, err := s.CredentialProjection(ctx, s.m.a.Request.Handoff.Config, s.m.a.Request.Prepared.ID)
	if err != nil {
		return r, err
	}
	if err := api.ValidateCredentialWithdrawal(r, receipt); err != nil {
		return r, err
	}
	r.State, r.Generation, r.Withdrawal = "withdrawn", receipt.Generation, &receipt
	return r, s.save("projection-record.json", r)
}
func (h *projectionHelper) ObserveCredentials(_ context.Context, id api.ID) (api.CredentialProjectionReceipt, error) {
	if id != h.m.held.ProjectionID {
		return api.CredentialProjectionReceipt{}, &api.Error{Code: api.CodeNotFound}
	}
	var receipt api.CredentialProjectionReceipt
	err := h.store.read("projection-held.json", &receipt)
	return receipt, err
}
func (h *projectionHelper) WithdrawCredentials(_ context.Context, r api.CredentialProjectionRecord) (api.CredentialWithdrawalReceipt, error) {
	if r.Authority.ID != h.m.withdrawal.ProjectionID || r.Fence == nil {
		return api.CredentialWithdrawalReceipt{}, &api.Error{Code: api.CodeForbidden}
	}
	return h.m.withdrawal, nil
}
func (c *projectionControl) Open(_ context.Context, prepared api.PreparedLaunch, permit api.LaunchPermit) (api.HelperOpenRequest, error) {
	if prepared != c.m.open.Prepared || permit != c.m.open.Permit {
		return api.HelperOpenRequest{}, &api.Error{Code: api.CodeForbidden}
	}
	return c.m.open, nil
}

func projectionCase(t *testing.T, modes ...string) (*projectionModel, api.VerifiedPeer) {
	t.Helper()
	return projectionCaseRuntime(t, nil, modes...)
}

func projectionCaseRuntime(t *testing.T, configure func(*api.RuntimeManifest, *api.Executable), modes ...string) (*projectionModel, api.VerifiedPeer) {
	t.Helper()
	mode, driver := "codex-file", api.DriverCodex
	if len(modes) > 1 {
		t.Fatal("projection fixture accepts one mode")
	}
	if len(modes) == 1 {
		mode, driver = modes[0], api.DriverClaudock
	}
	c := newLaunchCaseRuntime(t, mode, false, configure, driver)
	c.service.deps.CodexValidator = codex.CredentialValidator{}
	c.service.deps.HeadlessValidator = claudock.CredentialValidator{}
	c.service.deps.APIKeyValidator = claudock.APIKeyValidator{}
	if mode == "claudock-headless" || mode == "claude-api-key" {
		var storage api.LaunchStorage
		if c.store.read("storage.json", &storage) != nil {
			t.Fatal("cannot read headless home fixture")
		}
		storage.Home.Home.VendorDirectory = ".claude"
		if c.store.save("storage.json", storage) != nil {
			t.Fatal("cannot retain headless home fixture")
		}
	}
	env, _ := c.addSecret(t, "native-env", "env", "TASK_NATIVE")
	file, _ := c.addSecret(t, "native-file", "file", "tool-token")
	slot, err := c.acquire(context.Background(), c.target, c.grant)
	if err != nil {
		t.Fatal("cannot acquire native projection fixture")
	}
	injection, err := c.inject(context.Background(), c.target, []api.SecretGrant{env, file})
	if err != nil {
		t.Fatal("cannot prepare native projection fixture")
	}
	c.bind(t, slot, injection)
	var binding api.LaunchBindingRequest
	if c.store.read("binding.json", &binding) != nil {
		t.Fatal("cannot reload projection binding fixture")
	}
	plan := c.plan(t)
	cause := binding.Recovery.Handoff.Cause
	cause.ID, cause.Kind, cause.EffectID = "projection-prepare", api.InternalHelperPrepare, "projection-prepare-effect"
	request := api.CredentialProjectionRequest{Cause: cause, Handoff: binding.Recovery.Handoff, Prepared: binding.Prepared, Lease: plan.Plan.Lease, Home: plan.Plan.Data.Home}
	expires := api.Timestamp(c.clock.Now().Add(time.Minute).Format(time.RFC3339Nano))
	request.Claim = api.EffectLease{ClaimID: "projection-claim", ExpiresAt: expires, Record: api.EffectRecord{State: api.EffectClaimed, Generation: 1, ClaimID: "projection-claim", ClaimantID: "projection-owner", ClaimExpiresAt: expires,
		Effect: api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, HelperPrepare: &api.HelperLaunchRequest{Cause: cause, LeaseID: request.Lease.ID, PreparedSpecID: request.Handoff.Spec.ID, SpecSHA256: request.Handoff.SpecSHA256}}}}
	targets, err := api.CredentialTargets(request, c.clock.Now())
	if err != nil {
		t.Fatal("native projection fixture targets failed shared validation")
	}
	facts, boot := selfUsageFacts(t)
	helper := facts
	helper.HostUID, helper.HostGID, helper.ContainmentID = 0, 0, "helper-containment"
	a := api.CredentialProjectionAuthority{ID: "projection-a", Generation: 1, Request: request, Targets: targets, Helper: c.profile.Runtime, Broker: c.profile.Runtime, HelperPeer: helper, BrokerPeer: facts, ServiceUID: facts.HostUID + 1000, InstallationGeneration: 1, BootID: boot, Sources: []api.CredentialSourceVersion{}}
	for _, target := range targets {
		version := target.Version
		if target.SlotID != "" {
			version = c.profile.Source.Version
		}
		a.Sources = append(a.Sources, api.CredentialSourceVersion{Key: target.Key, Generation: 1, Version: version})
	}
	m := &projectionModel{c: c, a: a, effects: map[api.ID]api.EffectRecord{cause.EffectID: request.Claim.Record}}
	openCause := cause
	openCause.ID, openCause.Kind, openCause.EffectID = "projection-open", api.InternalHelperOpen, "projection-open-effect"
	m.open = api.HelperOpenRequest{Cause: openCause, Prepared: binding.Prepared, Permit: api.LaunchPermit{LaunchID: binding.Record.ID, PreparedID: binding.Prepared.ID, RecordSHA256: binding.Identity.RecordSHA256, CommittedSeq: binding.Identity.CommittedSeq}, OperationID: openCause.CauseOperationID, EffectID: openCause.EffectID}
	m.effects[openCause.EffectID] = api.EffectRecord{State: api.EffectClaimed, Generation: 1, ClaimID: "open-claim", ClaimantID: "open-owner", ClaimExpiresAt: expires, Effect: api.Effect{ID: openCause.EffectID, OperationID: openCause.CauseOperationID, Context: &openCause}}
	c.service.deps.Store, c.service.deps.ProjectionIdentity = &projectionStore{c.store, m}, m
	c.service.deps.Helper, c.service.deps.Control = &projectionHelper{c.helper, m}, &projectionControl{c.control, m}
	t.Cleanup(func() {
		for _, f := range c.service.projections {
			if err := f.closeRefreshLeases(); err != nil {
				t.Error("cannot close fixture refresh leases")
			}
			if !f.closed {
				closeProjectionFiles(f.transfer.Files)
				f.closed = true
			}
		}
	})
	return m, &usagePeerFixture{facts: helper}
}

func (m *projectionModel) hold(t *testing.T, transfer api.CredentialTransfer) api.CredentialProjectionReceipt {
	t.Helper()
	zero, count := uint64(0), uint64(len(transfer.Files))
	r := m.a.Request
	held := api.CredentialProjectionReceipt{ProjectionID: m.a.ID, Generation: m.a.Generation + 1, Prepared: r.Prepared, HelperLeaseID: r.Lease.ID, SpecSHA256: r.Handoff.SpecSHA256, Home: r.Home, CancellationEpoch: r.Cause.CancellationEpoch, GateClosed: true, HeldDescriptors: &count, InheritedSources: &zero, ObservedAt: api.Timestamp(m.c.clock.Now().Format(time.RFC3339Nano)), Targets: []api.CredentialHeldTarget{}}
	for i, file := range transfer.Files {
		fact, err := credentialFact(file)
		if err != nil {
			t.Fatal("cannot inspect actual projection export")
		}
		target := m.a.Targets[i]
		item := api.CredentialHeldTarget{Target: target, SourceObjectID: fact.ObjectID, ObjectID: "held-" + string(target.Key), RootID: r.Home.RootID, HomeGeneration: r.Home.Generation, OwnerUID: r.Lease.UID, Mode: target.FileMode, ParentMode: 0700, Links: 1}
		if target.Delivery == "env" {
			item.OwnerUID, item.Mode = 0, 0600
			if target.SlotID != "" {
				item.Links = 0
			}
		}
		if target.FileMode == 0400 {
			item.ParentMode, item.ReadOnlyView = 0500, true
		}
		if target.SlotID != "" && target.EnvironmentName != "" {
			item.ReadOnlyView = true
		}
		held.Targets = append(held.Targets, item)
	}
	m.held = held
	if m.c.store.save("projection-held.json", held) != nil {
		t.Fatal("cannot retain independent helper observation fixture")
	}
	return held
}

func TestProjectionFlow(t *testing.T) {
	m, peer := projectionCase(t)
	s := m.c.service
	transfer, err := s.TransferCredentials(context.Background(), peer, m.a.Request)
	if err != nil || len(transfer.Files) != 3 {
		t.Fatal("projection did not export its actual ordered private descriptors")
	}
	for _, file := range transfer.Files {
		fact, err := credentialFact(file)
		if err != nil || fact.Links != 0 || !fact.ReadOnly || !fact.CloseOnExec || fact.WritableHandles == nil || *fact.WritableHandles != 0 {
			t.Fatal("projection export is not an immutable private descriptor")
		}
	}
	held := m.hold(t, transfer)
	record, err := s.AcknowledgeCredentials(context.Background(), held)
	if err != nil || record.State != "held" || record.Receipt == nil {
		t.Fatal("projection did not commit its actual helper acknowledgement")
	}
	for _, file := range transfer.Files {
		if _, err := file.Stat(); err == nil {
			t.Fatal("broker originals survived committed acknowledgement")
		}
	}
	guard, err := s.LockCredentialProjection(context.Background(), api.CredentialGateRequest{ProjectionID: m.a.ID, ExpectedGeneration: record.Generation, Open: m.open})
	if err != nil {
		t.Fatal("acknowledged projection did not acquire its live gate guard")
	}
	if err := guard.Check(context.Background()); err != nil {
		guard.Close()
		t.Fatal("live projection gate guard lost its actual current sources")
	}
	if err := guard.Close(); err != nil {
		t.Fatal("projection gate guard did not close")
	}
	cause := m.a.Request.Cause
	cause.Kind, cause.ID, cause.EffectID = api.InternalHelperRelease, "projection-release", "projection-release-effect"
	fenced, err := s.BeginCredentialWithdrawal(context.Background(), api.CredentialWithdrawalRequest{ProjectionID: m.a.ID, ExpectedGeneration: record.Generation, Cause: cause, Reason: "release"})
	if err != nil || fenced.State != "withdrawing" {
		t.Fatal("projection withdrawal did not retain the actual fence")
	}
	_, err = s.LockCredentialProjection(context.Background(), api.CredentialGateRequest{ProjectionID: m.a.ID, ExpectedGeneration: record.Generation, Open: m.open})
	stageCode(t, err, api.CodeConflict)
	observation := m.c.finish(t, api.ProcessObservation{Handle: api.ProcessHandle{ID: "process-a", Target: m.c.target, ContainmentID: m.a.Request.Prepared.ContainmentID, Generation: m.a.Request.Prepared.ProcessGeneration}})
	observation.ObservedAt = api.Timestamp(m.c.clock.Now().Format(time.RFC3339Nano))
	zero := uint64(0)
	m.withdrawal = api.CredentialWithdrawalReceipt{ProjectionID: m.a.ID, Generation: fenced.Generation + 1, Cause: cause, Prepared: m.a.Request.Prepared, HelperLeaseID: m.a.Request.Lease.ID, Home: m.a.Request.Home, Observation: observation, HelperDescriptors: &zero, ProjectedFiles: &zero, EnvironmentBuffers: &zero, OpenGates: &zero, ObservedAt: observation.ObservedAt}
	done, err := s.FinishCredentialWithdrawal(context.Background(), fenced, m.withdrawal)
	if err != nil || done.State != "withdrawn" || done.Withdrawal == nil || done.Withdrawal.BrokerDescriptors == nil || *done.Withdrawal.BrokerDescriptors != 0 || done.Withdrawal.RefreshLeases == nil || *done.Withdrawal.RefreshLeases != 0 {
		t.Fatal("projection withdrawal did not retain measured zero completion")
	}
	for _, id := range m.a.Request.Handoff.Spec.Injection.SlotIDs {
		slot := readCaseSlot(t, m.c, id)
		if !slot.Released || len(slot.Material) != 0 {
			t.Fatal("projection withdrawal retained live slot material")
		}
	}
}

func TestHeadlessProjection(t *testing.T) {
	m, peer := projectionCase(t, "claudock-headless")
	transfer, err := m.c.service.TransferCredentials(context.Background(), peer, m.a.Request)
	if err != nil || len(transfer.Files) != 3 || transfer.Authority.Targets[0].RelativePath != ".runnerhome-runtime/.runnerhome-token" || transfer.Authority.Targets[0].EnvironmentName != "CLAUDE_CODE_OAUTH_TOKEN" {
		t.Fatal("headless projection did not retain its fixed selected token destination")
	}
	record, err := m.c.service.AcknowledgeCredentials(context.Background(), m.hold(t, transfer))
	if err != nil || record.State != "held" {
		t.Fatal("headless projection did not commit its read-only held token receipt")
	}
}

func TestProjectionGuards(t *testing.T) {
	for _, fault := range []string{"identity", "source", "ack", "holding", "durable", "policy", "claim"} {
		t.Run(fault, func(t *testing.T) {
			m, peer := projectionCase(t)
			s := m.c.service
			if fault == "identity" {
				m.identityErr = api.NotImplemented("lb-v2-identity", "fixture native projection identity")
				_, err := s.TransferCredentials(context.Background(), peer, m.a.Request)
				stageCode(t, err, api.CodeNotImplemented)
				return
			}
			if fault == "source" {
				m.a.Sources[0].Generation++
				_, err := s.TransferCredentials(context.Background(), peer, m.a.Request)
				stageCode(t, err, api.CodeConflict)
				return
			}
			transfer, err := s.TransferCredentials(context.Background(), peer, m.a.Request)
			if err != nil {
				t.Fatal("cannot establish projection refusal control")
			}
			t.Cleanup(func() {
				f := s.flight(m.a.ID)
				if !f.closed {
					closeProjectionFiles(f.transfer.Files)
					f.closed = true
				}
			})
			held := m.hold(t, transfer)
			if fault == "ack" {
				held.Targets = append([]api.CredentialHeldTarget(nil), held.Targets...)
				held.Targets[0].ObjectID = "changed-object"
				_, err = s.AcknowledgeCredentials(context.Background(), held)
				stageCode(t, err, api.CodeIntegrity)
				return
			}
			if fault == "holding" {
				held.HeldDescriptors = new(uint64)
				if m.c.store.save("projection-held.json", held) != nil {
					t.Fatal("cannot retain helper holding refusal")
				}
				_, err = s.AcknowledgeCredentials(context.Background(), held)
				stageCode(t, err, api.CodeInvalid)
				return
			}
			if fault == "durable" {
				m.omitCommit = true
				_, err = s.AcknowledgeCredentials(context.Background(), held)
				stageCode(t, err, api.CodeIntegrity)
				return
			}
			record, err := s.AcknowledgeCredentials(context.Background(), held)
			if err != nil {
				t.Fatal("cannot acknowledge gate refusal control")
			}
			if fault == "policy" {
				m.c.store.policy.Generation++
			}
			if fault == "claim" {
				value := m.effects[m.open.EffectID]
				value.State = api.EffectCompleted
				m.effects[m.open.EffectID] = value
			}
			guard, err := s.LockCredentialProjection(context.Background(), api.CredentialGateRequest{ProjectionID: m.a.ID, ExpectedGeneration: record.Generation, Open: m.open})
			if guard != nil {
				guard.Close()
			}
			stageCode(t, err, api.CodeConflict)
		})
	}
}

func TestProjectionSCM(t *testing.T) {
	data := syntheticBytes(t, 97)
	file, err := exportCredential(data)
	if err != nil {
		t.Fatal("cannot create actual anonymous transfer canary")
	}
	defer file.Close()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("cannot create actual native transfer pair")
	}
	leftFile, rightFile := os.NewFile(uintptr(pair[0]), "projection-left"), os.NewFile(uintptr(pair[1]), "projection-right")
	left, err := net.FileConn(leftFile)
	leftFile.Close()
	if err != nil {
		rightFile.Close()
		t.Fatal("cannot open native transfer sender")
	}
	defer left.Close()
	right, err := net.FileConn(rightFile)
	rightFile.Close()
	if err != nil {
		t.Fatal("cannot open native transfer receiver")
	}
	defer right.Close()
	if err := sendProjectionPacket(left.(*net.UnixConn), struct{ Kind string }{"synthetic"}, []*os.File{file}); err != nil {
		t.Fatal("actual SCM_RIGHTS send failed")
	}
	buf, controls := make([]byte, 1024), make([]byte, unix.CmsgSpace(4))
	raw, err := right.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal("cannot inspect actual native receiver")
	}
	var n, oob, flags int
	var recvErr error
	if err := raw.Read(func(fd uintptr) bool {
		n, oob, flags, _, recvErr = unix.Recvmsg(int(fd), buf, controls, unix.MSG_CMSG_CLOEXEC)
		return recvErr != unix.EAGAIN
	}); err != nil || recvErr != nil || n == 0 || flags&unix.MSG_CTRUNC != 0 {
		t.Fatal("actual SCM_RIGHTS receive failed")
	}
	messages, err := unix.ParseSocketControlMessage(controls[:oob])
	if err != nil || len(messages) != 1 {
		t.Fatal("native canary descriptor control count changed")
	}
	fds, err := unix.ParseUnixRights(&messages[0])
	if err != nil || len(fds) != 1 {
		t.Fatal("native canary descriptor count changed")
	}
	received := os.NewFile(uintptr(fds[0]), "projection-received")
	defer received.Close()
	actual, err := io.ReadAll(received)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("SCM_RIGHTS did not transfer the actual anonymous canary bytes")
	}
	if bytes.Contains(buf[:n], data) {
		t.Fatal("credential bytes entered native control metadata")
	}
	fact, err := credentialFact(received)
	if err != nil || !fact.ReadOnly || !fact.CloseOnExec {
		t.Fatal("SCM_RIGHTS changed immutable descriptor flags")
	}
	if _, err := unix.FcntlInt(received.Fd(), unix.F_GET_SEALS, 0); err != nil {
		t.Fatal("SCM_RIGHTS lost the actual source seals")
	}
	alias, err := unix.Open("/proc/self/fd/"+fmt.Sprint(received.Fd()), unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("cannot open the owned source seal control alias")
	}
	defer unix.Close(alias)
	if _, err := unix.Pwrite(alias, []byte{'x'}, 0); err == nil {
		t.Fatal("credential transfer retained a writable alias")
	}
}

func TestProjectionDrain(t *testing.T) {
	m, peer := projectionCase(t)
	s := m.c.service
	transfer, err := s.TransferCredentials(context.Background(), peer, m.a.Request)
	if err != nil {
		t.Fatal("cannot export guard drain control")
	}
	record, err := s.AcknowledgeCredentials(context.Background(), m.hold(t, transfer))
	if err != nil {
		t.Fatal("cannot acknowledge guard drain control")
	}
	guard, err := s.LockCredentialProjection(context.Background(), api.CredentialGateRequest{ProjectionID: m.a.ID, ExpectedGeneration: record.Generation, Open: m.open})
	if err != nil {
		t.Fatal("cannot acquire actual guard drain control")
	}
	cause := m.a.Request.Cause
	cause.Kind, cause.ID = api.InternalHelperAbort, "projection-abort"
	request := api.CredentialWithdrawalRequest{ProjectionID: m.a.ID, ExpectedGeneration: record.Generation, Cause: cause, Reason: "refused"}
	bounded, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, err = s.BeginCredentialWithdrawal(bounded, request)
	cancel()
	stageCode(t, err, api.CodeDeadline)
	if err := guard.Close(); err != nil {
		t.Fatal("guard drain did not release its actual journal lock")
	}
	again, err := s.LockCredentialProjection(context.Background(), api.CredentialGateRequest{ProjectionID: m.a.ID, ExpectedGeneration: record.Generation, Open: m.open})
	if again != nil {
		again.Close()
	}
	stageCode(t, err, api.CodeConflict)
	fenced, err := s.BeginCredentialWithdrawal(context.Background(), request)
	if err != nil || fenced.State != "withdrawing" {
		t.Fatal("drained projection did not commit its retained withdrawal fence")
	}
}

func TestWithdrawalZeros(t *testing.T) {
	m, peer := projectionCase(t)
	s := m.c.service
	transfer, err := s.TransferCredentials(context.Background(), peer, m.a.Request)
	if err != nil {
		t.Fatal("cannot export zero-count withdrawal control")
	}
	record, err := s.AcknowledgeCredentials(context.Background(), m.hold(t, transfer))
	if err != nil {
		t.Fatal("cannot acknowledge zero-count withdrawal control")
	}
	cause := m.a.Request.Cause
	cause.ID, cause.Kind, cause.EffectID = "zero-release", api.InternalHelperRelease, "zero-release-effect"
	fenced, err := s.BeginCredentialWithdrawal(context.Background(), api.CredentialWithdrawalRequest{ProjectionID: m.a.ID, ExpectedGeneration: record.Generation, Cause: cause, Reason: "release"})
	if err != nil {
		t.Fatal("cannot fence zero-count withdrawal control")
	}
	observation := m.c.finish(t, api.ProcessObservation{Handle: api.ProcessHandle{ID: "process-a", Target: m.c.target, ContainmentID: m.a.Request.Prepared.ContainmentID, Generation: m.a.Request.Prepared.ProcessGeneration}})
	observation.ObservedAt = api.Timestamp(m.c.clock.Now().Format(time.RFC3339Nano))
	zero, one := uint64(0), uint64(1)
	m.withdrawal = api.CredentialWithdrawalReceipt{ProjectionID: m.a.ID, Generation: fenced.Generation + 1, Cause: cause, Prepared: m.a.Request.Prepared, HelperLeaseID: m.a.Request.Lease.ID, Home: m.a.Request.Home, Observation: observation, HelperDescriptors: &zero, ProjectedFiles: &one, EnvironmentBuffers: &zero, OpenGates: &zero, ObservedAt: observation.ObservedAt}
	_, err = s.FinishCredentialWithdrawal(context.Background(), fenced, m.withdrawal)
	for _, id := range m.a.Request.Handoff.Spec.Injection.SlotIDs {
		slot := readCaseSlot(t, m.c, id)
		if slot.Released || len(slot.Material) == 0 {
			t.Fatal("nonzero withdrawal erased retained credentials")
		}
		clear(slot.Material)
	}
	count, countErr := s.flight(m.a.ID).refreshLeaseCount()
	if countErr != nil || count != 1 {
		t.Fatal("nonzero withdrawal retired its canonical refresh lease")
	}
	stageCode(t, err, api.CodeInvalid)
}

func TestProjectionEarlyRelease(t *testing.T) {
	m, peer := projectionCase(t)
	s := m.c.service
	transfer, err := s.TransferCredentials(context.Background(), peer, m.a.Request)
	if err != nil {
		t.Fatal("cannot export early release control")
	}
	t.Cleanup(func() {
		f := s.flight(m.a.ID)
		if !f.closed {
			closeProjectionFiles(f.transfer.Files)
			f.closed = true
		}
	})
	slot := readCaseSlot(t, m.c, m.a.Targets[0].SlotID)
	stageCode(t, s.projectionReleased(context.Background(), slot), api.CodeConflict)
	_, err = s.LockCredentialProjection(context.Background(), api.CredentialGateRequest{ProjectionID: m.a.ID, ExpectedGeneration: 1, Open: m.open})
	stageCode(t, err, api.CodeConflict)
	if len(transfer.Files) == 0 {
		t.Fatal("early release control did not retain actual exports")
	}
}

func TestRefreshOwnerReject(t *testing.T) {
	m, peer := projectionCase(t)
	s := m.c.service
	transfer, err := s.TransferCredentials(context.Background(), peer, m.a.Request)
	if err != nil {
		t.Fatal("cannot export refresh ownership control")
	}
	record, err := s.AcknowledgeCredentials(context.Background(), m.hold(t, transfer))
	if err != nil {
		t.Fatal("cannot acknowledge refresh ownership control")
	}
	cause := m.a.Request.Cause
	cause.ID, cause.Kind, cause.EffectID = "refresh-release", api.InternalHelperRelease, "refresh-release-effect"
	fenced, err := s.BeginCredentialWithdrawal(context.Background(), api.CredentialWithdrawalRequest{ProjectionID: m.a.ID, ExpectedGeneration: record.Generation, Cause: cause, Reason: "release"})
	if err != nil {
		t.Fatal("cannot fence refresh ownership control")
	}
	observation := m.c.finish(t, api.ProcessObservation{Handle: api.ProcessHandle{ID: "process-a", Target: m.c.target, ContainmentID: m.a.Request.Prepared.ContainmentID, Generation: m.a.Request.Prepared.ProcessGeneration}})
	observation.ObservedAt = api.Timestamp(m.c.clock.Now().Format(time.RFC3339Nano))
	var changed map[string]any
	if json.Unmarshal(m.c.material, &changed) != nil {
		t.Fatal("cannot decode synthetic native refresh bytes")
	}
	changed["last_refresh"] = string(observation.ObservedAt)
	data, err := json.Marshal(changed)
	if err != nil {
		t.Fatal("cannot encode synthetic native refresh bytes")
	}
	file, err := exportCredential(data)
	if err != nil {
		t.Fatal("cannot create nonroot refresh ownership control")
	}
	fact, err := credentialFact(file)
	if err != nil {
		file.Close()
		t.Fatal("cannot inspect refresh ownership control")
	}
	_, err = s.AcceptCredentialRefresh(context.Background(), peer, api.CredentialRefresh{ProjectionID: m.a.ID, ExpectedGeneration: fenced.Generation, SlotID: m.a.Targets[0].SlotID, ExpectedSourceGeneration: 1, Observation: observation, Fact: fact, File: file})
	stageCode(t, err, api.CodeInvalid)
	if _, err := file.Stat(); err == nil {
		t.Fatal("refused refresh leaked its received descriptor")
	}
}
