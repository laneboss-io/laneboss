//go:build linux

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"runtime/debug"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// These fixtures exercise native descriptor operations and private lifecycle
// components. They do not authenticate a broker or claim installed isolation.
func credentialCanary(t *testing.T) (*os.File, []byte) {
	t.Helper()
	id, err := randomID("ordinary-canary-")
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(t.TempDir(), "input-")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(id)
	if _, err := file.Write(data); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
	})
	return file, data
}

func TestCredAnonDistinct(t *testing.T) {
	input, data := credentialCanary(t)
	output, err := anonymousCredential(context.Background(), input, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	a, _, err := credentialObject(input)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := credentialObject(output)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(output)
	if err != nil || !bytes.Equal(got, data) || a == b {
		t.Fatal("acceptance: credential copy reused its source or changed bytes")
	}
	fact, err := credentialDescriptor(output, true)
	if err != nil || !fact.ReadOnly || !fact.CloseOnExec || fact.Links != 0 || fact.Mode != 0600 || fact.WritableHandles == nil || *fact.WritableHandles != 0 {
		t.Fatal("acceptance: credential destination lost native descriptor restrictions")
	}
	if _, err := output.Write([]byte("changed")); err == nil {
		t.Fatal("acceptance: credential destination remained writable")
	}
}

func TestCredDescriptorSeals(t *testing.T) {
	fd, err := unix.MemfdCreate("unsealed-control", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "unsealed-control")
	defer file.Close()
	if _, err := file.Write([]byte("ordinary control")); err != nil {
		t.Fatal(err)
	}
	if _, err := credentialDescriptor(file, true); err == nil {
		t.Fatal("acceptance: unsealed credential descriptor was accepted")
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, bootstrapSeals); err != nil {
		t.Fatal(err)
	}
	if _, err := credentialDescriptor(file, true); err != nil {
		t.Fatal(err)
	}
}

func TestCredSourceDisposal(t *testing.T) {
	file, _ := credentialCanary(t)
	count, err := inheritedCredentialSources([]*os.File{file})
	if err != nil || count != 1 {
		t.Fatal("acceptance: live credential source was reported absent")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	count, err = inheritedCredentialSources([]*os.File{file})
	if err != nil || count != 0 {
		t.Fatal("acceptance: closed credential source was not measured")
	}
}

func TestCredNoServiceFD(t *testing.T) {
	file, _ := credentialCanary(t)
	service := &Service{}
	_, err := service.InspectCredentialTransfer(context.Background(), api.CredentialTransfer{Files: []*os.File{file}})
	var typed *api.Error
	_, statErr := file.Stat()
	if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || !errors.Is(statErr, os.ErrClosed) {
		t.Fatal("acceptance: service retained a credential descriptor")
	}
}

func credentialSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var connections []*net.UnixConn
	for _, fd := range fds {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
			t.Fatal(err)
		}
		file := os.NewFile(uintptr(fd), "credential-socket-control")
		connection, err := net.FileConn(file)
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			t.Fatal("socket ownership handoff failed")
		}
		conn := connection.(*net.UnixConn)
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
		t.Cleanup(func() {
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	return connections[0], connections[1]
}

func credentialAliasCount(t *testing.T, file *os.File) int {
	t.Helper()
	_, want, err := credentialObject(file)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		var st unix.Stat_t
		err := unix.Stat("/proc/self/fd/"+entry.Name(), &st)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			t.Fatal("descriptor inventory unavailable")
		}
		if st.Dev == want.Dev && st.Ino == want.Ino {
			count++
		}
	}
	return count
}

func TestCredNativeFrame(t *testing.T) {
	// A finalizer must not hide a leaked received descriptor before inventory.
	previous := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previous)
	for _, fault := range []string{"valid", "writer", "framing"} {
		t.Run(fault, func(t *testing.T) {
			sender, receiver := credentialSocketPair(t)
			file, _ := credentialCanary(t)
			before := credentialAliasCount(t, file)
			encoded, err := frame([]byte(`{"kind":"ordinary"}`))
			if err != nil {
				t.Fatal(err)
			}
			if fault == "framing" {
				encoded[0] = 0x7f
			}
			if n, _, err := sender.WriteMsgUnix(encoded, unix.UnixRights(int(file.Fd())), nil); err != nil || n != len(encoded) {
				t.Fatal("native frame send failed")
			}
			expected := unix.Ucred{Pid: int32(os.Getpid()), Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid())}
			if fault == "writer" {
				expected.Pid++
			}
			body, received, err := readCredentialFrame(receiver, expected, nil)
			if fault == "valid" {
				if err != nil || len(received) != 1 || !bytes.Equal(body, []byte(`{"kind":"ordinary"}`)) {
					t.Fatal("acceptance: credential native frame lost its actual descriptor")
				}
				flags, err := unix.FcntlInt(received[0].Fd(), unix.F_GETFD, 0)
				if err != nil || flags&unix.FD_CLOEXEC == 0 {
					t.Fatal("acceptance: received credential descriptor could be inherited")
				}
				if err := closeCredentialFiles(received); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || len(received) != 0 {
				closeCredentialFiles(received)
				t.Fatal("acceptance: credential frame accepted a foreign writer or length")
			}
			if credentialAliasCount(t, file) != before {
				t.Fatal("acceptance: refused credential frame leaked its received duplicate")
			}
		})
	}
}

func TestCredChannelLifetime(t *testing.T) {
	sender, receiver := credentialSocketPair(t)
	channel := &credentialChannel{connection: receiver}
	if err := channel.transportAlive(); err != nil {
		t.Fatal("credential channel control is not live")
	}
	if err := socketControl(sender, func(fd int) error { return unix.Shutdown(fd, unix.SHUT_WR) }); err != nil {
		t.Fatal(err)
	}
	if err := channel.transportAlive(); err == nil {
		t.Fatal("acceptance: credential attachment retained a closed transport")
	}
}

type credentialGuardFixture struct {
	api.CredentialGateGuard
	checks, closes int
	refusal        error
}

func (g *credentialGuardFixture) Check(context.Context) error { g.checks++; return g.refusal }
func (g *credentialGuardFixture) Close() error                { g.closes++; return nil }

func TestCredGuardLifetime(t *testing.T) {
	manager := &leaseManager{}
	guard := &credentialGuardFixture{}
	waitErr := errors.New("ordinary exec acknowledgement error")
	_, err := manager.withCredentialGuard(context.Background(), guard, func() (api.ProcessHandle, error) {
		if guard.checks != 1 || guard.closes != 0 || manager.activeCredentialGuard != guard {
			t.Fatal("acceptance: credential guard ended before exec acknowledgement")
		}
		return api.ProcessHandle{}, waitErr
	})
	if !errors.Is(err, waitErr) || guard.closes != 1 || manager.activeCredentialGuard != nil {
		t.Fatal("acceptance: credential guard ownership survived completion")
	}
}

func TestCredGuardRefusal(t *testing.T) {
	manager := &leaseManager{}
	refusal := errors.New("ordinary guard refusal")
	guard := &credentialGuardFixture{refusal: refusal}
	opened := false
	_, err := manager.withCredentialGuard(context.Background(), guard, func() (api.ProcessHandle, error) { opened = true; return api.ProcessHandle{}, nil })
	if !errors.Is(err, refusal) || opened || guard.closes != 1 {
		t.Fatal("acceptance: credential guard refusal allowed gate release")
	}
}

func TestCredAckHolding(t *testing.T) {
	file, data := credentialCanary(t)
	destination, err := anonymousCredential(context.Background(), file, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	fact, err := credentialDescriptor(destination, true)
	if err != nil {
		t.Fatal(err)
	}
	count := uint64(1)
	zero := uint64(0)
	receipt := api.CredentialProjectionReceipt{Targets: []api.CredentialHeldTarget{{ObjectID: fact.ObjectID}}, HeldDescriptors: &count, InheritedSources: &zero}
	held := &heldCredentials{files: []*os.File{destination}, record: api.CredentialProjectionRecord{Receipt: &receipt}}
	if err := credentialAcknowledgementReady(held, receipt); err != nil {
		t.Fatal(err)
	}
	held.files = nil
	if err := credentialAcknowledgementReady(held, receipt); err == nil {
		t.Fatal("acceptance: credential acknowledgement preceded actual holding")
	}
}

func TestCredCleanupEcho(t *testing.T) {
	zero := uint64(0)
	one := uint64(1)
	measured := api.CredentialWithdrawalReceipt{ProjectionID: "ordinary-projection", HelperDescriptors: &zero, ProjectedFiles: &zero, EnvironmentBuffers: &zero, OpenGates: &zero, RotationRequired: true}
	completed := measured
	completed.BrokerDescriptors = &zero
	completed.RefreshLeases = &zero
	if !sameHelperWithdrawal(completed, measured) {
		t.Fatal("valid broker-only cleanup extension was refused")
	}
	for _, name := range []string{"files", "buffers", "gates", "rotation"} {
		t.Run(name, func(t *testing.T) {
			changed := completed
			switch name {
			case "files":
				changed.ProjectedFiles = &one
			case "buffers":
				changed.EnvironmentBuffers = &one
			case "gates":
				changed.OpenGates = &one
			case "rotation":
				changed.RotationRequired = false
			}
			if sameHelperWithdrawal(changed, measured) {
				t.Fatal("acceptance: credential owner replaced helper cleanup measurements")
			}
		})
	}
}

func TestCredCollectionFence(t *testing.T) {
	manager := &leaseManager{}
	for _, state := range []string{"receiving", "held", "withdrawing"} {
		if err := manager.ensureCredentialsWithdrawn(leaseRecord{Credentials: &credentialJournal{State: state}}); err == nil {
			t.Fatal("acceptance: unwithdrawn credentials allowed collection")
		}
	}
	if err := manager.ensureCredentialsWithdrawn(leaseRecord{Credentials: &credentialJournal{State: "withdrawn"}}); err != nil {
		t.Fatal(err)
	}
}

func TestCredRecoveryRetains(t *testing.T) {
	authority := api.CredentialProjectionAuthority{ID: "original-projection", Generation: 1}
	before := &credentialJournal{State: "held", Record: &api.CredentialProjectionRecord{State: "held", Generation: 2, Authority: authority}}
	if err := credentialRecoveryTransition(before, before); err != nil {
		t.Fatal(err)
	}
	if err := credentialRecoveryTransition(before, nil); err == nil {
		t.Fatal("acceptance: recovery discarded credential ownership")
	}
	changed := *before
	record := *before.Record
	changed.Record = &record
	changed.Record.Authority.ID = "replacement-projection"
	if err := credentialRecoveryTransition(before, &changed); err == nil {
		t.Fatal("acceptance: recovery replaced credential identity")
	}
}

func TestCredBindPermanent(t *testing.T) {
	service := &Service{}
	if err := service.BindCredentialProjection(nil, nil); err == nil {
		t.Fatal("acceptance: nil credential clients were bound")
	}
	var typed *api.Error
	if err := service.BindCredentialProjection(nil, nil); !errors.As(err, &typed) || typed.Code != api.CodeConflict {
		t.Fatal("acceptance: permanent credential bind allowed a retry")
	}
}

func TestCredAttachBoundary(t *testing.T) {
	m := newLeaseManager(testBinding(), "component-boot", nil, nil)
	status := m.credentialBinding(context.Background())
	if !status.Fresh || status.Bound || status.Failure != nil || m.credentialBindAttempted {
		t.Fatal("fresh helper attachment changed binding state")
	}
	m.credentialBindAttempted = true
	status = m.credentialBinding(context.Background())
	if status.Fresh || status.Bound || status.Failure == nil || !m.credentialBindAttempted {
		t.Fatal("acceptance: credential attachment reset a partial bind")
	}
	runtime := &credentialRuntime{manager: m, held: map[api.ID]*heldCredentials{}}
	m.credentials = runtime
	status = m.credentialBinding(context.Background())
	if status.Fresh || status.Bound || status.Failure == nil || m.credentials != runtime || !m.credentialBindAttempted {
		t.Fatal("acceptance: credential attachment accepted missing native owners")
	}
}

// A refusing identity port observes the actual file-backed journal at the
// authorization boundary. No native binding or source export is simulated.
type credentialJournalObserver struct {
	api.CredentialProjectionIdentity
	store   leaseStorage
	called  bool
	durable bool
	refusal error
}

func (o *credentialJournalObserver) AuthorizeCredentialProjection(_ context.Context, _ api.VerifiedPeer, q api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error) {
	o.called = true
	records, err := o.store.Records()
	if err != nil {
		return api.CredentialProjectionAuthority{}, err
	}
	if len(records) == 1 {
		j := records[0].Credentials
		o.durable = j != nil && j.State == "receiving" && j.Record == nil && j.Request != nil && reflect.DeepEqual(*j.Request, q)
	}
	return api.CredentialProjectionAuthority{}, o.refusal
}

func TestCredRequestDurable(t *testing.T) {
	m, registration, _, _, store := retainedGateFixture(t)
	records, err := store.Records()
	if err != nil || len(records) != 1 {
		t.Fatal("credential journal fixture is unavailable")
	}
	record := records[0]
	request := record.Gate.Request
	expires := api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	claim := api.EffectLease{ClaimID: "credential-claim", ExpiresAt: expires, Record: api.EffectRecord{State: api.EffectClaimed, Generation: 1, ClaimID: "credential-claim", ClaimantID: "credential-service", ClaimExpiresAt: expires, Effect: api.Effect{ID: request.Cause.EffectID, OperationID: request.Cause.CauseOperationID, Context: &request.Cause, HelperPrepare: &request}}}
	refusal := errors.New("ordinary identity port refusal")
	observer := &credentialJournalObserver{store: store, refusal: refusal}
	m.credentials = &credentialRuntime{manager: m, identity: observer, held: map[api.ID]*heldCredentials{}}
	err = m.prepareCredentials(context.Background(), credentialPrepare{Request: request, Claim: claim}, registration.Request.Prepared)
	if !errors.Is(err, refusal) || !observer.called || !observer.durable {
		t.Fatal("acceptance: credential authorization preceded the retained exact request")
	}
	retained, err := store.Records()
	if err != nil || len(retained) != 1 {
		t.Fatal("credential refusal journal is unavailable")
	}
	if retained[0].Credentials == nil || retained[0].Credentials.Request == nil || !reflect.DeepEqual(retained[0].Credentials.Request.Claim, claim) {
		t.Fatal("acceptance: credential refusal lost its original claim snapshot")
	}
}

func TestCredRefreshLost(t *testing.T) {
	runtime := &credentialRuntime{held: map[api.ID]*heldCredentials{}}
	_, err := runtime.collectRefresh(context.Background(), api.CredentialProjectionRecord{Authority: api.CredentialProjectionAuthority{ID: "lost-projection"}})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown {
		t.Fatal("acceptance: lost credential refresh ownership was replaced")
	}
}

type credentialBrokerClient struct{ api.CredentialProjectionBroker }
type credentialIdentityClient struct {
	api.CredentialProjectionIdentity
}

func TestCredBindRetry(t *testing.T) {
	for _, mode := range []string{"certified", "partial", "unknown", "permanent", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			service := &Service{credentialAttempted: true}
			cause := failure(api.CodeUnavailable, "ordinary binding failure")
			cause.Retryable = true
			result := credentialBindingResult{Unbound: true, Failure: cause}
			switch mode {
			case "partial":
				result.Unbound = false
			case "unknown":
				result = credentialBindingResult{}
			case "permanent":
				cause.Retryable = false
			case "foreign":
				cause.Owner = "lb-v2-secrets"
			}
			err := service.completeCredentialBinding(result, &credentialBrokerClient{}, &credentialIdentityClient{})
			wantRetry := mode == "certified"
			if err == nil || api.CredentialBindingRetryable(err) != wantRetry || service.credentialAttempted == wantRetry {
				t.Fatal("acceptance: credential binding retried without owning unbound certification")
			}
		})
	}
	service := &Service{credentialAttempted: true}
	broker := &credentialBrokerClient{}
	identity := &credentialIdentityClient{}
	if err := service.completeCredentialBinding(credentialBindingResult{Bound: true}, broker, identity); err != nil || service.credentialBroker != broker || service.credentialIdentity != identity {
		t.Fatal("accepted binding lost its exact clients")
	}
	var typed *api.Error
	if err := service.BindCredentialProjection(broker, identity); !errors.As(err, &typed) || typed.Code != api.CodeConflict {
		t.Fatal("acceptance: successful credential binding allowed a second bind")
	}
}

type credentialRefreshBroker struct {
	api.CredentialProjectionBroker
	want      string
	calls     int
	uncertain error
	bad       bool
	unchanged bool
}

func (b *credentialRefreshBroker) AcceptCredentialRefresh(_ context.Context, _ api.VerifiedPeer, refresh api.CredentialRefresh) (api.CredentialSourceVersion, error) {
	id, _, err := credentialObject(refresh.File)
	if err != nil {
		return api.CredentialSourceVersion{}, err
	}
	if id != b.want {
		return api.CredentialSourceVersion{}, errors.New("refresh object was replaced")
	}
	b.calls++
	if b.uncertain != nil {
		return api.CredentialSourceVersion{}, b.uncertain
	}
	version := api.CredentialSourceVersion{Key: refresh.SlotID, Generation: refresh.ExpectedSourceGeneration + 1, Version: "ordinary-version"}
	if b.bad {
		version.Key = "foreign-slot"
	}
	if b.unchanged {
		version.Generation = refresh.ExpectedSourceGeneration
	}
	return version, nil
}

func TestCredRefreshRetry(t *testing.T) {
	input, data := credentialCanary(t)
	export, err := anonymousCredential(context.Background(), input, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer export.Close()
	id, _, err := credentialObject(export)
	if err != nil {
		t.Fatal(err)
	}
	uncertain := errors.New("ordinary lost acknowledgement")
	broker := &credentialRefreshBroker{want: id, uncertain: uncertain}
	runtime := &credentialRuntime{broker: broker}
	refresh := api.CredentialRefresh{ProjectionID: "projection", SlotID: "slot", ExpectedSourceGeneration: 1, File: export}
	if _, err := runtime.acceptCredentialRefresh(context.Background(), refresh); !errors.Is(err, uncertain) {
		t.Fatal("refresh uncertainty was swallowed")
	}
	if _, err := export.Stat(); err != nil {
		t.Fatal("acceptance: refresh export closed before acknowledgement")
	}
	broker.uncertain = nil
	if _, err := runtime.acceptCredentialRefresh(context.Background(), refresh); err != nil || broker.calls != 2 {
		t.Fatal("acceptance: credential refresh retry replaced its original export")
	}
	broker.bad = true
	if _, err := runtime.acceptCredentialRefresh(context.Background(), refresh); err == nil {
		t.Fatal("acceptance: credential refresh accepted a foreign canonical receipt")
	}
	broker.bad, broker.unchanged = false, true
	if _, err := runtime.acceptCredentialRefresh(context.Background(), refresh); err == nil {
		t.Fatal("acceptance: credential refresh accepted an unchanged source generation")
	}
}

// The stage component is run with an actual nonzero native UID and zero
// capabilities. A true stage flag here is correlation input, not bwrap proof.
func init() {
	if len(os.Args) == 3 && os.Args[1] == "admin-credential-stage" {
		ready, err := strconv.ParseBool(os.Args[2])
		if err != nil {
			os.Exit(41)
		}
		_, err = credentialExecFacts(gatePayload{IsolationReady: ready, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())})
		if err != nil {
			os.Exit(42)
		}
		os.Exit(0)
	}
}

func TestCredExecStage(t *testing.T) {
	for _, ready := range []bool{true, false} {
		executable, err := os.Open("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/proc/self/fd/3", "admin-credential-stage", strconv.FormatBool(ready))
		cmd.Env = []string{}
		cmd.ExtraFiles = []*os.File{executable}
		if os.Geteuid() == 0 {
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
		}
		err = cmd.Run()
		if closeErr := executable.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if ready && err != nil {
			t.Fatal("unprivileged stage control did not reach its native observation")
		}
		if !ready {
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 42 {
				t.Fatal("acceptance: credential value stage preceded completed isolation")
			}
		}
	}
}

func TestCredMetadataNoValues(t *testing.T) {
	file, data := credentialCanary(t)
	encoded, err := json.Marshal(api.CredentialTransfer{Files: []*os.File{file}})
	if err != nil || bytes.Contains(encoded, data) || bytes.Contains(encoded, []byte(file.Name())) {
		t.Fatal("acceptance: credential descriptor bytes entered metadata")
	}
}
