//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Actual private frames, peer lifetime and helper gate release exercise the
// startup close. The server models the remote guard owner. The launch inputs
// remain component fixtures; the descriptor canary actually executes.
func TestCredentialGuardCloseAcknowledgement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("credential close peer pin requires the disposable root test process")
	}
	manager, registration, gate, captured, store := retainedGateFixture(t)
	assertGateClosed(t, captured, "credential startup canary executed before its native release")
	client, server := nativePair(t)
	peer, remote := nativePeer(t, client), nativePeer(t, server)
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := os.MkdirTemp("/opt", "lb-v2-case-secrets-guard-")
	if err != nil {
		t.Fatal(err)
	}
	keep := func(name string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(evidence, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	keep("admin.test", executable)
	keep("binary.sha256", []byte(testDigest(string(executable))+"\n"))
	keep("canary.input", []byte(gate.token))
	t.Logf("retained startup guard evidence: %s; binary_sha256=%s", evidence, testDigest(string(executable)))
	group, err := cgroupMembership(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	channel := &credentialChannel{connection: client, peer: peer, boot: strings.TrimSpace(string(boot)),
		binding: installation{Config: "admin-case", Generation: 1},
		pin: credentialPeerPin{UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), Bytes: int64(len(executable)),
			Executable: api.Executable{SHA256: testDigest(string(executable))}, Cgroup: group}}
	channel.generation, err = processGeneration(os.Getpid(), channel.boot)
	if err != nil {
		t.Fatal(err)
	}
	var operation sync.Mutex
	operation.Lock()
	defer operation.Unlock()
	channel.operationMu = &operation
	callContext := context.WithValue(context.Background(), credentialOperationKey{}, &operation)
	guardContext, cancelGuard := context.WithCancel(callContext)
	cancelGuard()
	projection := api.CredentialProjectionRecord{Authority: api.CredentialProjectionAuthority{Request: api.CredentialProjectionRequest{
		Cause: registration.Request.Cause, Handoff: registration.Binding.Recovery.Handoff, Prepared: registration.Request.Prepared}}}
	projectionWire, err := EncodeWire(projection)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrict(projectionWire, &projection); err != nil {
		t.Fatal("credential startup fixture did not preserve the real projection wire shape", err)
	}
	guard := &nativeCredentialGuard{channel: channel, context: guardContext, record: projection}
	type completion struct {
		handle api.ProcessHandle
		err    error
	}
	finished := make(chan completion, 1)
	go func() {
		handle, err := manager.withCredentialGuard(callContext, guard, func() (api.ProcessHandle, error) {
			return manager.openGate(callContext, registration)
		})
		finished <- completion{handle, err}
	}()
	check, err := readUnixFrame(server, remote)
	if err != nil {
		t.Fatal("credential startup did not check its real native guard", err)
	}
	var checkRequest helperRequest
	if err := decodeStrict(check, &checkRequest); err != nil || checkRequest.Method != "guard_check" || string(checkRequest.Params) != "{}" {
		t.Fatal("credential startup did not send its exact guard check", err)
	}
	keep("check.request.json", check)
	keep("check.response.json", projectionWire)
	if err := writeFrame(server, credentialResponse{Protocol: credentialProtocol, Revision: api.ContractRevision,
		Nonce: checkRequest.Nonce, Result: projectionWire}); err != nil {
		t.Fatal(err)
	}
	raw, err := readUnixFrame(server, remote)
	if err != nil {
		select {
		case result := <-finished:
			t.Fatal("native gate close abandoned its live broker guard", err, result.err)
		default:
		}
		t.Fatal("native gate close abandoned its live broker guard", err)
	}
	var request helperRequest
	if err := decodeStrict(raw, &request); err != nil || request.Method != "guard_close" || string(request.Params) != "{}" {
		t.Fatal("native gate close did not request its exact guard release", err)
	}
	keep("close.request.json", raw)
	if err := captured.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(gate.token))
	if _, err := io.ReadFull(captured, actual); err != nil || string(actual) != gate.token {
		t.Fatal("credential startup did not execute its actual primary canary", err)
	}
	keep("primary.capture", actual)
	if operation.TryLock() {
		operation.Unlock()
	} else {
		t.Fatal("native guard close lost the helper callback lock handoff")
	}
	select {
	case <-finished:
		t.Fatal("native gate close completed before the broker acknowledgement")
	default:
	}
	// This actual response represents the server's completed guard Close.
	response := credentialResponse{Protocol: credentialProtocol, Revision: api.ContractRevision, Nonce: request.Nonce,
		Result: json.RawMessage(`{}`)}
	if err := writeFrame(server, response); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-finished:
		if result.err != nil || result.handle.Generation != gate.Generation() {
			t.Fatal("native guard close did not accept its actual correlated acknowledgement", result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("native guard close did not finish after its acknowledgement")
	}
	if err := channel.transportAlive(); err == nil {
		t.Fatal("native guard retained its private stream after acknowledged release")
	}
	if err := guard.Close(); err != nil {
		t.Fatal("native guard close lost its original completion on repeated cleanup", err)
	}
	records, err := store.Records()
	if err != nil || len(records) != 1 || records[0].Gate.State != "opened" || manager.activeCredentialGuard != nil {
		t.Fatal("credential startup did not retain its opened native gate and release its guard", err)
	}
	if operation.TryLock() {
		operation.Unlock()
		t.Fatal("native guard close returned without regaining the helper lock")
	}
}
