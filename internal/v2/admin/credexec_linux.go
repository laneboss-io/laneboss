//go:build linux

package admin

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

type credentialExecObject struct {
	Key      api.ID
	Name     string
	ObjectID string
}
type credentialExecPacket struct {
	Record  api.CredentialProjectionRecord
	Objects []credentialExecObject
}

func (m *leaseManager) awaitCredentialGate(ctx context.Context, record leaseRecord) error {
	native, ok := m.gates[record.Lease.ID].(*nativeGate)
	if !ok || record.Spec == nil || record.Spec.Handoff.Spec.Runner == nil {
		return failure(api.CodeContainmentUnknown, "credential exec has no exact native runner")
	}
	return native.awaitCredentialExec(ctx, record.Spec.Handoff.Spec.Runner.Executable)
}

func (m *leaseManager) openCredentialGate(ctx context.Context, registration gateOpenRegistration) (result api.ProcessHandle, resultErr error) {
	m.credentialLeaseMu.Lock()
	defer m.credentialLeaseMu.Unlock()
	guard, err := m.lockCredentials(ctx, registration)
	if err != nil {
		return result, err
	}
	if guard == nil {
		return m.openGate(ctx, registration)
	}
	return m.withCredentialGuard(ctx, guard, func() (api.ProcessHandle, error) { return m.openGate(ctx, registration) })
}

func (m *leaseManager) withCredentialGuard(ctx context.Context, guard api.CredentialGateGuard, open func() (api.ProcessHandle, error)) (result api.ProcessHandle, resultErr error) {
	defer func() { resultErr = errors.Join(resultErr, guard.Close()) }()
	if err := guard.Check(ctx); err != nil {
		return result, err
	}
	m.activeCredentialGuard = guard
	defer func() { m.activeCredentialGuard = nil }()
	return open()
}

func (m *leaseManager) prepareCredentialExec(ctx context.Context, record leaseRecord) (_ *credentialExecDelivery, resultErr error) {
	if record.Credentials == nil {
		return nil, nil
	}
	if m.credentials == nil || record.Credentials.Record == nil || record.Credentials.State != "held" {
		return nil, failure(api.CodeContainmentUnknown, "credential exec has no acknowledged projection")
	}
	p := *record.Credentials.Record
	held := m.credentials.held[p.Authority.ID]
	if held == nil {
		return nil, failure(api.CodeContainmentUnknown, "credential exec lost its held objects")
	}
	native, ok := m.gates[record.Lease.ID].(*nativeGate)
	if !ok || native.control == nil {
		return nil, failure(api.CodeContainmentUnknown, "credential exec lost its native readiness channel")
	}
	packet := credentialExecPacket{Record: p, Objects: []credentialExecObject{}}
	delivery := &credentialExecDelivery{}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, delivery.close())
		}
	}()
	for i, target := range p.Authority.Targets {
		if target.EnvironmentName == "" {
			continue
		}
		if i >= len(held.files) {
			return nil, failure(api.CodeContainmentUnknown, "credential exec lost a selected held object")
		}
		_, st, err := credentialObject(held.files[i])
		if err != nil {
			return nil, err
		}
		if target.Delivery == "env" {
			fact, err := credentialDescriptor(held.files[i], true)
			if err != nil || fact.OwnerUID != 0 || fact.Links != 0 || !fact.ReadOnly || !fact.CloseOnExec {
				return nil, failure(api.CodeIntegrity, "credential environment holding is not a sealed root-owned anonymous object")
			}
		}
		// Never send a lane-owned file descriptor into the child. A distinct
		// root-owned sealed copy prevents /proc fd reopening around a ro view.
		export, err := anonymousCredential(ctx, held.files[i], st.Size)
		if err != nil {
			return nil, err
		}
		delivery.exports = append(delivery.exports, export)
		id, _, err := credentialObject(export)
		if err != nil {
			return nil, err
		}
		packet.Objects = append(packet.Objects, credentialExecObject{Key: target.Key, Name: target.EnvironmentName, ObjectID: id})
	}
	data, err := json.Marshal(packet)
	if err != nil {
		return nil, failure(api.CodeIntegrity, "cannot encode credential exec metadata")
	}
	encoded, err := frame(data)
	if err != nil || len(encoded) > 64<<10 {
		return nil, failure(api.CodeBudget, "credential exec metadata exceeds private packet bound")
	}
	delivery.data = encoded
	return delivery, nil
}

func (m *leaseManager) deliverCredentialExec(ctx context.Context, record leaseRecord, delivery *credentialExecDelivery) error {
	if record.Credentials == nil && delivery == nil {
		return nil
	}
	native, ok := m.gates[record.Lease.ID].(*nativeGate)
	if !ok || native.control == nil || delivery == nil || len(delivery.data) == 0 {
		return failure(api.CodeContainmentUnknown, "credential exec lost its prepared handoff")
	}
	if err := native.innerLifetime(m.bootID); err != nil {
		return err
	}
	actual, err := measureProcessUmask(strconv.Itoa(native.innerPID))
	if err != nil || native.bootstrapUmask == nil || actual != *native.bootstrapUmask || actual != 0077 {
		return failure(api.CodeForbidden, "credential bootstrap lost its measured private umask")
	}
	rights := make([]int, len(delivery.exports))
	for i, file := range delivery.exports {
		rights[i] = int(file.Fd())
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := native.control.SetWriteDeadline(deadline); err != nil {
		return failure(api.CodeUnavailable, "cannot bound credential exec handoff")
	}
	n, oob, err := native.control.WriteMsgUnix(delivery.data, unix.UnixRights(rights...), nil)
	if err != nil || n != len(delivery.data) || len(rights) > 0 && oob != len(unix.UnixRights(rights...)) {
		return failure(api.CodeContainmentUnknown, "credential exec descriptor handoff is uncertain")
	}
	return nil
}

func (g *nativeGate) awaitCredentialExec(ctx context.Context, executable api.Executable) error {
	defer helperStage(ctx, "credential_exec_proof")()
	if g.execAck == nil {
		return failure(api.CodeContainmentUnknown, "credential exec lacks its bootstrap-only close proof")
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := g.execAck.SetReadDeadline(deadline); err != nil {
		return failure(api.CodeUnavailable, "cannot bound credential exec acknowledgement")
	}
	var data [1]byte
	n, err := g.execAck.Read(data[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return failure(api.CodeContainmentUnknown, "credential bootstrap did not close control at exec")
	}
	if err := g.innerLifetime(strings.SplitN(g.innerGeneration, ":", 2)[0]); err != nil {
		return err
	}
	file, err := os.Open("/proc/" + strconv.Itoa(g.innerPID) + "/exe")
	if err != nil {
		return failure(api.CodeContainmentUnknown, "credential vendor exec could not be observed")
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil {
		return failure(api.CodeContainmentUnknown, "credential vendor executable is unreadable")
	}
	finishHash := helperStage(ctx, "credential_exec_hash")
	hashErr := verifyExecutableFileRead(file, api.ReleaseArtifact{OS: "linux", Arch: runtime.GOARCH, Bytes: st.Size(), SHA256: executable.SHA256}, g.execHashRead)
	finishHash()
	if hashErr != nil {
		return hashErr
	}
	if err := errors.Join(g.execAck.Close(), g.control.Close()); err != nil {
		return failure(api.CodeContainmentUnknown, "credential exec acknowledgement close failed")
	}
	return nil
}

func environmentNames(environment []string) []string {
	var names []string
	for _, item := range environment {
		if name, _, ok := strings.Cut(item, "="); ok {
			names = append(names, name)
		}
	}
	return names
}

func finalCredentialEnvironment(payload gatePayload) (environment []string, resultErr error) {
	peer, err := unix.GetsockoptUcred(5, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return nil, failure(api.CodeUnauthenticated, "credential exec has no inherited native peer")
	}
	if err := unix.SetsockoptInt(5, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		return nil, failure(api.CodePrerequisite, "credential exec writer verification is unavailable")
	}
	duplicate, err := unix.FcntlInt(uintptr(5), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "credential exec channel cannot be pinned")
	}
	file := os.NewFile(uintptr(duplicate), "private-credential-exec")
	connection, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "credential exec channel is unavailable")
	}
	defer connection.Close()
	conn := connection.(*net.UnixConn)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, failure(api.CodeUnavailable, "cannot bound credential exec receive")
	}
	data := make([]byte, 64<<10)
	oob := make([]byte, unix.CmsgSpace(64*4)+unix.CmsgSpace(unix.SizeofUcred))
	var n, control, flags int
	var receiveErr error
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	err = raw.Read(func(fd uintptr) bool {
		n, control, flags, _, receiveErr = unix.Recvmsg(int(fd), data, oob, unix.MSG_CMSG_CLOEXEC)
		return !errors.Is(receiveErr, unix.EAGAIN) && !errors.Is(receiveErr, unix.EWOULDBLOCK)
	})
	var files []*os.File
	defer func() {
		resultErr = errors.Join(resultErr, closeCredentialFiles(files))
		clear(data)
		if resultErr != nil {
			environment = nil
		}
	}()
	messages, parseErr := unix.ParseSocketControlMessage(oob[:control])
	valid, unknown := false, false
	for _, message := range messages {
		if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_RIGHTS {
			fds, e := unix.ParseUnixRights(&message)
			if e != nil {
				unknown = true
			}
			for _, fd := range fds {
				files = append(files, os.NewFile(uintptr(fd), "credential-exec-copy"))
			}
		} else if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_CREDENTIALS {
			actual, e := unix.ParseUnixCredentials(&message)
			if e != nil || valid || *actual != *peer {
				unknown = true
			} else {
				valid = true
			}
		} else {
			unknown = true
		}
	}
	if err != nil || receiveErr != nil || parseErr != nil || !valid || unknown || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n < 4 || int(binary.BigEndian.Uint32(data[:4])) != n-4 || len(files) > 64 {
		return nil, failure(api.CodeUnauthenticated, "credential exec packet or ancillary ownership was refused")
	}
	var packet credentialExecPacket
	if decodeStrict(data[4:n], &packet) != nil || len(packet.Objects) != len(files) || packet.Record.Authority.Request.Prepared.GateID != payload.GateID || packet.Record.Authority.Request.Prepared.ID != payload.PreparedID || packet.Record.Authority.Request.Handoff.SpecSHA256 != payload.SpecSHA256 {
		return nil, failure(api.CodeIntegrity, "credential exec metadata changed the sealed prepared gate")
	}
	facts, err := credentialExecFacts(payload)
	if err != nil {
		return nil, err
	}
	facts.VendorNames = environmentNames(payload.Environment)
	for _, object := range packet.Objects {
		facts.VendorNames = append(facts.VendorNames, object.Name)
	}
	if err := api.ValidateCredentialEnvironment(packet.Record, facts); err != nil {
		return nil, err
	}
	environment = append([]string{}, payload.Environment...)
	for i, object := range packet.Objects {
		matched := false
		keyStore := false
		for _, target := range packet.Record.Authority.Targets {
			if target.Key == object.Key && target.EnvironmentName == object.Name && object.Name != "" {
				matched = true
				keyStore = keyStoreTarget(packet.Record.Authority, target)
			}
		}
		fact, e := credentialDescriptor(files[i], true)
		if !matched || e != nil || fact.ObjectID != object.ObjectID || fact.OwnerUID != peer.Uid || fact.OwnerUID == payload.UID || !fact.Regular || !fact.ReadOnly || !fact.CloseOnExec || fact.Links != 0 || fact.Mode != 0600 || fact.Size <= 0 || fact.Size > api.MaxFrameBytes {
			return nil, failure(api.CodeIntegrity, "credential exec copy differs from its selected private object")
		}
		value, e := io.ReadAll(io.LimitReader(files[i], api.MaxFrameBytes+1))
		if e != nil || int64(len(value)) != fact.Size || strings.IndexByte(string(value), 0) >= 0 {
			clear(value)
			return nil, failure(api.CodeIntegrity, "credential exec value is incomplete or invalid")
		}
		if keyStore {
			key, err := claudock.DecodeKeyStore(value)
			clear(value)
			if err != nil {
				return nil, err
			}
			value = key
		}
		environment = append(environment, object.Name+"="+string(value))
		clear(value)
	}
	return environment, nil
}

func credentialExecFacts(payload gatePayload) (api.CredentialExecEnvironment, error) {
	status, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		return api.CredentialExecEnvironment{}, failure(api.CodeContainmentUnknown, "credential exec privileges are unreadable")
	}
	var capabilities uint64
	seen := map[string]bool{}
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || key != "CapEff" && key != "CapPrm" && key != "CapAmb" {
			continue
		}
		actual, e := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		if e != nil {
			return api.CredentialExecEnvironment{}, failure(api.CodeIntegrity, "credential exec privilege observation is malformed")
		}
		capabilities |= actual
		seen[key] = true
	}
	if !payload.IsolationReady || payload.UID == 0 || payload.GID == 0 || uint32(os.Getuid()) != payload.UID || uint32(os.Getgid()) != payload.GID || capabilities != 0 || len(seen) != 3 {
		return api.CredentialExecEnvironment{}, failure(api.CodeForbidden, "credential values cannot be read before the final unprivileged isolated exec")
	}
	return api.CredentialExecEnvironment{PreparedID: payload.PreparedID, Stage: "vendor_exec", UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), Capabilities: &capabilities, Backend: "linux-bwrap-landlock", IsolationReady: payload.IsolationReady, ObservedAt: gateTimestamp(), EarlierNames: environmentNames(os.Environ())}, nil
}
