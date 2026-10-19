//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestWorkerInputFD(t *testing.T) {
	input := []byte(" { \n\"task\": \"exact retained bytes\" }\n")
	ref := api.BlobRef{ID: "fixed-worker-input", Class: "materialize_input", Bytes: int64(len(input)), SHA256: digestBytes(input)}
	file, err := sealWorkerInput(input, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	actual, err := io.ReadAll(file)
	if err != nil || string(actual) != string(input) {
		t.Fatal("acceptance: worker immutable input bytes changed")
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&bootstrapSeals != bootstrapSeals {
		t.Fatal("acceptance: worker input lacks all immutable seals")
	}
	var st unix.Stat_t
	if unix.Fstat(int(file.Fd()), &st) != nil || st.Mode&07777 != 0444 {
		t.Fatal("acceptance: worker input projection is writable")
	}
	if _, err := file.WriteAt([]byte("x"), 0); !errors.Is(err, unix.EPERM) {
		t.Fatal("acceptance: sealed worker input accepted a write")
	}
	if err := unix.Ftruncate(int(file.Fd()), int64(len(input)+1)); !errors.Is(err, unix.EPERM) {
		t.Fatal("acceptance: sealed worker input accepted truncation")
	}
}

func TestWorkerInputPin(t *testing.T) {
	input := []byte(`{"task":"retained"}`)
	ref := api.BlobRef{ID: "fixed-worker-input", Class: "materialize_input", Bytes: int64(len(input)), SHA256: digestBytes(input)}
	for _, fault := range []string{"bytes", "length", "class", "id"} {
		t.Run(fault, func(t *testing.T) {
			pin, data := ref, append([]byte(nil), input...)
			switch fault {
			case "bytes":
				data[2] ^= 1
			case "length":
				pin.Bytes--
			case "class":
				pin.Class = "manifest"
			case "id":
				pin.ID = ""
			}
			file, err := sealWorkerInput(data, pin)
			if file != nil {
				file.Close()
			}
			if err == nil {
				t.Fatal("acceptance: worker input ignored its immutable pin")
			}
			requireCode(t, err, api.CodeIntegrity)
		})
	}
}

func TestWorkerNativeBinding(t *testing.T) {
	_, job, binding := dataTestReg(t)
	r := job.Reg
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion,
		Config: binding.Config, Class: api.EndpointWorker, LaunchID: r.LaunchID, WorkerLeaseID: r.Worker.ID, Target: &r.Worker.Target,
		ServiceUID: binding.Service.UID, ServiceGID: binding.Service.GID, Socket: "/runtime/laneboss-worker.sock", Backend: "linux-bwrap-landlock",
		ServiceVersion: binding.Release.Version, ArtifactSHA256: binding.Artifact.SHA256, InstallationGeneration: binding.Generation, EndpointGeneration: 1}
	observed := DataWorkerNativeBinding{Selector: r.Request, Lease: job.Lease, Endpoint: endpoint, BootID: "shape-boot",
		Prepared: api.PreparedLaunch{ID: "prepared-worker", GateID: "gate-worker", Target: r.Worker.Target, ContainmentID: job.Lease.ContainmentID, EndpointGeneration: binding.Generation, SpecSHA256: testDigest("spec"), ProcessGeneration: "shape-boot:1"},
		Peer:     api.PeerFacts{HostUID: job.Lease.UID, HostGID: job.Lease.GID, HostPID: 2, ProcessGeneration: "shape-boot:2", ContainmentID: job.Lease.ContainmentID}}
	if err := validateWorkerNative(observed, r, binding); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"selector", "uid", "pid", "prepared", "endpoint", "artifact"} {
		t.Run(fault, func(t *testing.T) {
			changed := observed
			switch fault {
			case "selector":
				changed.Selector.StageID = "foreign"
			case "uid":
				changed.Peer.HostUID = binding.Service.UID
			case "pid":
				changed.Peer.HostPID = 0
			case "prepared":
				changed.Prepared.ContainmentID = "foreign"
			case "endpoint":
				changed.Endpoint.WorkerLeaseID = "foreign"
			case "artifact":
				changed.Endpoint.ArtifactSHA256 = testDigest("foreign")
			}
			if err := validateWorkerNative(changed, r, binding); err == nil {
				t.Fatal("acceptance: native worker binding lost its retained tuple")
			}
		})
	}
}

func proofStoreFixture(t *testing.T) (*os.Root, *os.Root, probeReservation) {
	t.Helper()
	dir := privateTestDir(t)
	for _, name := range []string{"proofs", "proofs/probe-fixture"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(dir, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	proofs, err := proofRoot(root, "proofs", uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer proofs.Close()
	item, err := proofRoot(proofs, "probe-fixture", uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { item.Close() })
	held := probeReservation{Schema: "laneboss.isolation-reservation.v1", ID: "probe-fixture", BootID: "fixture-boot", Phase: "reserved",
		Lease: api.HelperLease{ID: "probe-fixture", ContainmentID: "probe-cgroup", UID: testBinding().Lanes[0].UID}}
	if err := proofWrite(item, "reservation.json", held); err != nil {
		t.Fatal(err)
	}
	return root, item, held
}

func TestProofRecovery(t *testing.T) {
	root, item, held := proofStoreFixture(t)
	if err := checkIsolationReservations(root, uint32(os.Geteuid())); err == nil {
		t.Fatal("acceptance: interrupted isolation probe freed its retained UID")
	}
	held.Phase = "collected"
	if err := proofWrite(item, "reservation.json", held); err != nil {
		t.Fatal(err)
	}
	if err := checkIsolationReservations(root, uint32(os.Geteuid())); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(item.Name(), "pending"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkIsolationReservations(root, uint32(os.Geteuid())); err == nil {
		t.Fatal("acceptance: pending isolation proof was credited as collected")
	}
}

func TestProofReadBack(t *testing.T) {
	_, item, _ := proofStoreFixture(t)
	nonce, err := randomID("proof-")
	if err != nil {
		t.Fatal(err)
	}
	value := struct{ Nonce api.ID }{nonce}
	if err := proofWrite(item, "proof.json", value); err != nil {
		t.Fatal(err)
	}
	raw, err := proofRead(item, "proof.json", uint32(os.Geteuid()))
	expected, encodeErr := json.Marshal(value)
	if err != nil || encodeErr != nil || string(raw) != string(expected) {
		t.Fatal("acceptance: retained proof bytes were not read back")
	}
	if err := os.Link(filepath.Join(item.Name(), "proof.json"), filepath.Join(item.Name(), "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := proofRead(item, "proof.json", uint32(os.Geteuid())); err == nil {
		t.Fatal("acceptance: linked isolation proof was accepted")
	}
}

func TestProofPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if err := isolationPipeEmpty(reader); err != nil {
		t.Fatal(err)
	}
	nonce, err := randomID("pipe-")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString(string(nonce)); err != nil {
		t.Fatal(err)
	}
	if err := isolationPipeEmpty(reader); err == nil {
		t.Fatal("acceptance: pre-release canary output was ignored")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw, err := readIsolationPipe(ctx, reader)
	if err != nil || string(raw) != string(nonce) {
		t.Fatal("acceptance: isolation pipe lost its exact marker or deadline")
	}
}

func TestProofPool(t *testing.T) {
	binding := testBinding()
	first, err := isolationPool(binding, nil)
	if err != nil || first.UID == 0 || first.UID == binding.Service.UID {
		t.Fatal("probe did not select an installed pool identity")
	}
	records := []leaseRecord{}
	for _, selected := range binding.Lanes {
		records = append(records, leaseRecord{Phase: "active", Lease: api.HelperLease{UID: selected.UID}})
	}
	if _, err := isolationPool(binding, records); err == nil {
		t.Fatal("acceptance: isolation probe reused an allocated pool UID")
	}
	for i := range records {
		records[i].Phase = "released"
	}
	if _, err := isolationPool(binding, records); err != nil {
		t.Fatal(err)
	}
}

// Adversarial wire-shape validation only. This fixture is never installed or
// submitted to the provider and is not native boundary measurement evidence.
func isolationShape(t *testing.T) (isolationProof, api.BlobRef, installation, time.Time) {
	t.Helper()
	binding := testBinding()
	account := binding.Lanes[0]
	nonce, err := randomID("shape-")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	zero, survivors := 0, uint64(0)
	runtimeRef := api.BlobRef{ID: "runtime", Class: "manifest", SHA256: testDigest("runtime"), Bytes: 100}
	p := isolationProof{Schema: "laneboss.isolation-proof.v1", Config: binding.Config, BootID: "shape-boot", InstallationGeneration: binding.Generation, ArtifactSHA256: binding.Artifact.SHA256,
		Runtime: runtimeRef, Kernel: "6.6-shape", LandlockABI: 3, Nonce: nonce, UID: account.UID, GID: account.GID, InputSHA256: testDigest("input"),
		Peer:         api.PeerFacts{HostUID: account.UID, HostGID: account.GID, HostPID: 2, ProcessGeneration: "shape-boot:1", ContainmentID: "shape-cgroup"},
		CgroupDevice: "1", CgroupInode: "2", NamespaceDevice: "3", NamespaceInode: "4", PrivateNamespaces: true, HostControl: true, ClosedGate: true, SecondReleaseRefused: true,
		Limits:     limitValues(leaseRecord{Request: api.HelperLeaseRequest{Budget: isolationBudget()}}),
		PipeMarker: string(nonce) + "\n", Collected: true, ObservedAt: api.Timestamp(now.Format(time.RFC3339Nano)),
		Observation: api.ProcessObservation{Handle: api.ProcessHandle{ID: "shape-proof", ContainmentID: "shape-cgroup", Generation: "shape-boot:2"}, State: "exited", ExitCode: &zero, Survivors: &survivors}}
	p.Canary = isolationCanary{Nonce: nonce, UID: account.UID, GID: account.GID, InputSHA256: p.InputSHA256, WrittenSHA256: digestBytes([]byte(nonce)), NoNewPrivileges: 1, Seccomp: 2,
		UnshareErrno: int(unix.EPERM), RuntimeErrno: int(unix.EROFS), LandlockErrno: int(unix.EACCES), NetworkErrno: int(unix.ENETUNREACH), PrivateProc: true}
	return p, runtimeRef, binding, now
}

func TestProofValidation(t *testing.T) {
	base, runtimeRef, binding, now := isolationShape(t)
	pin := api.BlobRef{ID: base.Observation.Handle.ID, Class: "manifest", SHA256: testDigest("proof"), Bytes: 1}
	capabilities, err := isolationCapabilities(base, pin, binding, runtimeRef, now)
	if err != nil || !capabilities.Available || len(capabilities.Checks) != 9 {
		t.Fatal("complete adversarial shape did not reach validator")
	}
	for _, check := range capabilities.Checks {
		if !check.Available || check.Evidence == nil || *check.Evidence != pin {
			t.Fatal("validated shape lost its exact proof pin")
		}
	}
	for _, fault := range []string{"empty", "nonce", "generation", "uid", "host-control", "namespace", "proc", "limits", "closed", "reuse", "seccomp", "runtime", "landlock", "network", "input", "pipe", "survivors", "collected", "expired", "reference"} {
		t.Run(fault, func(t *testing.T) {
			p, ref := base, pin
			switch fault {
			case "empty":
				p = isolationProof{}
			case "nonce":
				p.Canary.Nonce = "foreign"
			case "generation":
				p.InstallationGeneration++
			case "uid":
				p.UID = binding.Service.UID
			case "host-control":
				p.HostControl = false
			case "namespace":
				p.PrivateNamespaces = false
			case "proc":
				p.Canary.PrivateProc = false
			case "limits":
				p.Limits = append([][2]string(nil), p.Limits...)
				p.Limits[0][1] = "0"
			case "closed":
				p.ClosedGate = false
			case "reuse":
				p.SecondReleaseRefused = false
			case "seccomp":
				p.Canary.UnshareErrno = 0
			case "runtime":
				p.Canary.RuntimeErrno = 0
			case "landlock":
				p.Canary.LandlockErrno = 0
			case "network":
				p.Canary.NetworkErrno = 0
			case "input":
				p.Canary.InputSHA256 = testDigest("changed")
			case "pipe":
				p.PipeMarker = strings.TrimSpace(p.PipeMarker)
			case "survivors":
				live := uint64(1)
				p.Observation.Survivors = &live
			case "collected":
				p.Collected = false
			case "expired":
				p.ObservedAt = api.Timestamp(now.Add(-2 * time.Minute).Format(time.RFC3339Nano))
			case "reference":
				ref.ID = "foreign"
			}
			if _, err := isolationCapabilities(p, ref, binding, runtimeRef, now); err == nil {
				t.Fatal("acceptance: incomplete isolation measurements were credited")
			}
		})
	}
}
