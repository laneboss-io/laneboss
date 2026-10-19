//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// This unprivileged subprocess exercises the same inherited socket capability
// as the native adapter. It performs real HTTP and returns only measured bytes.
func init() {
	if len(os.Args) != 2 || os.Args[1] != "--judge-relay-canary" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
	if err != nil {
		os.Exit(2)
	}
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/proc/self/fd/3")
	}}
	client := &http.Client{Transport: transport}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://fixture.invalid/v1/systemone", bytes.NewReader(body))
	if err != nil {
		os.Exit(2)
	}
	response, err := client.Do(request)
	if err != nil {
		os.Exit(3)
	}
	answer, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || response.StatusCode != 200 {
		os.Exit(4)
	}
	if _, err := os.Stdout.Write(answer); err != nil {
		os.Exit(5)
	}
	os.Exit(0)
}

// This measures a distinct-UID native prepared gate, not a provider delivery.
// The source claim/enrollment is a component input. No D6 approval is asserted.
func TestJudgeGateNative(t *testing.T) {
	workerLaunchCanary(t, false, judgeGateCanary)
}

func judgeGateCanary(t *testing.T, ctx context.Context, m *leaseManager, data dataReg, runtime api.BlobRef, executable api.Executable) {
	t.Helper()
	parent, err := m.find(data.Request.AgentLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	beforeJobs, err := m.captureJobs(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	closeProc, err := mountHelperProc(m.binding.runtimePath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeProc(); err != nil {
			t.Error(err)
		}
	}()
	ref := func(id api.ID, class string, raw []byte) api.BlobRef {
		return api.BlobRef{ID: id, Class: class, Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
	}
	deadline := api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
	command := []byte("git status --short")
	request := api.JudgeRequest{ID: "native-ask", Purpose: "preview", Rules: []api.JudgeRule{}, Decisions: []api.DecisionCandidate{}, Task: []byte("native task"),
		Command: &api.CommandData{Tool: "shell", Command: command, RawSHA256: digestBytes(command), CWD: "/work", Argv: []string{}, DeclaredPaths: []string{}},
		Context: api.JudgeContext{Config: m.binding.Config, Target: data.Worker.Target, LogicalTurnID: "native-turn"},
		Config: api.JudgeConfig{Provider: api.DefaultJudgeProvider, Model: api.DefaultJudgeModel, DeploymentSHA256: digestBytes([]byte("deployment")), TokenizerSHA256: digestBytes([]byte("tokenizer")),
			ContextTokens: 32768, MaxBytes: api.MaxJudgeBytes, MaxQuestions: 12, CommandDeadlineMS: 2000, GuidanceDeadlineMS: 5000, OutagePolicy: "critical-only"},
		DeadlineMS: 2000, MaxCostMicros: 1}
	requestRaw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	cause := parent.Request.Cause
	cause.ID, cause.Kind, cause.CauseOperationID, cause.EffectID, cause.Target = "judge-execution", api.InternalJudgeEvaluate, "judge-operation", "judge-execution", data.Worker.Target
	execution := api.JudgeExecution{ID: cause.ID, Pin: digestBytes(requestRaw), Request: request, Intent: cause, ClaimID: "judge-claim", AttemptID: "judge-attempt", Deadline: deadline, Outcome: "pending"}
	input, err := json.Marshal(execution)
	if err != nil {
		t.Fatal(err)
	}
	lease := api.WorkerLease{ID: "judge-worker", Kind: "judge", Target: data.Worker.Target, OperationID: cause.CauseOperationID, EffectID: execution.ID,
		GrantSetID: data.Worker.GrantSetID, RuntimeManifest: runtime, Generation: 1, ExpiresAt: deadline, Input: ref("judge-input", "worker_input", input)}
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "judge", Input: lease.Input, GrantSetID: lease.GrantSetID, Executable: executable, Budget: parent.Request.Budget,
		Argv: []string{"laneboss", "internal", "judge", "--binding", "/runtime/laneboss-worker.json", "--lease", string(lease.ID)}}
	childCause := cause
	childCause.Kind = api.InternalObjectRetain
	r := judgeReg{Execution: execution, Lease: lease, LaunchID: "judge-launch", Actor: api.Actor{Kind: "worker", ID: "judge-actor"}, ParentLeaseID: parent.Lease.ID, Plan: plan,
		Claim: api.EffectLease{ClaimID: execution.ClaimID, ExpiresAt: deadline, Record: api.EffectRecord{State: api.EffectClaimed, Generation: 2, ClaimID: execution.ClaimID, ClaimantID: cause.Actor.ID,
			ClaimExpiresAt: deadline, Effect: api.Effect{ID: execution.ID, OperationID: lease.OperationID, Context: &childCause, Worker: &plan}}}}
	if err := os.MkdirAll("/etc/laneboss-v2/service", 0755); err != nil {
		t.Fatal(err)
	}
	observations := make(chan []byte, 1)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed, err := io.ReadAll(r.Body)
		if err != nil || r.URL.Path != "/v1/systemone" {
			t.Error("judge relay provider request differs")
			w.WriteHeader(400)
			return
		}
		observations <- observed
		if _, err := w.Write([]byte(digestBytes(observed))); err != nil {
			t.Error(err)
		}
	}))
	defer provider.Close()
	workerCanaryJSON(t, filepath.Join("/etc/laneboss-v2/service", m.binding.Config+".json"), map[string]any{"config": m.binding.Config, "judge": request.Config, "judge_endpoint": provider.URL}, 0444)
	job := struct{ Lease api.WorkerLease }{Lease: lease}
	allocation, err := m.allocateJudge(ctx, r)
	if err != nil {
		t.Fatal("judge native allocation unavailable", err)
	}
	if allocation.UID == parent.Lease.UID || allocation.UID == m.binding.Service.UID || allocation.UID == 0 {
		t.Fatal("judge did not receive its own native UID")
	}
	current, err := m.find(parent.Lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	duringJobs, err := m.captureJobs(ctx, current)
	if err != nil || duringJobs != beforeJobs+1 {
		t.Fatal("judge native job is absent from parent release inventory", err)
	}
	again, err := m.allocateJudge(ctx, r)
	if err != nil || again != allocation {
		t.Fatal("judge allocation replay replaced its original UID", err)
	}
	base := filepath.Join("/run/laneboss-v2/services", m.binding.Config)
	for _, directory := range []string{filepath.Dir(base), base, filepath.Join(base, "workers")} {
		if err := os.MkdirAll(directory, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Dir(base), 0755); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{base, filepath.Join(base, "workers")} {
		if err := os.Chown(directory, int(m.binding.Service.UID), int(m.binding.Service.GID)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	service := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion,
		Config: m.binding.Config, Class: api.EndpointHuman, ServiceUID: m.binding.Service.UID, ServiceGID: m.binding.Service.GID,
		Socket: filepath.Join(base, "human.sock"), Backend: "linux-bwrap-landlock", ServiceVersion: m.binding.Release.Version, ArtifactSHA256: m.binding.Artifact.SHA256,
		InstallationGeneration: m.binding.Generation, EndpointGeneration: m.binding.Generation}
	service.MappedServiceUID, service.MappedServiceGID, err = wire.NamespaceServiceIDs()
	if err != nil {
		t.Fatal(err)
	}
	workerCanaryJSON(t, filepath.Join("/etc/laneboss-v2/bindings", m.binding.Config+".json"), service, 0444)
	endpoint := service
	endpoint.Class, endpoint.LaunchID, endpoint.WorkerLeaseID, endpoint.Target, endpoint.Socket = api.EndpointWorker, r.LaunchID, job.Lease.ID, &job.Lease.Target, "/runtime/laneboss-worker.sock"
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(base, "workers", string(job.Lease.ID)+".sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chown(listener.Addr().String(), int(service.ServiceUID), int(service.ServiceGID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(listener.Addr().String(), 0666); err != nil {
		t.Fatal(err)
	}
	grants := data.Grants
	grants.ID, grants.LifeID = job.Lease.GrantSetID, job.Lease.Target.LifeID
	spec := api.LaunchSpec{ID: "judge-spec", Kind: "worker", LaunchID: r.LaunchID, Target: job.Lease.Target, Worker: &r.Plan, UIDLeaseID: allocation.ID,
		RuntimeManifest: runtime, Grants: grants, Budget: r.Plan.Budget, Backend: endpoint.Backend, EndpointGeneration: allocation.EndpointGeneration, PolicyGeneration: grants.PolicyGeneration,
		Materialization: api.Materialization{GrantSetID: grants.ID, Objects: []api.MaterializedObject{}},
		Injection:       api.Injection{Target: job.Lease.Target, Outcome: "prepared", SlotIDs: []api.ID{}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}}}
	raw, err := canonicalValue(spec)
	if err != nil {
		t.Fatal(err)
	}
	register := childCause
	register.Kind = api.InternalHelperRegister
	original := ref("judge-spec-object", "launch_spec", raw)
	handoff := api.PreparedSpecHandoff{Config: m.binding.Config, Cause: register, Spec: spec, Original: original, SpecSHA256: original.SHA256, OperationID: job.Lease.OperationID, RequestID: cause.CauseRequestID}
	if _, err := m.registerJudge(ctx, judgeSeal{Reg: r, Spec: specRegistration{Handoff: handoff, Original: raw}, Endpoint: endpoint, Input: input}); err != nil {
		t.Fatal("judge native registration unavailable", err)
	}
	prepared, err := m.prepareJudge(ctx, r)
	if err != nil {
		t.Fatal("judge native gate unavailable", err)
	}
	live, ok := m.gates[allocation.ID].(*nativeGate)
	if !ok || prepared.ProcessGeneration == "" || live.innerPID <= 1 || live.released {
		t.Fatal("judge preparation did not retain an actual closed native gate")
	}
	collected := false
	defer func() {
		if collected {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := live.Close(); err != nil {
			t.Error(err)
		}
		if err := m.waitContainmentEmpty(cleanup, judgeChild(parent, judgeNative{Reg: r, Lease: allocation})); err != nil {
			t.Error(err)
		}
	}()
	if _, err := workerDescriptor(live.workerFiles[0]); err != nil {
		t.Fatal("judge input was not retained as an actual sealed descriptor", err)
	}
	if _, err := workerDescriptor(live.workerFiles[1]); err != nil {
		t.Fatal("judge endpoint was not retained as an actual sealed descriptor", err)
	}
	if err := live.innerLifetime(m.bootID); err != nil {
		t.Fatal("judge native lifetime is unavailable", err)
	}
	if err := verifyPrivateNamespaces(live.innerPID); err != nil {
		t.Fatal(err)
	}
	relay := m.judgeRelays[allocation.ID]
	if relay == nil {
		t.Fatal("judge native provider relay is absent")
	}
	fd, err := unix.Open(relay.path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	connection := os.NewFile(uintptr(fd), "native-relay-capability")
	defer connection.Close()
	program := m.binding.binaryPath()
	payload := make([]byte, 64)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, program, "--judge-relay-canary")
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: allocation.UID, Gid: allocation.GID, Groups: []uint32{}}}
	child.Env = []string{"PATH=/usr/bin:/bin", "GOMAXPROCS=1"}
	child.ExtraFiles = []*os.File{connection}
	child.Stdin = bytes.NewReader(payload)
	answer, err := child.CombinedOutput()
	if err != nil {
		t.Fatal("judge provider relay lost exact worker bytes", err)
	}
	var observed []byte
	select {
	case observed = <-observations:
	case <-ctx.Done():
		t.Fatal("judge provider relay did not reach its independent provider")
	}
	if err != nil || !bytes.Equal(observed, payload) || !bytes.Equal(answer, []byte(digestBytes(payload))) {
		t.Fatal("judge provider relay lost exact worker bytes", err)
	}
	snapshot, held, found, err := m.judgeLaunchSnapshot(ctx, prepared.ID)
	if err != nil || !found || held != live || snapshot.Judge == nil || snapshot.Native.Lease != allocation || snapshot.Native.Peer.HostUID != allocation.UID ||
		snapshot.workerRegistration().Worker.ConsumedBy != r.LaunchID {
		t.Fatal("judge did not join its original native descriptor and identity tuple", err)
	}
	ticket, err := m.containment(ctx, containmentQuery{LeaseID: allocation.ID})
	if err != nil || ticket.Kind != api.EndpointWorker || ticket.WorkerLeaseID != job.Lease.ID || ticket.Lease != allocation {
		t.Fatal("judge containment did not resolve its actual worker lease", err)
	}
	replayed, err := m.prepareJudge(ctx, r)
	if err != nil || replayed != prepared {
		t.Fatal("judge prepare replay changed its actual native gate", err)
	}
	lost := newLeaseManager(m.binding, m.bootID, m.store, m.resources)
	_, err = lost.prepareJudge(ctx, r)
	requireCode(t, err, api.CodeContainmentUnknown)
	if err := live.innerLifetime(m.bootID); err != nil {
		t.Fatal("lost-owner control replaced the original native lifetime", err)
	}
	if _, err := m.observeJudge(ctx, r, true); err != nil {
		t.Fatal("judge native preparation was not collected", err)
	}
	collected = true
	if _, err := m.observeJudge(ctx, r, true); err != nil {
		t.Fatal("judge native collection did not replay", err)
	}
	retained, err := m.find(parent.Lease.ID)
	if err != nil || len(retained.Judges) != 1 || !retained.Judges[0].Collected || retained.Judges[0].Observation == nil ||
		retained.Judges[0].Observation.State != "exited" || m.gates[allocation.ID] != nil {
		t.Fatal("judge native collection lost its measured retained record", err)
	}
	afterJobs, err := m.captureJobs(ctx, retained)
	if err != nil || afterJobs != beforeJobs {
		t.Fatal("collected judge still holds parent release inventory", err)
	}
}
