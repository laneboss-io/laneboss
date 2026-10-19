package dataworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/reviewjob"
	"laneboss.io/laneboss/internal/v2/testjob"
)

type TestJob struct {
	Principal api.WorkerPrincipal
	Scope     api.Scope
	Bootstrap api.WorkerBootstrap
	Read      func(context.Context, api.BlobReadRequest) (api.BlobChunk, error)
	Clock     api.Clock
	// Only the fixed native entry opens these roots. Unit tests use actual
	// private files; serialized labels cannot open roots or select executables.
	Workspace  *os.Root
	Directory  string
	Executable *os.File
}

type testOutput struct {
	bytes.Buffer
	maximum int
}

func (b *testOutput) Write(raw []byte) (int, error) {
	if len(raw) > b.maximum-b.Len() {
		return 0, lstate.Error(api.CodeBudget, "TestChild output exceeds its retained bound")
	}
	return b.Buffer.Write(raw)
}

func RunTest(ctx context.Context, job TestJob) (receipt api.WorkerResultReceipt, resultErr error) {
	p := job.Principal
	if missing(job.Bootstrap) || missing(job.Clock) || job.Read == nil || job.Workspace == nil || job.Executable == nil || job.Directory == "" {
		return receipt, lstate.Error(api.CodePrerequisite, "TestChild requires its native worker and held private workspace/executable")
	}
	if p.Lease.Kind != "test" || p.Lease.Input.Class != "manifest" || job.Scope.Actor != p.Record.Actor || job.Scope.LaunchID != p.Record.ID || job.Scope.Config != p.Endpoint.Config {
		return receipt, lstate.Error(api.CodeForbidden, "TestChild cannot borrow another actor or worker kind")
	}
	if err := api.ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, api.WorkerInputRead, job.Clock.Now()); err != nil {
		return receipt, err
	}
	envelope, err := job.Bootstrap.WorkerInput(ctx, job.Scope, api.WorkerInputRequest{LeaseID: p.Lease.ID})
	if err != nil {
		return receipt, err
	}
	if err := api.ValidateWorkerInput(p, envelope, job.Clock.Now()); err != nil {
		return receipt, err
	}
	var input testjob.Input
	if err := api.DecodeObject(envelope.Bytes, &input); err != nil {
		return receipt, err
	}
	if input.Schema != "laneboss.test-input.v2" || input.Request.Child != p.Lease.Target ||
		input.Subject.Target != p.Lease.Target || input.Plan.Kind != "test" || input.Plan.Input != input.Request.Candidate || input.Subject.EndSeq == 0 || !manifest.ValidID(api.ID(input.Name)) {
		return receipt, lstate.Error(api.CodeIntegrity, "TestChild input changed its exact candidate, plan or frozen subject")
	}
	plan := input.Plan
	if manifest.Budget(plan.Budget) != nil || len(plan.Argv) == 0 || len(plan.Argv) > 4096 || plan.Budget != p.Claim.Record.Effect.Worker.Budget {
		return receipt, manifest.Invalid("TestChild plan has invalid argv or exceeds its native budget")
	}
	for _, arg := range plan.Argv {
		if strings.ContainsRune(arg, 0) {
			return receipt, manifest.Invalid("TestChild argv contains a zero byte")
		}
	}
	info, err := job.Executable.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<20 {
		return receipt, lstate.Error(api.CodeIntegrity, "TestChild executable is not its bounded enrolled file")
	}
	digest, err := hashOpenTestFile(job.Executable)
	if err != nil || digest != plan.Executable.SHA256 {
		return receipt, lstate.Error(api.CodeIntegrity, "TestChild executable bytes differ from its enrolled pin")
	}
	raw, err := readWorkerObject(ctx, job.Read, input.Request.Candidate)
	if err != nil {
		return receipt, err
	}
	var tree api.ObjectManifest
	if api.DecodeObject(raw, &tree) != nil || manifest.Object(tree) != nil {
		return receipt, manifest.Invalid("TestChild candidate is not its retained object tree")
	}
	var copied uint64
	for _, entry := range tree.Entries {
		if entry.Path == "." {
			continue
		}
		parent := filepath.Dir(entry.Path)
		if parent != "." {
			if err := job.Workspace.MkdirAll(parent, 0700); err != nil {
				return receipt, err
			}
		}
		switch entry.Kind {
		case "directory":
			if err := job.Workspace.MkdirAll(entry.Path, os.FileMode(entry.Mode)); err != nil {
				return receipt, err
			}
		case "symlink":
			if err := job.Workspace.Symlink(entry.LinkTarget, entry.Path); err != nil {
				return receipt, err
			}
		case "file":
			var body []byte
			for _, ref := range manifest.ContentRefs(entry) {
				part, err := readWorkerObject(ctx, job.Read, ref)
				if err != nil {
					return receipt, err
				}
				body = append(body, part...)
			}
			if entry.Assembly != nil && (int64(len(body)) != entry.Assembly.Bytes || manifest.Hash(body) != entry.Assembly.SHA256) {
				return receipt, lstate.Error(api.CodeIntegrity, "TestChild candidate assembly changed")
			}
			copied += uint64(len(body))
			if copied > plan.Budget.DiskBytes {
				return receipt, lstate.Error(api.CodeBudget, "TestChild candidate exceeds its disk budget")
			}
			file, err := job.Workspace.OpenFile(entry.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(entry.Mode))
			if err != nil {
				return receipt, err
			}
			_, writeErr := file.Write(body)
			closeErr := file.Close()
			if err := errors.Join(writeErr, closeErr); err != nil {
				return receipt, err
			}
		default:
			return receipt, manifest.Invalid("TestChild candidate entry has an unsupported kind")
		}
	}
	deadline, cancel := context.WithTimeout(ctx, time.Duration(plan.Budget.WallMS)*time.Millisecond)
	defer cancel()
	command := exec.CommandContext(deadline, testExecutablePath(job.Executable), plan.Argv[1:]...)
	command.Args[0] = plan.Argv[0]
	command.Dir = job.Directory
	command.Env = []string{"PATH=/runtime:/usr/bin:/bin", "HOME=" + job.Directory, "TMPDIR=" + job.Directory, "LANG=C", "GIT_CONFIG_NOSYSTEM=1"}
	stdout, stderr := &testOutput{maximum: api.MaxFrameBytes / 4}, &testOutput{maximum: api.MaxFrameBytes / 4}
	outPipe, err := command.StdoutPipe()
	if err != nil {
		return receipt, err
	}
	errPipe, err := command.StderrPipe()
	if err != nil {
		outPipe.Close()
		return receipt, err
	}
	outID, err := measuredTestPipe(outPipe)
	if err != nil {
		outPipe.Close()
		errPipe.Close()
		return receipt, err
	}
	errID, err := measuredTestPipe(errPipe)
	if err != nil {
		outPipe.Close()
		errPipe.Close()
		return receipt, err
	}
	if err := command.Start(); err != nil {
		outPipe.Close()
		errPipe.Close()
		return receipt, err
	}
	drained := make(chan error, 2)
	finished := make(chan struct{})
	go func() {
		select {
		case <-deadline.Done():
			outPipe.Close()
			errPipe.Close()
		case <-finished:
		}
	}()
	go func() {
		_, err := io.Copy(stdout, outPipe)
		if err != nil {
			outPipe.Close()
		}
		drained <- err
	}()
	go func() {
		_, err := io.Copy(stderr, errPipe)
		if err != nil {
			errPipe.Close()
		}
		drained <- err
	}()
	readErr := errors.Join(<-drained, <-drained)
	err = command.Wait()
	close(finished)
	if readErr != nil {
		return receipt, readErr
	}
	if deadline.Err() != nil {
		return receipt, deadline.Err()
	}
	code := 0
	if err != nil {
		var exited *exec.ExitError
		if !errors.As(err, &exited) || exited.ExitCode() < 0 {
			return receipt, err
		}
		code = exited.ExitCode()
	}
	result := testjob.Result{Schema: "laneboss.test-result.v2", Check: reviewjob.CheckRecord{Schema: "laneboss.check.v2", Name: input.Name,
		Target: p.Lease.Target, EndSeq: input.Subject.EndSeq, SnapshotSHA256: input.Subject.Snapshot.SHA256, ExitCode: code, WorkerLeaseID: p.Lease.ID, OperationID: p.Lease.OperationID},
		Stdout: append([]byte{}, stdout.Bytes()...), Stderr: append([]byte{}, stderr.Bytes()...), StdoutPipeID: outID, StderrPipeID: errID}
	raw, err = json.Marshal(result)
	if err == nil {
		raw, err = api.CanonicalJSON(raw)
	}
	if err != nil {
		return receipt, err
	}
	if len(raw) > api.MaxFrameBytes {
		return receipt, lstate.Error(api.CodeBudget, "TestChild result exceeds its native frame")
	}
	if err := api.ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, api.WorkerResultAppend, job.Clock.Now()); err != nil {
		return receipt, err
	}
	submission := api.WorkerResultSubmission{LeaseID: p.Lease.ID, ExpectedGeneration: p.Lease.Generation, InputSHA256: p.Lease.Input.SHA256, Result: raw}
	receipt, err = job.Bootstrap.WorkerResult(ctx, job.Scope, submission)
	if err != nil {
		return receipt, err
	}
	return receipt, api.ValidateWorkerResult(p, submission, receipt, job.Clock.Now())
}

func measuredTestPipe(stream io.ReadCloser) (api.ID, error) {
	file, ok := stream.(*os.File)
	if !ok {
		return "", lstate.Error(api.CodeIntegrity, "TestChild stream has no actual native pipe")
	}
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeNamedPipe == 0 {
		return "", lstate.Error(api.CodeIntegrity, "TestChild stream is not a measured pipe inode")
	}
	return api.ID(fmt.Sprintf("pipe-%d-%d", stat.Dev, stat.Ino)), nil
}

func hashOpenTestFile(file *os.File) (api.Digest, error) {
	raw, err := io.ReadAll(io.NewSectionReader(file, 0, 256<<20+1))
	if err != nil {
		return "", err
	}
	return manifest.Hash(raw), nil
}
