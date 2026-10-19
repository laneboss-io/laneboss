package boxrun

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
)

func TestRunHappy(t *testing.T) {
	f := newFixture(t)
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req, Suite: happySuite()})
	if err != nil || result.ExitCode != 0 || result.Verdict != "passed" || result.SuiteExit != 0 || !result.Terminated {
		t.Fatalf("happy run: %+v, error %v", result, err)
	}
	requireFile(t, filepath.Join(result.OutDir, "out", "nested", "result.txt"), "result run-demo1\n")
	requireFile(t, f.d.Config.Guest.DoneFiles[0], "")
	manifest, err := os.ReadFile(filepath.Join(result.OutDir, "out", "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(manifest)
	if result.ManifestSHA256 != hex.EncodeToString(digest[:]) || result.Files < 5 || result.Bytes <= 0 {
		t.Fatal("manifest digest or harvest counts do not describe the extracted files")
	}
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED")
	for _, event := range f.l.events {
		if text(event, "run_id") != result.RunID || text(event, "instance_id") != result.Box.ID {
			t.Fatal("ledger identity changed between phases")
		}
	}
	if number(f.l.events[1], "suite_exit") != 0 || text(f.l.events[1], "verdict") != "passed" ||
		number(f.l.events[1], "harvest_files") != float64(result.Files) ||
		number(f.l.events[1], "harvest_bytes") != float64(result.Bytes) || countCommands(f.tr, "harvest") != 1 {
		t.Fatal("done record is missing verified results, or harvest ran more than once")
	}
	if result.BilledSeconds != 40 || math.Abs(result.CostUSD-40.0/3600*(1+1.0/730)) > 1e-12 {
		t.Fatal("provider transition time or disk-inclusive billing was ignored")
	}
	if len(f.p.transports) != 2 || !strings.HasSuffix(f.p.transports[0].KnownHostsFile, "known_hosts.i-demo1") ||
		f.p.transports[0] != f.p.transports[1] {
		t.Fatal("host key file was not preserved through cleanup")
	}
	data, err := os.ReadFile(filepath.Join(result.OutDir, "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved boxcore.RunResult
	if err := json.Unmarshal(data, &saved); err != nil || !reflect.DeepEqual(saved, result) {
		t.Fatal("run.json is missing or differs from the returned result")
	}
	if traceIndex(f.trace, "transport:harvest") >= traceIndex(f.trace, "transport:done") ||
		traceIndex(f.trace, "ledger:DONE_SENT") >= traceIndex(f.trace, "provider:Describe") {
		t.Fatal("harvest and done/poll phases were reordered")
	}
}

func TestRunSuiteFail(t *testing.T) {
	f := newFixture(t)
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req, Suite: failedSuite()})
	if err != nil || result.ExitCode != 1 || result.Verdict != "failed" || result.SuiteExit != 3 ||
		result.ManifestSHA256 == "" || !result.Terminated || f.p.calls["Teardown"] != 1 {
		t.Fatalf("suite failure lost harvest or end: %+v, error %v", result, err)
	}
	requireFile(t, filepath.Join(result.OutDir, "out", "result.txt"), "failed\n")
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED")
	if number(f.l.events[1], "suite_exit") != 3 {
		t.Fatal("suite exit was omitted from the done record")
	}
}

func TestRunNeverReady(t *testing.T) {
	f := newFixture(t)
	f.tr.failFirst = 30
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req, Suite: happySuite()})
	if result.ExitCode != 10 || result.Verdict != "access" || err == nil || !result.Terminated ||
		countCommands(f.tr, "ready") != 30 || countCommands(f.tr, "upload") != 0 || f.p.calls["Teardown"] != 1 {
		t.Fatalf("unreachable launch leaked a box: %+v, error %v", result, err)
	}
	if len(f.clock.steps) != 29 {
		t.Fatal("readiness did not wait exactly between attempts")
	}
	for _, duration := range f.clock.steps {
		if duration != 6*time.Second {
			t.Fatal("readiness used the wrong backoff")
		}
	}
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED")
}

func TestRunPreempted(t *testing.T) {
	f := newFixture(t)
	f.tr.before = func(ctx context.Context, command string) error {
		if commandKind(command) == "poll" {
			return fault(boxcore.KindTransport)
		}
		return nil
	}
	start := f.clock.Now()
	f.p.describe = func(ctx context.Context, b boxcore.Box, now time.Time) (boxcore.State, error) {
		if now.Sub(start) < 30*time.Second {
			return boxcore.State{Name: boxcore.StateRunning}, nil
		}
		return boxcore.State{Name: boxcore.StateGone}, nil
	}
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req, Suite: happySuite()})
	if err != nil || result.ExitCode != 12 || result.Verdict != "preempted" || !result.Terminated ||
		f.p.calls["FetchHarvest"] != 1 || len(f.p.fetchRuns) != 1 || f.p.fetchRuns[0] != result.RunID ||
		f.p.fetchDirs[0] != filepath.Join(result.OutDir, "partial") || countCommands(f.tr, "poll") != 3 {
		t.Fatalf("preemption evidence or partial fetch is wrong: %+v, error %v", result, err)
	}
	requireFile(t, filepath.Join(result.OutDir, "partial", "partial.txt"), "partial "+result.RunID)
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED")
	if observed := traceIndex(f.trace, "state:gone"); observed < 0 ||
		traceIndex(f.trace, "ledger:TERMINATED_CONFIRMED") <= observed {
		t.Fatal("termination was recorded without a provider observation")
	}
}

func blockingSuite(f *fixture) {
	f.tr.after = func(ctx context.Context, command string) error {
		switch commandKind(command) {
		case "start":
			return awaitFile(ctx, filepath.Join(f.d.Config.Guest.OutDir, "sleep.pid"), true)
		case "kill":
			return awaitFile(ctx, filepath.Join(f.d.Config.Guest.OutDir, ".complete"), false)
		default:
			return nil
		}
	}
}

func TestRunTimeout(t *testing.T) {
	f := newFixture(t)
	blockingSuite(f)
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req,
		Suite: sleepingSuite(), TimeoutMin: 1})
	if err != nil || result.ExitCode != 13 || result.Verdict != "timeout" || result.ManifestSHA256 == "" ||
		!result.Terminated || countCommands(f.tr, "kill") != 1 || countCommands(f.tr, "harvest") != 1 {
		t.Fatalf("timeout failed to kill, harvest or end: %+v, error %v", result, err)
	}
	assertGroupKill(t, f)
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED")
}

func assertGroupKill(t *testing.T, f *fixture) {
	t.Helper()
	for _, call := range f.tr.calls {
		if strings.Contains(call.command, "pkill") || strings.Contains(call.command, "killall") {
			t.Fatal("cleanup used a process pattern")
		}
		if commandKind(call.command) == "kill" && !strings.Contains(call.command, ".wrapper.pid") {
			t.Fatal("kill command did not read the wrapper's process group pid")
		}
	}
	data, err := os.ReadFile(filepath.Join(f.d.Config.Guest.OutDir, "sleep.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		t.Fatal("suite did not report its sleeping child's pid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		live, err := livePID(pid)
		if err != nil {
			t.Fatal(err)
		}
		if !live {
			return
		}
		if err := ctx.Err(); err != nil {
			t.Fatal("sleeping child survived the process group kill")
		}
		// The child may be between signal delivery and process reaping.
		runtime.Gosched()
	}
}

func livePID(pid int) (bool, error) {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 || len(data) <= end+2 {
		return false, errors.New("invalid child process status")
	}
	return data[end+2] != 'Z', nil
}

func TestRunCanceled(t *testing.T) {
	f := newFixture(t)
	blockingSuite(f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.tr.before = func(ctx context.Context, command string) error {
		if commandKind(command) == "poll" {
			cancel()
		}
		return ctx.Err()
	}
	f.p.describe = func(ctx context.Context, b boxcore.Box, now time.Time) (boxcore.State, error) {
		return boxcore.State{Name: boxcore.StateGone}, nil
	}
	started := time.Now()
	result, err := f.s.Run(ctx, boxcore.RunOptions{Request: f.req, Suite: sleepingSuite()})
	if result.ExitCode != 10 || !errors.Is(err, context.Canceled) || !result.Terminated ||
		result.ManifestSHA256 == "" || countCommands(f.tr, "harvest") != 1 || f.p.calls["Teardown"] != 1 ||
		time.Since(started) >= 10*time.Second {
		t.Fatalf("cancel cleanup failed or stalled: %+v, error %v", result, err)
	}
	for _, call := range f.tr.calls {
		if (commandKind(call.command) == "harvest" || commandKind(call.command) == "done" ||
			commandKind(call.command) == "kill") && call.canceled {
			t.Fatal("cleanup reused the canceled context")
		}
	}
	assertGroupKill(t, f)
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED")
}

func TestRunPanic(t *testing.T) {
	f := newFixture(t)
	blockingSuite(f)
	panicked := false
	f.tr.before = func(ctx context.Context, command string) error {
		if commandKind(command) == "poll" && !panicked {
			panicked = true
			panic("scripted poll panic")
		}
		return nil
	}
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req, Suite: sleepingSuite()})
	if result.ExitCode != 70 || err == nil || !result.Terminated || result.ManifestSHA256 == "" ||
		f.p.calls["Teardown"] != 1 || countCommands(f.tr, "harvest") != 1 {
		t.Fatalf("panic bypassed cleanup: %+v, error %v", result, err)
	}
	assertGroupKill(t, f)
}

func TestRunEndPending(t *testing.T) {
	f := newFixture(t)
	f.p.describe = func(ctx context.Context, b boxcore.Box, now time.Time) (boxcore.State, error) {
		return boxcore.State{Name: boxcore.StateRunning}, nil
	}
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req, Suite: failedSuite()})
	if err != nil || result.ExitCode != 15 || result.Terminated || result.Verdict != "end-pending" || result.SuiteExit != 3 {
		t.Fatalf("end pending lost priority: %+v, error %v", result, err)
	}
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "END_PENDING")
}

func TestRunCostCap(t *testing.T) {
	f := newFixture(t)
	blockingSuite(f)
	f.req.RootGB, f.req.HardMin, f.req.CostCapUSD = 0, 120, 1
	f.p.wait = func(ctx context.Context, b boxcore.Box) (boxcore.Box, error) {
		if err := f.clock.Sleep(ctx, 61*time.Minute); err != nil {
			return b, err
		}
		b.Address = "127.0.0.1"
		return b, nil
	}
	f.p.describe = func(ctx context.Context, b boxcore.Box, now time.Time) (boxcore.State, error) {
		return boxcore.State{Name: boxcore.StateGone}, nil
	}
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req, Suite: sleepingSuite()})
	if err != nil || result.ExitCode != 14 || result.Verdict != "cost-cap" ||
		result.ManifestSHA256 == "" || !result.Terminated || countCommands(f.tr, "kill") != 1 ||
		f.p.launches[0].req.HardMin != 60 {
		t.Fatalf("elapsed launch cost was ignored: %+v, error %v", result, err)
	}
	assertGroupKill(t, f)
}

func TestRunSourceAndPut(t *testing.T) {
	f := newFixture(t)
	var archive bytes.Buffer
	w := tar.NewWriter(&archive)
	body := []byte("archive payload\n")
	if err := w.WriteHeader(&tar.Header{Name: "hello.txt", Mode: 0600, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "source.tar")
	if err := os.WriteFile(source, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	put := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(put, []byte("put payload\n"), 0600); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(f.tr.root, "put ' with space", "input.txt")
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req, Archive: source,
		Puts: []boxcore.Put{{Local: put, Remote: remote}}, Suite: sourceSuite(remote)})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("archive/put run: %+v, error %v", result, err)
	}
	requireFile(t, filepath.Join(result.OutDir, "out", "source.txt"), string(body))
	requireFile(t, filepath.Join(result.OutDir, "out", "put.txt"), "put payload\n")
	digest := sha256.Sum256(archive.Bytes())
	hexDigest := hex.EncodeToString(digest[:])
	requireFile(t, filepath.Join(result.OutDir, "src.tar.sha256"), hexDigest+"  src.tar\n")
	if text(f.l.events[1], "src_sha256") != hexDigest {
		t.Fatal("source digest was not carried into DONE_SENT")
	}
	fileUploads := 0
	for _, call := range f.tr.calls {
		if commandKind(call.command) == "upload" && call.fileInput {
			fileUploads++
		}
	}
	if fileUploads != 2 {
		t.Fatal("archive and put were not streamed directly from local files")
	}
}

func TestSuiteExitFromHarvest(t *testing.T) {
	f := newFixture(t)
	files := map[string][]byte{"suite.exit": []byte("3\n"), ".complete": {}, "result.txt": []byte("harvested\n")}
	files["manifest.sha256"] = manifestFor(files)
	f.tr.craftedTar = filesTar(t, files)
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req, Suite: happySuite()})
	if err != nil || result.ExitCode != 1 || result.SuiteExit != 3 || result.Verdict != "failed" ||
		number(f.l.events[1], "suite_exit") != 3 || result.ManifestSHA256 == "" || !result.Terminated {
		t.Fatalf("poll exit displaced the verified suite.exit: %+v, %v", result, err)
	}
	requireFile(t, filepath.Join(result.OutDir, "out", "result.txt"), "harvested\n")
}

func TestRunUploadFailure(t *testing.T) {
	f := newFixture(t)
	f.tr.before = func(ctx context.Context, command string) error {
		if commandKind(command) == "upload" {
			return fault(boxcore.KindTransport)
		}
		return nil
	}
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req, Suite: happySuite()})
	if result.ExitCode != 10 || err == nil || !result.Terminated || f.p.calls["Teardown"] != 1 ||
		countCommands(f.tr, "upload") != 1 || countCommands(f.tr, "start") != 0 {
		t.Fatalf("failed upload started a suite or leaked the box: %+v, %v", result, err)
	}
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED")
}

func TestRunUnrecorded(t *testing.T) {
	f := newFixture(t)
	f.l.failAppend = 1
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req, Suite: happySuite()})
	if result.ExitCode != 4 || result.Verdict != "launch-failed" || err == nil || !result.Terminated ||
		f.p.calls["Launch"] != 1 || f.p.calls["Teardown"] != 1 || countCommands(f.tr, "ready") != 0 ||
		!strings.Contains(f.err.String(), "box is UP but NOT recorded: i-demo1") {
		t.Fatalf("unrecorded run was retried or left alive: %+v, %v", result, err)
	}
	assertEvents(t, f.l, "DONE_SENT", "TERMINATED_CONFIRMED")
}

func TestRunNoAccess(t *testing.T) {
	f := newFixture(t)
	blockingSuite(f)
	f.p.teardownErr = nil
	f.p.describe = func(ctx context.Context, b boxcore.Box, now time.Time) (boxcore.State, error) {
		if len(f.p.teardowns) > 0 {
			return boxcore.State{Name: boxcore.StateGone}, nil
		}
		return boxcore.State{Name: boxcore.StateRunning}, nil
	}
	f.tr.before = func(ctx context.Context, command string) error {
		if commandKind(command) == "poll" {
			return fault(boxcore.KindTransport)
		}
		return nil
	}
	start := f.clock.Now()
	result, err := f.s.Run(context.Background(), boxcore.RunOptions{Request: f.req, Suite: sleepingSuite()})
	if result.ExitCode != 10 || result.Verdict != "access" || err == nil || !result.Terminated ||
		f.clock.Now().Sub(start) < 10*time.Minute || f.clock.Now().Sub(start) > 11*time.Minute ||
		f.p.calls["FetchHarvest"] != 0 || countCommands(f.tr, "kill") != 1 || result.ManifestSHA256 == "" {
		t.Fatalf("ten-minute access bound or cleanup was ignored: %+v, %v", result, err)
	}
	assertGroupKill(t, f)
}

func TestRunCleanupPanic(t *testing.T) {
	f := newFixture(t)
	blockingSuite(f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.tr.before = func(callCtx context.Context, command string) error {
		if commandKind(command) == "poll" && ctx.Err() == nil {
			cancel()
		}
		if commandKind(command) == "harvest" {
			panic("scripted harvest panic")
		}
		return callCtx.Err()
	}
	f.p.describe = func(ctx context.Context, b boxcore.Box, now time.Time) (boxcore.State, error) {
		return boxcore.State{Name: boxcore.StateGone}, nil
	}
	result, err := f.s.Run(ctx, boxcore.RunOptions{Request: f.req, Suite: sleepingSuite()})
	if result.ExitCode != 70 || err == nil || !result.Terminated || f.p.calls["Teardown"] != 1 ||
		countCommands(f.tr, "harvest") != 1 || countCommands(f.tr, "kill") != 1 {
		t.Fatalf("panic in cleanup bypassed end: %+v, %v", result, err)
	}
	assertGroupKill(t, f)
	assertEvents(t, f.l, "LAUNCHED", "DONE_SENT", "TERMINATED_CONFIRMED")
}
