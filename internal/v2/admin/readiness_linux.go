//go:build linux

package admin

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

const bootstrapFailurePrefix = "bootstrap-failure:"

// Only fixed bootstrap errors enter this closed vocabulary. Arbitrary decoder,
// syscall and runner text never becomes a packet or a parent diagnostic.
var bootstrapFailureReasons = map[string]string{
	"runner stdin has no exact committed prompt":                               "prompt.reference",
	"runner stdin is not its sealed read-only prompt":                          "prompt.seals",
	"runner stdin prompt read-back is incomplete":                              "prompt.read",
	"runner stdin prompt digest could not be measured":                         "prompt.measure",
	"runner stdin prompt digest differs":                                       "prompt.digest",
	"invalid fixed inherited descriptor inventory":                             "descriptors.inventory",
	"fixed inherited descriptor is unavailable":                                "descriptors.missing",
	"fixed worker socket descriptor type changed":                              "descriptors.socket",
	"fixed inherited input is not exactly sealed":                              "descriptors.seals",
	"fixed inherited descriptor projection changed":                            "descriptors.projection",
	"cannot retain fixed vendor descriptor":                                    "descriptors.retain",
	"cannot create bootstrap-only exec proof":                                  "exec_proof.create",
	"cannot transfer bootstrap-only exec proof":                                "exec_proof.transfer",
	"fixed bootstrap failure route is unavailable":                             "entry.route",
	"fixed bootstrap failure route could not close":                            "entry.route_close",
	"fixed bootstrap entry arguments differ":                                   "entry.arguments",
	"fixed bootstrap entry configuration differs":                              "entry.config",
	"fixed bootstrap context ended":                                            "entry.context",
	"fixed bootstrap input could not be decoded":                               "input.decode",
	"fixed bootstrap requires sealed inherited descriptor 3":                   "input.seals",
	"cannot read exact fixed bootstrap input":                                  "input.read",
	"fixed bootstrap identity or sealed mode differs":                          "identity",
	"fixed bootstrap retained supplementary groups":                            "groups",
	"bootstrap control socket is not inherited from outside its PID namespace": "control.peer",
	"bootstrap release is not its inherited pipe":                              "release.pipe",
	"bootstrap cannot observe native privilege state":                          "capabilities.read",
	"bootstrap retained effective capabilities":                                "capabilities.retained",
	"bootstrap capability observation is absent":                               "capabilities.absent",
	"fixed gate lacks its sealed executable and cwd":                           "input.executable",
	"NUL in fixed executable input":                                            "input.argument",
	"sealed runner cwd is unavailable":                                         "cwd",
	"cannot attest closed gate readiness":                                      "readiness.write",
	"cannot protect bootstrap control descriptors":                             "dumpable",
	"cannot install no-new-privileges":                                         "no_new_privileges",
	"cannot install native CPU limit":                                          "limit.cpu",
	"cannot disable bootstrap core dumps":                                      "limit.core",
	"cannot observe bootstrap descriptor limits":                               "limit.nofile_read",
	"cannot bound bootstrap descriptor inventory":                              "limit.nofile_set",
	"bootstrap descriptor limit did not read back":                             "limit.nofile_readback",
	"prepared gate requires Landlock ABI 3 or newer":                           "landlock.abi",
	"kernel refused fixed Landlock ruleset":                                    "landlock.create",
	"ambiguous fixed Landlock path":                                            "landlock.path",
	"fixed Landlock resource is unavailable":                                   "landlock.open",
	"Landlock resource type changed":                                           "landlock.type",
	"kernel refused a fixed Landlock path rule":                                "landlock.rule",
	"kernel refused fixed Landlock restriction":                                "landlock.restrict",
	"fixed gate has no seccomp architecture":                                   "seccomp.architecture",
	"kernel refused fixed seccomp filter on all bootstrap threads":             "seccomp.install",
	"cannot close inherited descriptors at vendor exec":                        "descriptors.cloexec",
	"gate owner disappeared or supplied a foreign release":                     "release.token",
	"gate release was not a single closed token":                               "release.eof",
	"cannot close ready channel before vendor exec":                            "readiness.close",
	"sealed vendor executable could not start":                                 "vendor.exec",
	"capture bootstrap lacks its bounded fixed pipe binding":                   "capture.input",
	"capture read end is not an inherited helper pipe":                         "capture.pipe",
	"capture spool is not an exclusive empty inherited file":                   "capture.file",
	"cannot protect capture descriptor inheritance":                            "capture.cloexec",
	"capture readiness owner is unavailable":                                   "capture.readiness",
}

func reportBootstrapFailure(fd int, err error) error {
	reason := bootstrapErrorReason(err)
	// Diagnostic delivery cannot wait for a failed/disappeared owner. The
	// caller retains the original refusal even when this send also fails.
	return unix.Send(fd, []byte(bootstrapFailurePrefix+reason), unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
}

func bootstrapErrorReason(err error) string {
	reason := "unclassified"
	var typed *api.Error
	if errors.As(err, &typed) {
		if known, ok := bootstrapFailureReasons[typed.Message]; ok {
			reason = known
		}
	}
	return reason
}

func bootstrapPacketReason(data []byte) string {
	value, found := strings.CutPrefix(string(data), bootstrapFailurePrefix)
	if found {
		if value == "unclassified" {
			return value
		}
		for _, reason := range bootstrapFailureReasons {
			if value == reason {
				return reason
			}
		}
	}
	return "not_reported"
}

// This is the production socket read. A refusal never returns control bytes
// that could continue to credentials, cgroup or namespace acceptance.
func readNativeReadiness(ready *net.UnixConn, token string, gate *nativeGate) ([]byte, error) {
	data, controls := make([]byte, 256), make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(8))
	n, oobn, flags, err := receiveNativeReadiness(ready, data, controls)
	kind := ""
	switch {
	case errors.Is(err, io.EOF):
		kind = "read=eof"
	case errors.Is(err, os.ErrDeadlineExceeded):
		kind = "read=deadline"
	case err != nil:
		kind = "read=" + nativeSpawnErrno(err)
	case flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0:
		kind = "truncated"
	case string(data[:n]) != token:
		kind = "token_mismatch"
	}
	if kind != "" {
		if oobn > 0 {
			if err := closeReadinessRights(controls[:oobn]); err != nil {
				return nil, err
			}
		}
		reason := "not_reported"
		// recvmsg may retain a negative count on error. Only a complete,
		// successful read can supply bytes for a bootstrap failure report.
		if err == nil && flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) == 0 {
			reason = bootstrapPacketReason(data[:n])
		}
		return nil, gate.readinessFailure(kind, reason)
	}
	return controls[:oobn], nil
}

func (g *nativeGate) readinessFailure(kind, reason string) error {
	initial := g.failureFacts()
	if kind == "read=eof" {
		// Readiness has already failed. Collect a natural setup exit briefly
		// before an explicit stop can replace its status with SIGKILL.
		grace := time.NewTimer(100 * time.Millisecond)
		select {
		case <-g.done:
		case <-g.primaryDone:
		case <-grace.C:
		}
		grace.Stop()
	}
	beforeStop := g.failureFacts()
	// Keep the original readiness deadline. This separate bounded stop/wait
	// collects the failed child; it cannot turn a late packet into readiness.
	stopErr := g.Close()
	collected := false
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case <-g.done:
		collected = true
	case <-timer.C:
	}
	wait := "child wait=unavailable"
	waitResult := "wait_result=unavailable"
	if collected {
		g.mu.Lock()
		wait = nativeReadinessWait(g.state)
		var exited *exec.ExitError
		if g.waitErr == nil || errors.As(g.waitErr, &exited) {
			waitResult = "wait_result=observed"
		}
		g.mu.Unlock()
	}
	stop := "stop=unavailable"
	if stopErr == nil {
		stop = "stop=requested"
		if collected && waitResult == "wait_result=observed" && wait != "child wait=unavailable" {
			stop = "stop=observed"
		}
	}
	return failure(api.CodeContainmentUnknown, "fixed bootstrap did not attest closed confined readiness ("+kind+"; "+wait+"; "+waitResult+"; bootstrap_report="+reason+"; "+g.stderr.diagnosticFacts()+
		"; on_refusal={"+initial+"}; before_stop={"+beforeStop+"}; helper_kill="+g.helperKillFact()+"; "+g.cgroupBefore.facts(readNativeCgroupSnapshot(g.cgroupFD))+"; "+stop+")")
}

func nativeReadinessWait(state *os.ProcessState) string {
	if state == nil {
		return "child wait=unavailable"
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok {
		return "child wait=unavailable"
	}
	if status.Exited() {
		return "child exited code=" + strconv.Itoa(status.ExitStatus()) + "; exit_stage_hint=" + bootstrapExitStage(status.ExitStatus())
	}
	if status.Signaled() {
		name := unix.SignalName(status.Signal())
		if name == "" {
			name = "OTHER"
		}
		return "child killed signal=" + name
	}
	return "child wait=unavailable"
}
