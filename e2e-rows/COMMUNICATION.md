# Lane communication and detached descendants

This change starts from release source `3d27d3d`. Runtime rows, builds and mutant
kills run only on the disposable Linux box. The development Mac performs static
checks only. A stand-in runner exercises the real built CLI, tmux supervisors,
kernel processes, event store, mail files and recipient prompts. It performs no
authenticated model or messaging-service request.

## Source prediction, before runtime measurement

The suspected regression is loss of caller proof after reparenting. These are
source predictions, not measured refusals or demonstrated security gaps.

At the starting revision, `internal/lane/process_linux.go:33` and
`internal/laneturns/process_linux.go:38` already enable a child subreaper in native
Linux mode. Both suppress it in portable mode, and silently return false if
`prctl` fails. Therefore a plain child, including a child that only calls
`setsid` while its parents remain alive, should already work. Native Linux
orphans should also work when the subreaper call succeeds.

For background jobs after their starting shell exits, nohup jobs whose starting
shell exits, setsid jobs after their parent exits, and a double fork, portable
Linux and macOS can lose the walk to the recorded run. Refusal is conditional:
a live helper remembered by the process sampler can still prove the caller's
ancestry. A retained process group or a controlling terminal can provide other
existing matches. This is why the rows use headless children in separate groups
and assert the actual parent PID, in addition to CLI results.

`internal/caller/caller.go:262` considers the recorded supervisor, runner and
sampled processes. At line 270 it requires ancestry, with terminal/session
matching restricted to callers with a controlling terminal.
`internal/caller/process.go:133` requires a live matching PID/start pair and walks
only current parents. It cannot recover vanished parents after reparenting.
With a retained lane label, `internal/caller/caller.go:290` refuses the unmatched
caller with `LANEBOSS_LANE disagrees with the caller's recorded lane identity`.
Without that label it can remain unidentified: `report` then uses
`RequireIdentity`, and `lane send` fails the existing recipient rule.
`internal/caller/sessions.go:125` also walks current kernel parents; a copied
session or role label cannot replace that proof.

## Linux change

`internal/subreaper/linux.go:14` enables `PR_SET_CHILD_SUBREAPER` independently of
the process-table reader. Both the ordinary supervisor in
`internal/lane/supervise.go` and the turn supervisor in
`internal/laneturns/worker.go` call it before runner execution. Both already
check their PID and start time against the run's recorded supervisor. An orphan
therefore reparents to a process the caller walk actually matches. Adoption
cannot bring an unrelated caller under this supervisor.

If kernel setup fails, both supervisor paths finish the record and append an
exit with code 125, zero survivors and no runner execution. A turn's mail is
returned through the existing settlement path. No identity resolver, option A
refusal, environment agreement check or peer permission is relaxed.

`internal/subreaper/faults.go` exists only in Linux `laneboss_faults` builds.
The `lane-no-subreaper` mutant omits the actual kernel setup and writes the
normal fault marker. It does not alter caller resolution or synthesize results.
Release builds compile the separate inert `release.go`, without that selector
or marker writer.

## macOS: session identity

The approved follow-up uses the runner's OS session ID, rather than a login audit
session or transferable token. Each runner starts as its own session leader.
An open run now records `runner_session` with the exact kernel PID/start/SID.
When ancestry fails, caller resolution requires the caller's kernel SID to equal
that runner PID and rechecks the live leader and exact kernel start time.
Darwin's proof uses microseconds; portable `ps` timestamps do not authenticate it.

A background job, nohup child or double fork retains this identity after its
parent exits if it keeps the session. A reparented child that calls `setsid()`
creates a new session and is refused on Darwin. macOS has no `setsid` utility by
default, so the row calls the actual syscall from Python. Sampled helper roots
are not an alternative Darwin authentication route. Linux keeps its unchanged
subreaper ancestry path first, with the session proof as a fallback only.
The explicitly authorized Darwin-only rows and their commands are in
`DARWIN-COMMUNICATION.md`; Linux discovery does not run them.

## Executable rows and failure reasons

Every fixture uses a real L4 supervisor lane and two real nested L3 lanes, so
upward mail is tested against an actual recorded parent lane. Files hold briefs,
messages and event inputs. The detached worker waits until its launcher exits
and is reaped before invoking report and send. The rows inspect kernel PPID,
PGID, SID and start time, and check nohup's actual SIGHUP disposition.

| Row | What makes it fail |
| --- | --- |
| C1: `test_c1_running_lane_paths` | Report, peer send, upward send with labels removed or self event append fails; actor/sender/target/digest/bytes is wrong; a recipient's real turn lacks complete mail; state verification fails. |
| C2: `test_c2_detached_native` | Any of background, nohup, setsid or double fork loses report/send identity, fails to reparent to the recorded supervisor, or fails message delivery to real recipient prompts. |
| C3: `test_c3_detached_portable` | The same failures when every command uses portable process records. |
| C4: `test_c4_non_descendants_stay_refused` | An unrelated headless caller can report or send from the lane directory, with absent or copied labels; a refusal writes events; the allowed descendant control fails. |
| C5: `test_c5_required_ask_contract` | The required `lane send --ask` is refused or fails to store the exact message with the lane actor. This is an unresolved acceptance row, not a passing inventory check. |
| C6: `test_c6_detached_turn_native` | Detached communication fails after resuming the reporter through the separate turn supervisor. |
| C7: `test_c7_detached_turn_portable` | The same failure on a portable second turn. |
| C8: `test_c8_linux_session_fallback` | An unsampled same-session orphan cannot report/send when the existing tagged subreaper mutant is enabled. Every ordinary Linux row still uses subreaper ancestry first. |

The supplied release tree has no `lane send --ask`:
`internal/laneturns/laneturns.go:60` lists only config, lane, file and from for
send; line 83 recognizes boolean flags only for turn and loop. The CLI syntax
and the architecture's mail command agree. C5 first invokes the real built
CLI help through `require_cli_send_ask_support`. The named
`CLI_SEND_ASK_SUPPORTED` assertion fails, never skips, if `--ask` is absent.
After decision-guide integration supplies it, the original successful-delivery
and exact-message assertions run unchanged.
Org instance inbox/outbox directories have no separate mail command in this
tree. Reserved `lane.mailed`, `report.*` and `owner.message.*` events remain
unavailable through event append; existing R4 tests that boundary.

The ordinary fixture copies its complete files, including generated inputs,
requests, actual command results, run records, worker logs, recipient prompts
and final collected state, into `LANEBOSS_COMMS_EVIDENCE` before temporary removal.
Cleanup uses the product to stop live lanes, abandon and clean them. No assertion
is weakened for a mutant. C2/C3/C6/C7 can fail at communication refusal or at the
kernel parent assertion if the old sampler remembered a helper. A setup error,
timeout, missing marker or collection failure is not a mutant kill.

## Commands for the authorized Linux box

These commands provision no machine. The box operator retains the consumed
source archive and its hash, both binaries and their hashes, every transcript
and its exit, and the fixture evidence. The source/toolchain must be supplied on
that box. From this checkout, build both variants and run the changed packages:

```sh
GOTOOLCHAIN=go1.26.0 CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -o /tmp/lb-comms-release ./cmd/laneboss
GOTOOLCHAIN=go1.26.0 CGO_ENABLED=0 go build -tags laneboss_faults \
  -trimpath -buildvcs=false -o /tmp/lb-comms-faults ./cmd/laneboss
GOTOOLCHAIN=go1.26.0 go test ./internal/subreaper ./internal/caller \
  ./internal/lane ./internal/laneturns ./internal/event ./internal/report
GOTOOLCHAIN=go1.26.0 go test -tags laneboss_faults ./internal/subreaper \
  ./internal/caller ./internal/lane ./internal/laneturns ./internal/event ./internal/report
sha256sum /tmp/lb-comms-release /tmp/lb-comms-faults
```

First measure the regression with an archived `3d27d3d` binary: run C3 and C7
against it with their normal assertions, and retain their nonzero results.
Demonstrate C1 and C4 red using the existing actor and env-trust mutants from
LB-235, plus H7/H10 for unrelated and unidentified callers; record the precise
failed assertion, not just a nonzero process exit.

Then, from `e2e-rows`, challenge all four detached rows using the new mutant:

```sh
LANEBOSS_BIN=/tmp/lb-comms-faults \
  LANEBOSS_COMMS_EVIDENCE="/tmp/lb-comms-mutant-evidence" \
  LANEBOSS_REPORT_MUTANT="lane-no-subreaper" \
  LANEBOSS_REPORT_MARKER="/tmp/lb-comms-subreaper-marker" \
  python3 -m unittest -v \
  test_lane_communication.LaneCommunicationRows.test_c2_detached_native \
  test_lane_communication.LaneCommunicationRows.test_c3_detached_portable \
  test_lane_communication.LaneCommunicationRows.test_c6_detached_turn_native \
  test_lane_communication.LaneCommunicationRows.test_c7_detached_turn_portable
```

That command must fail the described assertions, and the marker must exist.
Inspect the transcript and retained fixtures before proceeding; a marker alone
is insufficient. With mutant selectors absent, run the controls:

```sh
LANEBOSS_BIN=/tmp/lb-comms-release \
  LANEBOSS_FAULTS_BIN="/tmp/lb-comms-faults" \
  LANEBOSS_COMMS_EVIDENCE="/tmp/lb-comms-release-evidence" \
  python3 -m unittest -v \
  test_lane_communication.LaneCommunicationRows.test_c1_running_lane_paths \
  test_lane_communication.LaneCommunicationRows.test_c2_detached_native \
  test_lane_communication.LaneCommunicationRows.test_c3_detached_portable \
  test_lane_communication.LaneCommunicationRows.test_c4_non_descendants_stay_refused \
  test_lane_communication.LaneCommunicationRows.test_c6_detached_turn_native \
  test_lane_communication.LaneCommunicationRows.test_c7_detached_turn_portable \
  test_lane_communication.LaneCommunicationRows.test_c8_linux_session_fallback \
  test_headless.HeadlessRows.test_h7_env_only \
  test_headless.HeadlessRows.test_h10_unknown_commands \
  test_report_identity test_report_messages
```

Stop at an unexpected failed check.
Run C5 separately to expose the unresolved ask contract; its failure prevents
claiming the whole requested communication acceptance passed:

```sh
LANEBOSS_BIN=/tmp/lb-comms-release \
  LANEBOSS_COMMS_EVIDENCE="/tmp/lb-comms-ask-evidence" \
  python3 -m unittest -v \
  test_lane_communication.LaneCommunicationRows.test_c5_required_ask_contract
```

None of these runtime results or mutant kills has been measured on the Mac.
Static formatting, vet, compilation of Python source and the publication scan
are necessary local checks and do not establish runtime acceptance.
