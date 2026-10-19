# Darwin-only lane communication rows

The detached-communication follow-up authorizes only these runtime rows on the
development Mac. No Linux suite, Go unit suite or real model/service request is
part of this exception. The rows require already built release and tagged
binaries; they do not build a binary or import a product package.

The product retains a separate `runner_session` kernel PID/start/SID in each
new run. Both ordinary and turn supervisors record it. Caller resolution reads
the actual caller SID and checks the recorded session leader's live kernel start
time. Darwin uses `getsid` and `kern.proc.pid`, including microseconds. The rows
independently use `proc_pidinfo(PROC_PIDTBSDINFO)` and `getsid` without printing
process command names, settings objects or environment values.

Each row creates one real turn-based stand-in lane under a registered supervisor
role using the actual built CLI and tmux transport. Exactly one lane is open for
the cross-session mutant, so a multiple-lane ambiguity cannot hide an admitted
caller. Message inputs, requests, actual CLI outputs, kernel observations and
collected state are retained under `LANEBOSS_COMMS_EVIDENCE`.

The helper releases a worker only after its launching shell has exited and been
reaped. It checks that the resulting caller is headless, has reparented to
launchd and uses a different process group. The Darwin double fork keeps the
runner's session. The new-session control forks a non-leader and calls the real
`setsid()` syscall; macOS does not ship a `setsid` utility by default. No new
session can join the runner's existing session, and the runner PID cannot be
reused while that leader is alive.

| Row | What makes it fail |
| --- | --- |
| D1 `test_d1_preserved_sessions` | A background, nohup or double-fork orphan cannot report with inherited or removed labels; its real kernel SID/PPID/group is wrong; the stored report loses its lane actor, supervisor target or complete text. |
| D2 `test_d2_setsid_orphan_refused` | A reparented new-session child is admitted or changes events, or the same-session control cannot deliver. |
| D3 `test_d3_other_session_refused` | An unrelated session, with no labels or copied lane/run labels, can report or change events; the allowed orphan control fails. |
| D4 `test_d4_runner_exit_refuses_leftover` | A real surviving child can report after the recorded leader exits, even with the old SID; no actual live leftover exists; or the refusal writes events. |
| D5 `test_d5_kernel_start_mismatch` | A live same-session orphan can report against a different recorded kernel start time, or the restored-record control fails. |

D4 retains a child that two real product samples do not remember; it does not
delete tracking records or disable product cleanup. Every candidate is collected
by its PID and exact kernel start time. D5 briefly pauses only its own supervising
process by PID while poisoning the run's kernel start record, so the real sampler
cannot overwrite the canary. It retains the poisoned bytes, restores the original
record and resumes that same process before collection.

Three test-only points are compiled exclusively with `laneboss_faults`:

| Mutant | Required failed row and assertion |
| --- | --- |
| `caller-any-lane-session` | D3 must fail at `a caller without a valid live lane session was admitted`; its point accepts a different SID while retaining the other live-leader checks. |
| `caller-no-lane-session` | D1 must fail at `preserved session lost lane identity`; its point disables only the new fallback. |
| `caller-lane-session-no-start` | D5 must fail at `a caller without a valid live lane session was admitted`; its point removes only exact kernel start equality. |

Each mutant needs its marker and the indicated failed assertion. A timeout,
fixture setup failure, missing marker or cleanup failure is not a kill. Release
builds contain none of these mutation selectors or marker writers. C5 remains a
Linux acceptance row with a named CLI capability assertion that fails until
decision-guide integration supplies `lane send --ask`; it is never skipped.

## Commands for the supervising runner

Supply Darwin binaries built from the exact retained source. Record and keep
both binary bytes/hashes, the consumed source hash and bytes, each transcript
and its exit. From `e2e-rows`, first demonstrate each mutant before its control:

```sh
LANEBOSS_BIN="/tmp/lb-comms-darwin-faults" \
  LANEBOSS_COMMS_EVIDENCE="/tmp/lb-comms-darwin-any-session" \
  LANEBOSS_REPORT_MUTANT="caller-any-lane-session" \
  LANEBOSS_REPORT_MARKER="/tmp/lb-comms-darwin-any-session-marker" \
  python3 -m unittest -v \
  darwin_communication_rows.DarwinCommunicationRows.test_d3_other_session_refused
```

Run the same command with `caller-no-lane-session`, a new evidence/marker path,
and D1; then `caller-lane-session-no-start`, another new path, and D5. These
commands must fail for their indicated reasons. Inspect the retained result and
marker before proceeding, and stop on a failure that is not the intended mutant
assertion. With mutant selectors absent, run only the authorized Darwin suite:

```sh
LANEBOSS_BIN="/tmp/lb-comms-darwin-release" \
  LANEBOSS_COMMS_EVIDENCE="/tmp/lb-comms-darwin-release-evidence" \
  python3 -m unittest -v darwin_communication_rows.DarwinCommunicationRows
```

The module fails on a non-Darwin host; it does not skip or return a passing empty
suite. No runtime pass or mutant kill is claimed until these actual commands
have produced retained evidence. Static checks do not establish those results.
