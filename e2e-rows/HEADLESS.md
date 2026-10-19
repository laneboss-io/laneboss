# Headless caller rows

Run these on the disposable Linux box, with an unprivileged account, Python 3,
Git, tmux and the pinned Go toolchain. No runtime check or binary build runs on
the development Mac. The helpers use pipes and `setsid`, and check `/dev/tty`
and the kernel's `tty_nr` immediately before replacing themselves with the
real binary. The product's normal tmux lane transport is exercised unchanged.

`LANEBOSS_BIN` names the built release binary by absolute path.
`LANEBOSS_FAULTS_BIN` names the separately built `laneboss_faults` binary.
Neither row set builds a binary or imports a product module. The stand-in is
only the agent runner; it reads and saves the actual prompt bytes.

Build and run the changed packages on the box from the repository root:

```sh
GOTOOLCHAIN=go1.26.0 CGO_ENABLED=0 go build \
  -trimpath -buildvcs=false -o /tmp/lb-rl-headless \
  ./cmd/laneboss
GOTOOLCHAIN=go1.26.0 CGO_ENABLED=0 go build \
  -tags laneboss_faults -trimpath -buildvcs=false \
  -o /tmp/lb-rl-headless-faults ./cmd/laneboss
GOTOOLCHAIN=go1.26.0 go test ./internal/caller \
  ./internal/event ./internal/lane ./internal/laneturns \
  ./internal/report ./internal/start
GOTOOLCHAIN=go1.26.0 go test -tags laneboss_faults \
  ./internal/caller ./internal/event ./internal/lane \
  ./internal/laneturns ./internal/report ./internal/start
```

First demonstrate the regression with the old binary, if the acceptance box
has retained it: H1 must fail at the role-start command with the supervisor
process-identity refusal. No later runtime result is valid until that fixture
can start through the real launcher. Then demonstrate the three mutants below
before running their controls. The first two must exit 1 at `assert_refused`
with `unproven identity was accepted`; the third, `caller-unidentified-start`,
admits a lane start by a caller that nothing identifies and must exit 1 at C1's
first refusal assertion with `an unidentified caller was admitted`. Each
marker must exist. A setup error, timeout, unrelated assertion, missing marker,
or zero exit is not a kill.

```sh
cd e2e-rows
LANEBOSS_BIN=/tmp/lb-rl-headless-faults \
  LANEBOSS_HEADLESS_MUTANT='caller-session-no-start' \
  LANEBOSS_HEADLESS_MARKER='/tmp/lb-headless-start-mark' \
  python3 -m unittest -v \
  test_headless.HeadlessRows.test_h6_reused_pid
LANEBOSS_BIN=/tmp/lb-rl-headless-faults \
  LANEBOSS_HEADLESS_MUTANT='caller-session-env' \
  LANEBOSS_HEADLESS_MARKER='/tmp/lb-headless-env-mark' \
  python3 -m unittest -v \
  test_headless.HeadlessRows.test_h7_env_only
LANEBOSS_BIN=/tmp/lb-rl-headless-faults \
  LANEBOSS_HEADLESS_MUTANT='caller-unidentified-start' \
  LANEBOSS_HEADLESS_MARKER='/tmp/lb-headless-unidentified-mark' \
  python3 -m unittest -v \
  test_headless.HeadlessRows.test_c1_unidentified_start
```

With those selectors unset, run from the repository root. The discovery command
includes the existing R1-R8 report rows. Lane start and adoption refuse a caller
that nothing identifies, so R1's headless start runs under a session that
registered itself with `start --role`, and its graph assertions name that
supervisor as the lane's parent; the other assertions of R1-R8 are unchanged.
On the release tree that also holds role templates, lane start and adoption
need a role, so every configuration of these rows names an org that carries the
built-in role library (`orgsupport.py` runs the binary's own `org init` and lets
each role run the stand-in runner's program) and starts its lanes with a role.
R5 uses the supplied fault binary for its loopback Discord probe.

```sh
LANEBOSS_BIN=/tmp/lb-rl-headless \
  LANEBOSS_FAULTS_BIN='/tmp/lb-rl-headless-faults' \
  python3 -m unittest discover -s e2e-rows -p 'test_*.py' -v
```

| Row | What must make it fail |
| --- | --- |
| H1 | Headless role start refuses, lacks the private PID/start record, or starts a lane with the wrong actor or prompt. |
| H2 | A real headless send fails or records the wrong sender or message digest. |
| H3 | A permitted resume fails, loses its actor, or fails to deliver the follow-up bytes to the runner. |
| H4 | A permitted turn fails, loses its waking sender, or fails to deliver the mail bytes to the runner. |
| H5 | A record with the real ancestor PID and a wrong start time can send, or refusal changes the event store. |
| H6 | A changed recorded start time simulating PID reuse can send; `caller-session-no-start` must trigger this assertion. |
| H7 | Role labels alone, or an env-named live record without ancestry, can send; `caller-session-env` must trigger this assertion. |
| H8 | Adoption fails to replace the identity record, or later report, event append, attach, dashboard identity or adopted turn loses the proven caller. |
| H9 | Two sessions of one role overwrite each other, or an exited session's record permits an unrelated caller. |
| H10 | Any of send, resume, turn, report, event append, attach or dashboard admits an unknown caller or writes events. |
| H11 | Portable run tracking changes session proof or prevents a kernel-recorded headless caller from sending. |
| C1 | A headless caller that registered nothing starts or adopts a lane, the refusal lacks its first line `refused: the caller has no recorded identity` or either route of its Instead line, a refusal writes an event or runs the stand-in, or the same session cannot start once it has registered with `start --role`; `caller-unidentified-start` must trigger the first assertion. H1 (start) and H8 (adoption) are its controls. |

All headless commands start in a new OS session beneath the persistent recorded
parent. H5-H7 pair a rejected action with an allowed control and inspect actual
stored events. H6 changes only the saved start time, leaving the live PID and
ancestry intact. H7 selects another live controller's genuine record. Mutant
requests are scoped to the action being challenged; cleanup uses normal policy.

Each headless row has its own temporary working, configuration and state
directories. Teardown lists the lanes actually recorded in that state, checks
their live status, and stops only a live supervisor or surviving processes.
It then marks each unfinished lane abandoned and runs `lane clean` to release
its directory claim before temporary-directory removal. An already finished
lane needs no `lane stop`; that command refuses an idle lane. A start attempt
that never became a recorded lane is not treated as a running resource.

The release binary's claims registry is keyed by directory inode and survives
temporary state removal. Use a fresh disposable box for verification after a
run whose cleanup failed and deleted its original temporary state. Do not
delete registry files to repair a fixture run. Ordinary and mutant runs use
the same cleanup, and any failed cleanup command remains a test failure.
