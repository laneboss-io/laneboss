# Closed bootstrap readiness: run 31

Green30 now supplies read=eof, actual child exit 1 and no bootstrap report.
Run 32 moves the Go route ahead of parsing, assigns distinct exits and adds
bounded bwrap stderr categories. Its recorded namespace receipts use actual
restriction=0 and profile_action=not_needed. See
[the current exit-path handoff](BOOTSTRAP-EXIT.md) for the complete pre-route
inventory, access checks, controls and green31 contract. The run-31 account
below is historical; its pending green30 forecast is superseded.

Green29 on 4d73e6ea proves the scoped CAP_SETUID unit fix: the helper's startup
CAP_SETUID effective, permitted and bounding observations are present, and the
gate child spawns. Its next lane.claudock.start refusal is administrator-owned
containment_unknown: fixed bootstrap did not attest closed confined readiness.
Run 30's regressions were subsequently committed as f75656da, this run's base.

## Retained evidence and cause boundary

The supplied verify-4d73e6ea-20261017-030055.log under
~/.local / state / laneboss-top / evidence / lb-v2-serve2-green29-verify-evidence / 
was read completely in memory and retained byte for byte in run-31 evidence.
It contains 526 lines and 72,304 bytes; SHA-256 is
f991906688254f31 (SHA-256 prefix).
The generic readiness message occurs twice. There is no fixed bootstrap
failure reason, bwrap error prefix, EOF or deadline result in those bytes.
The original combined guard cannot distinguish the four failure cases.

The actual failing bootstrap step is not established by this log or by the
source trace below. No cause repair is supplied in this run. Green30 must
retain the actual read case, real child wait result and any fixed bootstrap
report before selecting a narrow repair. No longer readiness deadline,
root-child execution or weaker confinement is introduced.

## End-to-end source trace

The isolation probe reserves a free installed pool account, real leaf cgroup,
protected work directory and pinned runtime. Its work directory is explicitly
chowned to the selected pool UID/GID and projected at /work/main. It supplies
an actual sealed input and a retained denied-network namespace. A missing
work projection cannot be inferred merely from record.Storage being absent:
measureIsolation adds its owned work descriptor separately.

startNativeGate pins the cgroup and creates the sealed input (descriptor 3),
one-use release pipe (4) and readiness seqpacket socket (5). The helper joins
the retained netns on a locked thread. The unchanged Go child attributes drop
supplementary groups, GID and UID before executing the fixed bwrap program,
with mandatory atomic UseCgroupFD placement. There is no root exec fallback.

bwrap receives only the fixed namespace, descriptor-preservation and pinned
mount arguments. It creates the private user/PID/IPC/UTS and mount views,
uses the retained network namespace or creates its private one, drops all
capabilities and executes the pinned bootstrap projection. The root helper
keeps its own readiness end and closes its unused child socket/read-pipe ends.

runFixedBootstrap checks the seals/type/size and exact read of descriptor 3,
closes that descriptor, and strictly decodes the retained input. It checks the
nonroot UID/GID identity, configuration/mode, token grammar and empty groups.
It verifies descriptor 5's peer is outside the private PID namespace and
descriptor 4 is a pipe, then reads its own effective capability state. The
prepared-gate path validates executable/cwd input and locks its OS thread.

confineBootstrap disables dumpability, sets no-new-privileges, installs the
CPU/core limits, installs Landlock and synchronizes the seccomp filter across
all bootstrap threads. Landlock checks ABI, creates its ruleset, strictly
opens each projected path, verifies type, adds each exact path rule and
restricts the current thread. Seccomp retains the architecture, mount,
namespace, inspection, module and other syscall restrictions. These steps
precede chdir and the token send on descriptor 5.

After that readiness send, executePreparedGate sets inherited descriptors
close-on-exec, waits for the exact one-use release token plus EOF, closes the
readiness socket and execs the sealed vendor argv/environment. There is no
vendor instruction before release. The parent still requires the exact token,
one real kernel credential, exact UID/GID/PID, actual cgroup membership,
independently private namespaces, pinned inner lifetime, actual executable
bytes and a live generation before returning a prepared gate.

The inherited sealed file, pipe and socket are descriptors; their use does
not require reopening a root-only host pathname after the UID drop. The
privilege-setting prctls lower this process's authority, and Landlock uses
the preceding NNP setting. No root-only credential operation was found
between the bootstrap identity check and readiness write.

Suspected: bootstrapLandlock still uses direct openat2, while the helper's
mount-source pin already needed its strict component-walk route under the
same inherited hardening. A landlock.open report would identify that stage,
but source alone does not prove it is this run's first failure. An earlier
bwrap failure, identity/descriptor check, Landlock rule refusal, seccomp
installation, cwd or readiness write remains possible until measured.
Do not apply a speculative fallback or policy relaxation from this list.

## New failure observations

The production readNativeReadiness performs the real socket read and returns
no control bytes on failure. It distinguishes read=eof, read=deadline,
read=<fixed errno name or other>, truncated and token_mismatch. Its original
three-second readiness deadline, shortened by the caller's earlier deadline,
is unchanged. A late packet never becomes readiness.

Read errors do not inspect packet bytes or slice by the returned count, which
can be negative after recvmsg fails. Only a complete successful read can
supply a fixed bootstrap report. The real deadline regression exercises this
error path as well as the subsequent child collection.

On failure the helper stops the pinned spawned child and waits separately for
up to three seconds to collect its actual cmd.Wait result. The diagnostic
reports child exited code=N or child killed signal=NAME. Unavailable status,
wait reconciliation or stop remains explicitly unavailable. This is the
spawned bwrap child's status, not a guessed inner-process exit. The original
containment_unknown refusal remains a refusal even when collection is incomplete.

A failing runFixedBootstrap sends a bounded fixed reason on descriptor 5,
using nonblocking/no-SIGPIPE flags. The parent recognizes only the closed
vocabulary, such as input.seals, identity, control.peer, dumpable,
landlock.open, landlock.rule, seccomp.install or cwd. Unknown errors are
unclassified; absent or unknown packets are not_reported. A failed reason
send retains the original typed refusal and adds a fixed transport diagnostic.
bootstrap_report is an observed report, not acceptance or independent proof.
No token, path, ID, bitmap or arbitrary error string enters the message.

## Exact helper startup policy

helper.before_accounts now requires real, effective and saved UIDs all zero.
readHelperUIDs uses the actual getresuid syscall and checks its errno; a denied
read cannot masquerade as three initialized zeros. Existing real/effective
GID and set-id invocation checks remain. Process CapPrm must equal the
intended unit set exactly; missing and extra bits both refuse. The earlier
specific missing CAP_SETUID/CAP_SETGID diagnostic is retained.

The sole intended capability list remains CapabilityBoundingSet in
packaging/v2/linux/laneboss-helper.service.in. packaging/v2/linux/helper.go
embeds that actual installer template; helperCapabilitySet parses its unique
nonempty Service directive. The full Linux capability-name/number dictionary
is a namespace decoder, not a second intended subset. Unknown, duplicate,
inverted or ambiguous policy input refuses. A real-file regression compares
the embedded bytes with the nearest module's actual template. No unit or
installer directive changes, capability grant or startup repair is performed.

## Regressions and controls

The catalog retains all 329 preceding controls and adds 18, for 347. Each row
has one unique actual source edit, a focused named test and deciding assertion.
Require ordinary/faults reached-red then candidate on Linux. Source inspection
and static compilation are not runtime kills.

| Regression | Control and deciding failure |
| --- | --- |
| TestHelperExactStartup/exact | The real-template-derived exact set and three root UID inputs must be admitted by the actual startup function, with one read of each input. Missing/extra/UID controls exercise the corresponding opposite behavior. |
| TestHelperExactStartup/missing | helper-exact-missing removes the full-set missing guard. The sample removes CAP_CHOWN while retaining both credential bits, so the earlier UID/GID guards cannot kill this control. Actual admission must fail the typed-refusal assertion. |
| TestHelperExactStartup/extra | helper-exact-extra removes the extra-set guard. The sample adds CAP_NET_ADMIN while keeping the intended set intact; actual admission must fail. |
| TestHelperExactStartup/real, effective, saved | helper-uid-real, helper-uid-effective and helper-uid-saved each remove only their UID predicate. The other two UID inputs remain zero; actual admission must fail. |
| TestHelperExactStartup/uiderror | helper-uid-unavailable removes the read-error guard. Zero output accompanied by EPERM must not become root identity; actual admission must fail. |
| TestHelperPolicyTemplate | helper-policy-source embeds the service template instead; the real-file byte assertion must fail. helper-policy-shape admits duplicate bounding directives and must fail the ambiguous-policy assertion. Synthetic inputs are negative parser cases only. |
| TestProcessSetUIDNative | helper-permitted-native flips one actual parsed permitted bit, leaving the existing UID/GID fields alone; independent leader capget must disagree with the complete permitted set. |
| TestHelperUIDsNative | helper-uids-native flips the observed saved UID; actual getresuid and independent procfs status must disagree. No root is needed for either native observation test. |
| TestNativeReadiness/mismatch | readiness-token disables the exact-token guard. A real foreign packet must wrongly return control bytes and fail the acceptance-barrier assertion. |
| TestNativeReadiness/truncated | readiness-truncated removes the truncation branch; a real oversized seqpacket must lose its measured truncation category and fail the case/wait/reason/privacy assertion. The token check still refuses it. |
| TestNativeReadiness/eof, deadline | readiness-eof and readiness-deadline replace the respective category. Actual socket EOF and actual read deadline must retain their own case and real exit/signal wait. |
| TestNativeReadiness/signal | readiness-wait discards the actual wait observation. The real child must terminate by SIGTERM, and losing that retained status must fail. |
| TestNativeReadiness/bootstrap | bootstrap-reason-route sends the production bootstrap report to an invalid FD. A real unsealed descriptor-3 refusal must no longer deliver input.seals and must fail the case/wait/reason assertion. |
| TestBootstrapReasonPrivacy | bootstrap-reason-private sends raw arbitrary error data; the actual socket packet must fail the randomized-value privacy assertion. bootstrap-reason-unknown admits an unknown reason and must fail the parent's closed-vocabulary assertion. |

TestNativeReadiness also admits an exact packet only while retaining its real
SCM credential, and exercises an actually closed reader. Every negative must
return no controls, refuse with the owned type/code, collect the real child,
and agree with its observed exit/signal. It re-executes a disposable component
child and uses real seqpacket sockets/pidfds; it does not claim installed
namespace/cgroup confinement. TestInstalledNativeClosedGate,
TestInstalledIsolationProof and the real capability-loss canaries remain
separate required installed observations.

## Static results and green30 contract

The candidate passed all 16 static vet configurations for admin, the new
template package and their production/test importers: Linux amd64/arm64
default, faults, partial/authenticator, combined, integration and
integration/faults; Darwin amd64/arm64 default and partial/authenticator.
The shared Go cache, local toolchain, readonly modules and disabled downloads
were used. Formatting, diff checks and serve Python compilation passed.
Exact inputs, commands, outputs and exits are retained in run-31 evidence.

No runtime test, mutant/control overlay, installed service, machine launch,
model request, commit or new agent session ran on this Mac. Linux runtime
red/candidate qualification remains with the supervisor. Green30 must retain
the exact installed unit and pass the stronger startup gate, or report its
actual startup refusal. If readiness still fails, retain its actual case,
spawned-child exit/signal and fixed bootstrap report. Select any cause repair
only from that observation. The strict closed gate and complete native proof
remain required. Presence is simulated and human_approval=not_proven; no
authenticated AI-service result is claimed.
