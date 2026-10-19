# Linux component mutation pairs

Run this only on the supervisor's disposable Linux box, as its non-root test
identity, after the complete ordinary and fault-tagged component suites pass.
Use the current draft.4 source bundle, not the pre-merge lane commit. The
catalog is file-backed in `mutations.json`; `mutate.py` applies one exact anchor
to a new disposable source copy and never edits the supplied checkout or tests.
The earlier manual mutation requirements in `test-box.md` remain in force.

The box needs Go, noninteractive sudo for root-owned test installation, the
measured bwrap/kernel prerequisites and a populated Go module cache. Pass that
cache explicitly; the runner uses no module proxy or toolchain download. It
retains the pinned x/sys source bytes and manifest separately from its own
source snapshot. It creates private mode-0700 input/home/cache/evidence trees
under the test identity and copies no credential directory or environment.

For one red/candidate pair, from the composed source root:

```sh
python3 -I e2e/v2/cases/linux/mutate.py \
  --source /test/source --module-cache /test/go/pkg/mod \
  --mutation linux-worker-schema \
  --output /test/evidence/lb-v2-linux-schema
```

For all catalog entries in both variants, with each output initially absent:

```sh
set -eu
for linux_variant in plain faults; do
  for linux_mutation in linux-backend-label linux-worker-schema \
    linux-worker-kind linux-session-history linux-egress-lease \
    linux-network-argument linux-helper-overlap linux-runtime-overlap \
    linux-file-stream linux-truncate-mask linux-cloexec-live \
    linux-probe-before-runner linux-helper-cause linux-spec-digest \
    linux-measured-release linux-release-binding linux-commit-sequence \
    linux-stop-terminal linux-network-lease linux-mount-identity \
    linux-mount-alias linux-source-symlink linux-git-commondir \
    linux-injection-ready linux-observation-exit linux-observation-running \
    linux-abort-generation linux-offline-lease linux-host-probe \
    linux-budget-disk linux-budget-spend linux-network-mode \
    linux-plan-lookup linux-plan-gate linux-plan-phase \
    linux-runtime-home linux-runtime-work linux-runtime-executable \
    linux-runtime-bytes linux-runtime-mode linux-runtime-path \
    linux-stage-requester linux-stage-epoch linux-stage-effect \
    linux-bound-plan linux-bound-handoff linux-bound-phase \
    linux-agent-recovery linux-record-digest linux-agent-expiry \
    linux-service-actor linux-reserved-level linux-reserved-role \
    linux-reserved-driver linux-capture-policy linux-capture-generation \
    linux-record-kind linux-agent-kind linux-worker-actor \
    linux-worker-recovery linux-channel-command linux-channel-binding \
    linux-channel-lease linux-channel-argc linux-channel-input-class \
    linux-channel-input-id linux-channel-executable-id \
    linux-channel-input-empty linux-channel-input-max \
    linux-channel-endpoint linux-channel-endpoint-class \
    linux-plan-port linux-plan-foreign linux-plan-record \
    linux-plan-error-data linux-worker-zero-level linux-worker-zero-role \
    linux-data-agent-plan linux-data-entry linux-data-binding \
    linux-data-lease linux-data-argc linux-data-input \
    linux-data-input-id linux-data-exe-id linux-data-empty \
    linux-data-max linux-data-capabilities linux-data-source-count \
    linux-data-parent linux-data-destination linux-data-readonly \
    linux-data-relative linux-data-delivery linux-data-history \
    linux-data-endpoint linux-data-endpoint-class; do
    linux_output="/test/evidence/lb-v2-linux-${linux_variant}-${linux_mutation}"
    if [ "$linux_variant" = faults ]; then
      python3 -I e2e/v2/cases/linux/mutate.py --faults \
        --source /test/source --module-cache /test/go/pkg/mod \
        --mutation "$linux_mutation" --output "$linux_output"
    else
      python3 -I e2e/v2/cases/linux/mutate.py \
        --source /test/source --module-cache /test/go/pkg/mod \
        --mutation "$linux_mutation" --output "$linux_output"
    fi
  done
done
```

Each phase compiles the actual package, installs those exact bytes root-owned
under a uniquely named `/opt/lb-v2-linux-red` child, verifies the read-back hash
and executes the installed test binary through Go's `test2json`. The red phase
must reach the named test and its specified assertion, with a nonzero exit and
no skipped test. The unchanged green phase must reach and pass that same test
with exit 0. Their executable digests must differ. A stale/ambiguous anchor,
build failure, missing bootstrap, skip, timeout, surviving mutation, unrelated
failed positive control or changed source makes the pair incomplete and stops
the batch. No failed setup is counted as a killed security mutation.

Exit 0, `KILLED: ID`, `PASS: ID` and `complete: true` are all required. They
describe only the selected component scope, not installed OS-LINUX acceptance.
The result retains exact commands, PIDs, stdout/stderr/exits, failed-test names,
source/mutation/dependency manifests, source bytes, Go version/build metadata
and both tested executable bytes/hashes. Kernel tests additionally retain their
own native canary evidence. The root-owned installation path is recorded for
the supervisor's eventual disposable-machine collection. Nothing is force
deleted or recycled. After a timeout, descendants remain unknown for supervisor
inspection; the runner does not claim process quiescence.

| Mutation | Actual assertion and scope |
| --- | --- |
| `linux-backend-label` | Old/foreign backend metadata must get typed unsupported. |
| `linux-worker-schema` | The old worker schema must get typed invalid_request. |
| `linux-worker-kind` | An unknown worker protocol kind must get typed invalid_request. |
| `linux-session-history` | A session pointing to another private history must refuse. |
| `linux-egress-lease` | Network preparation must retain the controlled_egress prerequisite. |
| `linux-network-argument` | Layout construction must contain its unconditional private network flag. |
| `linux-helper-overlap` | Exports overlapping the installed helper must refuse. |
| `linux-runtime-overlap` | Exports overlapping runtime must refuse. |
| `linux-file-stream` | A real regular-file standard stream must refuse. |
| `linux-truncate-mask` | Independent ABI masks must include TRUNCATE. |
| `linux-cloexec-live` | A real event descriptor must remain live before exec and marked CLOEXEC. |
| `linux-probe-before-runner` | The real failed bwrap option probe must prevent proposed runner execution. |
| `linux-helper-cause` | An incomplete or changed causal helper intent must refuse. |
| `linux-spec-digest` | The retained original and canonical spec digest must match. |
| `linux-measured-release` | A malformed helper reply cannot reach release reporting. |
| `linux-release-binding` | Measured release must bind the actual operation. |
| `linux-commit-sequence` | A forged committed tuple must stop before helper contact. |
| `linux-stop-terminal` | A running process cannot become a successful terminal stop. |
| `linux-network-lease` | A missing private namespace cannot satisfy the network lease. |
| `linux-mount-identity` | Actual tmpfs descriptor identity differs from the other pinned mount. |
| `linux-mount-alias` | The real same-target bind overmount cannot be admitted as an independent root. |
| `linux-source-symlink` | Actual final and ancestor symlinks must fail source pinning. |
| `linux-git-commondir` | A real Git common-directory pointer must fail the administrative gate. |
| `linux-injection-ready` | An unready receipt cannot satisfy ordered grant/version/slot correlation. |
| `linux-observation-exit` | Known exit requires exactly one signed exit or signal fact. |
| `linux-observation-running` | Running observation cannot carry a termination fact. |
| `linux-abort-generation` | Never-opened abort must match the original generation. |
| `linux-offline-lease` | Offline launch cannot retain hidden network lease fields. |
| `linux-host-probe` | Installed-helper evidence cannot erase a failed current host prerequisite. |
| `linux-budget-disk` | Zero disk budget cannot authorize a launch. |
| `linux-budget-spend` | Negative spend cannot authorize a launch. |
| `linux-network-mode` | Network mode must use the frozen enum. |
| `linux-plan-lookup` | A retained selector cannot name another reservation; the actual read remains deferred. |
| `linux-plan-gate` | Agent Prepare must read and validate its retained plan before root registration. |
| `linux-plan-phase` | A bound/opened plan cannot prepare another gate. |
| `linux-runtime-home` | Runtime home must match reserved private storage. |
| `linux-runtime-work` | Runtime workspace must match reserved private storage. |
| `linux-runtime-executable` | Runtime object must identify the enrolled executable. |
| `linux-runtime-bytes` | Executable bytes must match the enrolled digest. |
| `linux-runtime-mode` | The enrolled executable must remain executable. |
| `linux-runtime-path` | Root-relative runtime objects cannot select a host path. |
| `linux-stage-requester` | Distinct helper stages retain the original requester. |
| `linux-stage-epoch` | Distinct helper stages retain the cancellation fence. |
| `linux-stage-effect` | Prepare cannot reuse the registration effect. |
| `linux-bound-plan` | Recovery passes the shared binding/plan correlation. |
| `linux-bound-handoff` | Recovery retains the exact original registration cause. |
| `linux-bound-phase` | Launch requires a bound/opened retained plan. |
| `linux-agent-recovery` | Missing agent recovery cannot open a legacy gate. |
| `linux-record-digest` | Committed identity hashes its actual LaunchRecord. |
| `linux-agent-expiry` | Expired grants cannot authorize agent launch. |
| `linux-service-actor` | Helper causes require the authentic service execution actor. |
| `linux-reserved-level` | The bound actor keeps the stored child level. |
| `linux-reserved-role` | The bound actor keeps the stored child role. |
| `linux-reserved-driver` | Both D8 drivers are checked against the stored reservation. |
| `linux-capture-policy` | Refused capture passes the D6 policy validator. |
| `linux-capture-generation` | The capture policy snapshot matches the reserved generation. |
| `linux-record-kind` | Missing/legacy record kinds cannot authorize a live launch. |
| `linux-agent-kind` | Agent records require a lane actor. |
| `linux-worker-actor` | Worker records require a worker actor. |
| `linux-worker-recovery` | A worker cannot acquire agent recovery authority. |
| `linux-channel-command` | Channel argv names only the fixed worker program. |
| `linux-channel-binding` | The channel binding path is fixed in the worker view. |
| `linux-channel-lease` | The channel lease selector is an ID rather than a path. |
| `linux-channel-argc` | The channel entry refuses extra arguments. |
| `linux-channel-input-class` | The worker input has the sealed channel class. |
| `linux-channel-input-id` | A channel input selector cannot be a caller path. |
| `linux-channel-executable-id` | An executable selector cannot be a caller path. |
| `linux-channel-input-empty` | The sealed input is nonempty. |
| `linux-channel-input-max` | The sealed input remains within the frame bound. |
| `linux-channel-endpoint` | The runtime endpoint retains the exact worker lease. |
| `linux-channel-endpoint-class` | The runtime endpoint has the worker class. |
| `linux-plan-port` | read invokes the actual shared source and selector. |
| `linux-plan-foreign` | consumer keeps the shared foreign-selector check. |
| `linux-plan-record` | consumer validates the retained record through the shared reader. |
| `linux-plan-error-data` | source error cannot expose partial fallback plan data. |
| `linux-worker-zero-level` | worker principal has no inherited agent level. |
| `linux-worker-zero-role` | worker principal has no inherited agent role. |
| `linux-data-agent-plan` | materialization cannot select an agent plan. |
| `linux-data-entry` | materialization invokes only its fixed worker entry. |
| `linux-data-binding` | materialization cannot choose a host binding path. |
| `linux-data-lease` | materialization selects an opaque worker lease. |
| `linux-data-argc` | materialization rejects extra argv. |
| `linux-data-input` | materialization uses only its sealed input class. |
| `linux-data-input-id` | materialization input cannot select a caller path. |
| `linux-data-exe-id` | materialization executable selector cannot be a caller path. |
| `linux-data-empty` | materialization input cannot be empty. |
| `linux-data-max` | materialization input remains bounded. |
| `linux-data-capabilities` | materialization cannot inherit agent capabilities. |
| `linux-data-source-count` | materialization has exactly one read-only source. |
| `linux-data-parent` | materialization source retains its parent grant selector. |
| `linux-data-destination` | materialization source projects only at its fixed job path. |
| `linux-data-readonly` | materialization cannot write its project source. |
| `linux-data-relative` | materialization cannot select another source subtree. |
| `linux-data-delivery` | materialization source remains a read-only held projection. |
| `linux-data-history` | materialization history uses the closed source scope. |
| `linux-data-endpoint` | materialization runtime retains its exact child worker lease. |
| `linux-data-endpoint-class` | materialization runtime is a worker endpoint. |

The first four entries cover metadata checks retained from draft.3. Seven
draft.4 entries cover causal context, immutable digest, measured release,
committed sequence, terminal observation and private namespace lease checks.
The fixtures in these tests check protocol rejection and propagate root errors;
they never claim a successful fake process or production probe. The 13 d4fix1
entries add actual mount/source/Git controls and frozen observation, injection,
budget and probe invariants. The 19 fix-9 additions exercise retained-plan,
runtime, causal and recovery checks. The 20 fix-10 additions cover stored pins,
D6 capture gating, explicit record kinds and the fixed channel worker grammar.
The 26 fix-11 additions cover the shared plan read, zero worker level/role and
materialization's fixed entry, sealed input, narrow grants and runtime lease.
All 97 entries require red/candidate box
execution. Fix-9 validator tuples are metadata controls only, never successful
agent Binding replies. Fix 11 now supplies the real shared Plan port. The
retained source fixture can return metadata, actual errors, a foreign selector
or malformed records. Preparation must consume that port and reach only the
failing helper registration test double; every source refusal stops before the
helper. The shared reader discards partial data accompanying an error. No
fixture returns a successful gate/process or substitutes the request's plan.
Selector and preparation-phase controls remain direct consumer checks.
Missing other-owner implementations cannot become a
successful fake launch. Current claim/policy checks and real restart recovery
still require the installed service/helper acceptance described in the Linux
contract gaps. No new pair has executed on the authoring Mac.
Focused output includes the selected test's child subtests, while an unrelated
test cannot provide its failure marker. Other entries exercise
existing review fixes. The layout/mask
component results do not prove network forwarding or kernel isolation alone.
Descriptor swap, sealed payload, full fd-200/truncate/seccomp and read-only bind
controls still run in the complete component suite; keep their separate manual
mutation rows. All new pairs need actual box execution; static anchor matching
or Python compilation is not a runtime result.

# Public boundary artifacts

The installed CLI case consumes separately built red release artifacts through
the shared E2E context. These eight IDs are distinct from the component catalog:

| `mutation_id` | Reached failing observation required |
| --- | --- |
| `linux-broad-root` | A real outside read/write/mmap/link canary succeeds. |
| `linux-writable-nested` | The nested write canary succeeds. |
| `linux-inherited-fd` | The inherited descriptor canary succeeds. |
| `linux-no-landlock` | The deliberately writable nested mount allows the denied write. |
| `linux-no-network` | A denied foreign TCP/UDP/Unix endpoint is reached. |
| `linux-no-cgroup` | A live marker process is outside its actual populated run cgroup. |
| `linux-false-zero` | The independent observer finds surviving processes after claimed zero. |
| `linux-unmeasured-release` | The actual helper.released event lacks measured counts or has a wrong lease/operation/containment binding. |

Each input fixture's `red_controls` lists its selected ID. `run.py` retains the
exact failing observation and sets reached=false for a red run that fails for
another reason, even after an earlier canary ran. A passing red artifact is a
survived mutation, never a killed one. Missing production helper/runtime/gate/
capture/egress dependencies remain setup failures, not boundary red evidence.
Use the shared harness with real authorized driver fixtures; these component
pairs cannot replace either restriction cell, hook mode or the ABI 3 floor.
