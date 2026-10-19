# Secrets acceptance cell

This case is an outside observer of the installed CLI and the actual confined
runner. Run it only on the supervisor's disposable Ubuntu 24.04 box. The case
does not start a machine or authenticate a vendor. It needs the real identity,
service, grant, isolation and runner implementations. Missing prerequisites
produce a reached=false, failing result, never a pass or a killed mutation.

This source implements session-bound staging, backend-first import/rotate/revoke
with atomic proof/event/reply transactions, and the secrets consumer of draft.4
fixes 9 through 11. Reserved Acquire/Inject, fixed-worker staging/delivery, protected room and
eligibility, canonical refresh and measured cleanup have real consumer paths.
The installed store/identity/helper implementations, authenticated profile and
room producer, concrete protected material adapter and physical projection/
collection still need their owning implementation and outside observation.
CONTRACT-GAPS.md in the secrets package names these dependencies and the exact
internal continuation/discovery requirements. The 209 available Go mutation
controls, seven observer/probe controls and two runner regressions remain
separate from SECRET-INJECT and CREDENTIAL-BOUND acceptance. Nine full live
controls remain unavailable; no runtime result is inferred from static checks.

The harness invokes `run.sh --context CONTEXT --result RESULT` using the frozen
context/result schema. A case-specific, protected `secrets-fixture.json` beneath
`test_root`, with schema `laneboss.e2e-secrets.v2`, supplies the following inputs,
generated on the box:

* `canary_files`: three private synthetic random-byte files named `env`, `file`
  and `undelegated`. Use printable random encodings for environment delivery
  and arbitrary bytes for file delivery. Never print them or place them in source.
* `steps`: ordered objects with `name`, `request`, `proof` (optional), `method`
  and `idempotency_key` for every mutation. Generate and retain each key before
  the operation; reuse it only with the same exact intent. The read-only key
  request may omit it. These are client IDs with at least 128 random bits.
  The entry fixes the expected success/refusal codes. Request and proof are
  paths relative to test_root. The first eight steps use one persistent shared
  client connection; later steps use the installed CLI with --proof and one
  explicit configuration/binding. They are retained exact
  inputs, not precomputed results. Proofs must come from the actual enrolled
  synthetic WebAuthn authenticator through human.challenge/human.confirm.
* `observations`: paths relative to evidence_root, written by outside capture
  and observer workers, to `injection.json`, `credential.json`, `events.jsonl`,
  and `archive.tar`. No lane-authored verdict or uncorrelated observation is
  acceptable: the observer must tie its actual syscall comparison, capture,
  launch, run, grant IDs and artifact digest to the case's lane.start receipt.

An outside coordinator watches human-flow.json during the first eight steps,
then cli-transcript.json, and creates each next request/proof file from the
actual prior output. The entry waits up to
120 seconds for each dependency file. It never treats elapsed time as human
approval. Restart/recovery/tamper setup also belongs to that authenticated
coordinator and is completed before it releases the corresponding request file.
The fixtures cannot be a static set of invented stage IDs or successful receipts.

Required steps, in order, are `human-session`, `key`, `stage-env`, `import-env`, `stage-file`,
`import-file`, `stage-hidden`, `import-hidden`, `start`, `reserved`, `wider`,
`bad-stage`, `stop`, `archive`, `restart-locked`, `recover`, `tamper`,
`lease-first`, `lease-second`, `release-running`, `release-quiet`.
The secret group (through tamper) and credential group (lease-first through
release-quiet) execute and evaluate independently. The coordinator must make
the credential group's inputs available independently of the secret group's
verdict. A failed secret boundary must not prevent a real credential assertion
from being reached, and a credential refusal must not erase an earlier secret
verdict. Cleanup is independently verified after both groups; none is inferred
from a failed command or an executor exit.
Staging requests must use fresh X25519/HKDF-SHA256/AES-GCM sealed uploads,
with the AAD and salt specified in the frozen contract. Real operation proofs
bind the actual stage IDs and mutation digests. The fixture builder coordinates
these dependent inputs with the human authenticator; a stale proof is a failure.

Draft.4's human-session step is the real human.session RPC with its exact
operation proof. The installed CLI holds that same connection open through key,
stage and import; separate CLI invocations cannot carry HumanSession.ID as read
authority. Proof creation/confirmation may use another genuine human connection
with the same principal/config/current endpoint and exact operation intent.
The entry retains prepared request and actual response envelopes as
human-N-request.json / human-N-response.json and publishes their hashes after
each call. A missing API implementation, expired key, broken connection or
failed response stops the flow. The outside entry verifies hashes, retained
inputs and every correlated result; there is no successful stand-in response.

After import, the same live client performs `secret.list` and retains
`human-metadata-request.json` and `human-metadata-response.json`. The outside
observer verifies configuration/request correlation, the metadata-only field
map, every actually imported source, uniqueness and absence of canary values.
No further mutation proof is used for this same-session read. Missing live
profile grants and missing private fixture preparation produce typed owner-wait
evidence with `completed: false`; they do not pass either acceptance assertion.

The entry invokes the matched installed binary through its file-backed flow:

```sh
laneboss human session --config example --binding /test/binding.json \
  --proof /test/session.proof.json --idempotency-key RETAINED_SESSION_KEY \
  --flow /test/human-plan.json
```

The entry writes a laneboss.client-flow.v2 plan for the seven dependent calls
and final metadata read. Each step names its retained request/proof files and
retry key. Replies arrive as JSON lines with name, request and response; the
entry immediately publishes the existing human-flow.json handoff. The CLI
emits an incomplete prerequisite wait while a dependent file is absent, then
stops with exit 69 if the bounded wait expires. A service refusal stops the
sequence. See [session flows](../../../../docs/v2-cli-session.md).

The standalone session helper is no longer an installed transport path:
its executable digest differs from the installed binding. No artifact check
is relaxed and no second client binary is selected by this case.

Create test_root and evidence_root as ordinary mode-0700 directories owned by
the case identity, and all request/proof/plan files as private regular files.
Retain the source/toolchain manifests and input bytes independently. The case
requires a matched installed human binding with contract_revision v2.0-draft.4
and the tested artifact digest. Its launch checks require the actual Task,
LaunchID, Session.HistoryID, cancellation epoch and failure/retry counters.

The optional frozen harness controls have live_auth false. They cannot operate
this live-auth credential cell; its independently authorized restart/recovery/
tamper setup remains a harness prerequisite. A fixture clock cannot change live
credential policy. Missing controls or setup never become successful evidence.

`injection.json` contains externally observed `binary_sha256`, `life_id`, `run`,
`operation_id`, `grant_ids`, `env_equal`, `file_equal`, `undelegated_absent`,
`reserved_unchanged`, `wider_not_launched`, `event_values_absent`,
`archive_values_absent`, `locked_restart_refused`, `recovery_equal`,
`tamper_refused`, and `quiescent`. The two equality verdicts compare the actual
injected bytes with the synthetic sources in memory. The independent observer
must also retain `injection_capture_sha256`, naming a capture file in
`observations.injection_capture`; its structured stdout contains only the
names `env`, `file`, `undelegated`, `reserved` with boolean `ok` values. The case verifies
the capture hash and the successful lane receipt rather than accepting a
verdict with no causal operation.

The actual lane executes the retained `probe.py` with a granted digest-only
plan. That JSON has `env_name`, `env_sha256`, `file_path`, `file_sha256`,
`hidden_env_names`, `hidden_file_paths`, `reserved_env_name` and
`reserved_sha256`. The last two select one explicit reserved target and the
SHA-256 of its expected baseline bytes; no environment is enumerated or printed.
The coordinator derives the expected digests from the actual baseline and
randomly generated source canaries in memory. The probe reads
only those explicit names/paths, compares hashes in memory, and tries an actual
write-open of the secret file, requiring EPERM/EACCES/EROFS. The outside observer
must first prove every hidden-file canary exists/readable outside confinement,
and correlate this actual probe execution and its retained script digest with
the primary capture. Quoted/model-authored verdict text is not probe evidence.

The reserved CLI step must return forbidden and the exact retained diagnostic
"secret target is a reserved or invalid environment name". An unrelated shape
error or forbidden scope error cannot pass that step. reserved_unchanged must
match the fourth actual capture verdict. Each probe runs independently, so an
absent selected file does not skip the undelegated or reserved comparison.

`credential.json` contains `binary_sha256`, `life_id`, `run`, `operation_id`,
`selected_profile_id`, `profile_grant_id`, `own_profile_turn`, `other_profile_absent`,
`other_history_absent`, `registry_absent`, `keyring_fallback_absent`,
`single_refresh_owner`, `running_release_refused`, `quiet_release_removed`,
and `quiescent`. `observations.credential_capture` is the outside primary
capture of the actual successful selected-profile turn. The observer records
its SHA-256 in `credential_capture_sha256`. This is a live-auth cell: a fixture
driver, successful login without a turn, or a missing capture cannot pass it.

`observations.collection` names an independent cleanup receipt with `state`,
`survivors`, a nonempty `processes` array of `pid`/Linux `start_time` records,
and a nonempty `removed_paths` array relative to test_root. The case checks the
actual /proc generations and absence of those runtime paths, plus correlated
zero-survivor events for the exact injection and credential runs. It also
requires the actual helper.released ReleaseReceipt, correlated with the allocated
lease, process containment and causal operation, with known-zero survivors,
live connections, queued jobs and writable exports. Missing counts are unknown.
The independent observer still checks the actual kernel and removed paths. It does not
infer collection from an executor's exit. The observer must inventory the whole
owned containment, including detached descendants, and retain its primary data.

The harness must run the red artifacts before the candidate, retaining their
different binary digests. Required guarding mutations are missing injection,
broad environment inheritance, reserved-name replacement, grant-subset bypass,
broad vendor-home/registry mount, plaintext key fallback, disabled GCM/AAD
verification, unsynchronized login copies, and cleanup before quiescence.
Each red artifact must reach its targeted assertion and fail on an actual
canary comparison or operation; setup failure is not evidence of a killed
mutation. Removing any requested observation or substituting a typed
not_implemented response fails this case.

The fixture/observer coordinator must still supply genuine confirmations,
installed launch inputs and independent observations. This adds no production
RPC, driver or authentication exception. Runtime inputs and protected
observations stay outside the checkout. Missing setup remains a typed wait.
The native backend's focused tests are a separate credential-free
cell and do not establish live credential or OS acceptance.

The named red controls, their check edits, exact failing tests and the disposable
red-before-green runner are documented in [MUTATIONS.md](MUTATIONS.md). Available
backend/crypto/preflight controls and blocked full live controls are explicit.

Fix 10 pins stored reservation role, level, driver and consumed authority,
prepared worker Kind, and current capture-refusal policy. Fix 11 adds an owned
UsageWindowSource implementation, real native worker-mapping consumption and
private active-worker credential delivery. It retains exact ordered vendor TSV,
successful post-exit from-profile exhaustion with known reset, current narrow
job grants and acknowledged private producer objects. The separate Linux
command engine executes a hash-checked sealed native binary with the exact
claudock usage --max-age 0 argv, private worker home and explicit environment.

The current assembly supplies no production UsageJobControl adapter. The
outbox/store/native owners still implement actual job dispatch, WorkerBinding,
bootstrap/result commits, selected-profile home projection and confinement.
These missing ports fail; they do not select a service-UID query. Component
fixtures start after authentication and use synthetic source bytes. The Linux
command fixture executes a byte-identical private mode-0500 copy of the test
binary as a file-backed native program,
checks actual argv/home/environment/stdout/exit and kernel executable seals,
and requires a nonroot Linux UID/GID. No vendor login, real quota query, forged
same-lane-pipe boundary or authenticated AI service has been measured here.

The two reported red-box rows remain available. The room replacement preserves
the local profile use so it can compile. The serialization test reads the
actual canonical owner immediately after the competing acquisition and checks
that exclusion before later restart/refresh assertions. The local red-box
collection contained only the summary, without the detailed build/test outputs;
the corrected source still requires both Linux builds to reach its named
failure and then pass the candidate.

Fix 12 adds the broker's private credential projection, acknowledgement, guard,
withdrawal and reverse refresh consumers, plus a Linux SCM_RIGHTS channel.
Thirty fix-12 controls bring the available catalogue to 209; all prior 179
available controls and nine existing unavailable live rows remain. The new
tests are component/native-primitive regressions, not installed acceptance.
ProjectionFlow and HeadlessProjection use typed post-authentication helper
holding facts; ProjectionSCM transfers an actual anonymous synthetic descriptor
and attempts a real sealed-write alias. Root-helper identity, actual projected
ownership and final-envp placement still require their separate native canaries.
