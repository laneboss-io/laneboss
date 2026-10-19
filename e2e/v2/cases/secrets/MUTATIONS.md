# Secrets mutation controls

Run these controls only in the supervisor's child-bounded worker on the approved
disposable Ubuntu 24.04 box. The Mac is static-check-only. These are deliberate
faults in retained source copies, not production fault flags or authorization
exceptions. The input checkout is read-only to this runner. Git is used only to
list source files, never to stage, commit, switch or alter an index.

`mutations.py` is the executable catalogue. Every available entry identifies one
production check or projection to remove/change, the owned source function and
the focused tests that must fail. The runner requires the matched draft.4
contract source. Exact source anchors must match once; drift
is a setup failure. Tests are never edited. The nine blocked live controls name
their future fault and existing black-box assertion but cannot be applied to
an unimplemented production capability. They exit 69 with killed=false.

`mutate.py` creates separate red and green copies, records their file manifests,
and builds retained test binaries with Go 1.26 and race instrumentation. It runs
the red binary first through Go's test2json and requires every target test to be
reached and to fail with its actual expected assertion diagnostic. Only then
does it compile/run the unmodified green copy and require the same tests to
pass. Compiler failures, absent tests, wrong failure reasons, skips, unexpected
successes, survivors or changed source inputs cannot become killed mutations.
The catalogue has 224 available mutations: the preceding 220 plus four
round-8 controls. Nine full live controls remain blocked. New controls are
prepared and have not been executed on the Mac.
All available results must have status `killed_then_green`, killed=true and
exit 0. A preflight result proves that guard only; it does not prove delivery,
login refresh, cleanup or an OS boundary.

On the box, provision an existing parent evidence directory, a public module
cache matching go.mod/go.sum, a dedicated build cache outside the source and
evidence directories, and the pinned Go tool. Run one entry as follows:

```sh
python3 e2e/v2/cases/secrets/mutate.py \
  --mutation record-aad \
  --source /test/src \
  --output /test/evidence/lb-v2-secrets-record-aad \
  --go /usr/local/go/bin/go \
  --module-cache /test/cache/go-mod \
  --build-cache /test/cache/lb-v2-secrets-build
```

Use a new output directory for every entry and tag setting. Repeat with
`--tags laneboss_faults`. `--list` prints only names, availability and target
test names. An explicit `--source-manifest` selects an exact retained JSON path
array. Without one, a Git checkout uses its read-only Git inventory; a source
archive uses a sorted, link-confined inventory of the supplied module tree.
Keep only curated source in that tree, never an owner home or credentials.
Escaping links,
special inputs and overlapping source/cache/output scopes refuse. Do not make
an ad hoc copy of an owner home or credential directory for this purpose.

The subprocess environment is constructed explicitly, with a fresh empty HOME,
private temp directory, local toolchain, telemetry disabled and module network
lookups disabled. No credential is copied. The runner retains both source
copies, source hashes, tool bytes/hash, tested binaries/hashes, actual commands,
exits, primary stdout/stderr, PID-based process receipts and result.json. It
never prints environment values, raw settings or arbitrary exceptions. Failure
JSON prints the step, a command summary with path redaction, actual command exit
(or null before any command), fixed diagnostic/errno and retained result path.
Exact argv and primary stdout/stderr remain in private command receipts.
Retain and inspect failures before collection; the shared harness must
also verify its enclosing worker containment and final collection.

The supervisor's short invocation is supported with the same safety checks:

```sh
python3 e2e/v2/cases/secrets/mutate.py \
  --mutation directory-mode --source /test/src \
  --output /test/evidence/lb-v2-secrets-defaults
```

When omitted, Go is discovered on PATH and must still report Go 1.26 under
GOTOOLCHAIN=local. The preloaded public module cache comes from the named
GOMODCACHE selector, then the first GOPATH, then Go's default public cache path.
Only those exact selectors are read; no environment is enumerated or printed.
A private lane-named temporary build cache is selected outside source/evidence.
Explicit flags still select pinned tools/caches. No missing dependency triggers
a download, inherited credential, alternate compiler or successful placeholder.

All setup checks now run inside evidence handling. Malformed options, missing
source/tool/cache, wrong contract, failed command/build, changed anchors and
wrong red diagnostics remain failures. Each result retains its own runner and
catalogue input bytes, command receipts, stdout/stderr hashes, fixed cause and
errno when applicable. A command that never started has exit null. Existing
outputs are preserved; when the requested output cannot be created, a fresh
private lane-named directory is printed as the retained evidence location.

Run the black-box runner regressions on Linux as well:

```sh
python3 e2e/v2/cases/secrets/check_runner.py \
  --source /test/src \
  --output /test/evidence/"lb-v2-secrets-runner-checks"
```

This driver retains separate script variants. The missing-evidence fault must
make missing-source, nonzero-tool, malformed-option, existing-output and blocked
69 checks fail for their named diagnostics. The old explicit-options fault must
reach its missing-option check and fail the minimal invocation. Only then must
the unmodified candidate pass, including an actual directory-mode red/green Go
run with retained test binaries. Compiler failures, unrelated setup failures or
fabricated Go output cannot pass that candidate. These two Python runner faults
are separate from the 224 Go catalogue rows and nine blocked live controls.

## Available mutations and failing tests

| Mutation | Check removed or changed | Test that must fail |
| --- | --- | --- |
| record-aad | Omit stored-record AAD on seal/open | TestEncryptedRoundTrip; TestRecordTamper |
| record-tag | Convert GCM authentication failure to success | TestRecordTamper |
| record-nonce | Clear each freshly generated nonce before sealing | TestImmutableAndRevoke |
| plain-record | Persist actual plaintext as an extra record-side file | TestEncryptedRoundTrip |
| key-fallback | Persist the actual key and reload it automatically at New | TestRestartRecovery |
| recovery-aad | Omit recovery AAD on wrap/unwrap | TestRecoveryTamper |
| source-version | Remove exact name/version matching at fetch | TestGrantMismatch |
| version-reuse | Suppress the immutable source/version conflict | TestImmutableAndRevoke |
| revoke-ignore | Ignore the authenticated revoked state at fetch | TestImmutableAndRevoke |
| private-mode | Remove record-mode equality | TestUnsafeFilesRefuse/public |
| private-links | Remove single-link record validation | TestUnsafeFilesRefuse/hardlink |
| stage-aad | Omit sealed-upload GCM AAD | TestSealedUpload |
| stage-salt | Derive HKDF salt without the AAD bytes | TestSealedUpload |
| reserved-env | Return before the reserved-variable blacklist | TestTargetBlacklist |
| file-traversal | Return before relative private-path validation | TestTargetBlacklist |
| secret-subset | Remove exact effective secret-grant membership | TestGrantSelection |
| profile-subset | Remove exact effective profile-grant membership | TestProfileSelection |
| profile-expiry | Ignore profile-grant expiry | TestProfileExpiryAndDriver |
| stale-grants | Ignore revocation in stored/revalidated grants | TestGrantSelection |
| cleanup-running | Ignore the exited-containment requirement | TestCleanupNeedsQuiescence |
| cleanup-survivors | Ignore a positive survivor count | TestCleanupNeedsQuiescence |
| human-proof | Ignore missing mutation proof | TestMutationStopsBeforeProof |
| stage-principal | Ignore the upload key's submitting principal | TestKeyScopeAndExpiry |
| stage-expiry | Retain expired upload keys | TestKeyScopeAndExpiry |
| json-case | Accept unknown case-alias keys | TestExactJSONKeys |
| typed-nil | Dereference an absent protected reader | TestTypedNilKeyInputs |
| directory-mode | Ignore the opened directory's current private mode | TestDirectoryModeDrift |
| lock-identity | Ignore replacement of the lock pathname's inode | TestLockIdentityDrift |
| read-peer | Ignore connector lifetime failure | TestReadConnectionGuards/closed |
| read-writer | Ignore every-frame writer verification failure | TestReadConnectionGuards/writer |
| read-endpoint | Ignore the read authority's endpoint generation | TestReadConnectionGuards/endpoint |
| read-idle | Ignore idle read expiry | TestReadConnectionGuards/idle |
| stage-connection | Ignore upload-key connection binding | TestStageReadSession |
| stage-session | Ignore upload-key read-session binding | TestStageReadSession |
| key-read-expiry | Permit a key to outlive read authority | TestKeyReadExpiryBound |
| eligibility-session | Ignore actual session/history equality | TestEligibilityCurrentState/session; history |
| eligibility-model | Ignore the current model | TestEligibilityCurrentState/model |
| eligibility-exclusion | Ignore current profile exclusions | TestEligibilityCurrentState/excluded |
| eligibility-paid | Introduce a paid destination from a nonpaid source | TestEligibilityCurrentState/paid |
| worker-lease | Ignore the stored lease tuple | TestWorkerLeaseAndSubset/lease; generation; runtime |
| worker-subset | Ignore current exact source membership | TestWorkerLeaseAndSubset/source; target; version |
| cli-semantic | Ignore the feature adapter's exact-name grammar | TestCLISemanticRefusal |
| key-check-enrollment | first unlock persists an empty sealed key check | TestEmptyKeyEnrollment |
| key-check-auth | wrong key fails on an otherwise empty enrolled store | TestEmptyKeyEnrollment |
| native-clock | grant expiry uses the injected clock | TestNativeClock |
| native-clock-required | native construction requires its clock | TestNativeRequiresClock |
| parent-mode | an unprotected parent refuses before directory creation | TestProtectedParent |
| lock-wait | contended locks wait until context deadline | TestContextLock |
| read-idle-bound | remaining idle authority cannot exceed the published bound | TestReadWindowContract/idle-over |
| read-absolute-bound | remaining absolute authority cannot exceed the published bound | TestReadWindowContract/absolute-over |
| read-connection | read authority belongs to the actual connection | TestReadConnectionGuards/connection |
| read-retained | retained dispatcher authority must match current connection facts | TestReadConnectionGuards/retained |
| proof-intent | mutation proof binds the exact request digest | TestProofPreflight/digest |
| proof-id | mutation proof has an opaque valid ID | TestProofPreflight/id |
| proof-expiry | expired mutation proof refuses before dependencies | TestProofPreflight/expired |
| read-proof | human reads cannot carry mutation proofs | TestReadsRejectProof/secret.key |
| cli-validator-registration | common file input requires the owning validator registration | TestCLIValidators/secret.stage/invalid |
| cli-proof-intent | ergonomic CLI proof binds its operation or human.session intent | TestCLIProofIntent |
| stage-clock | sealed upload expiry uses the caller clock | TestStageInjectedClock |
| installed-config | missing installed configuration is a prerequisite failure | TestInstalledInputs |
| installed-service-scope | fixed internal service lookup scope is derived from installed config | TestInstalledInputs |
| stage-import-principal | stage consumption retains its submitting principal | TestImportSessionBinding/principal |
| stage-import-connection | stage consumption retains the actual submitting connection | TestImportSessionBinding/connection |
| stage-import-session | stage consumption retains its human read session | TestImportSessionBinding/session |
| stage-import-endpoint | stage consumption retains its endpoint generation | TestImportSessionBinding/endpoint |
| stage-import-expiry | expired in-memory stages cannot be consumed | TestImportSessionBinding/expiry |
| stage-claim | one staged ciphertext is bound to one exact mutation request | TestStageIntentAndClaim |
| stage-intent | stage metadata matches the requested secret name and version | TestStageIntentAndClaim |
| mutation-proof-use | proof use is in the event and reply transaction | TestSecretLifecycle |
| mutation-check-proof | proof verification precedes protected backend work | TestProofBeforeBackend; TestMutationIntentRetry |
| backend-store-required | a successful event requires a real prior protected write | TestSecretLifecycle; TestBackendFailureDoesNotCommit |
| import-reconcile | restart retry reconciles the existing authenticated source | TestImportCrashRetry |
| pending-source | unrelated operations cannot bypass an uncommitted backend source | TestImportCrashRetry |
| import-replay | completed receipt replays before another proof check | TestSecretLifecycle |
| rotate-cas | two rotations cannot advance the same expected version | TestConcurrentRotations |
| revoke-operation | only the original operation reconciles an interrupted tombstone | TestRevokeCrashRetry |
| revoke-operation-aad | the tombstone operation ID is authenticated | TestRevocationOperationAAD |
| mutation-scope-end | a retained protected backend view cannot write after unlock | TestMutationScopeEnd |
| stage-import-tag | tampered ciphertext fails before Store or proof consumption | TestStageTamperAtImport |
| commit-reference | interrupted transaction retains a retryable operation reference | TestImportCrashRetry |
| backend-retry-rewrite | exact backend retry preserves the original ciphertext bytes | TestImmutableAndRevoke |

Both common --request and ergonomic --input use the same exported secrets
validators as the service. All six methods register at initialization; a missing
or failed registration is never a transport pass. TestCLIValidators supplies
an invalid and valid file for every method, requires typed invalid_request
before proof/socket work, and requires a foreign transport/binding refusal for
valid input. The accepted codes are explicitly not_implemented,
prerequisite_missing, unavailable, unauthenticated and version_mismatch; a
secrets-owned or invalid_request failure cannot satisfy the positive control.
TestCLISemanticRefusal retains both input forms. cli-semantic edits the shared
ValidateImportInput; cli-validator-registration drops the secret.stage row.
No test or another lane's common source is edited.

Run the independent outside-observer/probe controls on Linux:

```sh
python3 e2e/v2/cases/secrets/check_case.py \
  --source /test/src \
  --output /test/evidence/"lb-v2-secrets-case-checks"
```

Require red_then_green with all seven controls killed: reserved-code refuses an
unrelated invalid_request; reserved-diagnostic refuses an unrelated forbidden;
reserved-capture requires the fourth actual probe verdict; reserved-probe
compares a random baseline digest; assertion-abort keeps both assertions
independent; probe-abort keeps undelegated probing after an absent selected
file; late-reached retains causal launch/capture evidence before leak checks.
The checker retains red/green source bytes, named-test diagnostics, command
outputs, exit codes and hashes, then runs all candidate checks. These are
observer/runner controls, not authenticated live credential acceptance.

## Draft.4 fix-9 deciding controls

These controls edit only secrets-owned production functions. The first seven
restore the prior method barrier to make the corresponding positive test fail.
The other rows remove the deciding input check or material effect. Several
rows remove both independent checks of the same pin so a later check cannot
mask the intended boundary. Exact API-owned shape validation remains outside
this lane's mutation authority. A compiler/setup failure is never a kill.

The diagnostic column is the actual assertion substring required by mutate.py.
These are expected red diagnostics, not observed Linux results. Run every row
in both tag settings and retain its red failure before its green pass.

| Mutation | Deciding behavior | Focused test | Required red diagnostic |
| --- | --- | --- | --- |
| fix9-acquire | reserved-life acquisition uses the real slot implementation | TestReservedCredentialLifecycle | reserved-life profile acquisition did not prepare a real slot |
| fix9-inject | reserved-life injection uses the real slot implementation | TestReservedCredentialLifecycle | reserved-life injection did not retain its exact selected slots |
| fix9-worker | fixed worker injection prepares actual protected material | TestFixedWorkerCredentialLifecycle | claimed fixed worker did not prepare its selected real credential |
| fix9-release | profile release imports measured canonical refresh | TestFileLoginRefresh | measured file-login release did not import supported refresh |
| fix9-revoke | injection cleanup calls its real measured implementation | TestReservedCredentialLifecycle | measured injection cleanup did not release actual slots |
| fix9-room | Room consumes protected producer evidence | TestProfileRoomEvidence | profile room did not use actual protected evidence |
| fix9-eligibility | Eligibility produces a bound protected assessment | TestProtectedProfileEligibility | compatible enrolled profiles did not retain exact eligibility and evidence |
| fix9-prepared-agent | nonexecuting agent material equals selected source bytes | TestPreparedAgentMaterial | nonexecuting retained agent spec did not receive its exact selected material |
| fix9-prepared-worker | nonexecuting worker material equals selected source bytes | TestFixedWorkerCredentialLifecycle | retained fixed worker spec did not receive the exact selected bytes |
| fix9-plan-claim | expired planning claims cannot allocate a slot | TestReservationGuards/claim | expected stage error code conflict |
| fix9-plan-epoch | the planning cause matches the reserved cancellation epoch | TestReservationGuards/epoch | expected stage error code forbidden |
| fix9-plan-foreign | the reserved planning record belongs to the installed configuration | TestReservationGuards/foreign | expected stage error code forbidden |
| fix9-plan-inputs | both initial and final grants match the exact sourced reservation | TestReservationGuards / resolved | expected stage error code conflict |
| fix9-plan-policy | current policy is rechecked before and after protected preparation | TestReservationGuards/policy | expected stage error code conflict |
| fix9-plan-original | the retained original request digest agrees with the reservation | TestReservationGuards/request | expected stage error code integrity |
| fix9-profile-runtime | the acquired profile supports the selected enrolled executable | TestReservationGuards / executable | expected stage error code forbidden |
| fix9-private-slot | a retained home ID cannot become a credential slot | TestReservationGuards/history | expected stage error code forbidden |
| fix9-profile-retry | changed original input cannot replay a retained slot | TestCredentialChangedRetryAndRestart | expected stage error code conflict |
| fix9-injection-retry | a changed task selection cannot reuse an injection reservation | TestInjectionSelectionReplay | expected stage error code conflict |
| fix9-release-identity | cleanup validates the actual committed identity tuple | TestReleaseGuards/identity | expected stage error code invalid_request |
| fix9-release-comparison | the caller observation agrees with the independent helper measurement | TestReleaseGuards / disagreement | expected stage error code containment_unknown |
| fix9-release-commit | an uncommitted helper receipt cannot erase credentials | TestReleaseGuards/record | expected stage error code integrity |
| fix9-release-selection | cleanup preserves the full retained injection selection | TestInjectionCleanupSelection | expected stage error code forbidden |
| fix9-refresh-import | measured refresh writes the actual canonical returned bytes | TestFileLoginRefresh | refresh import did not preserve actual returned bytes |
| fix9-refresh-serialize | an expired unreleased canonical login owner still excludes aliases | TestCanonicalLoginRefreshWait | competing alias changed the unreleased canonical login owner |
| fix9-refresh-latest | a later alias receives the latest canonical refresh | TestCanonicalLoginRefreshWait | canonical alias copied stale pre-refresh credential bytes |
| fix9-refresh-identity | a returned refresh cannot change non-refresh identity fields | TestRefreshFieldGuards/identity | expected stage error code forbidden |
| fix9-refresh-unknown | a returned refresh cannot add unsupported fields | TestRefreshFieldGuards/unknown | expected stage error code forbidden |
| fix9-refresh-expiry | returned expiry is a supported future UTC timestamp | TestRefreshFieldGuards/expiry | expected stage error code forbidden |
| fix9-refresh-owner | only the original canonical owner may return refresh material | TestRefreshFieldGuards/owner | expected stage error code conflict |
| fix9-refresh-generation | returning a refresh rechecks enrollment generation | TestRefreshFieldGuards/generation | expected stage error code conflict |
| fix9-room-available | Room reports actual available and unavailable producer results | TestProfileRoomEvidence | profile room ignored a measured unavailable result |
| fix9-room-generation | room evidence pins the protected enrollment generation | TestProtectedRoomGuards/generation | expected stage error code forbidden |
| fix9-room-login | room evidence pins the canonical login | TestProtectedRoomGuards/login | expected stage error code forbidden |
| fix9-room-window | room evidence has at most a five minute observation window | TestProtectedRoomGuards/window | expected stage error code integrity |
| fix9-room-zone | room checked-at uses the exact UTC representation | TestProtectedRoomGuards/zone | expected stage error code integrity |
| fix9-room-producer | the protected evidence producer completed successfully | TestProtectedRoomGuards/producer | expected stage error code prerequisite_missing |
| fix9-evidence-origin | room evidence has protected service origin | TestEligibilityGuards / evidence-origin | expected stage error code forbidden |
| fix9-evidence-hash | protected object hash verification precedes semantic decoding | TestProtectedRoomGuards/hash | expected stage error code integrity |
| fix9-worker-claim | worker credential preparation requires its live current claim | TestWorkerGuards/claim | expected stage error code conflict |
| fix9-worker-target | worker cause targets the exact leased run | TestWorkerGuards/foreign | expected stage error code conflict |
| fix9-worker-runtime | the fixed worker executable matches protected runtime bytes | TestWorkerGuards/manifest | expected stage error code forbidden |
| fix9-worker-executable | worker staging rejects caller-selected executable paths | TestWorkerGuards / executable | expected stage error code forbidden |
| fix9-worker-plan-retry | worker slot identity pins the complete fixed job input | TestWorkerGuards / changed-retry | expected stage error code conflict |
| fix9-worker-subset-retry | worker retry preserves both requested input and prepared result | TestWorkerGuards / changed-subset | expected stage error code conflict |
| fix9-worker-spec-selection | the final worker spec preserves the exact prepared injection | TestFixedWorkerMaterialGuards/selection | expected stage error code forbidden |
| fix9-worker-resolver | worker material calls the actual post-spec helper resolver | TestFixedWorkerMaterialGuards/runtime | expected stage error code not_implemented |
| fix9-worker-spec-retry | material delivery cannot change its retained final handoff | TestFixedWorkerDeliveryReplay | expected stage error code conflict |
| fix9-eligibility-model | profile compatibility uses the destination enrolled model | TestProtectedProfileEligibility | profile compatibility ignored changed model enrollment |
| fix9-eligibility-vendor | profile compatibility uses the destination pinned vendor version | TestEligibilityGuards/vendor | profile eligibility accepted incompatible retained runtime or vendor |
| fix9-eligibility-runtime | profile compatibility uses the exact enrolled runtime | TestEligibilityGuards/runtime | profile eligibility accepted incompatible retained runtime or vendor |
| fix9-eligibility-binding | eligibility validates the committed private history binding | TestEligibilityGuards/identity | expected stage error code invalid_request |
| fix9-continuation-epoch | the durable continuation and submitted swap share the reservation epoch | TestContinuationCredentialGuards/epoch | expected stage error code conflict |
| fix9-continuation-claim | continuation acquisition rechecks a currently claimed intent | TestContinuationCredentialGuards/claim | expected stage error code conflict |
| fix9-broker-aad | broker ciphertext authenticates the complete documented AAD | TestEncryptedBrokerJournal | broker ciphertext failed independent AAD authentication |
| fix9-broker-id | broker AAD prevents id transplantation | TestBrokerAADTransplant/id | expected error code integrity |
| fix9-broker-kind | broker AAD prevents kind transplantation | TestBrokerAADTransplant/kind | expected error code integrity |
| fix9-broker-key | broker AAD prevents key transplantation | TestBrokerAADTransplant/key | expected error code integrity |
| fix9-broker-lifetime | journal writes cannot escape their locked callback | TestBrokerViewLifetime | expected error code forbidden |
| fix9-broker-cancel | cancelled journal callbacks cannot write | TestBrokerViewLifetime | expected error code cancelled |
| fix9-broker-revoked | a bound slot rechecks actual source revocation | TestBoundMaterialSourceRevocation | expected stage error code forbidden |
| fix9-broker-nonce | every encrypted journal write has a fresh nonce | TestBrokerNonceFresh | broker writes reused an encryption nonce |
| fix9-broker-private | ordinary metadata scans still enforce broker-file privacy | TestBrokerPrivateEnumeration | expected error code integrity |
| fix9-material-expiry | prepared profile bytes require an unexpired issued slot | TestPreparedAgentMaterialGuards/expiry | expected stage error code forbidden |
| fix9-material-binding | restart material lookup cannot ignore a missing retained binding | TestCredentialChangedRetryAndRestart | expected stage error code not_found |
| fix9-profile-selected | Acquire cannot choose another delegated profile over the retained selection | TestContinuationCredentialSelection | expected stage error code forbidden |
| fix9-storage-life | the helper-owned home belongs to the exact reserved life | TestReservationGuards/storage | expected stage error code forbidden |
| fix9-room-future | room evidence cannot claim an observation after the injected current time | TestProtectedRoomGuards/future | expected stage error code integrity |
| fix9-cleanup-replay | a released slot still rejects a changed process generation on replay | TestCleanupReplayBinding | expected stage error code containment_unknown |
| fix9-object-chunks | protected object reads retain all API-bounded chunks | TestProtectedObjectChunks | protected object reader did not retain every bounded chunk |
| fix9-object-offset | each protected chunk has its exact contiguous offset | TestProtectedObjectChunkGuards/offset | expected stage error code integrity |
| fix9-object-part-hash | each protected chunk authenticates its actual returned bytes | TestProtectedObjectChunkGuards/hash | expected stage error code integrity |

## Fix 10 and fix 11 controls

| Mutation | Test that must fail | Named assertion diagnostic |
| --- | --- | --- |
| fix10-level | TestReservedAuthorityPins/level | expected stage error code forbidden |
| fix10-role | TestReservedAuthorityPins/role | expected stage error code forbidden |
| fix10-driver | TestReservedAuthorityPins/driver | expected stage error code forbidden |
| fix10-ticket | TestReservedAuthorityPins/ticket | expected stage error code forbidden |
| fix10-proof | TestRetainedConsumedProof/missing; /foreign | expected stage error code forbidden |
| fix10-capture-current | TestCaptureCurrentPolicy / disabled; /approval | expected stage error code invalid_request |
| fix10-worker-kind | TestPreparedWorkerBindingKind | expected stage error code forbidden |
| f11-usage-percent | TestOutsideUsageGuards/percent | expected stage error code unavailable |
| f11-usage-fresh | TestOutsideUsageGuards/stale; /pre-exit; /future | expected stage error code invalid_request |
| f11-usage-profile | TestOutsideUsageGuards/profile | expected stage error code forbidden |
| f11-usage-producer | TestOutsideUsageGuards/producer | expected stage error code invalid_request |
| f11-usage-source | TestOutsideUsageGuards/header | expected stage error code invalid_request |
| f11-usage-known-reset | TestUsageTSVAllRows | TSV parser did not select the actual known exhausted row |
| f11-usage-all-rows | TestUsageTSVAllRows | expected stage error code invalid_request |
| f11-usage-grants | TestOutsideUsageGuards/grants | expected stage error code forbidden |
| f11-worker-mapping | TestMappedCredentialGuards/lease; /peer; /claim; /permission | expected stage error code invalid_request |
| f11-worker-material | TestMappedCredentialWorker | native mapped worker did not receive its exact selected material |
| f11-usage-command | TestUsageCommand | native usage command lost its exact argv private home environment or actual stdout |
| f11-usage-command-pin | TestUsageCommandGuards/pin | expected stage error code integrity |
| f11-usage-command-home | TestUsageCommandGuards/home | expected stage error code integrity |
| f11-usage-command-generation | TestUsageCommandGuards/generation | expected stage error code containment_unknown |
| f11-usage-producer-path | TestOutsideUsageWindow | outside usage did not retain its actual exhausted from-profile window |
| f11-usage-seals | TestUsageExecutableSnapshot | usage executable snapshot remained writable after pinning |
| f11-usage-output | TestUsageCommandGuards/overflow; /stderr-overflow | expected stage error code unavailable |
| f11-usage-cancel | TestUsageCommandCancellation | expected stage error code cancelled |
| f11-usage-executable-mode | TestUsageCommandGuards / writable-exe | expected stage error code integrity |

The five required usage rows edit only owned consumer gates. Where both an
owned parser and a shared validator decide the same condition, the fault
disables both owned call sites so the intended assertion can be reached.
The shared API implementation is unchanged. Source/profile controls keep the
rest of their sealed inputs self-consistent; they do not nominate an unrelated
setup error as exhaustion or provenance evidence. The worker mapping row
requires separate lease, peer, claim and operation assertions to fail.

The room predecessor mutation explicitly keeps profile used. Serialization
reads the actual canonical owner before testing its deadline/restart/refresh
sequence, so a competing transaction's ownership write cannot be hidden by a
later timeout. The local red-box summary did not include the detailed red
stdout/stderr files. Both corrected rows require Linux first-failure evidence;
their new source is not a claimed kill.

## Acceptance rules and pending live mutations

| Acceptance rule | Available primitive control | Full black-box mutation/test still required |
| --- | --- | --- |
| Human enrollment through sealed staging/import | stage-aad, stage-salt, human-proof, stage-principal, stage-expiry, stage-connection, stage-session, read-peer, read-writer, read-endpoint, read-idle, key-read-expiry | human-stage removes session/proof binding; SECRET-INJECT must reject wrong-session/replayed import. |
| One environment and one read-only file injection compare in memory | reserved-env, file-traversal and fix9-prepared-agent check targets and protected byte delivery | inject-env/inject-file remove the physical projection; SECRET-INJECT's actual helper comparison must fail. |
| Undelegated names and reserved replacement are absent/refused | secret-subset, reserved-env | inherit-env uses broad host inheritance; SECRET-INJECT must observe the undelegated canary and fail. |
| Events and archives contain no values | plain-record proves backend disk output only | emit-values appends actual bytes to committed event/archive output; SECRET-INJECT's independent scan must fail. |
| Restart without a key refuses; protected recovery works | key-fallback, recovery-aad | Run the same restart/recovery operations through the installed service once its identity/store/launch wiring is present. |
| Tampered ciphertext/AAD refuses | record-tag, record-aad, recovery-aad, stage-aad, stage-salt | Repeat through human import and actual lane start, not just the backend. |
| Concurrent logins have one refresh owner | fix9-refresh-serialize and fix9-refresh-latest check canonical alias exclusion and returned bytes across restart | refresh-race removes canonical-login lease exclusion; CREDENTIAL-BOUND must observe two concurrent installed owners and fail. |
| Cleanup waits for quiescence | cleanup-running, cleanup-survivors and fix9-release-comparison/commit check the consumer against an owned process and actual retained receipt | cleanup-early removes the physical-removal gate; CREDENTIAL-BOUND must observe a missing live slot and fail. |
| Broad registry/home mounts fail | profile-subset validates selection only | registry-mount widens a selected mount; CREDENTIAL-BOUND's other-login/history canary open must fail the assertion. |
| Plaintext fallback fails | plain-record and key-fallback use actual random canary/key bytes | Repeat through installed protected provisioning/restart. |
| Parent-subset bypass fails | secret-subset, profile-subset, stale-grants | subset-launch removes parent validation before gate release; SECRET-INJECT must observe the forbidden start/scope and fail. |

The earlier worker lease/subset controls validate preflight. Fix-9 controls
also reload current claims, real synthetic input/runtime bytes, final handoffs
and encrypted material. Their fixtures begin after authentication and do not
establish an installed single-use worker channel, physical projection or live
delivery. Eligibility controls verify existing protected producer metadata and
retained history; they do not authenticate a vendor or prove live quota.

Full live mutation adapters wait for the remaining launch and installed runtime dependencies
in the secrets package's CONTRACT-GAPS.md. General proof/read/receipt and
WorkerLease write ports are now supplied. Naming
these pending faults is not evidence that a stub was mutated successfully.
The supervisor's previous Linux unit pass applies to the previous source tree;
the new controls and red/green runner need their own box evidence.

Test scopes that reach production privacy checks are created with the owned
testdir helper: an explicit mode-0700 child under a protected temporary parent,
with ordinary-directory and test-identity assertions before use. A test that
intentionally makes a path public does so only after that setup. The drift
controls restore the original mode or inode and require the same actual canary
bytes to remain readable afterward; an unrelated setup failure cannot pass.

## Owned fix 12 controls

All twenty rows below mutate owned production code and name their own focused
assertions. All previous 179 rows remain available. No runtime red or candidate
pass is inferred from Mac static vet. The helper facts in projection component
fixtures start after authentication; the separate SCM test exercises actual
Linux descriptors/seals and an owned synthetic canary only.

| Control | Focused test |
| --- | --- |
| f12-required-id | TestProjectionDeps |
| f12-producer | TestProjectionFlow; TestHeadlessProjection |
| f12-source | TestProjectionGuards/source |
| f12-held-observe | TestProjectionGuards/ack |
| f12-held-shape | TestProjectionGuards/holding |
| f12-held-durable | TestProjectionGuards/durable |
| f12-gate-policy | TestProjectionGuards/policy |
| f12-gate-claim | TestProjectionGuards/claim |
| f12-withdraw-admit | TestProjectionDrain |
| f12-withdraw-zero | TestWithdrawalZeros |
| f12-refresh-native | TestRefreshOwnerReject |
| f12-rights | TestProjectionSCM |
| f12-seal | TestProjectionSCM |
| f12-early-release | TestProjectionEarlyRelease |
| f12-effect-state | TestPlanClaimState |
| f12-stage-cap | TestActorStageCap |
| f12-history-bound | TestHistoryWalkBound |
| f12-retry-source | TestRetrySourceRevocation/acquire; TestRetrySourceRevocation/inject |
| f12-retained-policy | TestRetainedPolicyAdvance |
| f12-journal-generation | TestBrokerAADTransplant/generation |

The acknowledgement cells distinguish independent held observation, shared shape
validation and a real commit read-back. The withdrawal-zero cell also requires
retained slot bytes to survive a refused nonzero helper receipt, so a later
store refusal cannot hide premature broker cleanup. Native transfer controls
remove actual SCM_RIGHTS or the write seal; the latter must fail a real write
through an opened alias. The reverse refresh cell sends a real nonroot export
and requires refusal/closure; a positive root-helper return remains an installed
native cell. The new actor, history, policy, effect-state, generation and revoked
retry tests exercise real inputs. Every runtime kill still needs the exact
nominated diagnostic from mutations.py, followed by the same candidate pass.

The history-byte regression uses the same human scope as the mutation fixture.
It first keeps a config-only scope forbidden, then accepts exactly 8 MiB of
valid, individually bounded JSON payloads and requires budget_exhausted one
byte above that total. Its f12-history-bound edit and expected budget diagnostic
are unchanged. The original scope omitted its actor and was refused before
replay; the production limits and authorization guard have not been weakened.

## Round 4 security controls

The available total is 201. All preceding 199 controls remain present. The
early-release control now targets the shared locked validator after its move;
its original assertion and refusal behavior are unchanged.

| Control | Focused tests | Required assertion diagnostic |
| --- | --- | --- |
| f12-worker-policy | TestWorkerPolicyDelivery/prepared; /bound; /copy | stale worker generation returned material |
| f12-release-race | TestReleaseBindRace/profile; /worker | late projection binding was released |

The worker test first compares actual selected bytes under the current policy.
It then advances the policy before prepared/bound delivery, or between the
bound port's initial policy read and its final journal read. The deliberate
fault restores the previous older-generation comparison.

The release test stops at a channel barrier after the actual helper receipt
has been recorded and after the outer projection check. It binds before
allowing the tombstone transaction to proceed. The profile cell invokes the
real broker transfer and held acknowledgement. The worker cell writes the
ProjectionID through the real encrypted journal to model that binder step.
Both must retain the exact material and refuse cleanup. The deliberate fault
ignores each release transaction's projection refusal. No sleep decides this
interleave, and a failure to reach or perform the binding fails setup.

These are prepared regressions, not measured exploit or mutation kills. Run
their exact assertions before candidate green on the authorized nonroot Linux
box, in both tag settings, and retain the primary failures and source bytes.

## Round 6 review controls

The current total is 209 available controls. All preceding 201 names and tests
remain. Twelve existing entries follow moved checks or remove both checks of
the same invariant after the refactor; their runtime kills must be revalidated.

| Control | Focused tests |
| --- | --- |
| r6-quarantine | TestExposureQuarantine/cancelled; /rotation |
| r6-worker | TestWorkerProjection/binding; /marker |
| r6-completion | TestWithdrawalCommit |
| r6-fence | TestDurableFence/exchange; /guard |
| r6-policy | TestLiveSlotPolicy; TestLockedPolicyRead |
| r6-partial | TestPartialBind/profile; /task; /worker |
| r6-ack | TestAckReplayShape; TestTransferAckID |
| r6-release-group | TestInjectionReleaseGroup |

The quarantine cell checks the actual originals are closed while canonical
ownership remains. Worker cells consume real encrypted slots and the retained
selection, then validate the native binding metadata and cleanup binding.
Completion failure must leave every slot and login lease intact. Fence cells
read the protected journal after control failure or guard cancellation.
The policy hook advances the policy after acquiring the journal, so a check
before the lock cannot pass it. Bind cells interrupt real journal publication
and require refusal when that same pending bind is retried. Replay cells
correlate the malformed held receipt before checking shared validation; the
transfer-ID cell isolates the channel preflight. Group release mutates the
last task after measurement and requires the earlier profile lease to remain.

Each control's exact assertion diagnostic is in FAILURE_TEXT. All new test
paths are shorter than 40 characters. Only static checks ran on the Mac;
no row is claimed killed until its named assertion fails and the unchanged
candidate passes on the authorized nonroot Linux machine.

## Round 7 observations

The eleven r7 controls add live-resource, current-authority and cleanup checks.
Every preceding control name and selected test remains. The helper-zero control
now removes the early helper-shape check and must fail because the live refresh
lease retired before invalid helper cleanup was rejected. The quarantine fault
also removes read-back validation so its original retained-owner assertion is
still reached. Neither change is an observed runtime kill on the Mac.

| Control | Named assertion it must break |
| --- | --- |
| r7-broker-count | An actual open original is counted despite a stale closed flag. |
| r7-lease-count | A held kernel refresh lock is counted before withdrawal. |
| r7-lease-missing | Missing original live lease inventory refuses completion. |
| r7-kernel-probe | An independent kernel probe observes an actual held lease. |
| r7-withdraw-lock | Each withdrawal decision uses one journal transaction. |
| r7-writable | A real write-access alias produces a nonzero observation. |
| r7-clear | Both selected byte slices clear on every tested refusal. |
| r7-policy | Agent, worker and delivery select the approved policy head. |
| r7-ticker | Changed authority closes the guard without an explicit Check. |
| r7-quarantine-retry | Quarantined acquisition refuses immediately. |
| r7-refresh-live | A retired kernel lease cannot authorize another use. |

The live withdrawal regression also duplicates the actual kernel lock's owning
file description, closes the original through normal completion, and requires
refusal with intact slots while the duplicate survives. Closing that duplicate
must let the exact retry complete. This tests live state instead of a journal
counter. All selected new test names are shorter than 40 characters.

## Round 8 controls

| Control | Focused behavior | Required red diagnostic |
| --- | --- | --- |
| r8-prepared | Profile and task copies recheck quarantine, pending release and exclusions at the final read. | prepared material ignored live delivery policy |
| r8-worker | First and retry worker copies see a policy advance at the final read. | prepared worker ignored final delivery policy |
| r8-policy-source | Locked delivery selects the approved head over the historical scope. | agent credentials used historical policy |
| r8-guard | Policy and claim refusals return a nil guard interface and retain the error. | refused projection returned a nonnil guard |

The preceding 220 available names and selected test targets remain. Expiry and
worker-generation controls now remove both their earlier check and the deciding
shared delivery check, so the added check cannot mask the original assertion.
Their named diagnostics are unchanged. New selected test names are at most
37 characters. Linux runtime red-before-green verification remains required;
static validity is not a mutation kill or a demonstrated security finding.
