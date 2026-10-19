# Draft.4 Linux verification handoff

Run only on the supervisor's authorized disposable Ubuntu 24.04 box from the
exact retained round-9 candidate with the fixture corrections.
The source base is 750422e; earlier results do not cover this candidate.
Retain the complete
source, manifest, toolchain/module inputs, tested binary bytes/hashes, actual
commands, primary outputs and exits. The current Mac checks are static only.
The earlier integrated-tree passes do not establish these results.

Use a private, empty nonroot test identity with nonzero UID/GID, a private home,
ordinary mode-0700 test/evidence/temp
directories, the pinned Go 1.26 toolchain, the race toolchain prerequisites and
preloaded public modules matching go.mod/go.sum. Copy no credentials or owner
home. The mutation runner constructs its own empty subprocess environment and
uses dedicated module/build caches; those scopes must not overlap source or
evidence. All commands below run from /test/src. Stop the dependent phase at a
nonzero exit and preserve its evidence.

## Unit and component checks

Run this broad phase after the named red-before-green phase below succeeds.
The seven method-predecessor controls restore the old typed barriers so the
new positive paths first fail for their intended missing behavior.

```sh
go test -race -count=1 ./internal/v2/secrets/...
go test -race -count=1 -tags laneboss_faults ./internal/v2/secrets/...
```

Both commands must exit 0 and report PASS for the tested packages. The
connection/frame and launch fixtures begin after authentication. Launch tests
retain/reload actual request/spec/blob/ciphertext bytes, hash synthetic runtime
files, and measure their owned process and resource-directory scope. They
exercise reserved acquisition/injection, worker pre/post-spec ordering, room,
eligibility, continuation, canonical refresh, restart and measured cleanup.
They do not authenticate an OS peer, implement production containment or prove
an AI service works. Missing owning dependencies remain typed errors. Physical
env/file projection and collection still require the installed acceptance cell.

## Runner failure evidence and defaults

```sh
python3 e2e/v2/cases/secrets/check_runner.py \
  --source /test/src \
  --output /test/evidence/"lb-v2-secrets-runner-checks"
```

Require exit 0 and result status red_then_green. The two retained runner faults
must break their actual diagnostic/default scenarios first. The candidate then
checks missing source, a real nonzero tool, malformed options without value
echo, preservation of existing output, typed blocked 69, and a real native
directory-mode mutation through the three-option invocation. The latter must
retain the exact targeted red failure, green pass and both tested binaries.

Go/cache flags are optional now; explicit pins below remain supported. Source
archives need no Git metadata. No module download or owner-home copy is used.
See MUTATIONS.md for discovery, confinement and failure-evidence details.

## Outside-observer and probe regressions

```sh
python3 e2e/v2/cases/secrets/check_case.py \
  --source /test/src \
  --output /test/evidence/"lb-v2-secrets-case-checks"
```

Require exit 0, red_then_green, all seven deliberately faulty variants killed
for their named diagnostic, and the complete candidate checks passed. The source
copies, hashes, primary outputs and command exits remain in that directory.
This checks the observer and actual synthetic probe script on Linux; it does
not start a real model or establish either live acceptance assertion.

## Red before green

Run the exact available catalogue in both tag settings. Provision the parent
evidence/cache directories first; each mutation output must be fresh. The list
is command output retained before parsing, and the catalogue count is checked
so a missing row cannot silently disappear.

```sh
set -eu
python3 e2e/v2/cases/secrets/mutate.py --list \
  > /test/evidence/lb-v2-secrets-mutations.list
awk -F ': ' '$2 ~ /^available;/ {print $1}' \
  /test/evidence/lb-v2-secrets-mutations.list \
  > /test/evidence/lb-v2-secrets-available.list
test "$(wc -l < /test/evidence/lb-v2-secrets-available.list)" -eq 224
while IFS= read -r secrets_mutation; do
  python3 e2e/v2/cases/secrets/mutate.py \
    --mutation "$secrets_mutation" \
    --source /test/src \
    --output "/test/evidence/lb-v2-secrets-$secrets_mutation-base" \
    --go /usr/local/go/bin/go \
    --module-cache /test/cache/go-mod \
    --build-cache /test/cache/lb-v2-secrets-build
  python3 e2e/v2/cases/secrets/mutate.py \
    --mutation "$secrets_mutation" \
    --source /test/src \
    --output "/test/evidence/lb-v2-secrets-$secrets_mutation-faults" \
    --go /usr/local/go/bin/go \
    --module-cache /test/cache/go-mod \
    --build-cache /test/cache/lb-v2-secrets-build \
    --tags laneboss_faults
done < /test/evidence/lb-v2-secrets-available.list
```

An explicit --source-manifest pins a retained path list. A source archive
without Git metadata is also supported directly; its confined file inventory
and exact copied bytes are retained, as documented in MUTATIONS.md.
Every available row must exit 0 with status killed_then_green and killed true:
its exact selected tests must run, fail red with the named diagnostic, then
pass green. Compiler/setup failures, skips or another diagnostic are failures.
MUTATIONS.md maps every fault to its actual assertion. All 81 preceding rows
remain, including directory-mode, lock-identity, eligibility-paid and the
d4fix1 mutation/retry hardening. The 72 fix-9 controls add method predecessor
failures and deciding reservation / claim / policy / input / private-slot, worker,
evidence/eligibility, canonical refresh, measured cleanup, journal and bounded
blob-read checks.
Retained keys in the CLI controls prevent a missing-key error from masking
their targeted input validation. No fix-9 kill or green is claimed from Mac
static checks; each row must produce its own retained Linux result.

All 153 prior rows remain. Seven fix-10 rows cover stored role/level/driver,
consumed ticket/proof, prepared worker Kind and current capture policy. Nineteen
fix-11 rows cover the five required outside usage gates, every-row/reset/grant
validation, worker mapping/material, the exact native command, executable pin,
private home, actual kernel lifetime, sealed executable bytes, complete bounded
output and the owned
producer path. The room and refresh-serialization controls are retained with
corrected source/setup, not counted as new or successful runtime rows.

The usage consumer fixture runs a real synthetic cat/false pipe and retains
its actual exit. The command fixture installs and reads back an exact private
mode-0500 copy of the retained test binary and executes it as a
native synthetic program whose private files determine stdout/exit; it checks
exact argv, private cwd/home, noninheritance of a named synthetic environment
canary and actual immutable executable seals. It never launches claudock or a
model. Production usage dispatch/mapping/bootstrap/profile projection and a
real outside query remain installed acceptance requirements. Save the actual
red-build.err and red-tests.out for every failed row; a summary alone cannot
establish the first failing assertion. The existing argv/home/environment/raw
assertions and cancelled/unavailable error expectations remain unchanged.
Cancellation now has an additional real started-child readiness-pipe test,
and overflow covers both stdout and stderr. Run the command controls first;
the earlier race failure reported only their generic assertions, not the
actual error codes. The fixture's build-permission assumption is corrected,
but the prior box cause remains suspected until exact-source Linux execution.

The nine blocked live controls are not included in the available phase. Calling
one still exits 69 with not_implemented and killed false, which is an incomplete
live test. Their named faults and acceptance targets remain in the catalogue.

## Installed black-box cell

Build and retain the actual product. The first eight operations use that same
installed executable's human session flow. The harness owns /test/fixture and
the protected installed bindings:

```sh
go build -o /test/fixture/laneboss ./cmd/laneboss
sha256sum /test/fixture/laneboss
sh e2e/v2/cases/secrets/run.sh \
  --context /test/fixture/secrets-context.json \
  --result /test/evidence/lb-v2-secrets-result.json
```

The context, installed binary pin, protected fixture, real synthetic WebAuthn
assertions and independent observers are described in README.md. Build success
does not create them. The harness must authorize the actual live profile cell;
this document grants no authentication, model calls, paid service or provisioning.
No fixture credential value enters the checkout, command line or diagnostic.

When every prerequisite and implementation exists, require exit 0, both
SECRET-INJECT and CREDENTIAL-BOUND reached/pass, real canary/capture/grant/task/
launch/history correlation, and independently checked process/resource collection.
Red artifacts must reach and fail their intended boundary before the candidate
can pass. A successful process with a fabricated receipt cannot satisfy this gate.

With this source the case is expected to fail on the missing installed client/
identity/service path, or later on the secret-specific typed dependencies in
the secrets package's CONTRACT-GAPS.md. That is an incomplete E2E, never acceptance. Draft.4 harness control
bindings require live_auth false and cannot drive this live credential cell.
Static checks and the credential-free demo runner are not authenticated-service
or OS-boundary evidence.

## Fix 12 broker follow-up

The round-6 source base is 8e40ecf with the eight review corrections.
That round required 209 available rows in both tag settings. Run the f12 controls before
the broader suite. ProjectionFlow/HeadlessProjection validate contract and
broker state against typed post-authentication helper observations. ProjectionSCM
uses real anonymous sealed descriptors, native ancillary transfer and an actual
write attempt through an opened alias. Those scopes do not establish root-helper
authentication or cross-UID native projection.

The installed cell must supply the real identity, store, helper and outside
worker host, then verify acknowledgement interruption, revocation/open races,
zero-count withdrawal, root-owned Codex refresh and NATIVE-TASK-ENVP-1. Keep a
random ordinary canary out of every earlier environment and observe it only in
the final unprivileged vendor exec. No environment dump, real credential/model
request or root-helper run is authorized by this Mac handoff. Darwin export and
uncertain original-broker recovery remain fenced until their native producers
can establish exclusive ownership and current authority.

Round 4 requires f12-worker-policy and f12-release-race before the broader
matrix. The first covers prepared, bound and final-copy policy advancement.
The second binds a projection after the outer cleanup check using a channel
barrier, then checks that the slot remains unreleased with identical bytes.
The profile cell reaches held through the real broker; the worker cell models
the protected binding write. Neither cell establishes native authentication.
Whole-tree static vet must also include linux/arm64 alongside linux/amd64,
linux with laneboss_faults, and darwin. Do not treat static validity as a red
control result or as confirmation of the suspected scan findings.

## Round 7 live resource observations

Run all 220 available rows, retaining the 209 preceding names and targets.
Run the r7 controls and the retargeted f12-withdraw-zero and r6-quarantine
before the broader matrix, in both tag settings. All new selected test names
are shorter than 40 characters. No Mac runtime pass is claimed.

BrokerDescriptors samples the original export File handles with Stat after
close. RefreshLeases probes actual private canonical-login kernel locks through
independent open file descriptions after closing their originals. A duplicated
owning FD therefore remains visible. Missing original live inventory, changed
lock identity, an unavailable probe or any survivor refuses store completion;
journal SlotID metadata never supplies a live count. Refresh and gate use require
the original live kernel lease. Durable canonical ownership stays allocated
until completion succeeds and every private slot write finishes.

WritableHandles observes write-access aliases to the exact inode in the current
Linux process FD table. The sample has process scope and is not atomic with
future opens. Full immutable seals independently prohibit writes through other
processes and future aliases. The alias regression opens a real read/write alias,
requires a nonzero observation, proves a write still fails under the seal, then
closes it and requires the observed count to fall.

The lock regression requires one journal transaction for each withdrawal step
and preservation of retained refresh metadata. Quarantine tests enter through
FinishCredentialWithdrawal, retain slots and ownership, and require acquisition
to refuse immediately. Buffer tests retain references to both selected slices
across profile, validator and canonical-owner refusals. Policy tests give the
historical and approved ports different generations. Ticker tests change policy,
claim, grants and lane epoch without an explicit Check call and require a durable
fence within the bounded observation window. These remain post-authentication
component tests until run; installed native acceptance is still separate.

## Round 8 prepared delivery and refusal

The current matrix has 224 available controls. Run the four r8 controls plus
the retargeted fix9-material-expiry and f12-worker-policy before the broad
matrix, in both tag settings. Keep the earlier names and test targets.

PreparedSlotMaterial and PrepareWorkerMaterial now run deliveryPolicy inside
their final journal callback before copying any bytes. Task delivery also checks
the retained selected profile slot and its canonical owner there. The prepared
policy regressions change quarantine, pending release or exclusion at the final
selected-slot read, after earlier checks have passed. Worker cases advance the
approved policy at that same point for both first copy and handoff replay.
Require no returned bytes and retained material on refusal.

The previous Linux failure was a typed nil guard pointer converted into a
nonnil interface on error. The public wrapper now returns a nil interface and
the actual refusal error. TestProjectionGuards keeps its original policy and
claim assertions and cleanup calls. TestGuardRefusal additionally requires a
usable positive guard, a conflict error on refusal, an actually nil interface
and the persisted fence. Its red control restores the typed nil conversion;
the required failure is the named interface assertion, not a panic or a skip.

The approved-head delivery source was already corrected in round 7. The focused
r8-policy-source control isolates that deciding read under the journal lock.
Mac checks remain static only. The retained old panic log is failure evidence
for the old source; it is not a runtime result for this candidate.

## Round 9 fixture enrollment order

Task sources must be enrolled before Acquire pins the complete grant-set digest
in the encrypted profile slot. Both corrected fixtures now follow that order.
Injection still uses the real current-policy and grant reads under the journal
lock. No production check, source resolver or successful response is replaced.

Run r8-prepared and r6-partial in both tag settings before the broad matrix.
The prepared-policy task cells must reach their final-read authority change,
refuse with no bytes and preserve the selected material. Partial-bind cells must
reach the configured interrupted journal-write attempt, return unavailable, then
refuse retry with conflict. The expected errors and all earlier assertions are
retained. A setup refusal before the intended write or policy change is a failed
control, not a mutation kill. The catalogue remains at 224 available controls.

The retained prior-source log contains six task setup failures and two task
partial-bind assertion failures across its race settings. That is old-source
failure evidence; corrected-source Linux results remain pending after the Mac's
static checks. The production source and the projres filename are unchanged.
