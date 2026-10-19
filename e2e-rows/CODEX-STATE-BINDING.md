# Codex state binding compatibility

Run these checks only on the designated disposable Linux test machine, with the
pinned private harness available on its normal Python import path. The public
rows use the harness's Codex provider double and lifecycle fixture. The vendor
input rows add a recording wrapper that delegates to the original provider
bytes in the same process. They make no authenticated AI-service request.

```sh
go test -count=1 ./internal/hookconfig
LANEBOSS_ROW_EVIDENCE="$EVIDENCE" python3 -m unittest discover -s e2e-rows -p test_codex_state_binding.py -v
```

Require exit zero, no errors or skips, and retain the source revision, complete
source inputs, built binary bytes/hash, stdout, stderr, exit codes and fixture
records. Keep the existing `test_codex_state.py` rows in the release run: they
cover the matching-org exact state grant, real report/send, protected writes and
the effective PATH controls.

The regression was an unconditional state/instance-binding requirement before
repository vetting. The launcher configuration's org can differ from the vetted
Codex hook home's org without requesting a state grant. Automatic state access
now applies only when those orgs match. A supplied `writable_roots` entry still
requires the matching binding and the original exact-root validation. Matching
orgs retain their existing PATH checks and state grant.

Fixture setup uses the support's `write_user_config` helper to supply its normal
org binding, then reads that binding from the product's `config show alpha`
JSON through the fixture's own run helper. The distinct-org assertion and the
matching-org control both use this product view, without assuming the raw
fixture TOML already contains `org_dir`.

For red-on-base evidence, copy the new `state_binding_test.go` unchanged into a
disposable source copy of `ca7d8fc` and run:

```sh
go test -count=1 -run '^TestUnrelated' ./internal/hookconfig
```

The new units call only product/fixture APIs already present on that base.
`TestUnrelatedStateBindingNoGrant` must fail with `a fully vetted unrelated home
without extra roots must pass`, for both default and custom state paths.
`TestUnrelatedBindingInjection` must fail with `repository
injection must retain its diagnostic before any probe`: the base returns the
state-root diagnostic before it reaches the repository source. Compile errors,
fixture errors or timeouts are not valid red evidence. Run the same units on the
fix and require all assertions to pass.

Run the public rows against the base and fixed installed binaries, with the
harness's supported binary selection. On the base,
`test_unrelated_home_without_state_grant` must fail at its named launch assertion
with the state-binding refusal, and the inherited
`test_repo_hooks_refused_early` must fail because the repository-injection
diagnostic is masked. On the fix the positive launch must execute both actual
probe processes and exactly one provider invocation, preserving the unrelated
configuration's bytes without adding writable roots.

The public suite directly reuses the private repository-injection and tampered
hook controls. Its mutation driver first requires a green repository-injection
control, then removes only the `vetRepository(actual, home)` call in a disposable
source copy and installs that mutant. Require exactly one assertion failure,
no errors, and the reason `repository hook injection must be refused before any
Codex invocation`. The unchanged private
`CodexHookMutationTest` method `test_trust_vetting_mutants_fail` remains
authoritative; its `repo-skipped` subtest should now reach the intended control
and mutation.

`TestUnrelatedBindingGrantRefused` and the public
`test_supplied_grant_needs_matching_org` are retained negative
controls: they supply the actual bound configuration's state directory to a
different org's hook home. Full vetting, preparation, execution vetting and
rendering must refuse with `writable_roots`, without invoking a probe or
discarding the supplied grant. These controls also pass on the base; their
purpose is to prevent solving the regression by accepting or silently dropping
a mismatched grant. The existing state-root refusal/alias units and
`TestLanePath` remain unchanged and must still pass.

Static checks alone do not establish a runtime or mutation pass. The supervising
release run supplies the red/green Linux evidence and unchanged private-suite
results.

## Linux enforcement and the vendor-input limit

On Linux, laneboss itself does not restrict the lane process (`nativeRunner` in `internal/lanesandbox/runner_linux.go` only probes Landlock); the vendor's own sandbox, fed by these exact `writable_roots`, is the enforcement point whose inputs these rows check.

The Linux launcher does not enforce these workspace roots on the provider
process. `internal/lanesandbox/runner_linux.go:nativeRunner` only probes the
Landlock ABI and returns `Prepared: false`; it never restricts the process.
`internal/lanesandbox/runner_other.go:ReplacesRunner` is false on Linux. The
supervisor's `lanesandbox.Prepare` call therefore leaves this fixture's runner
unchanged before `Start`. The normal Codex path passes the rendered
`CODEX_HOME/config.toml` and the sandbox selector to the vendor; the vendor owns
its tool sandbox.

The private fixture's `CODEX` provider is Python code that reads configuration
and records calls, without creating a write sandbox. A write by this provider
process would not distinguish the org bindings through a launcher-enforced
boundary. The separate `codex_state_standin.py` applies Landlock itself to tool
children; that does not establish launcher enforcement over this provider.
`linux_landlock_scope_rows.py` likewise labels its canaries as diagnostics, not
passing Laneboss enforcement rows. No test-owned Landlock or bubblewrap wrapper
is added here.

The new rows use the brief's permitted fallback: they verify the vendor's actual
configuration and argv, without claiming an OS-level write-denial canary or an
authenticated vendor test. Existing Landlock-based communication rows keep
their previously documented scope.

In `CodexStateBindingVendorRows`, `test_mismatched_org_vendor_roots` keeps the
two orgs different. Its `test_matching_org_vendor_roots` method binds the same
configuration to the hook home's org. Both select `--sandbox
workspace-write` in the fixture's runner templates and start a real lane through
the installed launcher. Both declare the same `CODEX_HOME` and safe `PATH` in a
literal runner `env` prefix and pin the fixture provider by absolute path, as
the existing matching-org state rows do. The default fixture org grants
inherited `CODEX_HOME`; the separately initialized hook-home org does not. The
explicit transport keeps that settings difference from dropping the hook home
before Codex vetting. It changes no org environment grant or sandbox permission.

Without that prefix, `settings.Environment` filters out the ungranted name when
the org binding changes. The Codex gate then joins an empty home with
`config.toml`, and `regularBytes` fails its `Lstat` on that relative path. This
happens before state-root rendering or provider execution; the observer neither
renames the configuration nor changes its mode or links. A recording wrapper
reads the actual TOML bytes and argv at each version probe, feature probe and
provider invocation, then executes
the original provider bytes in that same process. The original provider's own
call record must match the observation's PID and argv. No expected roots are
passed to this observer and it changes no permission or sandbox setting.

The mismatched row fails with `mismatched org must reach the vendor without any
writable state root` if any observed config contains `writable_roots`. The
matching row fails with `matching org must reach the vendor with exactly its
configuration state root` if the list is missing, different or broader than the
single canonical state directory. Both require the selected config path and
worktree, both temporary-root exclusions, exact probe argv and exact launch
argv. An extra root/profile/permission override, a changed sandbox mode, an
absent probe or a provider that does not complete fails its corresponding named
assertion. The no-grant row also preserves the original config bytes. Assertions
parse records in memory and print verdicts rather than dumping argv or settings.

With an absolute `LANEBOSS_ROW_EVIDENCE`, these rows retain the observation
JSONL, original probe/provider records, provider wrapper and original bytes,
configuration files and row source before fixture cleanup. The directory is
`lb-s0-codexstate/METHOD/FIXTURE` beneath that evidence root. Keep the supervising
suite's installed binary/source archive and transcript alongside these records.

## State-grant restoring mutant

In `CodexStateBindingMutationRows`, `test_mismatched_state_grant_mutant` first
runs both vendor-input rows green, then applies exactly one literal replacement to
`internal/hookconfig/state_root.go` in a copied Go tree. It requires exactly one
occurrence of this original literal:

```go
if actual != filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(home)))) {
```

It replaces that literal with:

```go
if false && actual != filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(home)))) {
```

This mutant makes `boundInstanceState` return the bound configuration's state
for a different org, so automatic rendering grants it too. The driver installs
that copied tree and requires the matching-org row to remain green. It then
requires exactly one mismatched-row failure containing `mismatched org must
reach the vendor without any writable state root`, with one test run, no errors
and no skips. A refusal before launch, a fixture error or a failed build is not
the required mutant kill. The original repository-vetting mutation remains in
the same public suite unchanged.

This follow-up changes the fixture, unit names and this guide. Product
enforcement and the accepted state-binding fix remain unchanged. Linux runtime
and mutant results must be supplied by the supervising disposable-box run; the
authoring session runs only the permitted static checks.
