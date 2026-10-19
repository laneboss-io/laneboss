# Org validation selectors after green19

Run 21 starts at 4222986d. The remaining empty OrgSnapshotRequest is in
policy.approvedSources, not the current templates callers. The correction is
confined to that policy caller and its regression/control files; templates,
API, store, assembly and the installed harness remain unchanged.

## Observed failure and exact path

The retained green19 log records 053-publication-org-validate, CLI exit 0,
71 ms, returning valid=false with the sole problem:
"org snapshot requires this configuration and an exact generation".
The supervisor reported 26 of 78 checks. This is a measured prior result;
the new source has not run installed validation on this Mac.

1. templates/stub.go:193 already supplies OrgID=ID(scope.Config) and
   Generation=request.Generation. templates/approved.go:187 also supplies
   the configuration ID and provided.Snapshot.Generation.
2. OrgValidate calls Policy.ConfigValidate at templates/stub.go:201.
   policy/service.go:349 enters getPolicy, which loads the real current scoped
   policy and validates its shape, context, policy generation and content hash.
3. In the tested source, policy/sources.go:18 calls Store.OrgSnapshot with an
   empty request. This is the exact remaining caller that loses the selectors.
4. store/contract_stubs.go:125-128 rejects that input before the scoped lookup.
   policy/service.go:349-353 converts this invalid_request into an invalid
   OrgValidation problem, explaining the returned valid=false and CLI exit 0.
   The installed harness correctly keeps that result as a failed check.

Paths above are under internal/v2. The tested log/source archive/checksum and
nine byte-matched trace sources are retained in run-21 evidence.

## State-derived selection

docs/design/v2-contracts.md:2314 defines SourceRef.Generation as the current
snapshot generation. ResourceFile.RevisionGeneration separately retains an
unchanged file's original revision. Org generation and policy generation are
explicitly independent.

The real stored policy's validated Sources therefore supply the expected org
generation. policy/sources.go now requires a nonempty set with one common
generation, constructs OrgSnapshotRequest with ID(scope.Config) and that source
pin, and applies ValidateOrgSnapshotRequest before lookup. The returned snapshot
must also match both selectors. Existing manifest, inventory, revision, source
membership and retained-content checks remain.

There is no generation-one default, policy-generation substitution, ambient
configuration selection or weakened store gate. If approved source pins are
missing/mixed, selection fails. If the current publication differs from that
exact pin, the store's conflict is preserved; the caller does not substitute a
new generation. No API or store extension is needed.

## Generation-one gate and next blockers

The generation-one initial bundle in scripts/v2-serve/bundle/main.go:214-215
has semantic Sources and explicit non-null empty Derived. Its source refs and
RevisionGeneration are generation 1, modes are 0444, content hashes are pinned,
and it supplies a renderer and ownership manifest. ValidateInitialSources
already checks that narrow publication shape.

api/org_snapshot.go:7-22 now admits explicit empty Derived at generation 1 and
requires nonempty file-kind Derived for later generations. Nil Derived at
generation 1 remains invalid. templates/approved.go:136 uses this shared gate
and retains its configuration, generation, renderer, ownership, mode, digest,
revision and unique source/path checks. The initial shape conforms to that
gate by source inspection. This is not a full OrgValidate pass.

The immediate next expected failure is earlier than validateOrg:

- policy/sources.go calls Store.Source for the actual policy's workflow source
  after the selected snapshot and inventory checks.
- store/contract_stubs.go:149 unconditionally returns lb-v2-service,
  not_implemented, "store.Source is not implemented".
- ConfigValidate only converts invalid_request into Problems. This named
  not_implemented propagates as an RPC error; it must remain a failed installed
  call rather than being relabeled as valid.

After that port lands, assembly/assembly.go:165-169 still wires policy's full
ValidateSources callback to briefings.OrgValidate. That method calls
Policy.ConfigValidate again at templates/stub.go:201. This is a source-visible
validation cycle, not a measured timeout. Supply an acyclic complete
source/policy validator before expecting full validation success. The narrow
initial validator is not a replacement for that gate.

## Regression and control scope

The policy test store now enforces the actual selector input contract and
records each request. Its org ID matches the installed configuration instead
of an unrelated fixture ID. Malformed output projections remain explicit
consumer fixtures, preserving the existing configuration/inventory checks.

TestOrgSnapshotSelectors checks org generations 1, 7 and 19 while policy
generation is 31, requiring the exact state-derived request and no policy
mutation or inference. TestOrgSnapshotSelectorRefusals checks missing/mixed
pins and an advanced current publication, preserving conflict and empty output.

TestApprovedSnapshots/stale-source still advances the current publication and
now requires the real exact-selector conflict. The separate stale-inventory
case requires integrity for a malformed inventory source generation. The
existing source-generation omission keeps its ID, edit and diagnostic and
targets that inventory case. Independent policy-source membership checks are
retained; this control must not be described as proof that every stale source
becomes readable when one inventory check is omitted.

Three new omission controls select TestOrgSnapshotSelectors/published and
must reach "approved sources omitted or changed the current publication selectors":

| Control | Deliberately wrong selector |
| --- | --- |
| org-selector-missing | Empty OrgSnapshotRequest |
| org-selector-policy-generation | EffectivePolicy.Generation |
| org-selector-initial-generation | Hard-coded generation 1 |

All three omission source variants passed Linux amd64 vet through retained
overlays. The candidate passed the ten required vet configurations over policy
and its production/test importers: Linux amd64/arm64 with default, faults,
partial/authenticator and partial/authenticator/faults tags; Darwin arm64 with
default and partial/authenticator tags. Every Go invocation used the requested
shared cache with readonly module mode and downloads disabled. These are static
type checks. Runtime red assertions, candidate tests and installed success
remain pending on authorized Linux.

The cross-lane files changed are internal/v2/policy/sources.go,
internal/v2/policy/fixture_test.go, internal/v2/policy/contracts_test.go and
internal / v2 / policy / source_selectors_test.go, plus the policy omission catalog.
This note and REQUESTS.md record the handoff. No templates G8 source is changed.

## What green20 should show

First qualify the three new omission controls and the retargeted inventory
control with named reached red assertions before unchanged-candidate passes.
Run the policy regressions with normal/faults and applicable installed tags.
Then retain the actual org.validate request and selected configuration/org
generation: the empty-selector problem should disappear without any generation
constant or removed gate. With only this patch, expect the owned store.Source
refusal next. Once that owner port and the acyclic validation composition are
ready, require full valid=true and problems=[] at the actual published generation.
Keep the real publication read-backs and prior G1/G4 behavior, and retain every
independent owner failure. No new end-to-end pass is claimed here.
