# Acyclic full source validation after the templates merge

Run 22 starts at 0729c23c, which contains the retained Source/TemplateSources
ports and templates.Service.ValidateSources. Green20 was still running when
this brief was issued; this lane does not claim or poll its runtime result.

## Callback correction

The production change is one call in internal/v2/assembly/assembly.go:169:
policy.Dependencies.ValidateSources now calls briefings.ValidateSources with
the original context, scope and exact generation request. It previously called
briefings.OrgValidate, which called Policy.ConfigValidate and re-entered the
same assembly callback.

The callback remains present. Its nil-binding refusal is unchanged. The called
templates.ValidateSources method at templates/org.go:131 checks scope, bounded
generation, the configuration's exact snapshot and returned selectors, then
calls validateOrg. It does not call ConfigValidate or OrgValidate.

validateOrg still checks the snapshot and ownership manifest, resolves every
source's exact committed reference, reads and verifies every source's bytes,
reads every derived file's bytes, and validates the complete template catalog.
readBlob and ReadVerifiedBlob still enforce scoped metadata, lengths, chunk and
full digests, cancellation and exact end. Public OrgValidate still performs
real policy validation and its own validateOrg call. No source-byte gate,
validator callback, selector or store ACL was removed.

The source graph is now:

OrgValidate -> Policy.ConfigValidate -> assembly.ValidateSources
-> templates.ValidateSources -> validateOrg -> retained store/blob reads.

The source-only branch has no edge back to policy or public org validation.
The templates, policy, store, API, harness and existing test sources used for
this trace remain byte-identical to HEAD; only the assembly call is changed.

## Generation-one end-to-end read-through

The installed harness at scripts/v2-serve/run.py:410 still requires actual
org.validate success at the publication receipt's generation. It does not
replace invalid validation with a pass.

1. Public templates.OrgValidate selects the installed configuration and the
   exact requested generation at templates/stub.go:193, then invokes real
   Policy.ConfigValidate at line 201.
2. Policy loads and validates the current scoped policy. approvedSources uses
   the run-21 configuration/source-generation selectors, checks the snapshot
   and inventory and resolves the workflow SourceRef through Store.Source.
3. The merged store.Source in store/sources.go:84 resolves the same exact org
   publication inside the protected read view, then calls templates.SelectSource
   at line 102. It no longer returns the old not_implemented stub.
4. SelectSource calls checkSnapshot at templates/inventory.go:58 before it can
   return the committed content reference. This is the first generation-one
   blocker in the merged path, before assembly's source-only callback is reached.

The initial bundle at scripts/v2-serve/bundle/main.go:214-215 supplies generation
1 with nonempty semantic Sources and explicit empty non-null Derived. Shared
api.ValidateOrgKinds at api/org_snapshot.go:7-22 permits that exact initial
shape and requires nonempty file-kind Derived only for later generations.

The merged templates/approved.go:130 also has an earlier unconditional
len(snapshot.Derived) == 0 check. It rejects the initial empty Derived before
the shared generation-aware gate at line 136. The next expected owned error is:

- Owner: lb-v2-templates.
- Code: integrity.
- Message: approved org snapshot omits its configuration, generation, renderer or inventory.
- Deciding predicate: templates/approved.go:130, len(snapshot.Derived) == 0.

Store.Source returns that SelectSource error unchanged. ConfigValidate converts
only invalid_request into an OrgValidation problem, so this integrity error
propagates through public OrgValidate as a refusal. This is a source prediction,
not an observed green20 or green21 result.

The next owner correction is to reconcile that presence check with fix 13's
generation-specific Derived contract while retaining semantic kinds and every
configuration, selector, renderer, ownership, inventory, path, revision, mode,
metadata and retained-byte gate. Adding a placeholder derived file, admitting
nil Derived or skipping source reads is not a valid repair. Run 22 does not
change that separate gate.

## Verification scope

All ten required vet configurations passed on Go 1.26.5, Darwin arm64, covering
assembly, the called templates package and their production/test importers:
Linux amd64/arm64 with default, faults, partial/authenticator and combined
partial/authenticator/faults tags; Darwin arm64 with default and
partial/authenticator tags. Every Go command used the requested shared cache,
readonly module mode and disabled downloads. gofmt and git diff --check passed.

No new test or constant-result stand-in was added for this one-call wiring
change. The existing TestSourceCallback makes the policy fixture fail if
re-entered and requires complete source reads without writes. Existing
TestInventoryKinds covers invalid source/derived shapes and corrupted retained
content. They compile in the vet scope; their runtime results remain for the
authorized Linux environment. No project test or binary ran on this Mac.

The source archive, exact brief, metadata, command outputs/exits and sixteen
trace-source files are retained in the lane's run-22 evidence. The handoff is
an acyclic implementation plus the next source-visible blocker, not a claimed
full org-validation or installed-service pass.

## What green21 should show

Verify the source-only callback and existing byte-validation regressions on
authorized Linux, then retain the installed org.validate result at the actual
published generation. The callback must remain wired and complete; it must not
re-enter public OrgValidate. With only this change, expect the generation-one
Derived refusal above, which the current merged Source port reaches before the
callback. After the owner reconciles that gate, require full valid=true and
problems=[] while exercising the actual ownership, source and derived reads.
Keep the publication read-backs, exact selectors, G1/G4 behavior and every
independent owner failure. Presence remains simulated and human approval
remains not proven.
