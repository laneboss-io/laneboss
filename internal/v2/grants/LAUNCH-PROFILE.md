# Reserved launch profile selection

ResolveProfile is a service-only capability implemented by grants.Service and
described by grants.ReservedProfileResolver. It accepts the existing opaque
GrantResolveRequest reservation selector. It is not registered as a public RPC
and accepts no caller-provided profile, grant member, path or credential.

The resolver loads the authenticated retained start/adopt frame, finds the exact
ProfileDelegation whose ParentGrantID equals that frame's ProfileGrantID, and
uses the same canonical resolver as GrantResolver.Resolve to derive the issued
member. Root issuance clears parent edges, so comparing a new root member ID
directly with its original template selector cannot establish this mapping.
Selection uses the ordered canonical derivation from the protected request;
it never searches for any available profile with the same driver or name.

Full ticket/starter, scope, original-input provenance/digest, current grant,
delegation, expiry, policy and source checks remain shared with Resolve.
The selected driver, profile identity, parent edge, delegation and expiry must
match; paid profiles require retained spend authority and current exclusions
still apply. A second fresh resolution compares the full reservation, grant
set and selected profile after source reads. Nothing is persisted, released,
acquired from the credential broker or inferred from a vendor-room response.

Resume/turn/continuation already select retained issued members. ResolveProfile
refuses those modes; a lifecycle caller must retain their existing selection
and slot/recovery checks rather than remapping them as a new start.

## Current consumer handoff

The supplied prewalk names lifecycle/plan_runner.go at revision 6cd128f7. This
checkout has no such file: lifecycle/launch_plan_stubs.go still returns its
own not_implemented from PlanLaunch. The retained evidence contains a small
unapplied lifecycle.patch against that exact pinned source. Its start/adopt
branch calls ResolveProfile and matches the entire returned member against
inputs.Grants.Profiles; all existing driver, expiry, spend, credential-slot,
session and runner checks stay. Retained modes use their existing issued ID.

Integration/lifecycle must apply that call when merging the real planner and
retain the actual issued member in the life/binding used by later resumes.
The original approved selector remains in the exact retained request. A
preparing Lane.ProfileGrantID copied from StartRequest is not that issued ID.
No lifecycle stub is replaced with a partial success in this checkout.

The original-request producer must also match lstate.Load's protected
metadata contract. This checkout requires private audience; the pinned planner
compares service audience. Preserve the owner-approved canonical contract when
composing those revisions instead of relaxing provenance in this resolver.

## Regression scope

TestLaunchProfilePick covers root start, root adoption and child start for both
drivers, exact equality with the canonical issued member, read-only replay and
closed read views. TestLaunchProfileChoice selects the second of two approved
profiles so a first-profile fallback fails. TestLaunchProfileSpend covers free,
paid-authorized and paid-without-spend inputs. TestLaunchProfileGuards refuses
unknown/ambiguous selection, driver/profile mismatch, widened/expired/delegating
authority, foreign/lane scope, changed policy, revocation, substituted stored
grants, altered original bytes, excluded/paid profiles and changes during source
verification. TestProfileRetainedRefused preserves the retained-mode boundary.

These are retained-state wiring fixtures, not installed vendor authentication.
Every new branch has an accepted and refused source trace. The named g7-*
mutations must reach their deciding assertions and then pass the unchanged
candidate on Linux; Mac static checks do not establish those runtime results.
