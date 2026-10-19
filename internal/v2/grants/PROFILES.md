# Protected root profiles

GrantsRoot verifies its existing live human scope, exact request/frame/proof,
immutable committed root-manifest bytes and manifest shape before resolving
profiles. The signed selectors remain in the issued set, with fresh member IDs
and unchanged driver, provider, paid, delegation and expiry fields. A profile-only
root is supported. Its set expiry is the maximum member expiry, as for data and
channels; no member's authority is widened.

Dependencies.Profiles is the existing bstate.Backend used by the protected
administrator/secrets enrollment. Resolution holds WithBroker's process/kernel
lock through the root Store.Transact and durable-reply validation. After waiting
for that lock, it opens a fresh scope/policy view and applies current profile
exclusions before reading exact profile records. Each decrypted payload must
match its schema, installed configuration, profile ID, driver, provider and paid
selection. Malformed enrollment metadata and source/evidence references fail
closed. Requested expiry cannot exceed either the enrolled profile or its source.
After channel and source reads, issuance opens another fresh authority view,
checks the live scope, current policy generation and profile exclusions, and
uses that scope for the root transaction. The broker lock protects enrollment
records; it does not serialize policy or the human connection with those reads.

The resolver reads only profile metadata. It never reads login/slot records,
fetches credential material, acquires a refresh lease, writes the encrypted
journal or creates a profile lease. Credential availability and later acquisition
remain secrets/lifecycle responsibilities. Root authorization does not prove
authenticated vendor access. The enrolled evidence reference is validated as
metadata; root issuance does not require a fresh vendor-room observation.

An unwired backend returns grants-owned prerequisite_missing. A locked or
missing record returns the actual protected backend error unchanged. A foreign
or mismatched selector and an excluded or wider expiry return forbidden;
malformed protected metadata returns integrity. Resource and secret roots use
the immutable protected record resolver documented in ROOT-ENROLLMENT.md.
Network still requires its protected endpoint resolver; non-copy data retains
its explicit unimplemented gate.

## Installation handoff

The composition root must construct native.New with its installed Config, Clock,
Directory and KeyHandle before grants.New, pass that same backend as Profiles,
and pass Config to secrets.New. These fields are already required by the owning
constructors. Integration owns that file. A proposed source patch is retained
outside the repository for review; this lane does not change composition.

The protected installer must perform its real native.Unlock and InstallProfile
flows. This change adds no enrollment RPC, key fallback, synthetic credential,
automatic login or replacement record. The installed G3 fixture keeps both
drivers' selectors; without genuinely enrolled records its run must still fail.

## Verification scope

TestRootProfiles uses the real encrypted native journal in private test-owned
directories, with a fresh random in-memory test key and declared synthetic
profile metadata for both drivers. Human/proof/store facts remain unit fixtures.
The positive cases require exact profile preservation and durable issuance;
negative cases require the exact typed code and no transaction. Journal wrappers
trap credential reads/fetches/writes and require the lock during the transaction.
TestRootProfileOrder requires proof, immutable bytes and current policy gates
before any protected profile read, including a policy change during lock entry.

The g3-profile-* mutation catalog names the stub, dropped-selector, profile-only,
missing / foreign / identity / driver / provider / paid / generation / exclusion, expiry and
policy-recheck controls. These are definitions for Linux red/green execution,
not measured red results or installed acceptance. Run them on the authorized
Linux machine using the commands in the case README. Mac vet compiles/analyzes
the tests but does not execute them or authenticate a vendor.

## Review round b

The original use of manifest.Blob for credential_evidence was incorrect: its
closed class list rejects that class, while the second condition rejected all
other classes. The corrected check uses the secrets owner's ID/digest/size
grammar and the exact credential_evidence class directly. The shared class list
is unchanged. Expiry checks remain required and keep their forbidden assertions.

Provider names now use wire.Name. Optional Usage metadata follows the secrets
enrollment grammar: Claudock driver, nonempty bounded UTF-8 vendor profile with
no tab/newline/NUL, bounded adapter version, complete executable pin, and a
bounded manifest-class runtime reference. An absent Usage remains valid; root
resolution performs no outside usage query.

The following are source reasoning checks, not runtime observations:

| Finding | Accepted path | Refused path and deciding regression |
| --- | --- | --- |
| P0 evidence class | The fixture's credential_evidence reference has a valid ID, digest and bounded size; it reaches expiry checks and durable issuance. | Artifact class, invalid ID/digest or out-of-range size returns integrity in TestProfileEvidence. Existing expired/ceiling/source-expiry cases still require forbidden, so an early integrity failure cannot pass them. |
| P1 root gates | Enrolled profiles retain their implemented path; an unwired profile backend returns prerequisite_missing. Resource/secret roots require actual protected immutable records. | TestRootAndRevokeStayClosed requires that exact prerequisite and no result/write. TestRootCapabilityGates requires not_found for unknown secret/resource handles, forbidden for an unwired endpoint, and not_implemented for non-copy exports. |
| P2 metadata | The normal provider, absent Usage, and a valid Claudock Usage with a space in its vendor name pass metadata checks. | TestProfileMeta changes one predicate at a time; matching malformed providers and fourteen invalid usage-field cases require integrity and zero transactions. |
| P3 release authority | Unchanged data/channel controls commit using a fresh open read view and the original human proof/frame. | TestProfileRelease changes policy, exclusion or the live peer during each actual fixture source/channel read; it requires conflict/forbidden before any transaction. |

Eleven g3b-* controls name these deciding assertions. The prior profile-exclusion
control now removes both initial and final defenses, preserving its original
test and diagnostic. TestProfileRelease separately targets the final guards.
Each control must fail at its named assertion on Linux, then the unchanged
candidate must pass. Static compilation alone cannot credit either result.
