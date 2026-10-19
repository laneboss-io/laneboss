# Landing review repairs

This candidate starts from the supervisor-reported `1a98b73d`. No commit,
merge, branch change or Git metadata mutation belongs to this authoring run.
The supervisor owns the composed Linux unit run, installed debug run and delta
reviews. Static compilation is recorded separately from runtime acceptance.

The Codex `TestLimitGrantBinding` failure was a fixture inconsistency. Its
original request now contains the full issued profile inventory. The test seals
a valid launch before changing only the credential event's selected grant and
requires the exact profile-binding refusal. The production inventory equality,
slot mapping, retained grant and materialization guards remain active. The
stand-in profile hook remains tagged and has no vendor-room authority.

The four mandatory Fable repairs have these regressions and controls:

| Repair | Regression | Deciding controls |
| --- | --- | --- |
| Ordinary native mounts use `--ro-bind-fd` and `--bind-fd`, with unchanged targets and access modes. ExtraFiles inheritance supplies the descriptors. | `TestNativeBwrapOptions` checks every projection and descriptor position against actual public bwrap help; the existing real descriptor canary remains required. | `native-bwrap-rofd`, `native-bwrap-rwfd`, `native-bwrap-fd-source`. |
| Codex retains the immutable service author and authenticates the fresh claimant through the exact durable lease. | `TestPlanningAuthor` checks a fresh claimant, invalid authors, a changed durable author and a foreign claimant. | `lp-retained-author`, `lp-author-kind`, `lp-author-id`, `lp-claim-actor-id`. |
| Lane recovery can remove an owned stale socket in its protected private directory. | `TestLaneSocketRecovery` and `TestLaneSocketReplacement` use real sockets, refused links/types, a foreign asserted owner and a replaced inode. | `lane-stale-recovery`, `lane-live-preserved`, `lane-inode-preserved`, `lane-owner-preserved`. |
| Fixture provenance describes the actual staged module build. | `fixture_provenance_test.py` checks selected module/vendor files, changed source/dependencies and retained harness bytes. | `provenance_controls.py` runs five strict red/candidate pairs, including an incorrect isolated-module digest. |

The socket recovery opens both parent and child without following links, checks
their type, mode and service owner, and requires `ECONNREFUSED` from a
nonblocking connect to the pinned inode. It rechecks parent and entry identity
before unlink. Live, foreign, linked, replaced or uncertain entries remain.
Public, administrator and worker listener bind behavior is unchanged.

Fixture selection comes from the same `go list -mod=vendor -tags
laneboss_e2e_authenticator -deps -json` module context as the fixture build.
Project rows must match `source-files.json`; vendor rows and `modules.txt` must
match `dependencies.tar` and `vendor-manifest.input`. The isolated fixture copy
and substitute `go.mod` are no longer recorded as build inputs. Standard-library
inputs belong to the recorded toolchain rather than the project manifest.

The Gemini credential-path finding is repaired at its cause. Credential home
lookup accepts exactly owner zero, the allocated lane group and mode `0710`.
File reservation and view lookup use the shared no-link descriptor walk.
Export source pinning uses that walk too. Export children are inspected as
inodes; contained relative data links are resolved with held descriptors,
bounded links and mount-ID checks. Absolute links, root escapes, magic links,
dangling links and same-device mount crossings refuse. The original supported
contained-link behavior remains. `TestCredStagedWalk`, `TestExportRestricted`
and `TestWalkMountCrossing` require real kernel `openat2` refusal and native
inode/byte read-back. Their route controls restore the blocked syscall.

The monitor EOF and PID-1 exposure claims remain suspected until the installed
Linux canary runs. The candidate supplies a bootstrap-created close-on-exec
socket after bwrap has started; its proof end is never inherited by the outer
monitor or PID 1. The helper checks its native creator, exact ancillary count
and atomic close-on-exec receipt. Acceptance still requires EOF, a live pinned
process and the exact vendor executable. Every bootstrap error return sends a
refusal byte before closing; an error return cannot become exec EOF even when
worker and bootstrap use the same executable. A failed refusal send keeps the
confined process's proof end open until the helper closes its bounded attempt.

`TestInstalledCredentialExec` runs the real installed bootstrap and bwrap gate
with actual synthetic credential files and a sealed environment export. It
checks the credential inside the vendor process, requires only stdio in
`/proc/1/fd`, and rejects unselected inherited regular, directory, pipe or socket
descriptors in the vendor. The vendor stays alive on its input pipe while the
helper observes EOF and hashes its executable. The test records the original
inherited channel as `monitor-control-eof=observed` or `retained`; that control
observation never supplies exec acceptance. Its EOF and PID-1 controls must
reach their named assertions on the debug box. `TestExecProofPeer` and
`TestExecProofRefusal` check native descriptor receipt, collection and refusal.
The credential authority is a declared synthetic component fixture; this is
not an authenticated model-service or broker-authorization test.

Gemini's endpoint-mount item is repaired: the lane client requires protected
root-owned ancestors, and exact/ancestor/descendant projection collisions are
rejected before endpoint files are pinned. `TestLaneClientAncestors` and
`TestLaneMountTargets` have deciding controls. The startup-only cgroup FD is
invalidated before close. Prompt, inherited-descriptor and exec-proof refusal
reasons now have closed diagnostic words and distinct bootstrap exit codes.

The smaller Fable items have these dispositions:

- Socket inventory matches exact paths under helper and actual service worker
  parents. `foreign-parent` and `nested-parent` are excluded controls; stream
  bounds, full EOF and malformed-tail refusals remain.
- The sealed lane binding is reopened read-only. The installed projection
  regression checks its actual access flags and unchanged immutable bytes.
- Grant-policy selection checks the returned reservation ID. Abandoned marks
  validate target and generation grammar before the contextual empty review.
  The unreachable raw short-write journal-reason branch is removed; actual
  journal failures retain their typed integrity refusal.
- The lane listener's global mutex still covers setup. Replacing it needs a
  per-launch setup reservation, waiting/retry semantics and a close/revocation
  race proof. That ownership change is deferred beyond this landing repair.
- Slow non-plan effects still follow their existing lease-failure policy. A
  general retry classification could repeat an uncertain native side effect;
  each effect needs an owning recovery/read-back decision before broadening it.
- Identity now has 325 distinct package/test/edit controls. The duplicate
  `f11-read-expiry` and `omit-root-cgroup-check` rows are removed; their unchanged
  canonical controls remain. A regression rejects repeated cases.
- Admin has 692 entries: 686 product mutations and six explicit fixture checks.
  All entries map to acceptance rules. Fixture-check kills remain separate
  from product mutation coverage. The Linux mutation runner keeps its stricter
  product-only test-target rule.
- Both service control documents now describe 325 current controls, 650 reds,
  650 candidate controls and fourteen package/tag suites. Older round counts
  are marked as historical.
- The state-suite launch receives a fresh `human.session` proof. Harness
  retention includes `native_cleanup_control.py` and every harness Python test.

The collection/namespace denial findings and withdrawal/stage-recovery findings
assigned elsewhere are untouched. Service planning tests, templates, protected
launch binding/authority files and store launch files are unchanged as well.

Run all runtime checks on the supervisor's disposable Linux environment. The
credential exec canary requires both `laneboss_root_canary` and
`laneboss_gate_integration` inside the existing exclusive gate-integration
helper control unit, with its original root/account/procfs/cgroup restrictions.
Compiling the test outside that environment supplies no installed evidence.
Run the Python provenance controls and reporter regressions there too. Each
mutation must compile, reach the named deciding assertion, fail for that reason
and then pass on unchanged candidate input; setup failures and timeouts earn
no credit. Presence is simulated and human approval remains unproven.
