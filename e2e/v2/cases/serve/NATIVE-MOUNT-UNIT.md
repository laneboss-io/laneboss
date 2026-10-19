# Native mount walk with required helper hardening

Run 26 starts at 8b790632. The LB-275 ruling supersedes run 25's unit-policy
proposal: the installed helper keeps RestrictSUIDSGID=yes. Compatibility belongs
in the native source pin. No green24 result had been forwarded when this handoff
was written; no new installed result is claimed.

pinNativeMount now passes the actual unix.Openat2 dependency into a private
implementation shared with its component tests. The first syscall retains
O_PATH, O_CLOEXEC, O_NOFOLLOW, RESOLVE_NO_SYMLINKS and RESOLVE_NO_MAGICLINKS.
Only ENOSYS or EPERM selects the component walk. Other initial errors remain
refusals and are never retried with a broader open.

The helper derives source paths from protected installation or storage data.
It requires an absolute source, then preserves and validates its root-relative
components without cleaning them. Empty, absolute, dot, parent and NUL
components refuse. The fallback opens the fixed process root once, owns a
close-on-exec duplicate, and uses one openat call per component relative to its
held parent. Every intermediate open requires O_PATH, O_DIRECTORY, O_NOFOLLOW
and O_CLOEXEC. The leaf requires O_PATH, O_NOFOLLOW and O_CLOEXEC; Fstat also
rejects a returned symlink inode because O_PATH can open the link itself.

No openat call receives the full source path. No procfs descriptor pathname is
used to perform the fallback resolution. The caller's root remains owned by
the caller; all traversal descriptors close on both success and failure.
The existing final UID, GID, mode and type checks run after either path. The
runtime caller still hashes the pinned inode and checks the actual retained
bytes. Neither a known containment result nor a mount is synthesized.

The helper unit restores its required SUID/SGID creation-mode restriction.
Every other active setting, the service template, installer and harness remain
unchanged. The supported installer still renders and publishes the reviewed
unit and includes its bytes in the installation fingerprint. A differing live
installation must retain its normal refusal; no manual unit edit or transient
property is authorized.

The existing safe errno categories remain. A fallback failure adds the fixed
component-walk stage and distinguishes an openat denial/unavailable syscall
from the initial openat2 refusal. Paths and arbitrary wrapped-error text do
not enter the public error. Initial errors such as EACCES, ENOENT, ELOOP,
EINVAL and ENOTDIR do not enter the fallback.

The regression scope is explicit:

| Test | What makes it fail |
| --- | --- |
| TestHelperOpenat2Policy | The current module's helper unit disables or ambiguously declares its SUID/SGID restriction, or changes the retained NNP/system/home controls. |
| TestMountFallback | A tracked first syscall is not reached exactly once; forced wrapped EPERM/ENOSYS cannot pin actual nested file/directory inodes; or the real walk admits intermediate/leaf/magic links or violates final owner/group/mode/type/descriptor checks. |
| TestMountFallbackParts | The walk cannot open a real nested source beneath its supplied trusted root, admits a forbidden component, opens the real sibling escape canary through a parent component, or closes the caller's root descriptor. |
| TestMountFallbackEligibility | A different original error is replaced by a fallback success on an existing real source, or loses its original error identity. |
| TestNativeMountPinDiagnostic | Safe errno categories or fallback stage are lost, owner/code change, or a randomized private source is disclosed. |
| TestInstalledIsolationProof | The actual installed helper cannot pin runtime descriptors or fails any complete boundary/canary/read-back/collection gate. |

Only the initial syscall result is injected in the forced tests. All openat
calls, root traversal, descriptor flags, inode checks and final metadata checks
are the real implementation operating on real temporary files. Successful
nested pins after the injected error establish that the walk was actually used.
These tests do not claim the software fixture is native installed evidence.

The native-mount-links control removes O_NOFOLLOW only from the intermediate
walk flags and targets the forced EPERM/middle-link test. A plain full-path
openat implementation would wrongly follow that intermediate link and fail
the same regression. The parent-component control has a real existing sibling
canary. Other controls omit the fallback, weaken final owner/type checks,
broaden fallback eligibility, weaken the unit policy or corrupt safe categories.
The catalog retains 288 existing IDs, adapts the applicable targets and adds
three, for 291. Each must reach its named failing diagnostic on Linux before
its candidate pass; none was executed or vetted as a mutant on this Mac.

The cross-lane files are:

| File | Change |
| --- | --- |
| packaging/v2/linux/laneboss-helper.service.in | Restore the required directive and document the gated helper compatibility path. |
| internal/v2/admin/gate_linux.go | Share the actual pin entry with forced-syscall tests; retain metadata checks and safe diagnostic categories. |
| internal/v2/admin/native_mount_linux.go | Implement the errno gate, trusted-root component walk, strict component grammar and descriptor ownership. |
| internal / v2 / admin / native_mount_linux_test.go | Force both fallback triggers, use real nested/link/escape fixtures, retain original error identity and require helper hardening. |
| e2e/v2/cases/admin/mutations.json | Adapt applicable controls and add three deciding controls. |
| e2e/v2/cases/admin/MUTATIONS.md | Record the exact reached-red and native qualification requirements. |
| e2e/v2/cases/serve/REQUESTS.md | Record the current owner handoff and superseded unit proposal. |
| This file | Retain the ruling, implementation trace, file scope and verification limits. |

Candidate verification uses the shared Go cache, local toolchain, readonly
modules and disabled downloads. The admin package and its production/test
importers are vetted for Linux amd64/arm64 with default, faults,
partial/authenticator, all three tags, native integration and native
integration/faults; Darwin amd64/arm64 with default and partial/authenticator.
Runtime tests, native canaries, installed services and model requests are not
run on this Mac. The final evidence records actual static results and retains
all input/source/output bytes.

This slice changes pinNativeMount only. Other direct openat2 callers in
bootstrap Landlock, storage and worker endpoints keep their existing separate
gates. A later refusal there must be reported with its actual owner/code;
mount compatibility alone does not establish complete native containment.

Green25 should retain the required helper hardening, use the real component
walk for a denied or unavailable initial syscall, retain exact source
descriptors and metadata/hash checks, and progress to the next actual native
gate. The complete installed isolation proof is still required for G5 credit.
If the forwarded green24 result names a different errno, retain and classify
that exact category before extending this two-error eligibility rule. No
exact PASS count, full lane completion or authenticated vendor result is
predicted.
