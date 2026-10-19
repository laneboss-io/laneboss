# Ubuntu namespace prerequisite entry

On the authorized fresh Ubuntu 24.04 test box, laneboss runs this single entry
as root from the supplied source tree:

```sh
bash scripts/v2-admin/namespace.sh --install
bash scripts/v2-admin/namespace.sh --check
```

`--install` is noninteractive. It installs missing bubblewrap, capability,
util-linux and (only when restriction 1 requires it) AppArmor tools from the
box's configured Ubuntu repositories. It does not upgrade unrelated packages.
Existing package configuration is preserved. Package-manager stdout, stderr
and actual exits remain in the invocation evidence; a failure stops setup.

`--check` installs no package, writes no policy/profile and reloads nothing.
It executes real availability and identity probes and retains their outputs.
On missing prerequisites it exits 69 with the route to `--install`. Use
`--install` first on a fresh box rather than treating that expected prerequisite
result as acceptance. Both modes are idempotent with respect to system setup:
an already ready exact profile is neither overwritten nor reloaded.

Every invocation reads the actual
`kernel.apparmor_restrict_unprivileged_userns` value. It never infers a value
from the image name. Restriction 0 installs/reloads no profile. Restriction 1
uses only the reviewed executable-specific `laneboss-bwrap` profile attached
to `/usr/bin/bwrap`. A differing, linked, writable or otherwise unsafe existing
profile is retained and refused; this entry cannot overwrite it to pass a check.
It also refuses broad or changed profile source bytes before package/policy work.

The sequence for restriction 1 is:

1. Retain kernel/restriction/clone facts and the exact profile and OS-tool inputs.
2. Verify non-setuid, non-setgid, root-owned bwrap with no file capabilities.
3. Drop all real/effective/saved/filesystem IDs to the existing nonroot nobody
   identity, clear supplementary groups and capabilities, and set no_new_privs.
   Retain actual kernel identity/capability verdicts. The probe cwd is `/`;
   an inaccessible root-owned source directory cannot masquerade as userns denial.
4. Run bwrap and an unprofiled private copy of unshare using
   \`--user --map-root-user --mount -- /usr/bin/true\`, saving each command's
   stdout/stderr/exit before inspecting it. A permission failure is distinct
   from a timeout, missing program or another setup failure.
5. When needed, invoke the existing bwrap-only installer to install, read back,
   reload only that profile and verify the kernel's loaded-profile record.
6. Repeat the identical unprivileged bwrap arguments successfully. The private
   unshare control must remain denied, and both host-switch byte snapshots must
   match. Set readiness only after all checks pass.

This is the fixed namespace availability probe, not an agent filesystem layout:

```text
--die-with-parent --unshare-user --unshare-pid --ro-bind / / -- /usr/bin/true
```

No probe invokes bwrap as root. The read-only host-root bind is used only for
the fixed availability command; it is not an isolation pass. Actual Landlock,
mount/grant, network, cgroup and lifecycle acceptance still belongs to the
production Linux/helper cells. This entry creates no service account, service
binding, model session or machine and performs no sign-in.

## Results and idempotence

Exit 0 and `ready: true` in the invocation's `result.json` are both required.
The final stdout marker is `PASS: unprivileged bwrap namespace prerequisites`.
Exit 2 is invalid invocation/platform identity; exit 3 is integrity/policy
failure; exit 69 is an unavailable prerequisite or failed OS probe. No failure
is converted into an unprotected launch or a fabricated successful probe.

The receipt records the actual restriction, mode, stopped stage, exit, profile
action, baseline, probe identity and switch comparison. Baseline `denied`
retains the original unprofiled bwrap refusal. `already_permitted` truthfully
records a repeat or preprofiled host; it does not prove the fresh unprofiled
UBUNTU-DEFAULT baseline. Restriction zero records `unrestricted`/`not_needed`.

The default evidence root is `/var/tmp/lb-v2-admin-namespace-evidence`. It and
each invocation directory are ordinary, root-owned mode 0700. A supplied
existing `--evidence` root must already satisfy that rule. Repeated commands
create separate invocation records beneath the same root:

```sh
bash scripts/v2-admin/namespace.sh --install \
  --evidence /test/evidence/lb-v2-admin-namespace
bash scripts/v2-admin/namespace.sh --check \
  --evidence /test/evidence/lb-v2-admin-namespace
```

A separate root-owned directory, group-readable by the probe identity with
mode 0750, holds the private unshare copy. The probe cannot replace its executable;
root-only evidence parents cannot cause a false permission
control. The receipt names that generated directory. Both input/evidence
directories are retained for collection with the disposable machine. There
is no automatic deletion, profile rollback, host-switch write or retry after
an unexpected failed check.

## Outside acceptance on the box

As root on separate actual restriction-one and restriction-zero Ubuntu cells:

```sh
python3 -I e2e/v2/cases/admin/namespace_cli.py \
  --source /test/source --evidence /test/evidence/lb-v2-admin-entry
```

The case runs check/install/repeated-install/check, independently executes
unprivileged bwrap, observes the real installed profile and unchanged switches,
and requires repeat installation to preserve profile inode/mtime/bytes. Its
broad-source negative control must refuse with exit 3 while installed policy
stays unchanged. A missing record, false ready result, nonprivate directory,
unnecessary restriction-zero profile, outside probe failure or unexpected
mutation makes the case fail. It is credential-free and is not authenticated
AI-service acceptance. No runtime pass for this entry has been measured on Mac.

## Complete protected boot bundle

The namespace entry does not provision service boot data. From a reviewed,
root-owned source bundle with no symlink or shared-writable ancestor, run:

```sh
bash scripts/v2-admin/install.sh --install \
  --config case-admin --binary /test/artifacts/laneboss \
  --manifest /test/artifacts/release.json --boot /test/admin/boot-input.json \
  --evidence /test/evidence/lb-v2-admin-install
bash scripts/v2-admin/install.sh --check --config case-admin
```

Run only as authorized root on the disposable Ubuntu box. Every input is an
absolute protected regular file. The release manifest and binary must match
actual bytes, platform, compiled version and contract v2.0-draft.4. The retained
binary's real --version output is checked. No provider, machine, agent, service
unit or paid request is started. Existing differing artifacts of one compiled
version require separate fresh boxes or a future approved coherent upgrade.

The boot input has this exact field map; there are no invented defaults for
runtime, key material, deployment hashes or credential handles:

| Field | Required actual input |
| --- | --- |
| schema | laneboss.boot-input.v2 |
| runtime_manifest | BlobRef with class manifest, enrolled ID, actual raw SHA-256 and byte count. |
| runtime_file | Protected absolute file containing those exact laneboss.runtime.v2 bytes, at most one MiB. |
| runtime_roots | Array of objects with exact fields id and path; each path is an approved protected root. |
| secret_key_file | Protected root-owned 0600 file containing the real 32-byte native AES-256-GCM data key. It is copied only into the private secret store. |
| judge | Complete JudgeConfig: provider, model, deployment_sha256, tokenizer_sha256, context_tokens, max_bytes, max_questions, command_deadline_ms, guidance_deadline_ms, cache_ttl_ms, outage_policy. Clef is primary, with the decided full model name and measured pins. |
| judge_endpoint | Actual enrolled HTTP/HTTPS endpoint without embedded credentials, query or fragment. |
| judge_credential_handle | Optional existing enrolled handle; never a credential value. |
| policy_max_cost_micros | Optional actual approved inference ceiling in exact integer micros; absent/zero grants no inference budget. The service also bounds each call by remaining lane spend. |
| judge_worker | Optional protected tokenizer executable/path/byte pin, tokenizer_args, price file/byte pin, safety_tokens and positive reserve_micros. A credential_file must match the enrolled handle. These are administrator-owned inputs, never values from a lane; no native worker job is created by supplying them. |
| judge_alternative | Optional object with config, endpoint and credential_handle for the explicit TypeSafe enrollment. It does not select active policy. |

RuntimeManifest must contain its exact schema/generation/artifact/bootstrap/
objects/bindings fields. Each RuntimeObject has id, role, root_id, relative_path,
content and mode. Every content pin is verified against actual bytes beneath
the enrolled source root. Object modes are immutable 0444/0555; executable pins
must resolve to executable objects, and Artifact must match this supplied release.
The fresh-install bindings array is empty because no active lane/worker identity
is imported. Per-run endpoint projections still require the real identity path.
The total retained object staging is bounded to 256 MiB. These enrolled runtime
assets are the outer sandbox inputs; this is no ordinary-command permission list.

The installer publishes these protected objects and verifies their read-back:

* /etc/laneboss-v2/service/CONFIG.json, root:root 0644, with the exact
  laneboss.service-install.v2 fields consumed by assembly.Installation.
* /etc/laneboss-v2/bindings/CONFIG.json, root:root 0644, matching the service
  UID/GID, mapped IDs, socket, artifact/version and exact draft.4 revision.
* /etc/laneboss-v2/admin/CONFIG.json, root:root 0644, with separate locked service
  and 32 lane accounts, release bytes and private helper binding.
* The exact RuntimeManifest and root-relative object copies under the immutable
  release's runtime/CONFIG tree, plus the enrolled roots inventory.
* Separate service-owned 0700 state, secret and runtime directories; root-owned
  0700 helper state, root:service-group 0750 helper runtime, and dedicated lane
  roots. Native key bytes remain 0600 under secret_directory/keys/HANDLE.key;
  enrollment.json binds the handle, aes-256-gcm algorithm and relative filename.
* Fixed helper/service units and tmpfiles definitions. The service unit passes
  the exact installed --installation file. Socket families preserve ordinary
  IPv4/IPv6 and private loopback; the helper keeps required kill/network/namespace
  setup capabilities and future lane execution must drop them before exec.
* A root-owned 0600 boot catalog containing the verified inventory and an input
  fingerprint. It is published after all required provisioning commands succeed.

The native key disk convention is recorded for lb-v2-secrets in the admin
CONTRACT-GAPS.md. The runtime BlobRef is retained bootstrap data. The protected
first-install publication below imports its exact retained bytes through the
service writer. Neither file provisioning nor the public human-class discovery
binding authorizes a caller.

--check verifies the actual catalog, file bytes/modes/owners/groups, directory
privacy, executable capabilities, locked account properties and matching boot/
endpoint metadata. It has no write path: no lock, evidence directory, mode repair,
account, unit, profile, bytecode or reload. Redirect its output in the harness.
Reinstalling identical completed inputs returns changed=false and preserves
installed inode/mtime/bytes. Differing or partial installations stop. Unknown
failed state has no automatic removal/overwrite route; preserve it for reviewed
recovery or collection of the disposable machine.

Supporting provisioning controls on the box are:

Fix-9 launch setup additionally accepts the paired optional boot fields
launch_enrollment (a manifest BlobRef) and launch_enrollment_file (the protected
administrator input file). Its schema is laneboss.launch-enrollment.v2 and its
exact field map is in api/launch_plan.go. The installer validates config,
generation, unique project/driver enrollments, exact source/base/history fields
and executable/runtime pins. It installs the bytes as launch-enrollment.json
next to the immutable runtime and retains its reference in the service boot
file and protected catalog. Omission preserves diagnostics and leaves launch
unavailable. The first-install publication below imports these exact private
objects; neither an uploaded manifest nor a caller path is enrollment authority.

This input extension does not complete the native gate or registered capture
producer. The current boundaries and Linux checks are in admin/FIX9-STATUS.md.

```sh
python3 -I -B e2e/v2/cases/admin/boot_cli.py \
  --source /test/source --config case-admin --binary /test/artifacts/laneboss \
  --manifest /test/artifacts/release.json --boot /test/admin/boot-input.json \
  --evidence /test/evidence/lb-v2-admin-boot-case
python3 -I -B e2e/v2/cases/admin/cleanup_test.py
```

The boot case runs install/check/repeat and rejects differing inputs, unsafe
installed modes and writable root code. Cleanup fault controls are component
evidence with injected command failures and actual private-directory file moves.
Only the separate installed serve E2E can complete this round. Its exact harness
requests and other-owner dependencies are in admin/CONTRACT-GAPS.md.

## Protected first-install publication

The serve harness must supply the following additional boot-input fields as
one explicit bundle. Omission leaves first-launch prerequisites absent. No
policy, task, role, profile, origin or source content is generated in production.
Omitting admin_enrollment alone leaves the ceremony uninstalled. Existing CLI
begin/complete modes consume its actual protected endpoint and registration
files. The boot CLI controls retain policy/pin round-trip and omission checks.

| Boot field | Exact input |
| --- | --- |
| admin_enrollment | Object with exactly origin and rp_id. origin is the approved HTTPS origin without path, user info, query or fragment; its hostname equals rp_id. The installer derives the service UID, private socket, generation and helper artifact pin. |
| launch_enrollment | Manifest BlobRef for the explicit LaunchEnrollment described above. |
| launch_enrollment_file | Protected absolute file containing exactly that reference's bytes. |
| initial_publication | Manifest BlobRef for the InitialManifest described below. |
| initial_publication_file | Root-owned, single-link, mode 0444 regular file containing those exact bytes. |
| initial_objects | Array with exactly ref and file in each entry. ref is an exact declared BlobRef; file is its root-owned, single-link, mode 0444 absolute regular file. Every declared object has exactly one entry. |

Every ancestor of each input must be a root-owned directory without shared
write permissions or symlinks. Stage inputs below a protected administrator
directory, such as /opt/test-admin, rather than under a shared temporary
ancestor. Secret key bytes remain in the existing private key input and are
never initial objects. Profile documents contain enrollment selectors, not
credentials. There are at most 512 initial objects and 64 MiB of object bytes.
The descriptor and typed JSON documents are bounded to one MiB.

A BlobRef has exactly id, class, sha256 and bytes. The digest is lowercase
SHA-256 of the exact supplied raw bytes; bytes is their byte count. An empty
artifact is allowed for a project file; descriptors, documents, source text
and tasks must be nonempty.
All IDs use letters, digits, underscore or hyphen. Initial objects use only
manifest, artifact or task classes. Descriptor IDs cannot collide with an
object ID or the reserved receipt ID initial-receipt-CONFIG. The seven selected
documents have distinct IDs and appear in the exact objects array.

The InitialManifest has exactly these fields:

| Field | Exact meaning |
| --- | --- |
| schema | laneboss.initial.v2 |
| config | The installation's explicit configuration name. |
| id | Unique administrator publication ID, at most 64 characters. |
| generation | Integer 1. |
| runtime | The same manifest BlobRef as boot runtime_manifest. |
| launch_enrollment | The same manifest BlobRef as boot launch_enrollment. |
| policy | Manifest BlobRef containing the explicit EffectivePolicy. |
| sources | Manifest BlobRef containing the explicit OrgSnapshot. |
| source_manifest | Manifest BlobRef containing an ObjectManifest with exactly one immutable file entry for each snapshot source. |
| profiles | Manifest BlobRef containing the explicit RootGrantManifest. |
| task | Task BlobRef containing nonempty UTF-8 L5 task text without NUL. |
| l5 | RoleContext with level 5, the explicit role and no instance_id. |
| l5_sources | RoleTemplateSources selecting Prompt and Drivers from the snapshot for that L5 role. Each selection has Source and Content. |
| objects | Exact BlobRef array of every selected document and all referenced source, runtime and project content bytes. It excludes the descriptor itself. |

Unselected objects are refused, including an unrelated manifest placed beside
the validated selections. Empty artifact bytes must still have an explicit
file, reference and the SHA-256 of the empty byte string.

The policy uses the JSON fields of api.EffectivePolicy, including generation,
sha256, context, rules, skip, sources, judge, guidance_source,
guidance_min_relevance, guidance_half_life_seconds and profile_exclusions.
Its generation is 1 and context equals l5. Arrays must be present and nonnull.
All rule, scope, provenance, threshold, skip, exclusion and judge fields are
validated. The judge provider and full model name must already be explicit;
deployment/tokenizer hashes and a positive measured context bound are required.
Its sha256 is the SHA-256 of Go json.Marshal of that typed policy with SHA256
set to the empty string. This is the existing policy content hash, not JCS.
Every policy SourceRef must match a retained snapshot source exactly. Initial
publication cannot enable capture refusal or assert a D6 approval ID.

OrgSnapshot and ResourceFile use their frozen Go field names, with exact case:
Ref, Config, Sources, Derived, Renderer, OwnershipManifest, PublishedBy and
PublishedAt; each resource has Source, Content, Kind, Mode and
RevisionGeneration. Ref has org_id, generation and manifest_sha256. SourceRef
has id, path, sha256 and generation. Source paths are canonical relative paths
and IDs/paths are unique. The initial source and revision generations are 1,
Mode is decimal 292 (0444), Content is an artifact BlobRef, and its hash equals
Source.sha256. Kind is prompt, drivers, policy, source or task. At least prompt
and drivers are required, and l5_sources selects their exact Source/Content
pairs. Derived is an empty array; PublishedBy and PublishedAt are empty strings
on input. The service stamps the publication ID and its clock time.

Ref.org_id and Config equal config. Ref.manifest_sha256 equals the exact
source_manifest SHA-256. That ObjectManifest uses schema laneboss.objects.v2
and entries containing the matching path, kind=file, mode=292 and content
BlobRef. Renderer is an explicit executable pin in the retained runtime.
OwnershipManifest is a retained manifest BlobRef containing an ObjectManifest;
it may have an explicitly empty entries array before generated outputs exist.
Its content and any referenced bytes are validated by the same object validator.
The initial source validator does not render a prompt or manufacture derived
files; rendering remains the templates owner's responsibility.

RootGrantManifest uses schema laneboss.root-grants.v2 and explicit nonnull
resources, data, secrets, profiles, network and channels arrays. profiles is
nonempty. Every root entry's id is the empty string and parent_grant_id is
absent, because the grants service assigns issued IDs later. A profile includes
profile_id, driver, provider, paid, delegate and expires_at. Expirations are
canonical UTC RFC3339Nano and must be in the future at first publication.
Existing root-grant validation checks all collections. Data source references
must select retained object manifests with matching hashes; no prior
publication_id can be asserted. Referenced project trees, runtime content and
all tree file parts must also be retained and pass existing object validation.
Initial publication imports these inert declarations; real capability-handle
resolution, human proof, root grant issuance and ticket issuance still apply.

Copy-source validation now fails closed during installation. Every root-grants
`copy` entry with `tree` or `snapshot` history must name a source manifest in
the protected initial inventory, with the exact object ID and SHA-256; its
referenced file parts must also be present. A missing or mismatched manifest
stops installation instead of waiting for copy preparation's `Prerequisite`
failure. This is an upgrade behaviour change: repeated `--install` validates
these sources before accepting an existing matching boot catalog, so an older
bundle that omitted a named copy manifest now fails at installation too.
Existing fingerprint and coherent-upgrade restrictions still apply when
correcting that bundle.

Installation runs the supplied binary's root-only --validate-initial mode
against a protected staged copy before account provisioning. It installs
initial.json, initial-ref.json and initial-objects beneath the immutable
runtime/CONFIG directory. initial-ref.json contains exactly a manifest field
equal to initial_publication. Installed initial files and object copies are
root-owned 0444, and the protected boot catalog hashes them. The installed
runtime and launch-enrollment files must also match the selected references.
--check verifies the catalog and exact installation relationship but never
publishes state. --install reports publication=pending whenever the optional
bundle is present, including on an identical reinstall.

On the authorized disposable Linux machine, run the existing install command,
then start the installed units through the service harness's existing startup
step. Once its protected administrator socket is listening, request publication:

```sh
bash scripts/v2-admin/install.sh --publish \
  --config case-admin --evidence /opt/test-evidence/initial-first
bash scripts/v2-admin/install.sh --publish \
  --config case-admin --evidence /opt/test-evidence/initial-retry
```

Each evidence directory must be new, with protected ancestors. --publish
accepts only config and evidence. It invokes the installed root helper with
--installation and the installed --publish-initial reference file. The fixed
native method is initial_publish in the existing helper envelope. It is absent
from the public RPC catalog. A lane or service UID cannot run the root helper.
The service checks native root peer and executable identity, frame credentials,
socket and installation pins before the private store entry. The transaction
publishes the policy, org snapshot, declared objects and immutable marker
together with org.bootstrapped, under an empty-org generation-zero compare.

The returned receipt has exactly schema=laneboss.initial-receipt.v2, config,
id, manifest, receipt, operation_id, event_id, committed_seq and generation=1.
receipt is the immutable marker BlobRef named initial-receipt-CONFIG. The
service reads its actual bytes and metadata, operation, event, snapshot,
policy and every object back before acknowledging. The installer retains
receipt.json and the helper's argv, stdout, stderr and exit records. The two
calls above must return identical receipts and leave one initial event and one
generation. The event read uses Since equal to the committed first sequence
minus one and accepts only an exact first returned publication event. Any
later events in that page belong to other activity and do not form the receipt.
A lost reply may be retried against the same installed bytes.
Conflicting documents, a changed baseline, missing receipt or read-back
disagreement stops publication; later policy changes use the normal approval
path. A replay after later policy changes can refuse its generation-one
read-back and never reapplies the import.

The composed service's separate listener now routes the fixed initial_publish
frame through admin.InitialRequest and Server.PublishInitialFrame using its
actual endpoint, Connection and Frame. The root CLI uses the installed daemon
relay for all three administrator modes. The daemon checks mapped artifacts;
the service checks the exact native control unit, writer/lifetime, protected
socket and installed artifact bytes. No service ptrace privilege is required.
The entry calls Server.PublishInitial; store.Service.CommitInitial guards the
private validated transaction and delegates to the real Transact. OrgSnapshot
reads the current projection at the exact requested generation, and internal
service Events reads configuration events for the strict receipt check. Event
validation accepts this exact marker in addition to ordinary ConfigView bootstrap
payloads. The nonce/result/error envelope remains unchanged. No caller-supplied
Scope, sidecar seed or constant receipt is an integration route. Materialization
and several source/briefing ports remain service-owned stubs. The composed
listener and real SQLite transaction still require an installed Linux run.

## Controlled egress and vendor programs

For launch enrollment with the controlled API endpoint, boot provisioning checks
the protected host executables `/usr/sbin/nft` and `/usr/sbin/ip` before publishing
installation state. Missing tools stop installation with their names and Ubuntu
package providers, `nftables` and `iproute2`. The tools must be root-owned regular
executables with one link, protected parents, safe modes and no file capabilities.

The retained Claude Code 2.1.296 startup audit records successful execve calls to
`/usr/bin/git`, `/usr/bin/sh` and `/usr/bin/uname`. Measured vendor enrollment sends
those exact programs through the same immutable interpreter/library collector as
the primary executables. Each program is pinned at 0555 and its closure is
projected by read-only file descriptors at the recorded ABI paths, within the
existing object and byte bounds. Additional programs require documentation or an
actual task audit. The native gate canary executes the three audited programs and
reads a README fixture; that filesystem probe does not establish completion of an
authenticated Claude Code task.
