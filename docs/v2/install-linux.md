# Install Laneboss v2 on Linux

This is the administrator route for source revision `d7403ec`. Read the
[snapshot limits](README.md#status-of-this-guide) first. The install can prepare
files while service composition is still incomplete. File installation is not
proof that the service can start or launch a lane.

Use a Linux host with systemd. The namespace setup entry targets Ubuntu 24.04.
The administrator performs setup as root. The owner performs security key
verification. Daily state requests use the installed client and service.
Do not use the older per-user installation walkthrough as v2 service setup.

## 1. Obtain a protected release and boot bundle

Obtain the binary, its release manifest and the reviewed source bundle from
your release administrator. They must describe the same artifact and contract.
The installer runs the supplied binary's version check and verifies its actual
SHA-256. It does not build a binary or download a judge deployment for you.

Stage administrator scripts and inputs under root-owned directories. No ancestor
may be a symlink or allow group or other writes. Do not run root code from a
user-writable checkout. `BINARY`, `RELEASE_MANIFEST` and `BOOT_INPUT` below are
canonical absolute paths to protected regular files. `INSTALL_EVIDENCE` is a new
absolute evidence directory with protected ancestors.

The boot file uses schema `laneboss.boot-input.v2`. Have the administrator
prepare these real inputs before installation:

| Input fields | Required content |
| --- | --- |
| `runtime_manifest`, `runtime_file`, `runtime_roots` | Exact `laneboss.runtime.v2` bytes, pinned executables and their protected source roots. A fresh runtime has an empty `bindings` array. |
| `secret_key_file` | A protected 0600 file with the real 32-byte native encryption key. Keep it outside source and evidence archives. |
| `judge`, `judge_endpoint` | The complete Clef configuration, full model name, actual deployment and tokenizer hashes, context limit and endpoint. |
| `admin_enrollment` | Approved `origin` and `rp_id`. The origin must be HTTPS and its hostname must equal the RP ID. |
| `launch_enrollment`, `launch_enrollment_file` | Exact `laneboss.launch-enrollment.v2` project and driver pins. Omitting them leaves lane launch unavailable. |
| `initial_publication`, `initial_publication_file`, `initial_objects` | The generation-one org publication and every referenced object. See the next section. |

The optional `judge_credential_handle` and `judge_alternative` contain enrolled
handles and deployment metadata. They are not places for plaintext credentials.
TypeSafe is an explicit alternative. Clef remains the initial default.
<!-- source: scripts/v2-admin/boot.py; internal/v2/assembly/installation.go -->

The first-publication descriptor uses schema `laneboss.initial.v2`. It selects
`runtime`, `launch_enrollment`, `policy`, `sources`, `source_manifest`, `profiles`
and `task` by exact blob reference. It also supplies `config`, `id`, `generation`
set to 1, `l5`, `l5_sources` and the complete `objects` array. `l5` selects level 5
and an explicit role. `l5_sources` selects that role's prompt and driver sources.

Ask the administrator for a validated bundle. The snapshot has no short command
that generates all these deployment inputs. The exact field and ownership
requirements are in the
[administrator bundle reference](../../scripts/v2-admin/README.md#protected-first-install-publication).
Do not fill missing references with sample hashes or test credentials.
<!-- source: internal/v2/admin/initial.go; scripts/v2-admin/boot.py; internal/v2/api/manifests.go -->

## 2. Prepare namespaces and install the units

Run the namespace entry from the protected bundle as root:

```sh
bash scripts/v2-admin/namespace.sh --install
bash scripts/v2-admin/namespace.sh --check
```
<!-- source: scripts/v2-admin/namespace.sh -->

Require exit 0, `ready: true` in the retained result and the marker
`PASS: unprivileged bwrap namespace prerequisites; evidence retained.`
This checks namespace
availability. It does not prove a complete lane boundary. The entry preserves
host-wide security switches. On a restricted Ubuntu host, it installs only the
reviewed bubblewrap-specific AppArmor profile. Preserve a differing existing
profile and stop on refusal.

Install the protected boot bundle as root:

```sh
bash scripts/v2-admin/install.sh --install --config NAME \
  --binary BINARY --manifest RELEASE_MANIFEST --boot BOOT_INPUT \
  --evidence INSTALL_EVIDENCE
bash scripts/v2-admin/install.sh --check --config NAME
```
<!-- source: scripts/v2-admin/install.sh; scripts/v2-admin/boot.py -->

Require both commands to exit 0. The check result has `verified`, `changed`
and `installation`; require `verified: true` and `changed: false`.
The check writes nothing. Installation with the initial bundle reports
`publication: "pending"`. That means publication is still required.
An identical completed install is reusable. A differing or uncertain partial
install stops without an overwrite route.

The installed executable is `/usr/lib/laneboss-v2/VERSION/laneboss`, where
`VERSION` comes from the verified release manifest. The installer does not add
a command-search link for you. When this guide says `laneboss`, use that exact
installed executable. Have the administrator arrange command lookup accordingly;
do not pick up an older per-user binary with the same name.
<!-- source: scripts/v2-admin/boot.py -->

The installer creates separate locked service, credential-broker and lane accounts, an immutable binary,
protected bindings, private data directories and these fixed systemd units:

| Installed item | Purpose |
| --- | --- |
| `/etc/laneboss-v2/admin/NAME.json` | Helper installation and dedicated account inventory. |
| `/etc/laneboss-v2/service/NAME.json` | Protected service boot document. |
| `/etc/laneboss-v2/bindings/NAME.json` | Human endpoint discovery and artifact pins. |
| `/etc/laneboss-v2/credential-peers/NAME.json` | Protected broker and identity executable, UID/GID, cgroup and installation-generation pins. |
| `laneboss-helper@NAME` (systemd unit) | Fixed root helper. |
| `laneboss-credential@NAME` (systemd unit) | Outside credential owner, with its own UID and a protected systemd key credential. |
| `laneboss-service@NAME` (systemd unit) | Unprivileged state and credential-identity owner. Requires the helper and credential units. |
| `/var/lib/laneboss-v2/service/NAME` | Private service state. |
| `/var/lib/laneboss-v2/secrets/NAME` | Private encrypted secret storage. |

`NAME` in these paths and unit names is the selected configuration.
The installer reloads systemd definitions. It does not activate the units.
Have the administrator start the installed helper and service units using the
host's systemd controls. Use their exact installed definitions. Do not run the
state owner as root or start a second copy against the same state.
<!-- source: scripts/v2-admin/boot.py; packaging/v2/linux/laneboss-helper.service.in; packaging/v2/linux/laneboss-service.service.in -->

Each unprivileged credential owner creates its own private listener. The helper
publishes those listeners into protected runtime locations and binds their
actual native peers before the first credential-bearing preparation. The
broker's distinct UID is outside the lane pool. The state service supplies
typed metadata and encrypted-record storage operations; credential descriptors
travel directly from the broker to the helper. Missing or changed native
ownership refuses preparation. A catalog by itself is not a successful bind.
The private owner directories and protected final sockets share
`/run/lb-v2-cred/HASH`, where HASH is the first 32 hex characters of SHA-256 of
the configuration name. Even a 32-character name has a longest socket path
of 90 bytes. The helper's atomic publication stays within one
configuration-scoped writable mount. Each unprivileged owner
can write only its own mode-0700 child beneath `owners`; the common parent and
final socket names remain protected. Changes to these unit write paths should
receive the same security review as the installer ownership declarations.
<!-- source: internal / v2 / admin / credowner_linux.go; internal/v2/admin/credwire_linux.go; internal / v2 / assembly / credbroker_linux.go -->

If a unit stops during construction, preserve its diagnostic and installation
evidence. In this revision, missing composition dependencies can prevent the
socket from opening. See the [known source gaps](README.md#status-of-this-guide).
Proceed only when the installed service is actually listening. The CLI's
`start` command renders a briefing; it does not start this service.
<!-- source: internal/v2/cli/commands_templates.go; internal/v2/assembly/assembly.go -->

## 3. Enroll the first human with a security key

Not yet verified on an installed service.

Use a hardware security key that supports WebAuthn user verification.
The ceremony requires a PIN or biometric verification. A touch alone is not
enough. The private key stays on the authenticator. Enrollment retains public
registration evidence and a service commit receipt.

The first enrollment is available only while the configuration's complete
enrollment inventory is empty. Even a revoked prior entry prevents repeating
that initial route. Root login alone is not human approval. Later credential
changes use the existing human approval path.
<!-- source: internal/v2/admin/human_enrollment.go; internal/v2/api/enrollment.go; internal/v2/identity/enrollment.go -->

Production hardware enrollment needs protected attestation trust roots bound to
the installation generation. In this snapshot, assembly supplies no attestation
policy to identity, and the boot installer has no input field for it. Without
those roots, production registration is closed. The implementation owner must
complete that wiring before the real-key ceremony below can succeed. Do not add
an invented boot field or substitute a software key to get past this limit.
<!-- source: internal/v2/identity/attestation.go; internal/v2/identity/service.go; internal/v2/assembly/assembly.go; scripts/v2-admin/boot.py -->

The browser component serves `/enroll`. Its **Enroll security key** button asks
for a cross-platform authenticator, required user verification and direct
attestation. Open it only at the installed approved HTTPS origin, after the
administrator authorizes a ceremony for your browser.

The supplied assembly does not configure an HTTP listener or bind
`BrowserEnrollmentTransport`. The page alone cannot enroll you. If the release
administrator has not supplied that protected integration, stop here and use
the fixed helper workflow below with their WebAuthn tooling. There is no CLI
command that reads a key or generates a genuine WebAuthn response by itself.
<!-- source: internal/v2/dashboard/enrollment.go; web/v2/enrollment.js; internal/v2/assembly/assembly.go -->

For the fixed helper workflow, have the administrator save a protected begin
request. It contains exactly `config`, a fresh `ceremony_id`, `principal_id`
and `expected_generation` set to 0. All file arguments below are canonical
absolute paths. Use the same installed artifact as the units, as root:

```sh
laneboss internal helper --config NAME --installation INSTALLATION \
  --enroll-begin BEGIN_REQUEST
```
<!-- source: internal/v2/cli/internal_admin.go; internal/v2/admin/human_enrollment.go; internal/v2/admin/enroll_linux.go -->

Retain the returned challenge. Its fields include `ID`, `Ceremony`, `Challenge`,
`Origin`, `RPID`, `EndpointGeneration`, `InstallationGeneration`, `ExpiresAt`
and `Consumed`. The ceremony expires within five minutes.
Have the approved WebAuthn tooling perform `webauthn.create` for those exact
challenge, RP and origin values, with required user verification.

The complete request contains `ceremony` copied from the begin request,
`challenge_id` from the response, and the actual `client_data_json` and
`attestation_object` bytes encoded as JSON base64 strings. Do not synthesize
registration bytes or add a test attestation marker. Save it as a protected
file, then run:

```sh
laneboss internal helper --config NAME --installation INSTALLATION \
  --enroll-complete COMPLETE_REQUEST
```
<!-- source: internal/v2/cli/internal_admin.go; internal/v2/admin/human_enrollment.go; internal/v2/admin/enroll_linux.go -->

Require a real receipt with `Generation` equal to 1, positive `CommittedSeq`,
and nonempty `OperationID`, `EventID` and `Evidence`. `SimulatedPresence` must
be false. Keep the receipt with the challenge and public registration evidence.
The installed E2E report does not establish a real hardware ceremony.
<!-- source: internal/v2/api/enrollment.go; internal/v2/admin/enroll_reply.go -->

A software key is **simulated presence, for tests only**. Normal builds refuse
marked software credentials. The dedicated `laneboss_e2e_authenticator` build
propagates `simulated_presence` markers. Its helper output labels presence as
`simulated` and human approval as `not_proven`. Never count that as owner
presence or production authentication.
<!-- source: internal/v2/api/human_presence.go; internal/v2/api/human_presence_release.go; internal/v2/api (file human_presence_testbuild.go); internal/v2/admin/human_enrollment.go -->

## 4. Check readiness with doctor

Not yet verified on an installed service.

First [publish the initial org](tutorial.md#2-publish-the-first-org-setup).
Then use the [human session proof flow](tutorial.md#3-prepare-human-authority).
Return here with a fresh session proof and run the ergonomic doctor command:

```sh
laneboss doctor --config NAME --format json --proof SESSION_PROOF
```
<!-- source: internal/v2/cli/commands_admin.go; internal/v2/cli/cli.go -->

Read its whole result. It is one Health object with `protocol`, `schema`,
`service_version`, `artifact_sha256`, `ready` and `capabilities`.
Each capability has `name`, `available`, `reason` and optional `evidence`.
Require exit 0, nonempty capabilities, `ready: true` and every capability
available. Read every failed reason before considering a launch.

If readiness is false, this adapter prints the health result and then returns
`doctor reports unavailable administrator or launch prerequisites` with exit 69.
Do not mistake the printed JSON for success. This v2 output is different from
the v1 JSONL list of checks. Doctor does not establish vendor sign-in, account
quota or successful model execution.
<!-- source: internal/v2/admin/doctor.go; internal/v2/admin/doctor_probe.go; internal/v2/cli/commands_admin.go -->

Continue with [the first lane tutorial](tutorial.md). Keep the already-completed
publication and enrollment receipts. Do not repeat them with different inputs.
