# Supervisor test commands

These commands are for the disposable Linux box only. They have not run on
the authoring Mac. Use the administrator lane's installed accounts, cgroups,
network prerequisites and bwrap-only profile; keep host switches unchanged.
Run under an unprivileged test account. Source Go, Git, a C compiler, Python 3,
the pinned bubblewrap package must already be available. Installed man pages
are not required; cloud images can omit them independently of binary behavior.

The kernel tests deliberately fail when their real prerequisites or root-owned
helper are absent. There is no skip or unconfined-success fallback. Build the
test executable first, install those same bytes under a root-owned path, then
execute it as the original non-root account:

```sh
set -eu
mkdir -p /var/tmp/lb-v2-linux-bin
go test -c -o /var/tmp/lb-v2-linux-bin/linux.test \
  ./internal/v2/isolation/linux
sudo install -d -o root -g root -m 0755 /opt/lb-v2-linux-test
sudo install -o root -g root -m 0755 \
  /var/tmp/lb-v2-linux-bin/linux.test \
  /opt/lb-v2-linux-test/linux.test
/opt/lb-v2-linux-test/linux.test -test.v -test.timeout=10m \
  -test.run='TestBwrapProbeRejectsBadOptions|TestBwrapFailureStopsRunner'
/opt/lb-v2-linux-test/linux.test -test.v -test.timeout=10m \
  -test.run='^TestPinnedBwrapBehavior$'
/opt/lb-v2-linux-test/linux.test -test.v -test.timeout=10m
```

Run the fault-tag build separately:

```sh
go test -c -tags laneboss_faults \
  -o /var/tmp/lb-v2-linux-bin/linux-faults.test \
  ./internal/v2/isolation/linux
sudo install -o root -g root -m 0755 \
  /var/tmp/lb-v2-linux-bin/linux-faults.test \
  /opt/lb-v2-linux-test/linux-faults.test
/opt/lb-v2-linux-test/linux-faults.test -test.v -test.timeout=10m \
  -test.run='TestBwrapProbeRejectsBadOptions|TestBwrapFailureStopsRunner'
/opt/lb-v2-linux-test/linux-faults.test -test.v -test.timeout=10m \
  -test.run='^TestPinnedBwrapBehavior$'
/opt/lb-v2-linux-test/linux-faults.test -test.v -test.timeout=10m
```

The d4fix1 review controls run in both complete builds above. In particular,
TestKernelMountAdmission creates a real private tmpfs and same-target bind
overmount, records actual descriptor mount IDs and reads random fixture bytes
through the alias. Its fixed diagnostic retains CAP_SYS_ADMIN only inside its
new user/mount namespace, with namespace UID/GID zero mapped to the original
non-root host account. It executes no agent. Missing mount capability is a
failed setup, never a skip.
Source symlink, independent Git metadata and frozen-contract tests are also
part of the complete suite. Keep all existing cells and boundary controls.

Run the credential-free public-case component controls on the same disposable
Linux box; they do not start the CLI service or authenticate a driver:

```sh
python3 -I e2e/v2/cases/linux/run_tests.py
```

Require exit 0 and every unittest passing. The UDP control really sends bytes
to the outside no-echo listener and must detect delivery despite receive
timeout. The cleanup control creates a real double-fork child, injects an
assertion failure and requires that finally removes its actual PIDs. It
intentionally refuses to fabricate missing service/cgroup collection evidence;
that component result is not a complete public OS-LINUX collection pass.
The 32 file-backed component red/candidate pairs and their named failure
assertions are in MUTATIONS.md. They all need actual Linux execution after
the unchanged positive controls pass; static authoring does not kill a mutation.

Keep each binary, input tree, stdout/stderr, exit and the evidence paths printed
by the tests. The test executable is also its root-owned bootstrap; running the
temporary `go test` binary as the bootstrap is intentionally refused.

Expected unit result after supported primitives are present: every selected
test passes with no skips. `TestPinnedBwrapBehavior` exercises the pinned
binary's descriptor mounts and seccomp with real operations. It checks the
mounted device/inode identities, random input hashes, a successful writable
mount, an EROFS read-only write, outside read-back, changed namespaces and an
actual denied syscall whose unrestricted control succeeds. Landlock is not
installed in this fixed diagnostic, so it cannot mask a broken read-only bind.
The tested bwrap bytes/hash and observations are retained. Missing/misbehaving
options produce named prerequisites before any runner code executes.

`TestBwrapProbeRejectsBadOptions` runs missing bind and read-only-bind options,
a writable replacement for the read-only bind, and a removed seccomp argument.
Each must fail at its named prerequisite. `TestBwrapFailureStopsRunner` also
requires that a failed real probe creates no proposed-runner marker. These
controls do not replace the public CLI acceptance case.

## Restriction-off and restriction-on box preparation

Use separate fresh Ubuntu 24.04 cells with their intended switch already set
by the supervisor's authorized box preparation. Measure the switch; do not
change it during either cell. The supervisor reported all tests passing for
tree `21bb370` in the restriction-off cell: plain and fault-tag builds, 220
PASS lines and 0 SKIP, including the behavioral probe and its red controls.
In the restriction-on cell, bare `unshare --user -- true` returned 0 while
unprofiled bwrap returned 1. The old bare-unshare precondition stopped profile
installation; the subsequent unit runs reported 36 bwrap startup failures.
That cell does not establish a restriction-on pass. The capability-requiring
controls below still need execution on a fresh restriction-on cell.

The subsequent supervisor result for combined tree `38ac17c` passed all three
ordinary and fault-tag runs in restriction-off. Restriction-on stopped with
exit 69 in the admin root entry's still-bare unshare precondition; the admin
owner is correcting it. Neither that baseline result nor the earlier counts
cover the new draft.4 public-method orchestration and receipt tests.

The later supervisor run at combined tree `4e63af3` passed restriction-off in
both builds. Restriction-on passed the corrected namespace control but stopped
with `FAIL: untrusted evidence ancestor.` and exit 3: the root entry's evidence
path was beneath the test user's directory. The procedure below keeps root
receipts separately beneath sticky `/var/tmp`; it preserves that ownership gate.

The next supervisor run at combined tree `01ac682` passed restriction-off in
both builds with 264 PASS lines. Restriction-on accepted the separate evidence
root, then refused the loader in the user-owned checkout. That is an intact
source-protection gate, not a restriction-on pass. The staging block below
copies reviewed inputs into a fresh protected bundle before any root entry.

The supervisor's combined draft.4 tree `a38bebf` passed restriction-off in both
builds. Its restriction-on setup passed both staged namespace entries and kept
unprofiled unshare denied before and after. The Linux tests then stopped at
their own root-only securityfs profile-list read. The service account cannot
read that registry either; the corrected prerequisite below measures behavior
as its unprivileged caller and never reads the registry. This correction still
needs a new restriction-on run; the setup success is not a kernel-test pass.

With restriction 1, the service checks the protected exact profile bytes, then
runs the same fixed bwrap availability arguments shown below between two
capability-requiring unshare controls. Bwrap must exit 0; both unshare calls
must exit 1 with an actual namespace permission diagnostic. A missing command,
timeout, unrelated error, permitted unshare or changed restriction refuses.
These mutable observations are remeasured outside the host-fact cache. The
later pinned FD/seccomp behavior probe remains mandatory before a runner.
The availability command executes only system `true`, never an agent or root
entry, and supplies no proof of the production filesystem layout by itself.

TestAppArmorUnreadableRegistry requires all three command results
and unchanged restriction bytes despite a real unreadable registry fixture.
TestAppArmorAbsentBehavior requires refusal when bwrap
behavior is absent with that same unreadable registry. The additional
TestAppArmorControlRefusals,
TestAppArmorProfileInputsRemainRequired and
TestAppArmorBehaviorAndSwitchRechecked cover false denials, missing integrity
inputs, stale success and changed policy. These are unit decision fixtures;
they do not establish real kernel readiness. Run them in both full builds and
retain their output alongside the actual pinned-probe and kernel results.

For red/candidate evidence on the disposable box, restore the root-only
registry requirement through the decision reader: the positive unreadable
registry test must fail with permission denied. Separately remove the bwrap
success requirement, each unshare-denial check, profile-byte comparison and
switch comparison; their corresponding refusal tests must fail because the
mutated decision accepts the supplied bad input. Each restored candidate must
then pass the same reached assertion. These pairs have not run on Mac.

The supervisor's next combined tree `22f6632` again passed restriction-off and
both staged restriction-on setup entries. The Linux prerequisite rejected the
actual mapping-stage diagnostic `unshare: write failed /proc/self/uid_map:
Operation not permitted` because it required the narrower `unshare failed:`
wording. The corrected classifier requires a permission cause at the namespace
syscall or its own UID/GID mapping or setgroups setup. An unrelated exit 1 or
a permission error on another file still refuses. Commands, locale, cwd and
before/after order stay the same. No switch or root-only registry is changed.

Every command-result refusal now puts the captured exit, bounded stderr head,
failed conditions and before/after phase before the wrapped cause. Newlines
inside stderr are quoted, so the first log line retains the decision evidence.
TestAppArmorUIDMapDenial uses the exact supplied diagnostic text;
TestAppArmorOtherExitOne rejects unrelated errors before and after bwrap.
TestNamespacePermissionDiagnostics covers the operation/cause combinations,
and TestNamespaceStderrHead checks complete draining with bounded head capture.
The existing missing/allowed/timeout/cancellation controls also require their
diagnostic fields. Their actual Linux red/candidate runs remain required.

For these new red/candidate pairs, restore the old syscall-only wording gate;
TestAppArmorUIDMapDenial must reject that mutation at the supplied mapping
diagnostic. Broadening acceptance to any exit 1, another file or a nonpermission
cause must fail TestAppArmorOtherExitOne. Restore tail-only capture or remove
the head bound; TestNamespaceStderrHead must fail. Removing the first-line
exit/condition/head fields must fail the diagnostic assertions in the refusal
tests. Retain each reached failure and the restored candidate's matching pass.

The earlier missing-option message can occur before its injected option probe
is called: startSandboxWithProbe checks the host prerequisite first. It is not
evidence that a produced bwrap_options cause was discarded. That test now
distinguishes an uncalled probe from a wrong returned cause and prints
the actual error in either case. An earlier prerequisite failure still fails
the test; it is never relabeled or counted as the deliberate option refusal.

Run the ordinary/fault suites below against the draft.4 source. New control
tests are TestCausalHelperRequests, TestHandoffDigestAndCause,
TestPreparePropagatesRootRefusal, TestLaunchReconcilesBeforeOpen,
TestMeasuredReleaseReceipt, TestObservationKeepsUnknown,
TestCollectRejectsUnmeasured, TestUnboundSourceNeverOpensGate and
TestNetworkLeaseBinding. Their protocol
fixtures advertise no successful fake process or helper readiness. The real
installed positive remains the serve case plus OS-LINUX, not these fixtures.

The required profile artifact and root setup entry belong to the admin slice:
`packaging/v2/linux/laneboss-bwrap.apparmor` and
`scripts/v2-admin/namespace.sh`. They were read from `lb-v2-admin`; laneboss must
compose that reviewed slice into the next test bundle. They are absent from
this Linux-only checkout. Preserve the directory layout because the script
locates its profile relative to the source root.

Use the root entry's `--install` followed by `--check`. It installs missing OS
prerequisites noninteractively, uses unprivileged availability probes and keeps
root-owned private invocation receipts. It starts no service or model session.
The current reviewed admin entry uses the capability-requiring unshare control
and checks ownership of its source and evidence ancestors. Use the reviewed,
administrator-staged root-owned source bundle created below. The entry must
not be bypassed or its failure ignored.

For the restriction-off component cell, require the actual restriction to be
0 and the Laneboss profile to be absent, then run both test builds above.
Do not install or reload a profile for that cell. Retain switch bytes and
profile absence before and after; infer no policy setting from the image name.

For the restriction-on component cell, run the following as the original
non-root test account from the composed source root. The availability controls
execute only the administrator-owned system `true`; the namespace-only root
projection here is not a Laneboss agent launch or filesystem-isolation proof.
The new behavioral probe and kernel tests use the actual minimal FD layout.

Ubuntu's restriction can allow creation of a user namespace while withholding
capabilities inside it. Bare `unshare --user -- true` therefore need not fail.
Use `/usr/bin/unshare --user --map-root-user --mount -- /usr/bin/true` both
before and after profile installation: creating the mount namespace requires
`CAP_SYS_ADMIN` inside the new user namespace. Before installation, both this
unprofiled control and bwrap must fail. After installation, the same bwrap
command must succeed through its executable-specific profile, while the same
unprofiled capability-requiring unshare command must still fail. Together with
unchanged switch bytes, these distinguish the bwrap exception from a host-wide
relaxation. This control is separate from the tests' `unshare(0)` seccomp probe,
which needs no namespace capabilities and must succeed outside confinement.

The root entry creates `/var/tmp/lb-v2-linux-namespace` as root-owned mode 0700
directly under the root-owned sticky system temp directory. It must not write
beneath `/var/tmp/lb-v2-linux-r1`, which belongs to the non-root observer. The
fresh-cell check requires the separate root evidence path to be absent, so
the read-only install/check receipt validation cannot accept an older invocation.

First stage the reviewed admin inputs from the composed source root, as the
same non-root observer. This needs no Git metadata. The seven files cover the
namespace entry, its loader/profile and the later install entry's Python code
and unit templates. Only new destination directories/files get root ownership;
the checkout is never chowned or executed as root. The staging command refuses
an existing destination, checks `/` and `/opt`, installs root:root directories
0755 and files 0644, and rejects symlinks or shared-writable staged paths.
Its stdout is the staged SHA-256 manifest; stderr and exit stay with the observer.
Both manifests use identical relative paths. Require the staged hashes and a
second checkout hash to equal the original checkout hashes before proceeding.
Preserve a failed or partial bundle; use a fresh cell rather than overwrite it.

```sh
set -eu
test "$(id -u)" -ne 0
mkdir -p /var/tmp/lb-v2-linux-r1
linux_source=$(pwd -P)
set -- scripts/v2-admin/namespace.sh scripts/v2-admin/apparmor.sh \
  scripts/v2-admin/install.sh scripts/v2-admin/boot.py \
  packaging/v2/linux/laneboss-bwrap.apparmor \
  packaging/v2/linux/"laneboss-helper.service.in" \
  packaging/v2/linux/"laneboss-service.service.in"
for linux_input in scripts scripts/v2-admin packaging packaging/v2 \
  packaging/v2/linux "$@"; do
  test ! -L "$linux_input"
done
for linux_file in "$@"; do
  test -f "$linux_file"
done
sha256sum -- "$@" > /var/tmp/lb-v2-linux-r1/source-before.sha256

if sudo -n bash -eu -c '
  umask 022
  cd -- "$1"
  shift
  for linux_parent in / /opt; do
    test -d "$linux_parent"
    test ! -L "$linux_parent"
    test "$(stat -c %u:%g -- "$linux_parent")" = 0:0
    linux_mode=$(stat -c %a -- "$linux_parent")
    test "$((8#$linux_mode & 0022))" -eq 0
  done
  test ! -e /opt/lb-v2-linux-src
  test ! -L /opt/lb-v2-linux-src
  mkdir -m 0755 -- /opt/lb-v2-linux-src
  chown root:root /opt/lb-v2-linux-src
  install -d -o root -g root -m 0755 \
    /opt/lb-v2-linux-src/scripts/v2-admin \
    /opt/lb-v2-linux-src/packaging/v2/linux
  for linux_input in scripts scripts/v2-admin packaging packaging/v2 \
    packaging/v2/linux "$@"; do
    test ! -L "$linux_input"
  done
  for linux_file in "$@"; do
    test -f "$linux_file"
    install -o root -g root -m 0644 -- "$linux_file" \
      "/opt/lb-v2-linux-src/$linux_file"
  done
  linux_bad=$(find /opt/lb-v2-linux-src \
    \( -type l -o ! -user root -o ! -group root -o -perm /022 \) -print)
  test -z "$linux_bad"
  cd /opt/lb-v2-linux-src
  sha256sum -- "$@"
' linux-stage "$linux_source" "$@" \
  > /var/tmp/lb-v2-linux-r1/source-staged.sha256 \
  2> /var/tmp/lb-v2-linux-r1/source-stage.stderr; then
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/source-stage.exit
else
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/source-stage.exit
  exit 1
fi
cmp /var/tmp/lb-v2-linux-r1/source-before.sha256 \
  /var/tmp/lb-v2-linux-r1/source-staged.sha256
sha256sum -- "$@" > /var/tmp/lb-v2-linux-r1/source-after.sha256
cmp /var/tmp/lb-v2-linux-r1/source-before.sha256 \
  /var/tmp/lb-v2-linux-r1/source-after.sha256
```

After that block succeeds, keep the staged bundle unchanged and run the
restriction-on controls below as the same observer. Both root namespace calls
use its absolute staged entry; they never read executable source from the checkout.

```sh
set -eu
test "$(id -u)" -ne 0
mkdir -p /var/tmp/lb-v2-linux-r1
cat /proc/sys/kernel/"apparmor_restrict_unprivileged_userns" \
  > /var/tmp/lb-v2-linux-r1/restriction.before
cat /proc/sys/kernel/"unprivileged_userns_clone" \
  > /var/tmp/lb-v2-linux-r1/clone.before
test "$(cat /var/tmp/lb-v2-linux-r1/restriction.before)" = 1
test ! -e /etc/apparmor.d/laneboss-bwrap
test ! -L /etc/apparmor.d/laneboss-bwrap
sudo -n test ! -e /var/tmp/lb-v2-linux-namespace
sudo -n test ! -L /var/tmp/lb-v2-linux-namespace

if /usr/bin/bwrap --die-with-parent --unshare-user --unshare-pid \
  --unshare-net --ro-bind / / -- /usr/bin/true \
  > /var/tmp/lb-v2-linux-r1/bwrap-before.stdout \
  2> /var/tmp/lb-v2-linux-r1/bwrap-before.stderr; then
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/bwrap-before.exit
  printf '%s\n' 'FAIL: unprofiled bwrap unexpectedly succeeded' >&2
  exit 1
else
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/bwrap-before.exit
fi
if /usr/bin/unshare --user --map-root-user --mount -- /usr/bin/true \
  > /var/tmp/lb-v2-linux-r1/unshare-before.stdout \
  2> /var/tmp/lb-v2-linux-r1/unshare-before.stderr; then
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/unshare-before.exit
  printf '%s\n' 'FAIL: unprofiled mount namespace unexpectedly succeeded' >&2
  exit 1
else
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/unshare-before.exit
fi

# Only the staged root entry is privileged; captures belong to the observer.
if {
  sudo -n bash /opt/lb-v2-linux-src/"scripts/v2-admin/namespace.sh" --install \
    --evidence /var/tmp/lb-v2-linux-namespace
} > /var/tmp/lb-v2-linux-r1/ns-install.stdout \
  2> /var/tmp/lb-v2-linux-r1/ns-install.stderr; then
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/ns-install.exit
else
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/ns-install.exit
  exit 1
fi
grep -Fq 'PASS: unprivileged bwrap namespace prerequisites' \
  /var/tmp/lb-v2-linux-r1/ns-install.stdout
if {
  sudo -n bash /opt/lb-v2-linux-src/"scripts/v2-admin/namespace.sh" --check \
    --evidence /var/tmp/lb-v2-linux-namespace
} > /var/tmp/lb-v2-linux-r1/ns-check.stdout \
  2> /var/tmp/lb-v2-linux-r1/ns-check.stderr; then
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/ns-check.exit
else
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/ns-check.exit
  exit 1
fi
grep -Fq 'PASS: unprivileged bwrap namespace prerequisites' \
  /var/tmp/lb-v2-linux-r1/ns-check.stdout

# Read root-owned receipts; the observer opens and owns the capture file.
sudo -n find /var/tmp/lb-v2-linux-namespace -mindepth 2 -maxdepth 2 \
  -type f -name result.json -exec cat -- {} + \
  > /var/tmp/lb-v2-linux-r1/ns-receipts.jsonl
python3 -I -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    receipts = [json.loads(line) for line in stream if line.strip()]
if len(receipts) != 2 or {r.get("mode") for r in receipts} != {"install", "check"}:
    raise SystemExit("FAIL: expected one install and one check receipt")
for receipt in receipts:
    if (receipt.get("schema") != "laneboss.namespace-setup.v2" or
            receipt.get("stage") != "completed" or
            type(receipt.get("exit_code")) is not int or receipt["exit_code"] != 0 or
            receipt.get("ready") is not True or
            type(receipt.get("restriction")) is not int or receipt["restriction"] != 1 or
            receipt.get("switches_unchanged") is not True):
        raise SystemExit("FAIL: namespace receipt is not ready with unchanged policy")
print("PASS: root namespace receipts verified")
' /var/tmp/lb-v2-linux-r1/ns-receipts.jsonl

cmp /opt/lb-v2-linux-src/"packaging/v2/linux/laneboss-bwrap.apparmor" \
  /etc/apparmor.d/laneboss-bwrap
sudo -n awk '$0 == "laneboss-bwrap (unconfined)" { found=1 } END { exit !found }' \
  /sys/kernel/security/apparmor/profiles

if /usr/bin/bwrap --die-with-parent --unshare-user --unshare-pid \
  --unshare-net --ro-bind / / -- /usr/bin/true \
  > /var/tmp/lb-v2-linux-r1/bwrap-after.stdout \
  2> /var/tmp/lb-v2-linux-r1/bwrap-after.stderr; then
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/bwrap-after.exit
else
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/bwrap-after.exit
  exit 1
fi
if /usr/bin/unshare --user --map-root-user --mount -- /usr/bin/true \
  > /var/tmp/lb-v2-linux-r1/unshare-after.stdout \
  2> /var/tmp/lb-v2-linux-r1/unshare-after.stderr; then
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/unshare-after.exit
  printf '%s\n' 'FAIL: unprofiled mount namespace became permitted' >&2
  exit 1
else
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/unshare-after.exit
fi
cat /proc/sys/kernel/"apparmor_restrict_unprivileged_userns" \
  > /var/tmp/lb-v2-linux-r1/restriction.after
cat /proc/sys/kernel/"unprivileged_userns_clone" \
  > /var/tmp/lb-v2-linux-r1/clone.after
cmp /var/tmp/lb-v2-linux-r1/restriction.before \
  /var/tmp/lb-v2-linux-r1/restriction.after
cmp /var/tmp/lb-v2-linux-r1/clone.before /var/tmp/lb-v2-linux-r1/clone.after
```

Require both root-entry exits 0, their
`PASS: unprivileged bwrap namespace prerequisites` lines and actual
`ready: true` invocation receipts, matching profile bytes, loaded
profile check, successful unprivileged bwrap and still-denied unprofiled mount
namespace creation. Inspect the retained original stderr to establish a
namespace-permission refusal; an unrelated setup error is not that baseline.
Then run both root-installed test binaries above as the same non-root account.
Retain both root-entry private invocation records beneath
`/var/tmp/lb-v2-linux-namespace`, their read-only capture `ns-receipts.jsonl`
under the observer's directory, all command outputs/exits, bwrap bytes/version/hash and
the new test evidence. Existing/differing profiles are preserved and stop the
fresh-cell procedure; never delete or widen policy to make the baseline pass.

For a later installed-product cell, `scripts/v2-admin/install.sh` stages the
actual Laneboss release artifact, accounts, binding and units. It is separate
from profile setup and is unnecessary for these component tests. First run the
same staging block above from that cell's reviewed composed checkout; retain
its matching manifests and observer captures. Reuse the verified bundle only
within the same unchanged cell. An existing or partial bundle is never replaced.
The installer also runs only from the absolute staged path. Supply the actual
protected artifact, release manifest and boot input required by the admin
README; their `/test` ancestors must be root-owned without symlinks or shared
writes. Boot key material stays in its private store, outside the source bundle.
Use a fresh root evidence directory under `/opt`, separate from observer
captures, because the installer also rejects user-owned evidence ancestors:

```sh
set -eu
test "$(id -u)" -ne 0
sudo -n test ! -e /opt/lb-v2-linux-install
sudo -n test ! -L /opt/lb-v2-linux-install
if sudo -n bash /opt/lb-v2-linux-src/"scripts/v2-admin/install.sh" --install \
  --config case-linux --binary /test/artifacts/laneboss \
  --manifest /test/artifacts/release.json --boot /test/admin/boot-input.json \
  --evidence /opt/lb-v2-linux-install \
  > /var/tmp/lb-v2-linux-r1/install.stdout \
  2> /var/tmp/lb-v2-linux-r1/install.stderr; then
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/install.exit
else
  printf '%s\n' "$?" > /var/tmp/lb-v2-linux-r1/install.exit
  exit 1
fi
```

After installation, retain the unprofiled restriction-on controls, run the
staged `namespace.sh --install` then `--check` and the read-back controls above,
then activate `laneboss-helper@case-linux` only when its composed binding and
fixed entry point are implemented. The installer itself starts no service
and loads no profile. A helper/service stub remains a failed installed-product
cell; it cannot be credited from the component tests.

The standalone kernel tests measure only namespace, filesystem, descriptor and
filter construction under the test account. They do not prove production
leased UID/cgroup/network/capture/gate integration. Public `Launcher` methods
require the protected service `ControlSource` and actual installed helper
backend described in CONTRACT-GAPS.md. Current composition still lacks that
source; it fails explicitly rather than supplying invented launch context.

After those dependencies and the harness's real-driver fixtures are installed,
run the public case through the shared runner, or invoke its identical entry:

```sh
sh e2e/v2/cases/linux/run.sh \
  --context /test/cases/linux/context.json \
  --result /test/evidence/linux/result.json
```

Until integration lands, an attempted public CLI operation must return its
typed failure and the case must fail, with no invented gate or zero-survivor
receipt. A missing fixture is a setup failure, not a killed mutation. A complete
candidate needs exit 0, reached OS-LINUX/pass, verified artifact/evidence hashes,
actual zero-survivor observations and observed cleanup. Repeat restriction-on
and restriction-off hosts, hook absent/allow, and a separate ABI 3 floor cell.
Real supported drivers require the supervisor's authorized login; no test in
this package authenticates or starts a model request.

The egress-lease-positive cell needs actual administrator-issued network
resources, their draft.4 lease and helper resolution. It must prove forwarding plus private
loopback and denied management/sibling/metadata IPv4, IPv6, UDP and abstract
Unix endpoints. Its current disposition is failing/incomplete, never skipped
or credited from the offline namespace tests.

For red-before-green evidence, rebuild one deliberate mutation at a time in
the disposable scope, retain its distinct digest, and execute the same tests:

The file-backed component pair commands and draft.4 control mutations are in
[MUTATIONS.md](MUTATIONS.md). They supplement the kernel/public rows below;
their narrow component scopes cannot replace installed boundary evidence.

| Mutation | Assertion that must fail |
| --- | --- |
| Drop unconditional network namespace or permit network without a lease | NoHostNetworkFallback / KernelPrivateNetwork / public network syscalls |
| Remove helper/runtime export overlap checks or root ownership | ExportsCannotOverlapRuntime / runtime owner tests / installed helper control |
| Replace descriptor binding with the original source name | DescriptorMountArguments / PinSurvivesAncestorSwap / KernelMountedSourceSwap |
| Restore named payload or remove seal checks | DescriptorMountArguments / SelectedPayloadAndSeals |
| Accept a raw file-backed standard stream | StreamAndTailBoundaries / KernelFileStreamRefusal |
| Remove CLOEXEC descriptor sweep | real fd-200 read changes from EBADF to planted bytes |
| Change the descriptor sweep to immediate close | CloexecLeavesRuntimeFDsLive loses its actual event descriptor before exec |
| Remove seccomp or allow nested namespaces | KernelProbeTruncateAndSeccomp / SeccompIsADenyList |
| Lose export/cause, stderr bounds, dangling-root target, pool exclusion or ABI clamp | corresponding paired layout, ownership, mask and cache tests |
| Broaden nested target Landlock rights or remove TRUNCATE handling | writable nested target succeeds / truncate-only probe succeeds |
| Fake cgroup stop or zero survivors | public case's marker-bearing detached process remains alive |

Do not count setup failure, unavailable live auth or an unrelated failing
positive control as a killed boundary mutation. The Mac static checks cannot
produce this executed red/green evidence.
