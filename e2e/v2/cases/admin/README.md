# Administrator acceptance

This is a draft.4 outside observer of installed CLI and helper socket behavior. Run
only as an unprivileged user on a disposable Ubuntu 24.04 machine with
passwordless sudo authorized by the supervisor. It does not authenticate a
vendor or start a model request. No fixture runner is a production driver.

For the Linux lane's root-operated fresh Ubuntu prerequisites, use the single
`scripts/v2-admin/namespace.sh --install` / `--check` entry. The script folder's
README gives exact commands. `namespace_cli.py` tests that entry independently
of service/identity/launch contracts and requires root on the disposable box.
The original unprivileged case below retains its original fresh-baseline role;
do not preinstall a profile before measuring its unprofiled refusal.

The harness supplies the frozen context and installs the candidate artifact.
It also supplies `test_root/admin-input.json`, containing:

* `restriction`: the intended measured cell, integer 1 or 0;
* `helper_binding`: the administrator-installed helper binding file;
* `launch_request`: a file with an actual authorized TestChildRequest for
  `grants test-child`, including immutable candidate/test-plan BlobRefs;
* `canary_file` and `ack_file`: fresh files inside the granted worker test
  data, with their outside-observer paths inside test_root;
* `nonce`: a fresh 16-byte random nonce represented as 32 hexadecimal digits;
* `helper_pid`: the actual administrator-started helper PID;
* `changed_binary`: the exact candidate with only ELF identification padding
  byte 15 changed, with unchanged length and all other bytes identical.

The launch executes the shipped `canary.py` as ordinary test content through
the production confined worker. Its arguments are `--out`, `--ack` and
`--nonce`; the first two are the corresponding paths inside that worker's
grant. It writes observed `uid`, `gid`, `cgroup`, `no_new_privs` and `cap_eff`.
It then waits at most 180 seconds for the observer's nonce acknowledgement.
The observer reads actual host cgroup/process facts while it is still alive,
then checks the operation receipt, helper release event and cgroup removal.
The supervisor supplies
real grants and authorization, never invented successful receipts. If the
production service cannot expose a credential-free bounded worker through its
frozen public interface, that dependency is a failing HELPER cell. It must not
be replaced by an unconfined stand-in or a third agent driver.

UBUNTU-USERNS runs twice on separately prepared machines: restriction 1 is
UBUNTU-DEFAULT, restriction 0 is UBUNTU-AWS. The observer reads the actual
switches before choosing expectations. On 1 it records the unprofiled bwrap
and unshare failures, installs/reads back/reloads only the shipped bwrap
profile with `scripts/v2-admin/apparmor.sh`, then repeats bwrap successfully
and requires the unprofiled unshare control still to fail. On 0 it requires
bwrap success and leaves the profile untouched. Both compare switch bytes.
No test changes either switch or makes bwrap setuid.

`focus.py` runs only this namespace cell when service/launch dependencies are
still unavailable. It retains the actual administrator stage receipt and
stopped-command evidence on failure. `MUTATIONS.md` and `mutations.json` define
the named red controls, their exact focused tests, and the copy-only runner.
The namespace control uses a private copy of the distro unshare binary so an
unrelated distro attachment cannot mask its before/after behavior.

HELPER-PEER sends valid framed requests as a nonservice peer, including
additional root argv/path fields, and requires typed refusal. It also calls
the CLI internal mode with arbitrary argv and a different artifact. HELPER
requires CLI doctor, the real worker launch, distinct service/worker UIDs,
the pinned helper executable, an actual helper.allocated event and a real
cgroup. Collection requires a successful service operation, matching
helper.released event and independently observed containment removal. Actual
agent-life start/resume/clean remains a separate integrated live-driver cell.
The protected helper binding and private frame must name v2.0-draft.4. Doctor
must be ready in both the exact-file and ergonomic JSON CLI forms and expose
the actual isolation.linux-bwrap-landlock probe. Event collection requires a
complete bounded snapshot and retains original request/requester causality for
both helper allocation and release. Older draft or fabricated event labels do
not establish production readiness.
Every CLI call uses the explicit context binding; mutations retain an explicit
key. HELPER-PEER keeps its VFS ACL row and additionally runs the fixed root
peer_probe.py from a protected root-owned source bundle, proving an actual
connection and framed peer refusal. It cannot pass on a directory mode alone.
Changed-artifact/setuid controls register cleanup before mutation and restore/
disarm from finally; any cleanup error fails collection. cleanup_test.py
provides separate component fault controls, with no installed-helper claim.

The outside human coordinator supplies a fresh protected
`test_root/authority/NNNNNN.proof.json` for each CLI invocation. Its number is
the observer's next command number, matching the retained request filename.
Reads use a new proof for `human.session`; the shared CLI establishes that
session on the same connection as the read. Exact mutations use their own
operation proof. The ergonomic doctor call needs its own fresh session proof.
Missing proof files stop with a retained `prerequisite_missing` owner wait and
an unreached failed assertion. A file is not treated as confirmation; the real
service must validate it. Event queries select the actual prepared child/run.

Only the installed serve E2E completes this round. This case, namespace entry,
boot_cli.py and unit/mutation tests are supporting controls. Complete protected
boot provisioning now requires a real file-backed --boot input; read the script
README and admin/CONTRACT-GAPS.md. Do not replace absent runtime/key/policy inputs
or the authorized caller path with placeholders or a label-only fixture.

Missing fixtures, stubs, unavailable sudo, malformed output, a setup crash or
uncollected resources fail. Every result retains command exits and exact
stdout/stderr/input bytes. This file is the red-control specification: first
run the same assertions against a candidate mutation that removes peer checks,
artifact checks, UID separation, or profile loading. The intended assertion
must be reached and fail; a setup error is not a killed mutation. The local
authoring Mac cannot establish these runtime results.

The entry is invoked as:

```sh
bash e2e/v2/cases/admin/run.sh \
  --context /test/admin/context.json --result /test/admin/result.json
```
