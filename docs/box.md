# Spot test boxes

`laneboss box` starts a disposable spot machine on AWS or GCP. It can run a suite,
bring its results back, request termination and wait for evidence that the machine
is gone. A ledger outside the repository records launches and their outcomes.

The command reads its own `box.toml`. It is independent of the launcher's lane
state store. `--config NAME` selects where to find that file; it does not bind the
box command to the launcher's state store.

## Quick start

Set up the cloud resources described below and keep their names in a local
`box.toml`. All names in this document are invented. Use your own resources when
preparing the configuration; keep credentials out of it.

```sh
laneboss box check --box-config box.toml
laneboss box launch demo --box-config box.toml --provider aws --dry-run
laneboss box run demo --box-config box.toml --provider aws \
  --suite 'uname -s' --out ./demo-results
laneboss box list --box-config box.toml --provider aws
```

`run` owns the machine's full lifetime. For a machine started with `launch`, keep
the printed id and use `end` when finished:

```sh
laneboss box launch demo --box-config box.toml --provider aws
laneboss box end --box-config box.toml --instance i-demo1
```

An exit of 4 means the machine is up without a ledger line. Do not launch another
machine to retry that operation. Keep its id, inspect it and collect it.

## Choosing a configuration and provider

`--box-config FILE` takes precedence over `LANEBOSS_BOX_CONFIG`. Otherwise the
locator uses `--config NAME`, then `LANEBOSS_CONFIG`, to find `box.toml` under the
configuration home. `LANEBOSS_HOME` and `LANEBOSS_STATE_HOME` are interpreted by the
box configuration loader; the user's home supplies their normal defaults.

The provider comes from `--provider`, then `[defaults].provider`, then the sole
provider table if exactly one exists. An ambiguous or absent provider is a usage
error. A provider must have a table in the loaded file.

For `end` without `--provider`, the last `LAUNCHED` record for the instance takes
precedence over the configured provider. A legacy launch record without a
provider means AWS. If there is no matching launch, the normal provider fallback
applies. An unreadable ledger refuses the operation.

Flags always win, including explicitly supplied zero values where allowed.
`--owner` takes precedence over `LANEBOSS_BOX_OWNER`; otherwise the owner and its
basis are `unknown`. An environment owner has basis `env`, and a flag owner has
basis `flag`. The lane comes from `--lane`, then `LANEBOSS_BOX_LANE`, then the
purpose. Provider, purpose, lane and owner must be short plain ASCII names: a
letter or digit first, followed by letters, digits, dots, underscores or hyphens.

Every subcommand accepts `--box-config`, `--config`, `-h` and `--help`. Help needs
no configuration or cloud access. Every subcommand except `check` accepts
`--format lines|json`; the default is `lines`. Diagnostics and progress go to
stderr. Usage errors print usage and one fixed diagnostic that repeats no typed
value, and exit 2.

## Commands

### `launch`

```text
laneboss box launch --provider P --purpose NAME [placement] [--dry-run]
```

The purpose may instead be the first positional argument. The placement
picker tries permitted candidates. A dry run asks whether a launch is allowed
and creates no machine. Its text output is exactly `dryrun: allowed` or
`dryrun: denied CODE`.

A launch with a machine prints exactly three lines:

```text
spot: demo.large demo-a $0.012345/h
iid=i-demo1
ip=demo-host
```

The price has six decimal places. For GCP, and whenever there is no address,
`ip=` contains the box name. The id always precedes that line. JSON output is one
object with `box`, `candidate`, `dry` and `exit_code`. Nested fields use lower-case
snake case, including `price_usd_hour`, `spot_request_id` and `launch_time_utc`.
The process returns the service's launch exit code, including partial successes.

### `run`

```text
laneboss box run --provider P --purpose NAME [placement]
  [--git-sha SHA --repo DIR | --archive FILE]
  (--suite TEXT | --suite-file FILE) [--put LOCAL[:REMOTE]]...
  [--timeout-min N] [--out DIR]
```

The purpose may instead be the first positional argument. Exactly one suite
argument is required. Suite text is UTF-8, contains no NUL and is at most 1 MiB.
The same limit applies to a suite file.

Source is optional: without either source form, only the suite and the put files
are uploaded. A git SHA is seven to forty lower-case hexadecimal characters.
The command runs `git -C DIR archive --format=tar SHA`, streaming stdout directly
to a file with mode 0600 in the system temporary directory. It removes this file
after the operation, including failure. Git failures are usage errors. A supplied
archive must already be a regular file and remains owned by its caller.

Each `--put` supplies a regular local file. Its default destination is
`/tmp/` followed by the file's base name. An explicit destination must be an
absolute remote path. A base name beginning with a hyphen is refused. Files reach
the service in the order given.

`--timeout-min` accepts one to 10080 minutes; without it, the CLI uses the
request's hard cap. Without `--out`, the service chooses a directory under
`[defaults].run_dir` using its generated run id.

The final text output has these lines, in this order. A line is absent if its
fact does not exist:

```text
run_id=run-demo
iid=i-demo1
suite exit 0
verdict=passed
harvest=./demo-results files=3 bytes=256 manifest=HASH
terminated=true billed_seconds=65 cost_usd=0.0123
exit=0 (ok)
```

The manifest is a SHA-256 digest. JSON is one object carrying the same facts:
`run_id`, `iid`, `suite_exit`, `verdict`, `harvest`, `files`, `bytes`, `manifest`,
`terminated`, `billed_seconds`, `cost_usd`, `exit_code` and `exit_name`. Missing
facts are omitted; a known suite exit of zero and a known false termination
result remain present. Text cost has four decimal places; JSON retains precision.

One interrupt or termination signal cancels the service context. The service
continues its harvest and termination cleanup, then returns its own exit code.
A second signal prints `laneboss box: second signal, leaving now` on stderr and
exits 130 immediately. A first signal is never permission to abandon collection.

### `end`

```text
laneboss box end [--provider P] --instance ID [--address HOST] [--bound-sec N]
```

The default bound is 600 seconds, with service polling every 15 seconds. The bound
must be positive. A confirmed end prints `terminated ID (BASIS)` and returns the
service's exit code. If the poll bound passes, stderr reports the id, last state
and bound, says `END_PENDING recorded`, and the service returns 3. An API request
to delete a machine is not evidence that it is gone.

JSON carries `instance_id`, `state`, `basis`, `terminated_utc`, `billed_seconds`,
`pending` and `exit_code`. A pending diagnostic still goes to stderr.

### `list` and `sweep`

```text
laneboss box list [--provider P] [--orphans] [--older-than-min N]
laneboss box sweep --provider P --older-than-min N [--delete]
```

`list` prints one tab-separated row per box: id, state, age in minutes, ledger
status (`open`, `ended` or `none`), orphan status (`yes` or `no`), type and zone.
JSON is an array of objects with `id`, `state`, `age_min`, `ledger`, `orphan`,
`type` and `zone`; `orphan` is a boolean. An empty list is `[]`.

`sweep` examines old orphans. The age must be supplied and be non-negative;
`--delete` is required to request deletion. The text summary is
`examined=N orphans=N deleted=N refused=N`, followed by `deleted ID` and
`refused ID REASON` rows. The service supplies refusal reasons. JSON has
`examined`, `orphans`, `deleted` and `refused`. A list or sweep error returns 2.
The name and managed-label checks still apply to every attempted deletion; a
machine that fails them is reported as refused and is never deleted.

### `check`

```text
laneboss box check [--provider P]
```

`check` loads the configuration, reports each present provider table, checks
whether the ledger is writable, and uses `exec.LookPath` to find needed programs.
It needs `git` always; AWS needs `aws`, `ssh` and `curl`; GCP needs `gcloud`.
With an explicit provider, it checks that provider's table and tools. Without
one, it checks every present provider. It never constructs or calls a provider,
executes a program, or prints a configuration value. The writable check may create
the ledger directory and lock file.

Each line is `ok: WHAT` or `FAIL: WHAT`. All checks passing returns 0; a failed
check returns 2. A failure to load the file prints `FAIL: config` and the loader's
fixed diagnostic.

## Placement flags

Absent numeric and architecture flags come from `[defaults]` once. Families are
provider selection hints; `--type` and `--zone` together bypass the picker.

| Flag | Meaning and accepted range |
|---|---|
| `--vcpu N` | Minimum CPUs: 2, 4, 8, 16, 32, 48 or 64. |
| `--mem-gib N` | Minimum memory in GiB; non-negative, zero means no minimum. |
| `--arch x86\|arm64\|any` | Required architecture or either one. |
| `--families a,b` | Comma-separated families, kept in their supplied order. |
| `--type T`, `--zone Z` | An explicit type and zone; required together. |
| `--root-gb N` | Root disk: 8 to 2000 GiB. |
| `--idle-min N` | Idle guard: 1 to 1440 minutes. |
| `--hard-min N` | Hard lifetime cap: 10 to 10080 minutes. |
| `--cost-cap-usd X` | Positive finite USD cap; the service may reduce the hard cap. |
| `--lane NAME` | Lane label; otherwise environment, then purpose. |
| `--owner NAME` | Owner label, with the basis recorded separately. |

The CLI leaves the run id empty. The service creates it once and uses it for
labels, the ledger, the results prefix and the local output directory.

## `box.toml` reference

The root key `org` names the organisation. The following tables list every field
in the shared box configuration contract. Paths and resource names belong in the
local file, never in this repository. The loader validates the file and applies
its defaults before the CLI applies flag overrides.

The file is TOML, UTF-8, at most 256 KiB, with `schema_version = 1` and a required `org` (a plain name). Unknown keys, wrong types and
out-of-range values are refused; an error names the file and the key path and never repeats a value. A string that looks like a
credential is refused before anything else. There is no key for a cloud key file, an access key or a password.

| `[ledger]` key | Meaning | Default and rules |
|---|---|---|
| `path` | Absolute path to the append-only JSON lines ledger. | `<state home>/boxes/ledger.jsonl`; `~/` is expanded |
| `schema` | The `schema` text written on every line. | `laneboss-box-event/v1`; 1 to 64 characters |
| `registry` | Optional path to a legacy registry file; empty disables it. | empty |

| `[defaults]` key | Meaning | Default and rules |
|---|---|---|
| `provider` | Default provider, `aws` or `gcp`. | none; the sole provider table is used when there is one |
| `vcpu` | Machine size in vCPUs. | 2; one of 2, 4, 8, 16, 32, 48, 64 |
| `mem_gib` | Minimum memory, or zero for no minimum. | 4; 0 to 2048 |
| `arch` | `x86`, `arm64` or `any`. | `any` |
| `root_gb` | Root disk size. | 150; 8 to 2000 |
| `idle_min` | Minutes idle before the machine ends itself. | 30; 1 to 1440, not above `hard_min` |
| `hard_min` | Hard cap on the machine's life, in minutes. | 360; 10 to 10080 |
| `cost_cap_usd` | The run's cost cap; `hard_min` is reduced to fit it. | 5; above 0, at most 10000 |
| `disk_usd_gb_month` | Disk price used in the cost estimate. | 0.10; 0 to 10 |
| `name_prefix` | Managed machine name prefix; the name gate of the delete check and of the GCP fence. | `lb-`; a letter, then letters, digits or `-`, at most 16, ending in `-` |
| `run_dir` | Absolute parent directory of the local run directories. | `<state home>/boxes/runs` |

| `[guest]` key | Meaning | Default and rules |
|---|---|---|
| `done_files` | Marker files; touching any of them ends the machine. | `["/var/tmp/lb-done"]`; 1 to 8 safe paths |
| `busy_files` | A file younger than ten minutes keeps the machine alive. | `["/var/tmp/lb-busy"]`; 1 to 8 safe paths |
| `out_dir` | On-machine directory that is harvested. | `/var/lib/lb-box/out`; a safe path, not `/` |

A safe guest path is absolute, at most 200 characters, with no space, quote or `..` segment. Done and busy files must differ from each
other and from `out_dir`.

| `[aws]` key | Meaning | Default and rules |
|---|---|---|
| `profile` | Named CLI profile; required. `default` is refused unless `allow_default_profile` is true. | letters, digits, `.`, `_`, `-`; at most 64 |
| `region` | Region used by the provider. | required |
| `project_tag` | Value of the Project tag. | the `org` value |
| `vpc` | Network id. | required; `vpc-` and hex digits |
| `security_group` | Existing group for these machines; never created or deleted. | required; `sg-` and hex digits |
| `ami` | Image id for x86 machines. | `ami-` and hex digits; `ami` or `arm_ami_ssm` is required |
| `arm_ami_ssm` | Parameter name of the arm64 image. | starts with `/` |
| `key_name` | Existing key-pair name. | required |
| `ssh_user` | Login user of the image. | `ubuntu` |
| `ssh_identity` | Path of the private key file used by ssh; `~/` is expanded. | required |
| `families_x86` | Instance families the picker may use for x86. | `c5 c5a c6i c6a c7i c7a m5 m6i m6a m7i m7a` |
| `families_arm` | Instance families for arm64. | `c6g c7g m6g m7g` |
| `max_candidates` | Placement candidates to try, cheapest first. | 3; 1 to 10 |
| `ensure_ssh_ingress` | Add this machine's address on port 22 of the existing group when it is missing. | false |
| `my_address_url` | HTTPS address that answers with the caller's public address. | a public `checkip` address; `https` only |
| `allow_default_profile` | Permit the profile named `default`. | false |
| `allow_terminate` | Permit the terminate call; off, the machine's own guard ends it. | false |

`[aws.subnets]` is an optional map from zone name to `subnet-` and hex digits; a zone with no entry uses the first public subnet of the network.

| `[gcp]` key | Meaning | Default and rules |
|---|---|---|
| `project` | Cloud project id. | required |
| `region` | Region of the zones. | required |
| `zones` | Zones to try, in order. | required; 1 to 8, each the region, `-` and one letter |
| `network` | Dedicated network name. | empty (the default network of the project) |
| `subnetwork` | Subnetwork name; optional with a network. | empty |
| `external_ip` | Whether a machine gets an external address. | true |
| `network_tags` | Network tags the tunnel's firewall rule targets. | none; at most 8 |
| `box_service_account` | Account id (no `@`) of the machine's runtime identity. | required |
| `impersonate_service_account` | Account id the launcher acts as through impersonation. | empty (the caller's own login) |
| `results_bucket` | Bucket of the harvest safety net. | required |
| `object_prefix` | Prefix under which run results are stored. | `runs` |
| `image_project` | Project that supplies the image. | `ubuntu-os-cloud` |
| `image_family_x86` | Image family for x86. | `ubuntu-2404-lts-amd64` |
| `image_family_arm` | Image family for arm64. | `ubuntu-2404-lts-arm64` |
| `boot_disk_type` | Boot disk type. | `pd-balanced`; or `pd-standard`, `pd-ssd` |
| `preemption_notice_sec` | Preemption notice; 120 uses the beta command group of the cloud tool. | 0; 0 or 120 |
| `gcloud_config_dir` | Isolated cloud-tool configuration directory. | empty |
| `gcloud_configuration` | Named cloud-tool configuration. | empty |

Each `[[gcp.shape]]` row defines one machine type the lane may use; it is the launch table, and `price_usd_hour` is the cost basis (put the
on-demand rate there, an upper bound for a spot price):

| Key | Meaning | Default and rules |
|---|---|---|
| `type` | Machine type name. | required |
| `vcpu` | CPU count. | required; 1 to 416 |
| `mem_gib` | Memory in GiB. | required; 1 to 11776 |
| `arch` | `x86` or `arm64`. | `x86` |
| `price_usd_hour` | Hourly price used to order candidates and bound cost. | required; above 0, at most 1000 |

The two service-account settings hold account ids, not account addresses and
never key files. The provider constructs account addresses at run time.

## Ledger and safety

The ledger is append-only, with one JSON object per line. Event records carry an
`event` and their evidence fields. A `LAUNCHED` line identifies the machine with
`instance_id` and, for new records, `provider`. Launch evidence also identifies
the run, purpose, lane, owner and owner basis, provider placement and price.
Launcher version and executable digest identify what created it. Run, suite,
harvest and termination evidence are recorded by the service as it proceeds.
`END_PENDING` records that the termination bound passed without confirmation.

For example, these are the fields used to infer a provider from a launch record:

```json
{"event":"LAUNCHED","instance_id":"i-demo1","provider":"aws"}
```

Keep the complete service-written records; the example only shows the lookup
fields. Legacy records without a provider are treated as AWS. The ledger is
checked for writability before any machine is created, so a failed write gate
cannot start a box. A post-launch recording failure is reported with exit 4.

The on-machine guest runs an idle guard and an independent hard lifetime cap.
Done and busy markers inform the idle guard. Neither the suite nor its caller
can make the hard cap disappear. The harvest safety net saves output before or
during shutdown where the provider permits it; on GCP, periodic and shutdown
uploads to the results bucket offer another way to recover files after the
machine becomes unreachable. Harvest evidence includes counts, bytes and a
manifest, so incomplete collection is visible.

No cloud account key is held or generated by this command. Cloud tools use their
configured short-lived identity. Child environments are built from nothing,
adding only basic process variables and the provider's explicit allowlist.
Before deletion, the provider checks the managed name prefix and ownership tags
or labels. On GCP the same check, a strict fence, also guards every command sent
to a machine (a pass covers the commands of the next 30 seconds, then the machine
is read again) and every harvest: the provider reads the live machine first and
acts only when its name is the requested one and starts with the configured name
prefix, and its `managed-by`, `lb-org`, `lb-owner`, `lb-lane` and `lb-run`
labels are present with the right values (`lb-run` must match the run being
handled when one is named). Every comparison is exact. A refusal names the failed
checks, never a name or a label value, and the machine is not touched. A machine
counts as gone, which is no refusal, only when gcloud's answer names it; a read
that fails (a crashed gcloud, a zone or project that is not found) lets nothing
act and confirms nothing. The ledger write gate precedes launch. A delete request is followed by bounded
polling; only provider state evidence confirms the box is gone.

### What to set up in your cloud account

- A dedicated network and the subnets or firewall rules needed to reach a box.
- A short-lived launcher identity with permissions for placement, launch,
  inspection and the permitted cleanup operations.
- A machine image and runtime identity suitable for the suite.
- For AWS, an existing SSH key-pair registration and local SSH identity.
- For GCP, the tunnel, OS Login permissions, two service accounts, and a results
  bucket with a lifecycle rule that expires old run objects.
- For GCP in a project shared with other workloads, rights conditioned on the
  machine name prefix, and a proof before the first launch and before every role
  or condition change: `scripts/gcp-fence-proof.sh` reads, as the launcher, one
  status per machine and disk of the project. Every machine and disk that is not
  yours must answer 403, your probe name in each permitted zone 404, and a decoy
  name or a probe name outside the permitted zones 403. It changes nothing.
- Quotas and budgets that fit the intended machine shapes and lifetime caps.

### AWS notes

Use a named CLI profile unless `allow_default_profile` explicitly permits the
default one. Keep resource selection in a dedicated VPC and security group. The
SSH ingress option is a controlled configuration choice, and the SSH identity
remains outside the repository. Candidate families, subnets and the candidate
limit constrain placement. Without `allow_terminate`, the provider may refuse
API termination and rely on the machine's own shutdown guard; verify the final
state instead of treating a request as proof.

### GCP notes

Use a dedicated network and the tunnel for SSH access. Restrict its firewall rule
to the tunnel's documented source range and the configured network tags. Enable
OS Login and grant the launcher the needed tunnel and login permissions. Keep
the two identities separate: one service account is impersonated by the
launcher, and the other is attached to the machine. Grant the machine only the
bucket access it needs. No service-account keys are needed.

Give the results bucket a lifecycle rule. The periodic harvest and shutdown hook
can leave recoverable objects after preemption; the lifecycle rule bounds their
retention. Keep the CLI configuration directory isolated and list the permitted
shapes with their price estimates. A GCP stopped machine still exists: final
collection must prove deletion, not just observe a stopped state.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done and recorded. |
| 1 | Launch: every candidate failed and no machine exists. Run: the suite ran and exited non-zero. |
| 2 | Usage, configuration or a refusal before a machine was created. |
| 3 | Launch or run: no candidate at all. End: the poll bound passed and `END_PENDING` was written. |
| 4 | The machine is up and has no ledger line. Never relaunch. |
| 5 | The machine is up and in the ledger, but absent from the legacy registry. |
| 6 | Dry run denied. |
| 7 | Dry run gave an unexpected answer. |
| 10 | The machine never became reachable. |
| 11 | Harvest failed or is incomplete. |
| 12 | The provider took the machine before the suite finished. |
| 13 | The suite timed out. |
| 14 | Refused or stopped by the cost cap. |
| 15 | Run: the machine was not confirmed gone within the bound. |
| 70 | Internal error. |

Service exit codes pass through to the process. An otherwise successful operation
with a service error, or an output write failure, returns 70. A second signal
forces exit 130.

## Troubleshooting

Start with `check`. Its program checks only locate executables; they do not
authenticate or contact a cloud. Fix a missing tool or unreadable configuration
before requesting a machine. A failed ledger check means no launch should begin.

For an access failure, inspect network rules, image login settings and the
selected identity. For a capacity failure, check the permitted families, zones
and candidate limit. For a cost refusal, inspect the configured estimate and
request's cap before changing the request.

For an incomplete harvest, keep the run directory and its manifest. On GCP,
recover the run's bucket objects if available. Do not label missing results as a
passing suite. After exit 3 from `end` or exit 15 from `run`, inspect the box and
repeat collection until the provider confirms it is gone. Keep the ledger and
any printed machine id when recording or registry writes fail.
