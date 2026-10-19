# The lane sandbox

This document describes the lane sandbox. The identity service is described
separately in [service.md](service.md).

## Platform behavior

The owner chose macOS option A. With `[lanes] sandbox = "laneboss-files"`,
Laneboss starts the runner under sandbox-exec with an allow-default profile and
write denials only for Laneboss-owned paths. The runner's own sandbox is OFF:
Codex receives the documented `--sandbox danger-full-access` option. For Claude
and Claudock, lane start/resume/turn creates a read-only per-run settings overlay
with `sandbox.enabled=false`, preserving the other source fields and hooks.
Org-hook rendering passes the org's own sandbox setting through unchanged.
Linux and non-opted macOS configurations keep that setting and receive no overlay.
The overlay stays beneath the selected vendor home's protected `.laneboss-lanes`
directory; its path is retained in the run invocation. `CheckClaudeSettings`
still checks the effective file before execution.
Consequently, the rest of the machine is not protected by a sandbox for these
lanes. The owner chose this composition to preserve the agent's normal abilities
while protecting Laneboss's files; it does not provide a worktree boundary or
limit reads, networking, package managers, Git, temporary files or caches.

The replacement is configuration-owned, selected before dispatch and recorded
in `lane.started`, `lane status` and the run's watch log as:

```text
runner sandbox: replaced by laneboss lane sandbox
```

Full-access Codex arguments remain refused outside that replacement. The
launcher removes conflicting sandbox selectors before rendering one full-access
selector, and checks the exact invocation again before execution. If the wrapper
cannot be prepared after the runner's own sandbox has been disabled, the runner
is not started unconfined. An absent sandbox-exec before planning leaves the
runner's own sandbox unchanged and records an unavailable-wrapper notice.

Linux's requested design is Landlock write protection for Laneboss-owned paths,
stacked with the runner's own Landlock ruleset. **That enforcement is not yet
implemented in this branch.** The current Linux path records an unavailable
notice and starts the original runner. It must not be described as protected.
Landlock exposes additive path-beneath grants, rather than an explicit deny-path
rule. An existing-path complement also affects unrelated future paths beneath
ancestors of the protected set. The exact deny-only policy therefore still needs
a compatible design and real Linux canaries before it can be accepted. The
Linux stack stand-in calls actual Landlock syscalls; a successful stand-in call
alone cannot establish that an outer Laneboss sandbox was applied.

## Protected paths

`internal/lanesandbox` reuses `internal/hookpaths` for org configuration, shared
and level hook/refusal policy, every instance definition, rendered Claude and
Codex hook/configuration files, hook registries and the launcher executable. It
keeps both rendered vendor homes protected, with the exceptions described below.
The set includes the whole org `.laneboss` container, its `instances` directory
and each instance container, including when `org_dir` is outside both launcher
roots. New descendants inherit the container's write denial. Only the selected
instance's named SDK paths are carved out of those container predicates; the
per-run settings overlays remain protected.
It also protects the whole `LANEBOSS_HOME` and `LANEBOSS_STATE_HOME` trees, including
other configurations, plus an explicitly relocated configuration/state directory.
Both roots must be nonempty existing directories that resolve successfully;
otherwise preparation returns false and the full-access runner is not started.
Existing aliases are resolved without widening a missing leaf to its ancestor.

Required data paths beneath the selected vendor home receive explicit write
allow rules: session, log, temporary/cache and known SDK state/authentication
files. Directory exceptions permit descendants; file exceptions match only
their exact names. The root deny predicates exclude only those named paths,
followed by explicit allow rules. They never grant a whole vendor home or another
configuration's directory. An exception that resolves outside the selected
vendor home, exposes a launcher root, or overlaps a protected policy input
refuses preparation. Explicit extra denials also suppress conflicting allows.
The selected home must be an ordinary rendered vendor directory of an instance
in the configured org; values elsewhere in the runner's arguments do not select
homes or providers.

`[lanes] sandbox_deny_extra` adds explicitly configured absolute paths. Its
absence adds nothing. A configured extra such as the user's home deliberately
broadens the write-denied set and can prevent ordinary work; the proof sheet uses
that setting as the broad-deny negative control. It changes no read or network
permission. Root paths and unresolved protected links cannot generate a policy.

The separate service integration can supply
`Configuration.ServiceSocketDir`. File-write denials protect that directory
while leaving connection operations allowed. The current 0.7.0 launcher has no
service location to supply, so joining that integration remains required. The
service's own OS user protects its identity records through ordinary ownership;
that is separate from the process sandbox and does not replace option A.

## Verification and limits

The owner runs [the Darwin Terminal sheet](darwin-sandbox-owner-sheet.md) at
08:00, with stand-in runners and a temporary HOME, Laneboss homes, org, repository
and claims registry. Agents do not run those rows on this Mac. The rows require
actual protected-write denials, successful Go build/test, a real worktree Git
commit, temporary/cache and SDK session writes, local curl, and the runner's own
sandbox being off. The other-configuration row checks both launcher roots, and
an empty-root mutation must stop the full-access runner before execution. The
dropped-denials, broad-home and dropped-home mutants must fail their respective
checks for the correct reason, with actual bytes and denial errno retained.

The previous sandbox_apply refusal did not enter the runner and was not a
passing enforcement canary. Profile-generation unit tests and static analysis
are not runtime enforcement evidence. The current option A rows and Linux rows
remain unexecuted; none is claimed passing. No authenticated AI-service test is
performed by these stand-ins.

On an authorized existing Linux box, acceptance still requires Go build/test,
npm install, pip install --user, Git commit/branch/worktree, /tmp and ~/.cache
writes, tmux new-session and local curl from the actual outer sandbox, plus
protected writes, both mutants and a successful nested landlock_restrict_self.
No test box may be launched by this lane. Preserve input bytes, executed binary
bytes and hashes, outputs, exits and state with each phase's evidence.

The sandbox belongs to the runner's process tree. Already-running external
processes and services do not enter it; do not infer account-wide integrity
from one process's profile or from its preparation message.

This same-account path policy is not inode isolation. A hard link to a protected
file through a writable path on the same volume can refer to the same inode;
the deny list does not provide an anti-hard-link boundary. Read access and
ordinary linking remain available under option A. This residual applies to
policy, state, settings and executable files even with container coverage.

On a case-insensitive filesystem, literal-only leaves can have alternate
spellings. An external org's `org.toml` and `instance.toml` previously lacked
covering container denials; changing their leaf case or renaming an unprotected
container was a suspected alternate path or relocation/availability risk in
the static review. The new container subpaths cover those leaves under the
matched parent and deny renaming the containers themselves. This does not turn
SBPL into an inode-based boundary: literal-only executable/extra-file paths,
alternate ancestor spellings and same-account services remain residual concerns.
No exploit canary for these residuals has run in this lane. Review policy and
the separate service's OS ownership remain necessary for stronger isolation.
