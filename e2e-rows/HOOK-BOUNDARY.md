# LB-235 hook boundary rows

Run these commands only on the disposable Linux test box. The rows use the
already built CLI and a credential-free stand-in runner. They make one empty
commit in each new disposable Git repository, then let `lane start` create a
separate sibling worktree. The runner's real process record authenticates each
hook command. Push, writes and curl are hook inputs; the fixture does not execute
those requested operations or contact an AI service.

The installed fixture policy refuses push with its recorded `no-push`
description and permits the other inspected calls. This deliberately leaves
the boundary responsible for restricting those calls. Production policies may
be stricter; the fix does not widen their write scopes or change their reasons.
Rule data and instance data are edited, then the real `org render` produces the
generated settings and manifests.

Build the two executables on the box from the repository root:

```sh
GOTOOLCHAIN=go1.26.0 CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -o /tmp/lb-235-hookfix-bin ./cmd/laneboss
GOTOOLCHAIN=go1.26.0 CGO_ENABLED=0 go build -tags laneboss_faults \
  -trimpath -buildvcs=false -o /tmp/lb-235-hookfix-faults ./cmd/laneboss
```

Demonstrate both restoring mutants before running their controls. Use fresh
marker paths. Each row must exit 1 at the named decision assertion, and the
marker must exist. A setup error, cleanup error, timeout, missing marker or an
unrelated assertion is not a mutant kill. Fault requests apply only to the hook
under examination; cleanup uses the ordinary policy.

```sh
LANEBOSS_BIN=/tmp/lb-235-hookfix-faults \
  LANEBOSS_REPORT_MUTANT='orghook-boundary-before-policy' \
  LANEBOSS_REPORT_MARKER='/tmp/lb-235-hookfix-order.marker' \
  python3 e2e-rows/test_orghook_lane_boundary.py \
  OrgHookBoundaryRows.test_installed_push_refusal -v
LANEBOSS_BIN=/tmp/lb-235-hookfix-faults \
  LANEBOSS_REPORT_MUTANT='orghook-boundary-repository-path' \
  LANEBOSS_REPORT_MARKER='/tmp/lb-235-hookfix-worktree.marker' \
  python3 e2e-rows/test_orghook_lane_boundary.py \
  OrgHookBoundaryRows.test_recorded_worktree_write_allowed -v
```

The first mutant restores the boundary before the installed policy. Its row
must fail with `the installed rule must speak before the boundary`, showing
the boundary reason in place of the installed description's `Refuses` and
`Why` lines. The second mutant substitutes the instance's repository path for
the authenticated lane's recorded worktree. Its row must fail with `a recorded
lane worktree write must be allowed`, showing the boundary refusal for an
ordinary write in that separate worktree.

The same two mutants can demonstrate the corresponding Go assertions:

```sh
LANEBOSS_FAULTS='{"point":"orghook-boundary-before-policy","marker":"/tmp/lb-235-hookfix-unit-order.marker"}' \
  GOTOOLCHAIN=go1.26.0 go test -count=1 -tags laneboss_faults \
  -run '^TestInstalledPolicyBeforeLaneBoundary$' ./internal/orghook
LANEBOSS_FAULTS='{"point":"orghook-boundary-repository-path","marker":"/tmp/lb-235-hookfix-unit-worktree.marker"}' \
  GOTOOLCHAIN=go1.26.0 go test -count=1 -tags laneboss_faults \
  -run '^TestLaneHookUsesRecordedWorktree$' ./internal/orghook
```

Without a mutant selector, run the ordinary package checks and CLI rows:

```sh
GOTOOLCHAIN=go1.26.0 go test -count=1 ./internal/orghook ./internal/caller
GOTOOLCHAIN=go1.26.0 go test -count=1 -tags laneboss_faults \
  ./internal/orghook ./internal/caller
LANEBOSS_BIN=/tmp/lb-235-hookfix-bin \
  python3 e2e-rows/test_orghook_lane_boundary.py -v
```

| Row | What makes its assertion fail |
| --- | --- |
| `test_installed_push_refusal` | A push is allowed, or its first two reason lines differ from the installed refusal description. |
| `test_recorded_worktree_write_allowed` | A file-tool or shell write within the recorded worktree is denied, with either the original lane label or no lane label. |
| `test_outside_worktree_write_refused` | A write to the original repository, a sibling sharing the worktree's name prefix, or the org's shared message area is allowed or lacks the complete boundary reason. |
| `test_lane_curl_refused` | Curl is allowed or loses the complete network boundary reason, including to a generic opaque-command error. |
| `test_no_lane_keeps_instance_scope` | The original L3 instance scope changes, or an unproven environment label grants a lane identity. |

Both providers' shell adapters and Claude's file tool and Codex's patch tool
are exercised. Path names vary for each fixture. The Go checks also cover
symlink escapes, shared-message exclusion within a broad recorded root,
missing/closed/malformed lane records and an authenticated live process with
no lane label. All normal rows must pass; the static checks on the Mac do not
constitute runtime or mutant evidence.
