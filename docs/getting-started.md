# Getting started with Laneboss

## Quick start

After installing the launcher, put `claudock`, `claude` or `codex` on `PATH`
and use an unbound shell. Point init at existing Git working repositories:

```console
laneboss init myorg --project ~/code/a --project ~/code/b
laneboss start --config myorg --role top
```

Init creates `~/.config/laneboss/configs/myorg/` with `config.toml`, one
project TOML per repository and standing rules, plus an L3–L6 org under
`~/.config/laneboss/orgs/myorg/` with its supervisor instances and rendered
hooks. It reports every created path, its chosen runner and the next command.
It chooses the first executable on `PATH` in this order: `claudock`, `claude`,
`codex`. Existing configurations and orgs are preserved. Init starts no agent,
contacts no service and writes no account names or secret values. `start`
prints the supervisor briefing. For Claudock, the owner supplies their profile
names in `runners.claudock.accounts` before dispatching a real lane.

## What init does, step by step

Use `--runner` to select one explicitly and `--top-level 6` to use L6 instead
of the default L5. Top levels are 5 and 6, matching project landing authority.
Project names come from repository directory names and follow the configuration
name rule. Repeated repositories or names are refused.

Existing configurations and orgs are preserved: repeating init refuses to
overwrite them. Files are staged, validated and rendered for their final
location before publication; an ordinary failure rolls back both destinations.
Init honors `LANEBOSS_HOME`, `LANEBOSS_STATE_HOME` and an existing session
binding. Run it from a separate unbound shell when creating another scope.
The two publication renames are separate operations; interruption by a process
kill or power loss can require inspecting the destinations before retrying.

The initial model routes use `claude-sonnet-5-5` for Claude/Claudock and
`gpt-6.1-sol` for Codex; review the routes and instance policy for your setup.
Codex starts with its generated hook home; its resume template is not supplied
because this version does not establish a Codex conversation identifier.
The printed `start` command reads the supervisor briefing; it starts no AI
session. Use `config validate myorg`, `org validate` on the printed org path,
and `doctor --config myorg` to inspect prerequisites before dispatching work.

The walkthrough below explains the configuration, project, org and briefing
steps separately. Its runner is a credential-free stand-in; init instead
selects an installed real runner and leaves authentication to the owner.

This walkthrough is for a person and their agent using the Go launcher
(Laneboss `0.7.0`, embedded protocol `1.3.0`). It installs the
launcher, defines a supervisor, runs and resumes a lane, verifies its result,
records a decision and collects its worktree. It also creates an org and shows
the dashboard available in this version.

The release one-liner, `curl -fsSL https://raw.githubusercontent.com/laneboss-io/laneboss/main/install.sh | sh`,
installs both Laneboss and checksum-verified claudock-cli `0.1.0`, without Go. Pass `--without-claudock`
after `sh -s --` for Codex-only use. An existing matching claudock is kept; a different version requires
`--upgrade-claudock`. [install.md](install.md) covers these options and fresh-box release verification.
The shell blocks below check the lower-level Laneboss source installer and its stand-in runner;
they do not test the release downloader or install claudock-cli.

All walkthrough commands work on Linux and macOS. Use a POSIX shell, Git, tmux,
Go and jq on `PATH`. Go must be able to obtain the pinned Go 1.26.0 toolchain and
the modules in `go.mod` and `go.sum`, or have them cached. jq is a walkthrough
verification tool; the installed launcher itself is one Go binary with SQLite
included. Obtain a checkout or source archive of this version and run the blocks
below from its repository root, in order, in the same shell.

The first lane uses the shipped **example-agent**. It reads a real rendered
brief and exits; it does not call an AI service. This lets you check the launcher
without signing in, sending credentials or spending on model requests. The
[real-agent setup](#use-a-real-agent) covers Claude Code, Codex and
**claudock-cli**. The installer includes claudock-cli by default, and it is the
recommended setup for Claude users. It is optional: direct Claude Code and
Codex runners are alternatives, and Codex users can install with
`--without-claudock`.

Every command below must exit 0. The `jq -e` assertions print `true`; a false,
missing or malformed result exits nonzero. Other checks are silent on success.
The commands save full output before inspecting it, so a failed launcher exit
cannot be hidden by a successful pipe. Paths, ids, timestamps, hashes and byte
counts vary; the assertions check the stable fields and the paths created by
this run. Stop at the first failed command and use the failure table below.

## 1. Prepare an empty demonstration

Use an unbound shell and an unused configuration name. These checks stop before
touching an existing `example` configuration. A supervised session already bound
to another configuration should use the isolated checker described at the end;
it should keep its existing binding.

```sh
set -eu
test -z "${LANEBOSS_CONFIG:-}"
test -z "${LANEBOSS_HOME:-}"
test -z "${LANEBOSS_STATE_HOME:-}"
test ! -e "$HOME/.config/laneboss/configs/example"
test ! -e /var/run/laneboss/example
bootstrap=$(mktemp -d "${TMPDIR:-/tmp}/lb-docs-bootstrap.XXXXXX")
bootstrap=$(CDPATH= cd -- "$bootstrap" && pwd -P)
export PATH="$HOME/.local/bin:$PATH"
test -f go.mod
test -f cmd/laneboss/main.go
```

Expected: no output, exit 0. `bootstrap` names a new private scratch directory.
The checks inspect whether variables are set without printing their values.

## 2. Install and check the version

```sh
sh scripts/install.sh > "$bootstrap/install.json"
jq -e '.installed == "0.7.0" and
       (.directory | type == "string") and (.link | type == "string")' \
    "$bootstrap/install.json"
laneboss --version > "$bootstrap/version.json"
jq -e '.program == "laneboss" and .version == "0.7.0" and
       .protocol_version == "1.3.0"' "$bootstrap/version.json"
```

Expected: two `true` lines. The installer may report Go downloads on stderr.
It installs under `~/.local`, without administrator rights, and saves a JSON
result with `installed`, `directory` and `link`. The version result contains
`program`, `version` and `protocol_version`. Installation, immutable versions,
alternative prefixes and the plugin are explained in [install.md](install.md).

Check the command surface you will use:

```sh
laneboss lane start --help > "$bootstrap/help-start.txt"
laneboss lane resume --help > "$bootstrap/help-resume.txt"
laneboss lane mark --help > "$bootstrap/help-mark.txt"
laneboss lane clean --help > "$bootstrap/help-clean.txt"
grep -Fq -- '--brief' "$bootstrap/help-start.txt"
grep -Fq -- '--difficulty' "$bootstrap/help-start.txt"
grep -Fq -- '--message' "$bootstrap/help-resume.txt"
grep -Fq -- '--state' "$bootstrap/help-mark.txt"
grep -Fq -- '--lane' "$bootstrap/help-clean.txt"
```

Expected: no output, exit 0; the saved help files list those options. A different
version or a missing option means the binary and this guide do not match.

## 3. Create the first configuration and project

A configuration is the launcher's named scope: its runners, projects, rules and
event store. A project identifies a repository inside that scope. Copy the
invented example and install its stand-in runner:

```sh
mkdir -p "$HOME/.config/laneboss/configs" "$HOME/.local/bin"
cp -R examples/minimal "$HOME/.config/laneboss/configs/example"
cp examples/minimal/bin/example-agent "$HOME/.local/bin/example-agent"
chmod 755 "$HOME/.local/bin/example-agent"
laneboss org init "$bootstrap/roles-org" --levels 3 --name bootstrap-roles \
    > "$bootstrap/roles-org-init.json"
jq -e '.ok == true and .changed > 0' "$bootstrap/roles-org-init.json"
laneboss org roles init "$bootstrap/roles-org" > "$bootstrap/roles-library-init.json"
jq -e '.ok == true and .changed > 0' "$bootstrap/roles-library-init.json"
cp examples/bootstrap/drivers.toml "$bootstrap/roles-org/.laneboss/L3/roles/executor.toml"
jq -Rrs --arg org "$bootstrap/roles-org" \
    'gsub("\"@ORG_DIR@\""; ($org | tojson))' \
    examples/bootstrap/org-binding.toml.in > "$bootstrap/org-binding.toml"
cat "$bootstrap/org-binding.toml" examples/minimal/config.toml \
    > "$HOME/.config/laneboss/configs/example/config.toml"
laneboss config validate example > "$bootstrap/config-valid.json"
jq -e '.valid == true and .configs == ["example"]' \
    "$bootstrap/config-valid.json"
```

Expected: three `true` lines. Explicit role installation supplies editable library sources, and the kept
driver source explicitly permits `example-agent` for its L3 executor role.
The binding template selects that org without adding a lane-supplied policy path.
Validation reads `config.toml`, the project TOML files, listed rules and org roles;
it does not launch a runner. The example's secret names and
cloud settings are invented data. This walkthrough neither needs a secret nor
launches a cloud machine; test-machine and cost fields are not automation in
this version.

Create a disposable Git repository with one empty commit. This commit is only
in the demonstration repository, not in the Laneboss checkout. The project
template comes from a file; only its repository path is substituted.

```sh
git init -q "$bootstrap/repo"
git -C "$bootstrap/repo" -c user.name=demo -c user.email=demo \
    -c commit.gpgsign=false commit -q --allow-empty -m bootstrap
example_config="$HOME/.config/laneboss/configs/example"
jq -Rrs --arg repository "$bootstrap/repo" \
    'gsub("\"@REPOSITORY@\""; ($repository | tojson))' \
    examples/bootstrap/project.toml.in \
    > "$example_config/projects/demo.toml"
laneboss config validate example > "$bootstrap/project-valid.json"
jq -e '.valid == true and .configs == ["example"]' \
    "$bootstrap/project-valid.json"
laneboss config path example > "$bootstrap/paths.json"
state_dir=$(jq -er '.state_dir' "$bootstrap/paths.json")
jq -e --arg expected "$HOME/.config/laneboss/configs/example" \
    '.name == "example" and .config_dir == $expected and
     (.store | type == "string") and (.socket | type == "string")' \
    "$bootstrap/paths.json"
```

Expected: two `true` lines; Git and the template substitution are silent.
`demo.toml` has `schema_version = 1`, `name = "demo"`, an absolute `repository`,
`workers = ["agent"]` and `landing_authority = "top"`. `config path` supplies the
actual state directory, store and tmux socket. With the default homes, state is
under `~/.local/state/laneboss/example/`. Keep using `--config example` explicitly
on every state command. See [configuration.md](configuration.md) for the schema.

Check the environment before starting a lane:

```sh
laneboss doctor --config example > "$bootstrap/doctor.jsonl"
jq -es 'length > 0 and all(.[]; .ok == true) and
        any(.[]; .check == "tool.git") and
        any(.[]; .check == "tool.tmux") and
        any(.[]; .check == "runner.agent")' "$bootstrap/doctor.jsonl"
```

Expected: `true`. `doctor` emits one JSON object per check, including `check`,
`ok` and `detail`. It actually checks state writes and a scratch-store round
trip, and finds configured programs on `PATH`; it does not invoke those programs.
Its exit is 1 if any check fails. Read the failed check's `detail` and repair
that prerequisite before proceeding.

## 4. Read the first supervisor's briefing

The copied configuration already defines `[supervisors.top]`: level 5, runner
`agent`, and project `web`. Here, `top` is a role name; its level is L5. Read its
briefing in human and machine forms:

```sh
laneboss start --config example --role top > "$bootstrap/supervisor.md" 2> "$bootstrap/registration-notice.txt"
grep -Fxq 'notice: no identity service is configured; R25 is not enforced (legacy open registration).' "$bootstrap/registration-notice.txt"
test "$(wc -l < "$bootstrap/registration-notice.txt")" -eq 1
grep -Fxq '# Laneboss session briefing' "$bootstrap/supervisor.md"
grep -Fxq -- '- Role: top' "$bootstrap/supervisor.md"
grep -Fxq -- '- Level: L5 (top supervisor)' "$bootstrap/supervisor.md"
laneboss start --config example --role top --format json \
    > "$bootstrap/supervisor.json"
jq -e '.configuration.name == "example" and .role.selected == "top" and
       .role.entry.level == 5 and .role.entry.runner == "agent" and
       .protocol.version == "1.3.0" and .lanes.running == [] and
       .configuration.warnings == [] and
       all(.checks.read[]; .ok == true)' "$bootstrap/supervisor.json"
```

Expected: `true`. The Markdown begins `# Laneboss session briefing` and includes
configuration, protocol, standing rules, role, checks, lanes and recent events.
Give that saved file to your supervisor session and have it read the entire
briefing before dispatching work. `laneboss start` is a read-only briefing
command: it does not start an AI session, create lanes or append events. The
supervisor is the person or existing agent session that reads it and issues the
following lane commands. The role's `projects` describe briefing context; they
do not restrict the supervisor to that project when it launches this demo.

## 5. Start the first lane and read its result

```sh
laneboss lane start --config example --project demo --lane demo-first \
    --brief examples/bootstrap/brief.md --role executor --level 3 --difficulty standard --budget 1 \
    > "$bootstrap/start.json"
jq -e --arg worktree "$bootstrap/repo-demo-first" \
    '.lane == "demo-first" and .run == 1 and .how == "start" and
     .runner == "agent" and .model == "example-model-medium-1" and
     .role == "executor" and .role_context.level == 3 and
     .effort == "high" and .account == "example-main" and
     .branch == "demo-first" and .worktree == $worktree and
     (.brief.path | type == "string") and (.event.seq > 0)' \
    "$bootstrap/start.json"
laneboss event tail --config example --lane demo-first --follow \
    --until lane.ended > "$bootstrap/events-1.jsonl"
jq -es 'any(.[]; .kind == "lane.started" and .payload.run == 1) and
        any(.[]; .kind == "lane.ended" and .payload.run == 1 and
            .payload.reason == "exit" and .payload.exit_code == 0 and
            .payload.survivors == 0)' "$bootstrap/events-1.jsonl"
```

Expected: two `true` lines. `lane start` returns after the run has started in
tmux; it does not wait for completion. It renders and keeps the brief, selects
the standard route, creates branch `demo-first` and worktree
`$bootstrap/repo-demo-first`, and records the start and the selected role's source
hashes. Shared and level policy and the executor template precede the original
task in the rendered brief. `event tail` prints one event
per line and stops only after seeing `lane.ended`; check the event's exit code,
reason and survivor count, not just the tail command's exit 0.

The end event can arrive just before the supervising process exits. Before
resume or collection, wait for both the recorded outcome and live processes to
settle. Define this bounded helper once; it is used for both runs:

```sh
wait_for_demo() {
    demo_run=$1
    demo_status=$2
    demo_attempt=0
    while :; do
        laneboss lane status --config example --lane demo-first > "$demo_status"
        jq -e --argjson run "$demo_run" \
            '.lane == "demo-first" and .run == $run and
             .state == "verifying" and .running == false and
             .reason == "exit" and .exit_code == 0 and .cleaned == false and
             .live.pending_events == 0 and .live.refused_events == 0 and
             .live.survivors == 0' "$demo_status" > /dev/null
        demo_quiet=$(jq -er \
            '(.live.supervisor.alive == false and .live.session_alive == false)
             | tostring' "$demo_status")
        if [ "$demo_quiet" = true ]; then
            break
        fi
        demo_attempt=$((demo_attempt + 1))
        if [ "$demo_attempt" -ge 60 ]; then
            echo 'FAIL: the demonstration supervisor did not exit' >&2
            exit 1
        fi
        sleep 1
    done
    jq -e '.running == false and .live.supervisor.alive == false and
           .live.session_alive == false' "$demo_status"
}
wait_for_demo 1 "$bootstrap/status-1.json"
cat "$state_dir/lanes/demo-first/output.log"
grep -Fxq '# Bootstrap lane' "$state_dir/lanes/demo-first/output.log"
grep -Fq 'example-agent: run in ' "$state_dir/lanes/demo-first/output.log"
grep -Fq 'example-agent: read ' "$state_dir/lanes/demo-first/output.log"
grep -Fxq 'example-agent: done' "$state_dir/lanes/demo-first/output.log"
```

Expected: `true`, then these four log lines, with varying paths and byte count:

```text
example-agent: run in <the demo-first worktree>
example-agent: read <byte count> bytes from <the kept rendered brief>
# Bootstrap lane
example-agent: done
```

The saved status is one JSON object, with `state: "verifying"`, `run: 1`,
`running: false`, `exit_code: 0`, and zero survivors and pending/refused events.
The final assertions also require the supervising process and tmux session to
be gone. Output is at `STATE_DIR/lanes/LANE/output.log`; diagnostic messages from
the supervising process are in `watch.log`. A successful runner exit is evidence
to review, not automatic acceptance of real work.

## 6. Resume before cleaning

```sh
resume_since=$(jq -er '.last_seq' "$bootstrap/status-1.json")
laneboss lane resume --config example --lane demo-first \
    --message examples/bootstrap/follow-up.md --budget 1 \
    > "$bootstrap/resume.json"
jq -e --arg worktree "$bootstrap/repo-demo-first" \
    '.lane == "demo-first" and .run == 2 and .how == "resume" and
     .worktree == $worktree and .branch == "demo-first" and
     (.resumed.seq > 0)' "$bootstrap/resume.json"
laneboss event tail --config example --lane demo-first --since "$resume_since" \
    --follow --until lane.ended > "$bootstrap/events-2.jsonl"
jq -es 'any(.[]; .kind == "lane.resumed" and .payload.run == 2) and
        any(.[]; .kind == "lane.ended" and .payload.run == 2 and
            .payload.reason == "exit" and .payload.exit_code == 0 and
            .payload.survivors == 0) and
        all(.[]; .kind != "lane.ended" or .payload.run == 2)' \
    "$bootstrap/events-2.jsonl"
wait_for_demo 2 "$bootstrap/status-2.json"
grep -Fq 'example-agent: resume in ' "$state_dir/lanes/demo-first/output.log"
grep -Fxq '# Continue the bootstrap lane' "$state_dir/lanes/demo-first/output.log"
```

Expected: three `true` lines. Resume adds `lane.resumed`, starts run 2 in the
same directory and appends output to the same log. `--since` is essential:
without it, tail can replay run 1's end and return before run 2 ends. The runner
must have a `resume` template; this example's template reads `{message}`.

Resume requires an ended run, no surviving processes, the original directory
and its valid claim, and an uncleaned lane. For real session continuation, the
runner must preserve its own conversation; the launcher cannot reconstruct it.
Turn-based lanes use mail and turns instead; they are outside this walkthrough.

## 7. Review, mark and clean

For this demo, verify the two input headings and the two successful runs above,
then record acceptance. For real work, also inspect the worktree diff and run
the checks the brief requires in its named environment before accepting it.

```sh
laneboss lane mark --config example --lane demo-first --state accepted \
    > "$bootstrap/accepted.json"
jq -e '.lane == "demo-first" and .kind == "lane.state" and
       .state == "accepted" and .scan.not_covered == [] and
       .scan.appended.refusals == 0 and .scan.appended.suspicions == 0' \
    "$bootstrap/accepted.json"
laneboss start --config example --role top --format json \
    > "$bootstrap/accepted-dashboard.json"
jq -e '.lanes.running == [] and .lanes.ended == [] and
       (.lanes.accepted | length) == 1 and
       .lanes.accepted[0].lane == "demo-first" and
       .lanes.accepted[0].state == "accepted"' "$bootstrap/accepted-dashboard.json"
laneboss lane mark --config example --lane demo-first --state merged \
    > "$bootstrap/merged.json"
jq -e '.kind == "lane.state" and .state == "merged" and
       .scan.not_covered == []' "$bootstrap/merged.json"
laneboss lane clean --config example --lane demo-first > "$bootstrap/clean.json"
jq -e '.lane == "demo-first" and .pending == false and
       ([.removed[].item] | sort) == ["branch", "worktree"] and
       any(.kept[]; .item == "lane-directory" and .why == "record")' \
    "$bootstrap/clean.json"
test ! -e "$bootstrap/repo-demo-first"
demo_branch=$(git -C "$bootstrap/repo" branch --list demo-first)
test -z "$demo_branch"
laneboss lane status --config example --lane demo-first \
    > "$bootstrap/cleaned-status.json"
jq -e '.state == "merged" and .run == 2 and .running == false and
       .cleaned == true' "$bootstrap/cleaned-status.json"
test -s "$state_dir/lanes/demo-first/output.log"
laneboss state verify --config example > "$bootstrap/verified.json"
jq -e '.ok == true and .exists == true and .config == "example" and
       .lanes == 1 and .events > 0' "$bootstrap/verified.json"
```

Expected: six `true` lines. Marking `merged` records a supervisor decision; it
does **not** run Git merge or deploy. This demo branch has no new commits, so it
is already contained in its base. The example guard scan covers the recorded
text log; unreviewed suspected workarounds or uncovered records would prevent
acceptance. Do not add `--accept-uncovered` just to make a failed check pass.

Clean requires a stopped lane marked `merged` or `abandoned` and first runs the
same verified archival path as `lane archive`: report/log records, tar, manifest
read-back and receipt must succeed before collection. Its existing result fields
remain, with archive/manifest/receipt paths and verification details added.
If the event store is temporarily read-only, clean still finishes the verified
file-backed archive and returns `pending: true`: its verification/index/cleanup
events wait durably in the lane queue. After writes are restored, `lane start
--reuse` drains them before recording the next start. Archive failures still
prevent removal.
It removes a clean launcher-created worktree without force and deletes a merged
branch when Git agrees it is merged. An abandoned branch is retained. With an
existing directory supplied by `--worktree`, clean retains that directory. It
also finishes when a managed worktree is already absent, off its recorded branch
or without this lane's valid claim: the tar contains the report/logs, the worktree
is kept with `missing` or `not-this-lane`, and nothing in that directory is removed.
A symlink at the worktree path still refuses clean. A lane caller may collect
lower-level lanes only when their recorded starter chain reaches the same
caller life. Each parent's start/adoption event must precede its child; reusing
a name does not transfer its old life's children to the new life. Unrelated
supervisor subtrees and human-started lanes do not become its descendants.
Clean keeps events, inputs, rendered briefs and raw runner records such as `output.log`;
diagnostic logs are collected only after archival. A cleaned lane cannot resume: create new work with a
new lane name, or explicitly reuse a finished lane by adding `--reuse` to a
complete `laneboss lane start` command.
The checker retains this demonstration's files as evidence rather than deleting
configuration or history.

## 8. Create an org and understand its levels

An org is a folder of shared policy sources and agent instances. The org-tree
commands take that folder explicitly; they do not automatically bind the named
configuration above or launch its supervisor/lanes. Create a separate empty org:

```sh
laneboss org init "$bootstrap/org" --levels 3-6 --name bootstrap \
    > "$bootstrap/org-init.json"
jq -e '.ok == true and .changed > 0' "$bootstrap/org-init.json"
laneboss org instance add "$bootstrap/org" L3-review --level 3 --role reviewer \
    > "$bootstrap/org-add.json"
jq -e '.ok == true and .changed > 0' "$bootstrap/org-add.json"
laneboss org render "$bootstrap/org" > "$bootstrap/org-render.json"
jq -e '.ok == true and .changed == 0' "$bootstrap/org-render.json"
laneboss org validate "$bootstrap/org" --format json \
    > "$bootstrap/org-valid.json"
jq -e '.valid == true and .problems == []' "$bootstrap/org-valid.json"
test -s "$bootstrap/org/AGENTS.md"
test -s "$bootstrap/org/CLAUDE.md"
test -f "$bootstrap/org/.laneboss/instances/L5-top/instance.toml"
test -f "$bootstrap/org/.laneboss/instances/L3-review/instance.toml"
```

Expected: four `true` lines. Init creates `.laneboss/`, shared protocol sources,
L3–L6 policy directories and example instances `L3-lane-example`, `L4-stream`,
`L5-top` and `L6-super-top`, plus `worktrees/` and generated root rules. Adding
`L3-review` creates its identity and state and renders its rules; it starts no
review session. Rendering unchanged sources returns `changed: 0`. Validation
checks schemas, rendered rules, hooks and owner-channel data without signing in
or contacting an owner. The template's `keychain` secret-store setting is
metadata here; no Keychain operation is needed on Linux. For a real Linux secret
store, use the supported `file` kind with an absolute path outside the org; the
store must be supplied separately. Never put secret values in org files.

The only seeded hook policy is the twelve Laneboss-first blacklist entries in
`org.toml`. Init writes no shared or level `hooks/rules.toml`, refusal catalog,
starter examples or tool allowlist field. Add your own entries during bootstrap
using [org-hooks.md](org-hooks.md#bootstrap-add-your-own-entries). Laneboss-file
protections, including the decision store and `shared/services/`, and L3 lane
boundaries are built in and remain active without those optional files.

### Levels

| Level | Responsibility described by the template |
|---|---|
| L6, super top | Sets org policy and gives top supervisors outcomes. |
| L5, top supervisor | Coordinates a domain, resolves reversible decisions and escalates owner decisions. |
| L4, mini-supervisor | Divides a stream into lanes, checks evidence and reports to a top supervisor. |
| L3, executor or reviewer | Carries out one brief and reports evidence to its supervising stream. |
| L2 and L1 | Reserved; the launcher does not manage these levels. |

The intended reporting line is owner → L6 → L5 → L4 → L3, with results and
escalations flowing back up. **Today this is policy text**, level numbers and
roles, not an enforced parent-child graph. Neither the org nor instance schema
has a `reports_to` key, and no CLI command assigns a lane to an org instance.
The named configuration validates supervisor levels 4–6 and a project's
`landing_authority` as an L5/L6 supervisor. Those checks do not grant Git merge
permission or automatically route reports. Only L5/L6 org instances can register
owner Discord channels; this tutorial creates no channel and sends no message.

Edit `.laneboss/shared/protocol/rules.md`, the relevant
`.laneboss/L<N>/protocol/role.md`, or an instance's `state/notes.md`, then render.
Do not edit generated `AGENTS.md`, `CLAUDE.md`, the render manifest, or generated
hook settings. The Go executable supplies the shared hook. Org-instance runner
checks at lane start/resume, automatic report delivery, and the owner-channel
gateway remain planned. [org.md](org.md) describes the tree, and
[org-hooks.md](org-hooks.md) describes hook policy and refusal handling.

The earlier demo configuration selects its small `roles-org` with `org_dir`.
The separate org in this section demonstrates all levels and instances. For real
lanes, choose an org-owned role explicitly and ensure its driver file permits
the real runner; replacing the stand-in runner also requires reviewing that
role's driver list. [org.md](org.md#role-library-and-lane-roles) explains migration,
human principals and the per-role driver gate.

## 9. Read the dashboard

The available dashboard is the supervisor's **CLI briefing**, with a machine
readable equivalent. This tree has no web dashboard command or listening port;
a web dashboard and automatic reporting are future work, not installation
steps. Refresh the briefing after the lane is collected:

```sh
laneboss start --config example --role top > "$bootstrap/dashboard.md"
grep -Fxq 'Running (0):' "$bootstrap/dashboard.md"
grep -Fxq 'Ended, waiting for the supervisor (0):' "$bootstrap/dashboard.md"
grep -Fxq 'Accepted or merged, not yet cleaned (0):' "$bootstrap/dashboard.md"
grep -Fxq 'Lanes in none of these groups (queued, merged or abandoned): 1' \
    "$bootstrap/dashboard.md"
laneboss start --config example --role top --format json \
    > "$bootstrap/dashboard.json"
jq -e '.lanes.running == [] and .lanes.ended == [] and
       .lanes.accepted == [] and .lanes.lost == [] and .lanes.idle == [] and
       .lanes.others == 1 and .lanes.pending_events == 0 and
       .lanes.refused_events == 0 and
       any(.events.recent[]; .kind == "lane.cleaned") and
       .configuration.warnings == [] and
       all(.checks.read[]; .ok == true)' "$bootstrap/dashboard.json"
```

Expected: `true`. The Markdown has all three groups at 0 and one lane outside
them: the cleaned `merged` record. Read `dashboard.md` for the human view and
`dashboard.json` for exact counts. `start` checks the recorded state but omits
the writing probes that `doctor` performs. Its exit 0 alone is insufficient:
check warnings and each `checks.read[].ok` as above.

With no identity service configured, the role commands above deliberately use the
0.7.0 open-registration bootstrap and emit the R25-not-enforced notice. The checker
asserts that notice once and requires no installed system binding for `example`.
For a configured service, the human first issues a ticket at its attested terminal;
the persistent supervisor presents it with `--ticket-file PATH`. Keep that file
outside prompts and repositories. See [configuration.md](configuration.md) for
service setup and legacy activation.

## Use a real agent

After the smoke test, choose a runner for your agent program. Laneboss can run
Claude Code or Codex directly. The installer includes
[claudock-cli](https://github.com/laneboss-io/claudock-cli) by default; it is the
recommended setup for Claude users, especially for several Claude accounts and
per-lane account selection. The wrapper is optional. Codex users can install
with `--without-claudock` and use a direct Codex runner.
If you used only the source walkthrough, install claudock-cli using
[claudock.md](claudock.md#portable-cli-setup).

Install and configure your chosen agent program using its own instructions.
The owner signs in outside the public checkout. Authentication, billing and
real model execution are a separate live setup, not part of the
credential-free bootstrap check.

Choose **one** of the following TOML fragments to replace the stand-in runner's
`command`, `resume` and `accounts` in your private configuration. Each uses
`[runners.agent]`, so the example's supervisor and project entries still name
the same runner.

### Claude Code directly (alternative)

Use `claude` on `PATH` with the owner's existing Claude Code authentication:

```toml
[runners.agent]
command = ["claude", "-p", "--session-id", "{session}",
           "Read the file {brief} completely and carry out the task it describes.",
           "--model", "{model}"]
resume = ["claude", "-p", "--resume", "{session}",
          "Read the file {message} completely and carry on from it.",
          "--model", "{model}"]
accounts = []
```

`-p` selects non-interactive execution. `{session}` establishes one identity
with `--session-id` on start and reuses it with `--resume`. No wrapper profile
is selected by this fragment.

### Codex directly (alternative)

Use `codex` on `PATH` with the owner's existing Codex authentication:

```toml
[runners.agent]
command = ["codex", "--model", "{model}", "exec",
           "Read the file {brief} completely and carry out the task it describes."]
resume = ["codex", "--model", "{model}", "exec", "resume", "--last",
          "Read the file {message} completely and carry on from it."]
accounts = []
```

This follows the repository's `codex exec resume --last` runner example.
Codex chooses its own session identity; this fragment omits `{session}` from
both templates. `--last` resumes the most recent Codex conversation in the
lane's working directory. Keep that directory dedicated to this lane and do
not start another Codex conversation there before resuming. This fragment
serves ordinary lanes; it cannot be used with `--turns`, which requires
`{session}` in both templates and a prompt on standard input.

<a id="use-claudock-cli-for-a-real-agent"></a>

### claudock-cli (recommended for Claude users)

claudock-cli is optional and included by default by the Laneboss installer.
Use it for several Claude accounts and per-lane account selection. The portable
executable is `claudock` on `PATH` on Linux and macOS; no desktop application
is required. The owner chooses and signs in to a profile outside the public
checkout. The following fragment uses the invented subscription profile name
`tutorial`; replace it with your own profile name:

```toml
[runners.agent]
command = ["claudock", "run", "{account}", "--", "-p", "--session-id", "{session}",
           "Read the file {brief} completely and carry out the task it describes.",
           "--model", "{model}"]
resume = ["claudock", "run", "{account}", "--", "-p", "--resume", "{session}",
          "Read the file {message} completely and carry on from it.",
          "--model", "{model}"]
accounts = ["tutorial"]
```

The profile selector fills `{account}`, and `--` separates Claudock arguments
from Claude Code arguments. `{session}` establishes one identity on start and
reuses that exact identity on resume.

### Validate the chosen runner

These fragments belong in a private configuration, not in the public source
tree. Keep its rule files, supervisor entries and routing, but replace the
invented `example-model-*` routes with **full model names supported by your
agent program**. In every fragment, `{brief}` and `{message}` name kept files;
they do not embed their document contents in an argument.

If you retain `records = [{format = "text", paths = ["{log}"]}]` from the demo,
the scan covers only stdout/stderr. Configure the real runner's raw session
records and your actual guards before treating that as tool-call coverage;
[configuration.md](configuration.md) defines the supported record formats.
The hook settings generated for an org instance must also be loaded explicitly
when starting that instance's agent. Merely naming a configuration runner does
not attach the org instance or its hooks.

Validate the edited configuration and rerun doctor using the same operations
as step 3, then read the supervisor briefing and start a **new lane name** with
the same operations as steps 4–5. Expected: configuration validation is true,
`runner.agent` finds `claude`, `codex` or `claudock`, according to the chosen
fragment, and the start result records the real model. The Claude Code and
claudock fragments also record a session identity; the claudock fragment records
the selected profile. Doctor checks executable availability; it does not prove
sign-in, quota or a successful model request. The real end event and work must
be checked independently. A vendor refusal stops the action; retain its exact
message and follow its stated recovery path.

For profile setup, CLI build commands, sign-in and expected results, use
[claudock.md](claudock.md#portable-cli-setup). No live profile operation is run by
the checker in this guide, and it makes no authenticated-service claim.

### Direct Claude and Codex runners

You can also use Claude Code directly, with its own authenticated account:

```toml
[runners.claude]
command = ["claude", "-p", "--session-id", "{session}", "--model", "{model}",
           "Read the file {brief} completely and carry out the task it describes."]
resume = ["claude", "-p", "--resume", "{session}", "--model", "{model}",
          "Read the file {message} completely and carry on from it."]
accounts = ["local"]
```

For Codex-only use, install with `--without-claudock` and configure the direct CLI:

```toml
[runners.codex]
command = ["codex", "exec", "--model", "{model}",
           "Read the file {brief} completely and carry out the task it describes."]
resume = ["codex", "exec", "resume", "--last", "--model", "{model}",
          "Read the file {message} completely and carry on from it."]
accounts = ["local"]
```

Here `local` is an invented Laneboss account label; it does not select or authenticate a vendor account.
Install and authenticate the selected vendor CLI separately, choose full supported model names in
routing, and add the selected runner to the project's `workers`. These snippets belong in a private
configuration. Codex chooses its own session identifier: `--last` resumes the latest session for the
same directory, so keep one Codex conversation in that lane's dedicated worktree. This Codex snippet
serves ordinary lanes and does not provide Laneboss's `{session}` identity or turn-based mode.
Configure actual raw records and guards for each runner; the demo text log alone does not cover tool calls.
Validate, run doctor, read the supervisor briefing and start a new lane, as described above.

## When a step fails

| Observation | What to do before continuing |
|---|---|
| A preparation `test` fails | Use a new isolated demonstration. Preserve the existing configuration and active session binding. |
| Installer says Go is missing or a download fails | Install Go or make the pinned toolchain/modules available. A partly installed or mismatched version needs review; do not overwrite an immutable version to suppress the failure. |
| `config validate` exits 2 | Read the named field/path, check TOML types, names and referenced files, then repair only this configuration. Never guess a key or copy credential values into it. |
| Doctor exits 1 | Read every `ok: false` line. Missing `git`, `tmux` or `example-agent` is a prerequisite failure. State/store failures require repair before a launch. |
| `start` has warnings or failed read checks | Treat the dashboard as incomplete and repair the reported isolation, store or program problem. Exit 0 does not override those checks. |
| Lane start returns nonzero | Read stderr and this lane's `watch.log` if created. Do not mark, clean or blindly reuse the lane name. |
| Follow produces no end event | Interrupt the follow with Ctrl-C, inspect `laneboss lane status --config example --lane demo-first`, and reconcile with `laneboss lane check --config example --lane demo-first`. A stopped follow is not evidence that the lane ended. |
| Reason is `timeout`, `limit`, `dropped` or `hook-config`, exit is nonzero, or processes survive | Retain status and output. If this lane must stop, use `laneboss lane stop --config example --lane demo-first`; inspect its returned survivor count. Repair the stated cause before a permitted resume. Do not kill by a command-line pattern. |
| Resume says cleaned, missing directory/claim, or no session/template | Preserve history. A cleaned lane needs a new start; a surviving process needs collection; other problems need their original directory, claim or runner configuration repaired. Do not fabricate session history. |
| Mark refuses uncovered records or suspected workarounds | Read `laneboss lane refusals --config example --lane demo-first` and let the supervisor review the actual records and paths. Do not bypass the gate. |
| Clean refuses dirty work or Git removal | Preserve the worktree and branch, inspect the diff and resolve through the supervisor. Do not force-remove it. |
| State verify exits 3 | Stop state-changing operations and preserve the store and kept inputs for integrity investigation. |
| Any guard or permission layer refuses an action | Stop that action, report the refusal verbatim and take only the explicitly allowed recovery path. |

For these commands, 0 means command success; 1 is doctor's failed-check result;
2 means invalid input or a refusal; 3 means an integrity problem; 70 means an
unexpected internal error. Shell/jq checks may also exit nonzero. Never turn
any of them into a pass by ignoring an exit or replacing measured output.

## Run the walkthrough as an E2E check

On a disposable Linux machine, run `sh docs/check-bootstrap.sh` from this
checkout. To check a supplied build, run `sh docs/check-bootstrap.sh
/absolute/path/to/laneboss`. Both modes run the source installer in an empty
temporary HOME. Supplied-build mode then uses that exact copied binary for all
`laneboss` walkthrough calls and also checks the source-installed binary's
version. It requires the same Git, tmux, Go and jq prerequisites, plus the
Linux `timeout`, `tar` and `sha256sum` utilities.

The script extracts and runs **every shell block above**, in order, with its
exit and output assertions. It creates its own empty environment and retains
the guide, source inputs, tested binary, hashes, transcript and temporary state
outside the checkout. It stops nonzero at the first mismatch or the overall
hang deadline; normal success prints `PASS: getting-started walkthrough`.
The Linux run of this script is the E2E evidence for this tutorial. Reading the
code or checking shell syntax alone is not that evidence. A separate live
agent setup requires owner authentication and is not an AI-service E2E.

An agent should use the matching [repository checklist](../AGENTS.md) and
report the saved output and its remaining limits to its supervisor.
