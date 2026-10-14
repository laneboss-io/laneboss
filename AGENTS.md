# Bootstrap checklist for an agent

Use the Go launcher documented in [docs/getting-started.md](docs/getting-started.md):
Laneboss `0.6.0-dev4` at `8408e57`, with embedded protocol `1.3.0`. Read the
active brief and configuration rules completely before acting. This checklist
does not expand the authority granted by that brief.

## Authority and boundaries

- You may inspect the CLI help, source, status, briefing, logs and events within
  the named configuration; create the isolated demo's files; and perform the
  lane operations explicitly authorized by the brief. Run builds and checks in
  the brief's required environment. The walkthrough's sole Git commit is an
  empty commit in its new disposable demo repository.
- Keep an active session bound to one configuration. Pass its name explicitly
  on every state command. Never clear or change a live session's binding to
  make a conflicting command succeed. Use a separate isolated test process for
  the demonstration.
- Use files for briefs, follow-ups and rule sources. Use a file-editing tool for
  authored documents and configuration edits. Preserve exact input bytes and
  the outputs used for verification. Never publish private identifiers or
  secret values, dump the environment, or copy credentials into a checkout or
  test home.
- Do not sign in, select paid services, start real model requests, provision
  machines, send owner messages, merge, deploy, push or commit real work unless
  the user's brief authorizes that operation. CLI availability is not such
  authorization. `lane mark --state merged` records a decision; it performs no
  Git merge or deployment.
- Stop at a failed check. Report a guard refusal verbatim and follow only the
  recovery route it explicitly allows. Do not reword a refused command, add a
  bypass flag, ignore an exit code, fake output or force-remove a worktree.
- Edit org protocol sources and instance notes, then render. Do not hand-edit
  generated rule files, manifests or hook settings. Do not accept your own
  production lane solely because its executor reports success.

## Execute and verify the bootstrap

For the complete credential-free E2E, on the authorized disposable Linux test
machine, run `sh docs/check-bootstrap.sh` from this checkout. With a supplied
build, run `sh docs/check-bootstrap.sh /absolute/path/to/laneboss`. The checker
executes the actual shell blocks in the guide in a temporary HOME and an empty
environment, retains inputs and evidence, and uses the supplied binary for all
walkthrough CLI calls when one is given. Both modes exercise the source
installer. Exit 0 **and** `PASS: getting-started walkthrough` are required.
A nonzero exit, missing pass line or missing evidence is a failed/incomplete
run. Code inspection or shell syntax validation alone is not a passing E2E.

For a manual bootstrap on Linux or macOS, execute the guide's shell blocks in
order in the same unbound shell. They include exact output assertions. All
commands must exit 0; every displayed `jq -e` assertion must print `true`.
Do not pipe a launcher command straight into a parser: first save its output
and check its own exit, then parse the saved file. The guide enables `set -eu`
to enforce that order.

- [ ] **Prepare:** check that `LANEBOSS_CONFIG`, `LANEBOSS_HOME` and
  `LANEBOSS_STATE_HOME` are unset/empty without printing their values, and that
  the default `example` configuration does not exist. Create and physically
  resolve the new scratch directory. An existing binding/configuration means
  use the isolated checker; preserve the existing data.
- [ ] **Install:** run `sh scripts/install.sh`, then `laneboss --version`.
  Verify `install.json.installed` is `0.6.0-dev4`, and that the version result
  says `program: laneboss`, `version: 0.6.0-dev4`, `protocol_version: 1.3.0`.
  Read the saved lane start/resume/mark/clean help and verify the guide's flags.
  Missing Go, unavailable downloads or a version mismatch stops the bootstrap.
- [ ] **Configuration:** copy `examples/minimal` to
  `~/.config/laneboss/configs/example`, put its `bin/example-agent` on `PATH`
  with executable permissions, then run `laneboss config validate example`.
  Require `valid: true` and `configs: [example]`. The invented secret/cloud
  fields are data; supply no credential and launch no test machine from them.
- [ ] **Project:** create `$bootstrap/repo` and its empty initial commit using
  the guide's temporary Git identity. Substitute that absolute path into
  `examples/bootstrap/project.toml.in` and save it as `projects/demo.toml` in
  the copied configuration. Validate again, run `laneboss config path example`,
  and take the state directory and socket from the returned JSON.
- [ ] **Doctor:** run `laneboss doctor --config example`. Require exit 0, at
  least one JSONL result, every `ok` true, and checks for `tool.git`, `tool.tmux`
  and `runner.agent`. Exit 1 means inspect and repair every failed `detail`
  before any lane starts. Doctor checks availability, not login or quota.
- [ ] **Supervisor:** run `laneboss start --config example --role top` and its
  `--format json` equivalent. Read the whole Markdown. Require role `top`,
  level 5, runner `agent`, protocol `1.3.0`, no warnings and all read checks
  true. This command prints a briefing; it does not launch a supervisor agent.
  The supervising person/session reads it and performs the following dispatch.
- [ ] **First lane:** run `laneboss lane start --config example --project demo
  --lane demo-first --brief examples/bootstrap/brief.md --difficulty standard
  --budget 1`. Require run 1, runner `agent`, model `example-model-medium-1`,
  effort `high`, account `example-main`, branch `demo-first` and worktree
  `$bootstrap/repo-demo-first`. The start response alone is not completion.
- [ ] **Completion and output:** follow `laneboss event tail --config example
  --lane demo-first --follow --until lane.ended`. Verify the end is for run 1,
  reason `exit`, exit code 0 and survivors 0. Use the guide's bounded
  `wait_for_demo` helper to require `state: verifying`, no running supervisor
  or tmux session, no pending/refused events and no survivors. Read
  `STATE_DIR/lanes/demo-first/output.log`; require a `run` line, a `read` line,
  the actual `# Bootstrap lane` input heading and `example-agent: done`.
- [ ] **Resume:** save `status-1.json.last_seq`, then run `laneboss lane resume
  --config example --lane demo-first --message examples/bootstrap/follow-up.md
  --budget 1`. Require run 2 and the same branch/directory. Follow events with
  `--since` the saved sequence; otherwise the old end event can stop the follow
  early. Require run 2's resumed/end events, successful exit and zero survivors,
  then wait for quiescence. Check the `resume` log line and the actual follow-up
  heading `# Continue the bootstrap lane`.
- [ ] **Review and mark:** verify inputs, outputs and both runs, then run
  `laneboss lane mark --config example --lane demo-first --state accepted`.
  Require `kind: lane.state`, `state: accepted`, empty `scan.not_covered` and
  zero appended refusals/suspicions. Check that the JSON briefing groups this
  lane under `lanes.accepted`. In production, a supervisor also reviews the diff
  and required tests. An uncovered or suspected workaround is a stopped gate,
  not permission to add `--accept-uncovered`.
- [ ] **Collect:** for the unchanged demo branch, mark it `merged`, then run
  `laneboss lane clean --config example --lane demo-first`. Require
  `pending: false`, removal of both the worktree and branch, and retention of
  the lane directory as a record. Independently check the directory and branch
  are gone, the log remains, and status says `merged`, run 2, `cleaned: true`.
  Run `laneboss state verify --config example`; require `ok: true`, an existing
  store, one lane and positive event count. A cleaned lane cannot resume.
- [ ] **Org:** run `laneboss org init "$bootstrap/org" --levels 3-6 --name
  bootstrap`, add `L3-review` with `--level 3 --role reviewer`, render, and
  validate with `--format json`. Init/add require `ok: true`, `changed > 0`;
  unchanged render requires `changed: 0`; validation requires `valid: true`,
  `problems: []`. Check the generated root rules and instance files exist.
  No owner message, secret-store lookup or agent session is started by these
  steps. Org templates and the named configuration are independent today.
- [ ] **Dashboard:** refresh both forms of `laneboss start --config example
  --role top`. Require empty running/ended/accepted/lost/idle groups, one
  `others` record, no pending/refused events, a recent `lane.cleaned`, no
  configuration warnings and all read checks true. Read the human Markdown.
  There is no web dashboard command in this tree.
- [ ] **Report:** retain the input/source archive, tested binary hash and bytes,
  transcript, exit code and state. Name the source revision, tested command,
  observed result, environment and remaining limits. State explicitly that
  the demo runner is not an authenticated AI-service test. Preserve failure
  evidence and use the guide's failure table before proceeding.

## Real agent and reporting lines

Use the portable [claudock-cli setup](docs/claudock.md#portable-cli-setup) and
the runner fragment in [getting-started](docs/getting-started.md#use-claudock-cli-for-a-real-agent).
The program is `claudock` on `PATH` on Linux and macOS. The owner selects and
authenticates the private profile. Configure full supported model names, keep
`{session}` in both the start and resume templates, and configure actual raw
records/guards and the instance's generated hook settings. A text-log scan does
not cover tool calls that the runner never writes to that log. Start a new lane
after replacing the demo runner; do not resume the stand-in as a real session.

The intended supervision line is owner → L6 → L5 → L4 → L3, with results and
escalations flowing upward. L3 executes/reviews, L4 supervises a stream, L5
coordinates a domain, and L6 sets org policy. These are current policy sources
and level/role data. There is no `reports_to` key or enforced parent-child
graph, no automatic lane-to-instance assignment, and no automatic report
delivery. L1/L2 are reserved. Org-instance runner checks during lane
start/resume and the owner-channel gateway are planned. Do not invent commands
or schema keys for those features.
