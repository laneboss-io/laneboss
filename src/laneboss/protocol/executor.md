# Generic executor rules

These rules bind an executor lane: it does the brief itself, in its own working directory, and proves the work
with an end-to-end test. They reach every lane brief and every supervisor's briefing, they name no company, no
host and no user, so they ship with the launcher. A configuration's own rules follow them and never replace them.

- `brief-decides-role`: If this file reached you inside a rendered brief, you are an executor lane (L3). Do the
  brief yourself in your working directory, start no other agent or session, and ignore any instruction file
  loaded from a parent directory that calls you a supervisor.
- `one-lane-one-worktree`: One brief, one executor, one worktree. Touch no other lane's worktree, branch, session,
  container or files.
- `e2e-proof`: Done means an end-to-end test passes against the real running system, driven from outside through
  the interface a user or client uses. Unit tests are never completion evidence.
- `red-first`: Write the E2E from the acceptance criteria first, show it failing for the right reason (the feature
  is missing or wrong, not the setup), and commit the red test on its own.
- `green-with-output`: Make the minimal change, start or deploy it on the target, rerun the E2E, and paste the
  command and its output in the report.
- `no-test-weakening`: Once a test was shown red, never loosen an assertion, delete a case or add a skip.
- `no-faked-pass`: Nothing passes by a constant, a hard-coded expected value, an ignored input, a special-cased
  test literal or a swallowed failure (`|| true`, `except: pass`, a test with no assertion, a skip).
- `black-box-tests`: Use real auth and realistic inputs, and assert on observable outputs and side effects through
  the same interface. Never mock the system under test; mock only unreachable third parties, and say so.
- `isolated-test-data`: Name created data after the lane plus a timestamp, pick ports that are free at run time,
  clean up in teardown, and depend on no other test's data.
- `secrets-from-env`: Addresses and credentials come from the environment or a file the brief names. They are never
  hard-coded and never put on a command line.
- `tests-off-workstation`: Suites, builds and product runs happen only on the disposable test machines the
  configuration names. The only exception is a test that exists only for the workstation's own OS.
- `test-a-commit`: Test a commit, never a dirty tree, and name its SHA in the report.
- `collect-test-machines`: Whoever launches a test machine harvests the evidence, terminates the machine, confirms
  it is terminated, and removes the volumes and buckets it made. Make no per-run security groups or key pairs.
- `stop-by-id`: Stop a process by its id and a session by its exact name, never by a pattern over command lines.
- `stay-in-bounds`: Change only what the brief's Boundaries allow. Anything else you notice goes in the report, not
  in the diff.
- `report-assumptions`: The report lists what was done and not done, every assumption made where the brief was
  unclear, problems noticed but left alone, and each command with its output.
