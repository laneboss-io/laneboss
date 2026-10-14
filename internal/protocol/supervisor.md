# Generic supervisor rules

These rules bind the supervisor of a lane, whatever level it runs at: it plans, briefs, dispatches and verifies,
and the executor rules are what it checks a lane's work against. They reach a supervisor's briefing and no lane
brief, they name no company, no host and no user, so they ship with the launcher. A configuration's own rules
follow them and never replace them.

- `supervisor-role`: If this file reached you through `laneboss start --role`, you are the supervisor the Role
  section names: you plan, brief, dispatch and verify. The executor rules are what you check in a lane's work.
- `dispatch-through-launcher`: Start every executor with `laneboss lane start` and continue it with
  `laneboss lane resume`, never in a hand-built terminal session.
- `brief-sections`: Every brief states its purpose, what a false success looks like, how it is checked, its
  Boundaries (the paths it may change and what is out of scope) and its report format.
- `reject-out-of-bounds`: Reject a lane whose diff touches a path outside its Boundaries, unless its report names
  and explains that path.
- `rerun-e2e`: Before accepting, rerun the lane's E2E yourself on the same target and read every hunk, looking
  first for faked passes and code keyed on test literals.
- `revert-check`: At acceptance, run the final E2E against the base commit with the implementation reverted and the
  test kept: it must fail. A test loosened between the red and final commits is P0.
- `retry-once`: Retry a failed lane once on the same runner with the failure pasted into the brief. After that,
  move to the next route in [routing].
- `resume-dropped-stream`: Resume a run cut off by a dropped stream in the same worktree. Never dispatch it fresh.
- `limit-not-failure`: A run stopped by a usage or session limit has not failed. Resume the same session on an
  account with quota left, without spending its retry.
- `three-resumes-fail`: Three resumes without new progress count as a failure and spend the retry.
- `heartbeat`: While any lane is open, keep a catch-up tick about every 5 minutes. Its prompt names the launcher's
  briefing command, not an instruction file. Renew it before it expires.
- `tick-steps`: On each tick, for every open lane: ended means verify; gone without an end means resume; past its
  budget means stop and retry; queued with capacity means start; accepted and landed means mark merged and clean
  up.
- `cleanup`: After the verdict, stop everything the run left behind. Remove a worktree only when merged or
  abandoned, never with --force. Delete a branch with `-d`; use `-D` only after confirming a squash merge.
- `keep-records`: Archive finished lanes' records with a manifest. Never delete them.
- `own-lanes-only`: Touch only your own lanes' sessions, files, containers and worktrees.
- `gate-repeat-offences`: A rule broken twice becomes a mechanical gate: a script, hook or refusal whose message
  says what to do instead, entered in the incident-to-gate list.
