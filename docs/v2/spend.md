# API credential spend floor

Every `claude-api-key` launch requires an enrolled operator tool reading and
registered outside capture. The minimum floor is 5 USD. The operator may set a
higher floor in the protected operator configuration.
Subscription credential modes retain their existing controls.

## Enroll and reconcile a reading

Keep a private, administrator-owned JSON configuration outside the checkout.
For example, these identifiers and the tool path are invented:

```json
{
  "command": "/opt/operator/bin/balance-tool",
  "selector": "TOTAL",
  "credential_id": "pool-one",
  "profile_ids": ["profile-one", "profile-alias"],
  "floor_micros": 5000000
}
```

`command` names the operator's balance-reading executable. It receives no
arguments. Use the existing pool balance script, which reads vendor usage and
prints no secret. The operator command runs it before opening administrator
IPC. The service receives the exact stdout and the reading's start time; it
never executes the tool or queries Claudock itself. There is no input field for
a balance number. A failed command, malformed output, duplicate selector or
missing selected reading refuses enrollment.

The tool output consists of one line per profile and a `TOTAL` line. Each line
is `SELECTOR  DECIMAL USD`; a colon after the selector and a dollar sign before
the amount are also accepted. The configured selector must occur exactly once.
All aliases drawing from the same credential or billing pool must use the same
stable `credential_id`. A profile's pool mapping cannot subsequently be changed.
For a shared billing pool, select `TOTAL` and enroll all of its API profiles in
that single pool. Neither keys nor private vendor profile names belong in a
public configuration or report.

After profile enrollment, and again after every released run, use the installed
administrator entry with retained files:

```console
laneboss internal helper --config NAME --installation INSTALLATION \
  --spend-reconcile /absolute/private/balance-config.json
```

The installation and configuration files follow the existing administrator
ownership and path checks. The new private method is `spend_reconcile`; it is
absent from the public RPC catalog. The writer rechecks the native connection
and exact frame before committing. A reading older than one minute, a reading
that predates the last release, or a replay with changed bytes is refused.
An exact frame replay returns its original receipt without another journal line.

## Accounting and enforcement

The initial tool reading remains the seed. The store sums the top-level vendor
`result.total_cost_usd` records, preserving the accompanying `usage` token counts
and the primary capture reference. It uses the sealed run's credential profile
and vendor session, handles JSON split across capture chunks, and deduplicates
result UUIDs across replays and streams. `cost_usd`, `modelUsage.costUSD`, token
price calculations and lane budget estimates cannot replace the result total.
Costs round up to USD micros; available balances round down.

The remaining estimate is at most the initial seed minus recorded spend and at
most the latest tool reading. A lower tool reading also becomes a conservative
anchor: additional captured spend reduces it. A later tool reading replaces
that reading, while the initial seed and recorded spend remain unchanged.
Refills cannot increase authority above the initial seed minus recorded spend.

At or below the floor, assembly, lifecycle sealing/recovery and the store's
prepare/open boundary refuse another API launch. A result crossing the floor
atomically changes affected current lanes to `stopping`, advances their
cancellation epochs, journals the crossing and queues the normal durable stop
effect for the measured native process handle. The existing reconciler measures
shutdown and retains `lane.ended`; an outbox intent alone does not claim physical
quiescence. A result that precedes the initial native observation retains its
spend and a pending stop; the first measured handle finishes that stop in the
observation transaction. Malformed or missing cost evidence similarly fences the credential,
retains the raw capture and requires a later operator reading.

Release drain accounts for any final unread bytes and marks the pool as needing
a new reading. Launches remain refused until a reading started after that
release is reconciled. `lane.status` includes `credential_spend`, including the
remaining estimate, floor, reading requirement and any accounting error.

Each newly committed reconciliation retains one `spend.reconciled` event with
the fixed line:

```text
spend.reconciled estimate_micros=N reading_micros=N floor_micros=N
```

That line contains only amounts. Exact tool stdout is retained privately in the
store's reading receipt, and exact vendor bytes remain in primary capture.
The feature does not require or authorize sending a real credential to a test
machine. Recorded fake-key error results can demonstrate zero recorded cost;
they are not an authenticated AI-service test.
