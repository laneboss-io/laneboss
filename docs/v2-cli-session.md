# Public session flows

Use the installed CLI when several calls must share a human read session.
Secret upload keys and encrypted stages belong to the issuing connection, so
separate CLI processes cannot perform their key, stage and import sequence.

Create a plan file with schema laneboss.client-flow.v2 and an ordered steps
array. Each step contains name, method and request, plus proof, request_id and
idempotency_key when needed. Request and proof name local files; relative
paths resolve beside the plan. Every mutation retains its retry key before
execution. The initial session has its own key from the command line.

```json
{
  "schema": "laneboss.client-flow.v2",
  "steps": [
    {"name": "key", "method": "secret.key", "request": "empty.json"},
    {"name": "stage", "method": "secret.stage", "request": "sealed.json",
     "idempotency_key": "RETAINED_STAGE_KEY"},
    {"name": "import", "method": "secret.import", "request": "import.json",
     "proof": "import.proof.json", "idempotency_key": "RETAINED_IMPORT_KEY"},
    {"name": "metadata", "method": "secret.list", "request": "empty.json"}
  ]
}
```

Supply a genuine human.session confirmation proof and run:

```sh
laneboss human session --config example --binding /test/binding.json \
  --proof /test/session.proof.json --idempotency-key RETAINED_SESSION_KEY \
  --flow /test/flow.json --wait 120s
```

The key labels above stand for retained random client IDs. empty.json contains
an empty JSON object. Each stdout line contains name, the prepared public
request and its actual response. The first line records human-session. Keep
stdout private along with the request/proof files. No secret value is read by
this flow adapter; secret.stage receives an already encrypted request.

An outside coordinator reads each reply and supplies the next request or
confirmation file atomically. For example, it seals upload bytes using the
actual key, then confirms the import intent containing the actual stage ID.
Confirmation can happen on another genuine human connection; the operation
uses its proof on the flow's original connection. A stage never moves to that
other connection.

An absent file produces a typed prerequisite wait with completed false. The
default wait is 120 seconds per file; --wait 0s returns the wait immediately.
Elapsed time supplies no approval. A timeout, cancellation, invalid request
or service refusal ends the flow before later steps. The CLI uses the same
installed binding, native client and typed invocation as individual commands;
it has no state database or helper access. Existing calls without --flow keep
their ordinary single-request output.

Flows contain individual request/reply calls. Event follow and lane attach use
their ordinary streaming commands; a flow returns unsupported for a stream
instead of discarding its frames.
