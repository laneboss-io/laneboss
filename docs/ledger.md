# Employee ledger

Run `laneboss ledger --config example --instance L5-top --format json`, or select
one lane with `--lane example-lane`. Text is the default format. Without either
selector, the ledger covers the configuration. `--since` accepts an RFC3339 time
or a UTC date. Reads create no ledger file, projection or database.

The dashboard's Employee ledger button in each org node drawer opens the same
reader through `/api/ledger?instance=ID` or `?lane=NAME`. It offers record-kind and
date filters, a chronological table, daily turn/success trends, and source links.
The endpoint uses the existing token and exact Host gate. Empty employees or
periods return no records rather than an error. Endpoint failures clear the view.

Tasks are recorded run/turn attempts, including resumes. The top task counters
use each selected lane's latest included run outcome; the median uses all included
completed run durations. Daily trends count attempts by start day and use their
completed outcomes. Tokens and USD come only from complete recorded vendor log
intervals; missing measurements remain null and incomplete usage stays partial.
Resumes use their recorded previous-end reason, rather than reading follow-up
prompt text. The original brief's first heading is screened before its display
cap and read only from a hash-checked kept input. Original and rendered hashes
are included in JSON/text, while prompt bodies and environment values are omitted.

Instance association uses explicit event references/actors, matching lane names,
verified stored history scope, and configured supervisor project assignments.
The association source accompanies every task. Project assignments represent
current configured scope; historic assignment changes are not recorded or
invented. The anonymous launcher actor is never treated as an employee.

Decision references include persisted event IDs, direct lane/instance cited
feedback and the org history hook's existing injection receipts. Message rows
contain sender/recipient metadata, counts and dashboard links, not message bodies.
The configuration's decisions.sqlite and the standard org shared/services store
are read through the CLI's own verifier/parser in memory. Custom org history DB
locations and report-path citation attribution are not implemented by this ledger.

The real-CLI e2e rows launch two provider-double lanes, fail and resume one, then
compare the CLI and HTTP objects and recorded outcomes/durations/models/seats,
usage sums and resume counts. A tagged ledger-drop-resumes fault must make the
ordinary equality/count assertion fail. Both endpoint token/method/hash checks
and an explicit missing-token 403 row are included. These rows run on the test
box; Mac compilation does not claim runtime success or mutant kills.
