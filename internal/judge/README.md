This package implements `laneboss judge list`, `ask`, and `egress` in Go. The command in
`cmd/laneboss-judge` calls `Run`; it does not invoke the Python launcher implementation.
An external judge may use any interpreter or executable named by its configuration.

The request preserves subject order and the documented member order. Text files are
bounded to 1 MiB and must be UTF-8. Credential screening precedes truncation, and the
truncated text is screened again. Answer probabilities are checked as exact decimals
before conversion to a floating-point number. Duplicate JSON fields, invalid Unicode,
extra answer fields, and credential-shaped metadata make the answer unavailable.

The state ownership marker uses format 2. Egress records keep the existing sent and
outcome schemas, UTC timestamps with six fractional digits, and spaced JSON separators.
The separators matter while Python writers share the log: they count unfinished asks
from those markers. Each log write locks its directory, writes and syncs a complete
temporary file, renames it into place, and syncs the directory. A judge starts only
after the sent line is durable. The state lock is held only to create a missing marker.

`LANEBOSS_JUDGE_MAX_EGRESS_BYTES` optionally sets a stricter log cap. It must be an
integer from 1 through 67108864 bytes; the default is 67108864 bytes. Both the reader
and writer use the selected bound, and every unfinished ask reserves 1024 bytes for
its outcome. The setting cannot raise the published 64 MiB limit, and it is removed
from the external judge's environment with every other `LANEBOSS_` variable.

Before sending another ask, Go validates every existing nonblank log line and counts
the parsed event fields. It refuses malformed earlier lines as well as a malformed
last line. Reading egress validates the entire log before producing any output.

The judge runs without a shell, in its own session, with bounded pipes and a total
deadline. Cleanup targets its process group by its leader's process identifier.
Descendants that create a separate session have the same limitation as the Python
implementation; closing inherited pipes ends writers such as `yes` through SIGPIPE.
A launcher killed with SIGKILL may leave the judge running and only its sent line.

Configuration validation is private to this package so the port can operate before
the configuration command group is merged. It includes projects, rules, ownership,
other configurations' locations, and schema cross references. The current validation
of configured guard and output patterns accepts Go regular expression syntax;
Python-specific lookaround, back references, and unsupported flags are refused.
Supporting those configuration patterns remains a compatibility limitation.

Runtime verification belongs on the disposable test box. The existing black-box
rows are in `laneboss-e2e:tests/e2e/test_judges.py`. Provider adapters are external programs;
the Jev example builds from `examples/judges/typesafe_jev/`.

The referenced black-box files live in the separate `laneboss-e2e` repository. Run its commands there with `LANEBOSS_SRC` set to an absolute laneboss checkout. Go unit tests remain `go test ./...` in this repository.
