# Shell substitution observations

Run the rows and Go tests only on the authorized disposable Linux machine with
Python 3, Git, tmux and the pinned Go toolchain. For this follow-up, the development
Mac runs only gofmt, go vet under both tag sets and Python py_compile.
This procedure launches no machine, makes no Git commit and requests no model.
The stand-in reads the kept prompt and writes supported raw JSONL; commands
under observation remain data and are never submitted to a shell.

Set E to an absolute evidence folder outside the checkout. Keep the source
revision, source bytes and diff, every supplied binary and its SHA-256, command
transcripts and actual exits. Supply release and tagged executables by absolute
path. The scripts do not build one for themselves.

On the authorized machine, build the current source:

~~~sh
go build -trimpath -buildvcs=false -o "$E/subst-laneboss" ./cmd/laneboss
go build -tags laneboss_faults -trimpath -buildvcs=false -o "$E/subst-faults" ./cmd/laneboss
sha256sum "$E/subst-laneboss" "$E/subst-faults"
~~~

First run each original flagged row separately against the retained pre-fix
release at b4a1e3a05bb4. Save full stdout/stderr and the actual exit for each
command, including an expected nonzero exit:

~~~sh
LANEBOSS_SUBST_BINARY="$E/pre-fix-laneboss" \
LANEBOSS_SUBST_EVIDENCE="$E/subst-before" \
python3 e2e-rows/test_refusal_substitution.py ShellSubstitutionRows.test_flag_backticks -v
LANEBOSS_SUBST_BINARY="$E/pre-fix-laneboss" \
LANEBOSS_SUBST_EVIDENCE="$E/subst-before" \
python3 e2e-rows/test_refusal_substitution.py ShellSubstitutionRows.test_flag_dollar -v
LANEBOSS_SUBST_BINARY="$E/pre-fix-laneboss" \
LANEBOSS_SUBST_EVIDENCE="$E/subst-before" \
python3 e2e-rows/test_refusal_substitution.py ShellSubstitutionRows.test_flag_nested -v
~~~

Each must exit 1 at its own named expected-observation assertion, after a real
successful lane end, zero survivors and a fully covered scan. The row derives
observations from the older listing shape until that assertion, so a missing
new field cannot impersonate the detection regression. Setup errors, malformed
records, timeouts or coverage failures are incomplete evidence.

The 0559e60 release already stores observations but has the replay failure and
the broad dollar rule. Run the replay row and new idiom/ANSI controls separately:

~~~sh
LANEBOSS_SUBST_BINARY="$E/pre-review-laneboss" \
LANEBOSS_SUBST_EVIDENCE="$E/subst-review-before" \
python3 e2e-rows/test_refusal_substitution.py ShellSubstitutionRows.test_start_doctor_after_observation -v
LANEBOSS_SUBST_BINARY="$E/pre-review-laneboss" \
LANEBOSS_SUBST_EVIDENCE="$E/subst-review-before" \
python3 e2e-rows/test_refusal_substitution.py ShellSubstitutionRows.test_ctrl_plain_substitution -v
LANEBOSS_SUBST_BINARY="$E/pre-review-laneboss" \
LANEBOSS_SUBST_EVIDENCE="$E/subst-review-before" \
python3 e2e-rows/test_refusal_substitution.py ShellSubstitutionRows.test_ctrl_echo_idiom -v
LANEBOSS_SUBST_BINARY="$E/pre-review-laneboss" \
LANEBOSS_SUBST_EVIDENCE="$E/subst-review-before" \
python3 e2e-rows/test_refusal_substitution.py ShellSubstitutionRows.test_ctrl_ansi_literal -v
~~~

The replay row must first establish one stored observation, then fail on start's
store-replay prerequisite. The other rows must fail their named count assertions
because the old parser observes ordinary idioms or literal ANSI-C text. Retain
every failure and let the supervisor distinguish expected regressions from
unrelated failures before proceeding.

For the path regressions, copy only the unchanged
internal/lane/backtick_paths_test.go into the disposable pre-fix source copy.
It uses the existing exported path scanner and no new detector API, so both
subtests can fail on their actual path assertions rather than compilation.
Keep the test bytes and that temporary source copy, then run:

~~~sh
go test ./internal/lane -run '^TestBacktickWriteCandidates$' -v
~~~

Challenge the current tagged build with the one fault point
scan-skip-shell-substitution-in-text:

~~~sh
LANEBOSS_SUBST_BINARY="$E/subst-laneboss" \
LANEBOSS_SUBST_FAULTS="$E/subst-faults" \
LANEBOSS_SUBST_EVIDENCE="$E/subst-mutant" \
python3 e2e-rows/test_refusal_substitution.py ShellSubstitutionRows.test_mutant_skips_kind -v
~~~

The driver exits 0 only after every listed positive row fails exactly once at
its own named detection assertion, with no setup errors and an empty reached
marker. It saves each real traceback in mutant-result.json. The fault selector
is passed only to the explicit scan after quiescence, so a live scan cannot
pre-record the observation. The release build ignores the fault selector.
The driver covers the original three cases and the new context, heredoc and
parser-boundary cases without changing their assertions.

Each count assertion also saves detection-assertion.json immediately before its
comparison, with the row name, assertion text, actual count, expected count and
computed result, and whether the actual listing has an observations field.
The driver requires that field to exist and the file to show actual 0 versus expected
1 at the row's own assertion, along with its real traceback and reached marker.
Neither a failed CLI prerequisite nor a missing observation field counts as a
mutant kill. The replay row saves replay-assertion.json before start and doctor.

Before the full CLI phase, run the observation reader and policy regressions on
both tag sets, retaining complete output and actual exits:

~~~sh
go test ./internal/lane ./internal/laneturns ./internal/eventstore ./internal/start ./internal/doctorbase ./internal/doctor ./internal/textcontext -run 'TestObservation|TestPolicyFileLoad' -v
go test -tags laneboss_faults ./internal/lane ./internal/laneturns ./internal/eventstore ./internal/start ./internal/doctorbase ./internal/doctor ./internal/textcontext -run 'TestObservation|TestPolicyFileLoad' -v
~~~

The reader tests seed the production store and require its payload column to
equal the same canonical fixture bytes. They then use each reader's own stored
event parser, validation and replay. The start and doctorbase tests no longer
use json.Unmarshal's float conversion or repair the fixture's command hash.
The doctor test runs its actual recorded-store check in a temporary configuration.
Both scanner tests compare the full emitted payload with those same bytes and
require one event after a rescan. Contract tests first require the valid fixture,
then reject floats, exponent spellings, strings, missing items, out-of-range
positions and invalid observation links. They also accept the documented large
excerpt bound. Retain the earlier 6998e4e failure as evidence of the bad test
decoder and policy-loading prerequisite; runtime success must come from the new
Linux run.

Run all 28 CLI rows on the current binaries and both Go tag sets. Require
exit 0 from each command:

~~~sh
LANEBOSS_SUBST_BINARY="$E/subst-laneboss" \
LANEBOSS_SUBST_FAULTS="$E/subst-faults" \
LANEBOSS_SUBST_EVIDENCE="$E/subst-after" \
python3 e2e-rows/test_refusal_substitution.py -v
go test ./internal/lane ./internal/laneturns ./internal/eventstore ./internal/start ./internal/doctorbase ./internal/doctor ./internal/textcontext
go test -tags laneboss_faults ./internal/lane ./internal/laneturns ./internal/eventstore ./internal/start ./internal/doctorbase ./internal/doctor ./internal/textcontext
go test ./internal/lane -run '^TestLongUnicodeShellWord$' -bench '^BenchmarkUnicodeShellWord$' -benchmem
~~~

The benchmark measures actual allocation and time for the long Unicode word;
no performance figure is claimed from source inspection or static checks.

| Row | What makes the assertion fail |
| --- | --- |
| test_flag_backticks | The code argument's active backtick pair produces no observation. |
| test_flag_dollar | The code argument's active dollar substitution produces no observation. |
| test_flag_nested | Longer text loses its expansion or duplicates one call's observation. |
| test_flag_inner_quotes | A backtick command's own quotes end the outer word early. |
| test_flag_even_escape | Even backslash parity hides an active expansion in code. |
| test_flag_after_ansi_quote | An escaped ANSI-C quote swallows the later code argument. |
| test_ctrl_ansi_literal | Literal ANSI-C text is treated as active shell expansion. |
| test_flag_line_continuation | Removing backslash-newline does not restore the dollar opener. |
| test_flag_group_fallback | A spaced close is incorrectly treated as arithmetic. |
| test_flag_two_group_fallback | Sequential subshell groups are incorrectly treated as arithmetic. |
| test_flag_positional_backtick | A positional prose backtick pair is omitted. |
| test_flag_configured_prose | The actual org source fails to identify positional prose. |
| test_flag_text_option | A joined text option value loses its expansion. |
| test_ctrl_plain_substitution | A normal whole substitution argument is flagged. |
| test_ctrl_echo_idiom | An ordinary echo/date expansion is flagged. |
| test_ctrl_unconfigured_prose | An unconfigured positional dollar argument is flagged. |
| test_ctrl_file_option | A file input value is classified as prose. |
| test_ctrl_single_quotes | Shell single-quoted markers are flagged. |
| test_ctrl_escaped | Escaped markers are flagged. |
| test_ctrl_outside_quotes | Normal substitutions outside quotes are flagged. |
| test_ctrl_quoted_heredoc | A quoted delimiter fails to disable body expansion. |
| test_flag_unquoted_heredoc | A direct interpreter's expanding heredoc is omitted. |
| test_ctrl_escaped_heredoc | Escaped body markers are flagged. |
| test_ctrl_arithmetic_pid | Arithmetic or PID expansion alone is flagged. |
| test_ctrl_file_tool | A Write tool is treated as a shell call. |
| test_start_doctor_after_observation | A stored observation prevents start or doctor from replaying the store. |
| test_turn_live_scan | Live turn recording loses its run/call/hash or is duplicated by an ordinary rescan. |
| test_mutant_skips_kind | A positive row stays green, fails elsewhere, or lacks a reached marker. |

Ordinary rows also require complete coverage, no invented refusal, no unreviewed
gate item, a separate observations listing, the actual command hash and position,
rescan deduplication, state verification and acceptance without a bypass.
The turn row reads before an explicit rescan and follows run 2 from the saved
sequence. Successful fixtures release their own claims through mark and clean
while retaining the supplied working directory and every input. Unexpected
failures retain their state for supervisor review.

Go assertions fail if either path shape invents or loses a write/name, quote
boundaries change expansion activity, configured recipients/options become prose,
a long Unicode word loses bytes or its following redirect, incomplete heredocs
panic or lose expansion, a writer changes the shared payload bytes, a stored
reader rejects a valid integer or changes an observation's identity/fields,
replay loses an observation or adds an acceptance hold, duplicate replay is
accepted, an invalid observation/policy is accepted, regular TOML is subjected
to Markdown heading requirements, or a policy symlink is followed.

Collect evidence at the end of every phase, including an expected-red phase.
The entire subst-before, subst-review-before, subst-mutant and subst-after
directories must come back, not just their summary log. Each row directory
contains row.txt, its isolated HOME and claims, configuration and org sources,
the kept brief, raw.jsonl, received prompt files and command.txt. Retain every
call-N.argv.json, call-N.stdout, call-N.stderr and call-N.exit; retain any
call-N.timeout or call-N.fault.json. Retain detection-assertion.json for each
positive/control/turn row and replay-assertion.json for the replay row. Mutant rows additionally require
mutation-reached and mutant-result.json. Keep the phase transcript and exit,
source archives/diff, binary bytes/hashes, Go test/benchmark output, and a manifest.

Package a completed phase's row directory on the box, copy it through the
supervisor's established transfer route, and compare the archive hash after
transfer. The following archive command is run only on that box, with phase
names substituted literally:

~~~sh
tar -czf "$E/subst-before-rows.tar.gz" -C "$E" subst-before
sha256sum "$E/subst-before-rows.tar.gz"
~~~

Independently list/extract the copied archive in an evidence directory and
check the named files above, including each raw failure and mutant traceback.
A summary mentioning an assertion cannot replace its original output.
A failed transfer, missing row tree, timeout or setup failure stops the phase;
retain it and do not claim a complete E2E.

These checks exercise the actual CLI using credential-free recorded fixtures.
They are not an authenticated AI-service test and do not claim that the
recorded command strings were executed.
