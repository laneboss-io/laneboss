# Text-observation policy

`shell-substitution-in-text` observes shell expansions that can turn text into
commands before an interpreter or a messaging tool receives it. It runs in the
existing configured raw-record scan. It does not refuse a tool call or hold
acceptance, and it does not establish whether the recorded call ran.

Backtick pairs in double-quoted shell words are observed everywhere. Dollar
substitutions need an inline interpreter code argument, one of the built-in text
options, an unquoted interpreter heredoc, or a configured positional prose
argument. Single quotes and escaped markers remain literal. Plain substitution
arguments and ordinary echo/date strings remain normal shell idioms.

The bound org supplies `text-observations.toml` in
`.laneboss/shared/services/`. The org is selected by the configuration's
`org_dir`, or by `organisation` under its configuration home. A lane cannot
provide a policy path. Missing policy enables no additional positional tools;
the backtick, interpreter and text-option rules still apply. No command or
private tool list is hard-coded as a positional-prose exception.

Use [the generic example](../examples/text-observations.toml) as a source file,
then replace its invented tool names with the org's actual programs. Keep that
deployment-specific source in the private org. Edit source configuration and
render the org through the authorized supervisor; do not edit generated rules.

| Field | Meaning |
| --- | --- |
| `schema_version` | Must be `1`. |
| `tools` | At most 64 entries. An empty list disables additional positional contexts. |
| `command` | One to sixteen literal prefix words, beginning with a program basename. Later words match literally. |
| `text_from` | Zero-based prose index, counting the command as zero after leading assignments and wrappers are removed. Defaults to the prefix length. Known global value options before a subcommand are ignored when counting. |
| `text_option` | Optional literal option selecting the following prose arguments. Separate and joined values are supported. Without the option, that entry selects no prose. |
| `value_options` | Optional value-taking options whose next word is not prose, including known global options before a subcommand. |

For example, `command = ["message-tool", "send"]` with `text_from = 3`
describes `message-tool send recipient "prose"`. The recipient is not prose.
A prompt tool with global `--model VALUE` can list `--model` in `value_options`
so `prompt-tool --model model-1 exec "prose"` matches its `exec` prefix.
`-F` and `--file` values are excluded even on a configured tool.

The source must be a regular, readable UTF-8 TOML file of at most 64 KiB, with
no unknown keys or credential shapes. A symlink at the policy file is rejected.
Invalid policy produces a scan error that names the source and field form,
never the offending value. It cannot silently become a different allowlist.

`lane refusals` returns `observations` and `observation_count` separately from
refusal-linked `suspicions`. An observation has `refusal: null`, one `how` kind,
`paths: ["(command)"]`, and `similarity: null`; it has no `reviewed` field.
Its command hash and record position let the supervisor inspect the original
call. `lane review` accepts actual refusal IDs, so it cannot review an independent
observation. The existing refusal-linked review gate remains in force.

Stored run numbers and record `line`, `offset` and `item` values are JSON
integers. A record item of `0` is valid; `0.0`, `0e0` and `"0"` are rejected.
The ordinary and live-turn writers share payload construction. The event store,
lane, turn, start and doctor readers check the same independent-observation
contract. Their regression tests use the identical canonical payload bytes from
`internal/testdata/shell-observation.json`, including its actual command hash,
through the production SQLite readers and numeric decoders.

The tokenizer reads the first 65,536 runes and at most 10,000 tokens. It does
not recurse into double-quoted words inside an unquoted substitution or legacy
backtick command. It does not trace heredocs through pipelines. It does not
interpret eval, shell-code or SSH strings a second time. ANSI-C quote boundaries,
line continuations and arithmetic fallback are recognised, but this bounded
observation is not a complete shell parser or a security boundary.

The [CLI rows and collection procedure](../e2e-rows/REFUSAL-SUBSTITUTION.md)
exercise the real launcher with retained raw-record fixtures on a disposable
Linux machine. Read-only corpus counts can estimate observation volume, but
Bash strings alone cannot label author intent. The flagged-call proportion is
a conservative upper bound on false positives among all sampled Bash calls.
