# Judge adapter for TypeSafe's Jev

Build from the repository root with the pinned Go toolchain:

```sh
GOTOOLCHAIN=go1.26.0 go build -trimpath -o bin/typesafe_jev ./examples/judges/typesafe_jev
```

The tests build the Go program and exercise it as a subprocess. Their interpreter is a test-harness
requirement, not a runtime dependency of the helper.

`typesafe_jev` is a stand-alone example of a launcher *judge*: an external command that the launcher runs for
a scalar yes/no question or typed batch. It reads one JSON object, sends one state and all independent questions together, and prints one validated object. The Go source shares `internal/typesafe` wire validation with the launcher; the built executable needs no launcher runtime. HTTP 429/529 get bounded exponential retries, and the adapter writes no files. Nothing that holds the key's exact text is ever printed (the
scope of that rule is stated in [The key file](#the-key-file)).

## The contract

The launcher writes one request:

```json
{"laneboss_judge": 1, "question": "refusal.is-refusal", "kind": "noul",
 "prompt": "Is this tool result a refusal by a guard, a hook or a permission layer?",
 "subject": {"result": "<text>", "command": "<text>"}}
```

The scalar contract uses `kind: "noul"`; typed guide batches and job catalogs use the extensions described below. For scalar asks, `subject` holds one to eight named texts of at most 4000 characters
each. The program prints one answer, the probability of YES from 0 to 1, the model that answered and the provider's
request identifier (`null` when the service sent none or sent something that is not an identifier):

```json
{"probability": 0.93, "model": "jev-1.13.0", "request": "req_01..."}
```

Anything else is *no answer*: a non-zero exit status and one line on standard error (nothing on standard output).
The line never holds the key or the service's response body, and it repeats no free text of the request; the one
text of the service that it may hold is the provider's request identifier, which is an identifier and could equal a
short identifier-shaped subject text.

| Exit | Meaning |
| - | - |
| 2 | a bad request (not a supported scalar/typed/catalog contract, missing state/questions, malformed criteria, or excessive text) or bad options; the line names an option at most and never repeats what was typed |
| 3 | the key file is refused or unreadable, has no line for the key's name, or holds a key of fewer than 16 characters |
| 4 | an HTTP error (the line names the status), a connection that failed, an answer that is not the documented one, or a text that held the key (the line is then "the answer held the key and was not printed") |
| 5 | a time-out |
| 1 | a bug in the program (the line names the exception class, never its text) |

## Configuration

In a launcher configuration the judge is a command:

```toml
[judges.jev]
command = ["/path/to/typesafe_jev", "--env-file", "/path/to/typesafe.env"]
```

The org's decision guide asks `decision.conflicts` and `decision.answers`
as `kind: "typed"` batches. All candidate decisions and action windows share
named `state` with a map of independent Nouls, explicit state references and
yes/no criteria. A Noul near 0.5 is uncertainty; these are binary propositions,
not severity scales. Ordinary guidance always adds advice. The legacy
`refuse_threshold` remains an answer-reuse cutoff and grants no hook refusal.

Catalog asks use `kind: "laneboss-jobs"`, an `owned` Noul and `command`
Choice with `none`. The adapter preserves the official model/answers/usage
envelope and every Choice option probability, confidence and selected value.
Missing answers, distributions, model/usage or invalid fields make the whole
ask unavailable. Low Choice confidence produces uncertainty advice without a
route; catalog probabilities cannot refuse ordinary work, including with
legacy refusal settings. The job budget is ten seconds within the shared
30-second guide deadline, including process and log handling.

The typed adapter also validates Score answers: a weighted position on ordered
descriptive levels, with its legend, distribution and confidence. Decision and
job applicability remain Nouls because the desired judgments are yes/no. See
[the full wire contract](../../docs/judges.md#typed-batches-and-the-typesafe-boundary)
and [the decision dial](../../docs/decisions.md#the-dial).

`/path/to/typesafe_jev` is wherever you keep a copy of the file. The program can also be run by hand:

```sh
printf '%s\n' '{"laneboss_judge": 1, "question": "refusal.is-refusal", "kind": "noul", "prompt": "Is this a refusal?", "subject": {"result": "Blocked by hook: not allowed."}}' \
    | bin/typesafe_jev --env-file /path/to/typesafe.env
```

| Option | Meaning |
| - | - |
| `--env-file PATH` | required; the key file (below) |
| `--key-name NAME` | the line to read; default `TYPESAFE_API_KEY`, the name the documentation gives for the key's environment variable |
| `--model MODEL` | default `jev-latest`; the answer reports the version that answered. Select a supported version using the provider's [Models](https://docs.typesafe.ai/models) reference. |
| `--base-url URL` | default `https://api.typesafe.ai`; for tests and private gateways; `https://` for any host (`https://localhost` too), or `http://` only when the host is the literal address `127.0.0.1`; no credentials, query or fragment |
| `--timeout SECONDS` | default 8, at most 3600; the whole wait for the service, not one read |
| `-h`, `--help` | the usage, on standard output |

## The key file

The file holds lines `NAME=value`, with an optional `export ` in front, optional single or double quotes around the
value, and `#` comments:

```sh
export TYPESAFE_API_KEY="..."
```

The program opens the file (a link is followed) and checks the TARGET: it must be a regular file that group and
others cannot access at all, so mode `600` or `400` (`chmod 600 /path/to/typesafe.env`); a link to a file that others
can read is refused (exit 3, naming the mode and never the content). The file may hold at most 64 KiB. The key is read
once, kept in memory, sent only in the `Authorization` header to the address given, and never printed:

- ONE function writes to standard output and standard error. Once the key has been read, it refuses every text in
  which the key's value occurs: nothing of that text is printed, the exit status is 4 and the line is "the answer held
  the key and was not printed". This holds for a request identifier or a model that a faulty service fills with the
  key as much as for anything else.
- The scope of that rule: it looks for the key's exact text, so an echo that is encoded, split or otherwise changed is
  not seen; and a key whose text occurs in an ordinary answer (in the model name, say) makes that answer unprintable,
  exit 4, which fails closed.
- A key must have at least 16 characters. A shorter value is refused when it is read (exit 3, "the key's value is too
  short to be a key", never the value): a short value is far more likely to occur in an ordinary answer or in the
  program's own fixed lines. A longer key can still coincide with such a text, and is then withheld as the rule above
  says.
- A usage error prints one fixed line that names an option at most, never a value (`--help=VALUE`, an unknown option,
  a bad value of an option); a key name that the file does not hold is reported as "the key file has no line for the
  name given with --key-name", not by the name.
- Redirects are not followed, so the key cannot be passed on to another address.

## How it asks, and where that comes from

The original provider reference collection (2026-10-09) is listed below. The
2026-10-15 audit uses the saved official API, primitives, state, confidence,
System One and composite-scoring pages, as described in the judge contract:

| Page | Address |
| - | - |
| Documentation index | https://docs.typesafe.ai/llms.txt |
| API reference | https://docs.typesafe.ai/api.md |
| Noul | https://docs.typesafe.ai/primitives/noul.md |
| State | https://docs.typesafe.ai/concepts/state.md |
| Models | https://docs.typesafe.ai/models.md |
| Quick start | https://docs.typesafe.ai/introduction/quickstart.md |
| Exceptions (Python SDK) | https://docs.typesafe.ai/sdk/python/api/exceptions.md |
| Constants (Python SDK) | https://docs.typesafe.ai/sdk/python/api/constants.md |
| Retries and Usage (Python SDK, read in part) | https://docs.typesafe.ai/sdk/python/api/retries.md, https://docs.typesafe.ai/sdk/python/usage.md |
| JavaScript SDK: APIError, RateLimitError, SystemOneResult, NoulResponse, SystemOneRequestPayload | under https://docs.typesafe.ai/sdk/javascript/api/ |
| Jev 1.13 jaggedness | https://docs.typesafe.ai/model-jaggedness/jev-1.13.md |
| Legal | https://docs.typesafe.ai/legal.md |
| Data Processing Agreement, Privacy Policy | https://typesafe.ai/legal/data-processing, https://typesafe.ai/legal/privacy-policy |

One request: `POST https://api.typesafe.ai/v1/systemone`, headers `Authorization: Bearer <key>` and
`Content-Type: application/json`, and the body

```json
{"state": {"result": "<text>", "command": "<text>"},
 "model": "jev-latest",
 "questions": {"answer": {"type": "noul", "instructions": "<the prompt>",
                          "criteria": {"true": "The proposition in instructions is true for the named state.",
                                       "false": "The proposition in instructions is false for the named state."}}}}
```

`state` is the subject, so every text keeps its name, and `instructions` is the prompt unchanged. The question's key
(`answer`) is the program's own; the documentation says it is not sent to the model. The answer is read from
`answers.answer.noul` (the probability of yes), the required top-level `model`/`usage` envelope and the
response header `x-typesafe-request-id`. The documentation says only "a JSON body describing what went wrong" about an
error, so the program reads nothing from an error body.

The answer is read strictly. The number is read exactly as the service wrote it (a decimal, not a float), checked
against 0 and 1 on that exact value and only then made a float: `1.0000000000000001` and `-1e-999` are not answers,
and zero is printed without a sign. A repeated member anywhere in the response is not an answer. A request identifier
or a model must be an identifier, `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`: an identifier that is not one becomes `null`
(or is left out of an error line), a model that is not one makes the answer not the documented one (exit 4).

HTTP 429/529 are retried at most twice, after 100 ms and 200 ms, inside the same Go context deadline. HTTP 401/422, exhausted retries, connection failures and malformed success envelopes return no answer. A retry repeats the complete batch.

## What is sent, and the limits

For each logical batch one request goes to the base URL's host, over HTTPS, or over plain HTTP only to the literal
address `127.0.0.1` (no name is resolved for a plain-HTTP request, so no resolver or hosts-file mistake can carry the
key in the clear to another machine). It carries:

- the headers `Authorization: Bearer <the key>`, `Content-Type: application/json`, `Accept: application/json` and
  `User-Agent: laneboss-judge-typesafe-jev/1`, which names the launcher;
- the prompt, as `instructions`;
- the subject's NAMES and texts, as `state`;
- the chosen model name (`jev-latest` unless `--model` says otherwise);
- the scalar `answer` question or the complete typed questions map, including instructions and criteria.

The launcher's question identifier, the lane's name, files and environment variables are not sent. Like any HTTPS
client, the program shows the provider its network address.

Limits: the request on standard input and the service's answer are each limited to 1 MiB (more is exit 2 for the
request and exit 4 for the answer) and the key file to 64 KiB (exit 3); a subject holds at most eight texts of at
most 4000 characters.

Proxies: the address `127.0.0.1` is asked without any proxy at all, whatever `http_proxy`, `HTTP_PROXY`, `all_proxy`
or `no_proxy` say, because over plain HTTP the key travels in the clear on that connection. For any other host (which
must be `https://`, `https://localhost` included) the environment's proxy settings keep applying; the key travels
inside TLS, and the proxy sees the host name.

Certificates: Go's default HTTP transport verifies HTTPS certificates and never disables verification. Local HTTP stand-ins verify request/response plumbing only; these rows make no authenticated-service or live TLS claim. A connection failure returns exit 4 without printing provider bodies.

## What leaves the machine

Everything in the list above, and so the prompt and the subject texts (up to eight, 4000 characters each, already
screened by the launcher; this program does not screen them again). The pages above promise no retention period. The
Models page says "Jev is not trained on customer requests or responses." The Privacy Policy defines "Input" as "your
prompts, data, instructions, and other input" and says "We (1) will not train or fine tune any artificial
intelligence or machine learning models on Input, and (2) will not disclose any Input to a third party other than our
service providers" and "We retain personal data about you for as long as reasonably necessary to provide you with the
Services, or otherwise in support of our business or commercial purposes". The Data Processing Agreement says
"Customer Personal Data will be retained for as long as necessary taking into account the purpose of the Processing,
and in compliance with applicable laws, including laws on the statute of limitations and Data Protection Law". The
Legal page says "We also offer zero data retention (ZDR) for enterprise customers"; nothing here says whether your
key's account has it. Send nothing that those terms do not suit.

The model can be steered by the text it judges. The jaggedness page says "State is data, and `jev-1.13` does not
treat it as hostile by default. Content written to adversarially steer the model, whether that is an injected
instruction, a deliberately misleading framing, or text that argues for its own classification, can move the answer."
The Models page says "English is the primary training language and where accuracy is currently best. Other languages,
including CJK scripts, are handled but not equally well". The probability is a signal for the launcher to weigh, not a
verdict.

## Tests

`laneboss-e2e:tests/e2e/test_judge_jev.py` builds the Go adapter and drives it against a local HTTP stand-in.
It checks input and output screening, file permissions, exact probability bounds, redirects, timeouts,
and standalone execution with no interpreter on PATH. Runtime checks belong on a disposable test host.

The referenced black-box files live in the separate `laneboss-e2e` repository. Run its commands there with `LANEBOSS_SRC` set to an absolute laneboss checkout. Go unit tests remain `go test ./...` in this repository.
