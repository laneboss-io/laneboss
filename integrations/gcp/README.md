# integrations/gcp

`with_identity.py` runs ONE command under ONE named identity, with an environment it builds from scratch. It
is for the case where the machine is already logged in to a cloud provider and a command must not act as that
identity: the command gets the identity you name and none of the ambient one. It is one stand-alone file that
uses only the Python standard library: nothing in the launcher imports it and it imports nothing of the
launcher. Python 3.11 or newer.

    python3 -I with_identity.py --identities FILE NAME -- COMMAND [ARGUMENT ...]

The -I option makes the interpreter ignore the caller's Python environment variables and user directories,
so the caller's environment cannot change which code the interpreter loads.

`FILE` is the identities file you keep, `NAME` is one identity in it, and everything after the two characters
`--` is the command and its arguments. `python3 -I with_identity.py -h` prints the usage text.

## The identities file

TOML, UTF-8, at most 64 KiB. The top level holds the key `schema_version = 1` and tables named
`identities.NAME`; nothing else. NAME matches `[a-z0-9][a-z0-9-]{0,31}`. A table holds these keys and
nothing else.

| Key | Type | Required | Rule |
|---|---|---|---|
| `config_dir` | string | yes | An absolute path (starts with `/`) of an existing directory. |
| `project` | string | no | Matches `[a-z][a-z0-9-]{4,28}[a-z0-9]`. |
| `key_file` | string | no | An absolute path of an existing regular file; only the path is used. |

The program never opens or reads `key_file`; it only checks that the file is there.

An example, with invented values:

```toml
schema_version = 1

[identities.demo-identity]
config_dir = "/home/example/identities/demo"
project = "demo-project-name"
key_file = "/home/example/identities/demo/key.json"
```

    python3 -I with_identity.py --identities /home/example/identities.toml demo-identity -- ./report.sh

## The environment the command gets

It is built from nothing. Of the caller's environment, exactly these five variables are copied when they are
set, and nothing else is: `PATH`, `HOME`, `TMPDIR`, `LANG`, `TERM`. Then the program sets:

- `CLOUDSDK_CONFIG` to `config_dir`, always;
- `CLOUDSDK_CORE_PROJECT` to `project`, only when the table has one;
- `GOOGLE_APPLICATION_CREDENTIALS` to `key_file`, only when the table has one;
- `WITH_IDENTITY_NAME` to NAME.

Every other variable of the caller is dropped, in particular any of the caller's whose name starts with
`GOOGLE_`, `CLOUDSDK_`, `GCLOUD_`, `AWS_` or `AZURE_`. A key the table does not have sets nothing: an absent
`project` means no `CLOUDSDK_CORE_PROJECT` at all, not an empty one and not the caller's.

COMMAND is found without a shell, the way a shell would find it except that empty parts of PATH are skipped:
with a `/` in it, it must be an existing executable file; otherwise it is searched on the `PATH` that
was copied (the caller's `PATH`, or `/usr/bin:/bin` when the caller has none). The program then replaces
itself with the command, so the command's exit status is the wrapper's and no wrapper process stays behind;
standard input, output and error pass through unchanged.

## What it refuses

Anything that is not exactly as specified above is a refusal: the shape of the command line; a NAME that does
not match its grammar; a file that is missing, is not a regular file, is larger than 64 KiB or is not valid
TOML; a `schema_version` that is not the integer 1; a top-level key that is not `schema_version` or
`identities`; a NAME that is not a table; a key the table is not allowed to have; a `config_dir` that is
missing, is not an absolute path or is not an existing directory; a `project` or `key_file` that breaks its
rule; a command that was not found.

It also refuses `gcloud` when its first arguments are `auth login`, `auth activate-service-account`,
`auth application-default` (followed by anything), `config set` or `config configurations` (followed by
anything): this wrapper does not log in or change the configuration. Nothing else is denied.

A refusal is one line on standard error starting `refused:` that names the key and the rule, never a value:
neither the identities file nor the caller's environment is ever printed. There is no fallback to another
identity, to a default, or to the caller's own variables, and the program writes no file and runs no shell.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | `-h` or `--help` printed the usage text. |
| 2 | Every refusal, one line starting `refused:` on standard error. |
| 70 | An unexpected internal error: the line `internal error` and nothing else on standard error. |
| otherwise | The command's own exit status, because the wrapper has been replaced by it. |

## Known limits

- It does not stop the command from logging in by itself: `sh -c 'gcloud auth login'` runs, because only the
  plain forms above are denied. Other spellings of the same forms also run, for example a flag before or
  between the words (gcloud --quiet auth login), a link to gcloud under another name, and, on a
  case-insensitive file system, Gcloud auth login; only the plain forms are refused. Other commands that log
  in, such as gcloud init, also run. What the wrapper does is remove the ambient variables and refuse those
  forms.
- A command that reads files under the home directory may find the person's own configuration there, because
  `HOME` is kept.
- The identity's files (`config_dir`, `key_file`) are only as secret as the file system makes them.
- The program checks the shape of the request and the existence of what the file names. It does not know
  whether the identity is valid, usable, or narrower than the one it is meant to replace.
