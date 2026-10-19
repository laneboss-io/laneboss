# Attach sender rows

Run `test_attach_sender.py` only on the designated disposable Linux test
machine. Supply an already built CLI through the absolute `LANEBOSS_BIN` path
and retain the fixtures with an absolute `LANEBOSS_ROW_EVIDENCE` directory.
Python, Git and tmux must be available. The fixture makes no model requests.

Use the same new rows first against the release base, then against the fix:

```sh
LANEBOSS_BIN="/absolute/path/to/base-cli" \
LANEBOSS_ROW_EVIDENCE="/absolute/path/to/base-evidence" \
  setsid -w python3 -m unittest discover -s e2e-rows -p test_attach_sender.py -v
```

Both base rows must fail at the assertion that the stored mail's sender equals
`attach`; a setup error, absent message or cleanup failure is not the intended
regression. Retain the nonzero exit and full transcript. The current release
base records the resolved supervisor ID in that field.

```sh
LANEBOSS_BIN="/absolute/path/to/fixed-cli" \
LANEBOSS_ROW_EVIDENCE="/absolute/path/to/fixed-evidence" \
  setsid -w python3 -m unittest discover -s e2e-rows -p test_attach_sender.py -v
```

The fixed run requires exit 0, two tests, no skips and no errors. Each attach
and turn action retains its exact stdin, stdout, stderr, arguments and exit
code in the fixture. The first row
checks exact Unicode message bytes, their digest and size, the input-source
label, the authenticated actor, a real resumed prompt and delivery. It also
requires a foreign supervisor's attach and a forged `--from attach` to refuse
without changing events. The second row queues a line during a live run, removes
the sender's configured identity and requires a later turn to refuse without
writing a prompt or changing events. Restoring that identity must deliver the
same stored bytes. These assertions fail if the label replaces authentication,
if permission is checked only at enqueue, or if restoring permission loses mail.

The authoritative regression covered by the change is
`tests.e2e.test_attach.KeyboardTest.test_typed_line_is_mail_and_a_turn`.
The two attach interrupt/mail-lock rows and the loop lanes-lock row belong to
the separate mail-lock repair. This change does not modify their lock order.

The runner-edited loop case needs input reconciliation before any product
change: its configuration writer replaces the entire file without retaining
the automatically added org binding and supervisor. Event reads while waiting
do not perform that setup. After the template is restored, source inspection
predicts a missing-policy refusal. Retain the actual skip details
on Linux before classifying the runtime outcome. The role gate must continue
to require a current configured org and its driver policy. The private suite
is read-only; no expectation or helper is changed by these rows.

These commands are verification instructions, not a claim that either run has
been executed. The development lane performs only its authorized static checks.
