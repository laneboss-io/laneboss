# Installed fake-key canary

Laneboss runs this entry on the authorized disposable Linux machine after its
serve checks. From the supplied candidate checkout, run:

```sh
bash e2e/v2/cases/canary/run.sh \
  --source /test/candidate \
  --evidence /test/evidence/lb-v2-r3canary
```

The entry selects the real pinned vendor executables, enrolled API egress and
ephemeral fake key. After initial profile publication, the harness reads the
published profile manifest through the installed service. It creates a private,
root-owned balance executable and passes its configuration file to the installed
`internal helper --spend-reconcile` entry. The CLI executes the tool and sends
its exact stdout through native administrator IPC. The service commits the
reading through the existing spend writer.

`CANARY  10.00 USD` is a fixed **fake reading**, with a 5 USD floor. It describes
test data, no vendor balance or spending authority for a real account. The
retained tool source, administrator input, exact CLI stdout/stderr/exit and
`canary-spend.fixture.json` identify it explicitly. The response must contain
the expected fresh, unfenced balance before lane dispatch. Its actual receipt
is retained in `canary-spend.balance.json` and the `admin.publication` observation.
An enrollment refusal or mismatched receipt stops the run. The spend guard is
unchanged, and no harness code opens or writes the database.

For a real credential, the operator instead uses the pool's actual balance tool
and protected configuration described in `docs/v2/spend.md`. Never reuse this
fake reading with a real credential. This canary is not an authenticated
AI-service test, and hardware presence remains simulated.

The Linux root package entry `TestCanarySpendHarness` executes eight Python
harness controls. On base `3358c5c3`, they fail because the protected tool and
enrollment step are absent, dispatch precedes enrollment, and the administrator
route rejects `spend-reconcile`. CLI boundary stubs test harness behavior only.
The unprivileged Linux `TestSpendLedger/missing_reading` control separately
requires the real store guard to refuse a credential without a reading.
Only an installed lifecycle report satisfying all existing serve checks can
establish an installed E2E result. Laneboss owns that run and its first refusal.
