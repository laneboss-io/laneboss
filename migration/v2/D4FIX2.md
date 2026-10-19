# Migration combined-tree fix 2

The input tree is `d60bd08`, the migration checkpoint plus the combined
draft.4 fixes 3 through 7. This round is restricted to static checks on macOS.
It cannot establish a post-fix unit-test pass or a runtime mutation kill.

The command adapter now registers migration.plan and migration.apply with the
method-owned input registry. Each callback exact-decodes its request and uses
the ergonomic handler's semantic validator. The decisions migrate file form
shares the plan registration. Unsupported source versions, malformed object
IDs or digests, out-of-range sizes, wrong manifest classes and invalid plan IDs
refuse before proof reads, key generation or transport. The callback cannot
change the retained body.

CLI tests moved from internal/v2/migration/cli_test.go to the feature-owned
internal/v2/cli/commands_migration_test.go. This allows an injected connection
through the common invocation without a new production hook or binding lookup.
The ownership rule in docs/design/v2-lanes.md assigns feature command tests to
their feature owners. The test keeps local flag/file/symlink assertions and
requires exact typed failure identity, every error field against a pre-call
value snapshot, exit 69,
empty success output, correct request bodies, method order and borrowed
connection ownership. Both transport errors and RPC error replies are covered.

The migration source reader preserves typed dependency errors unchanged,
including unavailable, forbidden and cancelled. Missing referenced objects
still become migration integrity errors, preserving the incomplete-source red
control. The propagation fixture now supplies its own StateStore read boundary
and verifies the actual scoped object/offset/limit; no concrete service,
identity or dataworker stub is used.

The continuation brief supplies the pre-fix runtime evidence from the combined
Linux tree at 28c5a55. The post-fix runtime result remains pending until the supervising
Linux run observes it. Static compilation or inspection is not a test pass.

| Named test | Supplied pre-fix failure | Changed assertion and expected deciding behavior |
| --- | --- | --- |
| TestStubDependencyPropagation | A real closed writer returned unavailable, which migration wrapped as integrity instead of the expected service-stub error. | Four injected typed failures must return the exact original error object and unchanged field snapshot after one correctly scoped blob read. Wrapping, replacing, mutating or swallowing the failure fails the test. |
| TestCLIMigrationCommands: valid-plan | The common file form stopped at the missing migration.plan validator. | The exact file form must pass registered semantic validation and reach the injected RPC boundary, then preserve its exact failure. Missing registration or altered body fails the test. |
| TestCLIMigrationCommands: valid-decisions-migrate | A real client returned a protected-binding prerequisite instead of the expected stub error. | The alias must submit its typed plan to the injected connection and preserve its failure. No installed client or binding is consulted. |
| TestCLIMigrationCommands: committed-plan-with-session-proof | The installed-binding result differed from the expected stub result. | The same injected connection must first receive a valid human.session call and then a proof-free migration.plan call, whose precise error is preserved. Stopping at session setup, wrong ordering or reopening/closing the connection fails the test. |
| TestCLIMigrationCommands: valid-apply | The installed-binding result differed from the expected stub result. | The injected connection must receive the exact plan ID and retained key and preserve its precise failure. |
| TestCLIMigrationFileInputValidation | This is a new regression case; no pre-fix runtime result was supplied for it. | Every shape-valid semantic negative must return the exact migration-owned invalid_request message before deliberately missing proof/binding files can be read. A missing validator or one that accepts everything fails these cases. |

Run the named cases on the authorized disposable Linux machine in both normal
and laneboss_faults builds. CLI command tests now belong to the cli package:

```sh
go test ./internal/v2/migration -run '^TestStubDependencyPropagation$'
go test ./internal/v2/cli -run '^TestCLIMigration(Commands|FileInputValidation)$'
go test -tags laneboss_faults ./internal/v2/migration -run '^TestStubDependencyPropagation$'
go test -tags laneboss_faults ./internal/v2/cli -run '^TestCLIMigration(Commands|FileInputValidation)$'
```

The complete combined-tree unit suites and the eleven existing migration
mutations remain required. Their source anchors, focused tests and diagnostics
must be checked again on these final bytes. No prior green result substitutes
for the named post-fix runs.
