# Production startup regression and constructor audit

The run-2 scope fixes host startup before any human or lane operation. Public
health remains the first product RPC after startup in the existing serve driver.
The native secret backend receives the same wallClock instance as the store,
identity, transport, broker and other clocked components. Its Now uses time.Now;
no fixed clock or test-only branch is used in the production graph.

TestProductionStartup is in the assembly package under the Linux-only
laneboss_installed integration tag. It starts the actual installed production
helper/service units, so the real Serve/Build path constructs the whole graph.
It does not replace constructors with memory stores, fake peers, zero-value
services or fixture runners. It rejects build tags on the installed artifact,
requires the real cmd/laneboss main package and pinned executable bytes, and
rejects serve-fixture runtime enrollment. Missing inputs fail rather than skip.

Run the test only on an authorized fresh Linux installation of the untagged
production artifact, with the normal administrator installer, protected boot
inputs and a fresh state directory. Use a separate disposable box from the tagged
lifecycle fixture because a release-version installation is immutable. Obtain
startup_installation from the actual administrator installation receipt.

    sudo -n go test -count=1 -tags laneboss_installed \
      ./internal/v2/assembly -run '^TestProductionStartup$' -args \
      -service-installation "$startup_installation" \
      -startup-evidence /opt/lb-v2-serve-startup-evidence

The evidence directory must not exist. The test retains exact argv, outputs,
exits, installation input and per-invocation journals. It requires a real socket,
the actual process executable pin and public health capabilities for transport,
the complete method registry, the real state snapshot and the native peer.
Any command error, startup prerequisite_missing/not_implemented or other typed
journal error fails. Named units are stopped once and MainPID must become zero.
A refused stop has no alternative route.

The known missing-clock red control is removal of Clock from the native.New
dependency literal in assembly/resources.go. On a separate fresh candidate box,
this test must fail at startup with the native store's actual
prerequisite_missing and no health response; restoring the wiring must permit
startup. Reverting any constructor/registration to its startup scaffold must
likewise fail. These runtime controls and the restored execution have not run
on this Mac. Vet checks compilation and analysis only.

The constructor audit covers every constructor reached by Linux service Build.

| Constructor | Required startup inputs checked and wired |
| --- | --- |
| store.New | Explicit Config, canonical protected Directory, dedicated nonroot UID, real Clock, exclusive writer ownership and valid persisted state. Optional Enrollment is passed from the protected installation. |
| admin.New | Config, service UID, artifact digest, compiled version/protocol/schema, real protected administrator installation, matching installed artifact and effective service UID. Store and runtime/launch references are supplied. |
| peer/linux.New | Real containment registry and actual SO_PEERPIDFD support; there is no PID-only substitute. |
| identity.New | Peer verifier, containment registry, StateStore and Clock. Connections are bound to the actual server. |
| service.New | Store, authenticator and Clock, plus measured executable bytes and installed binding. |
| service.NewServer | Explicit config, binding file and binding, store, authenticator and Clock; real protected binding, artifact, service UID/GID and private runtime directory checks remain. |
| isolation/linux.New | Installed helper and pinned runtime manifest. Actual server LaunchControlSource is supplied. |
| dataworker.New | Store, helper, launcher and Clock, with valid installed Config and actual server MaterializationControl. |
| grants.New | Config, Store, confined Worker and Clock. Actual human verifier is also supplied. |
| native.New | Config, private records Directory, KeyHandle and real Clock. Protected key enrollment is validated and unlocked with the actual installed bytes. |
| secrets.New | Backend, Store, Human, Clock and Config. Grants, Helper, LaunchControlSource and WorkerBootstrap are bound to production objects. |
| judge.New | Store, Clock and default provider adapter. Both configured provider adapters remain lazy and policy-selected; startup makes no model request. |
| policy.NewInstalled | Store, scoped Judge, Clock and bounded command deadline. The source validator calls the actual templates object after graph construction. No positive cost cap is invented; missing approved inference configuration is a method-level refusal. Strict policy.New retains its positive-cap requirement. |
| guidance.New | Store, scoped Judge and real Clock. |
| templates.New | Store, Policy, Publisher and Clock. Real typed RPC handlers are registered; unfinished operations retain their owner errors. |
| claudock.NewInstalled | Config, State, Clock, Sources, Storage, Grants, Credentials, UsageWindows and CaptureControl. Strict claudock.New still validates every missing run callback, pinned vendor and compatibility input before planning/capture. |
| codex.NewInstalled | Installed config in ReadScope, Store, Clock, Sources, Storage, Materialization and UsageWindows. Missing vendor runtime remains a method error; strict codex.New and existing operation checks still validate actual pins and protected per-run context. |
| lifecycle.New | Store, Identity and Clock. Grants, Launcher, Sources, Capture, both real runners, Credentials, Guidance, Templates, Blobs, Worker and Review are bound. Missing operation-only dispatch/review ports remain explicit errors. |
| watchdog.New | Config, Store, Credentials, Lifecycle continuation, Launcher, Claudock, Grants and Clock. It is bound back to lifecycle. |
| messaging.New | Store and Clock. Launcher, credential broker and real channel worker are also supplied. |
| approval.New | Store, Human, Worker, Publisher and Clock. |
| dashboard.New | Store, Human, Lifecycle, Messaging and Approval, all production instances. |
| records.New | Store and Clock. Actual data worker is supplied; additional record/resource worker integration remains operation-specific. |
| migration.New | Store, Human and Worker. Real typed handlers preserve unfinished method errors. |
| distribution.New | Store, Human, Helper, dispatch Control, Installer and Migration. Real typed handlers preserve unfinished method errors. |
| BindRuntime and registration | The exact same store/authenticator are required; actual durable dispatch/effect/launch inventories are inspected. All catalog methods and both streams must be registered before listen. |

The four earlier scaffold packages now validate and retain their real
dependencies and register their actual typed methods at startup. Assembly no
longer constructs zero-value replacements after constructor errors. Their
unimplemented operations still return owner-named failures, never successful
empty results. Policy and vendor adapters distinguish stable installed service
construction from optional operation enrollment; their existing strict New
contracts remain available and unchanged.

Darwin construction remains outside the installed Linux acceptance scope; the
Darwin build is vetted, not claimed as a native startup result. Raw judge provider
constructors are operation-lazy and still require approved endpoints, deployment
pins and private provider-specific bindings. None is called by the startup test.
