# Completed launch observation and native cleanup composition

The candidate starts at 3acf9ec4. Linux runtime evidence is pending the
supervisor's merge with serve2b round 4 and disposable debug machine. Mac vet,
catalog inspection and Python compilation are static evidence only.

`service.Server.Observe` now uses the installed store's
`ProcessObservationAuthority` port. Under one store read lock it resolves the
exact persisted helper handle, validates the original identity event and
recovery binding, and requires the current lane life/run/launch, immutable
launch identity and matching endpoint ownership. A successful original
PlanLaunch outcome, with its exact process and full plan, permits read-only
running/quiescence observation after that launch claim has completed.
An incomplete or failed launch still needs the existing actual stage claim.
Fixed workers retain that claim route. Stop, Open, Abort and Release continue
to use their original claimed effects. Revoking a run's identity and endpoint
does not remove the installed service's responsibility to measure that same
current containment; a replaced or cleaned run cannot use this authority.

The store is now constructed with a private `helperCleanupNative` capability.
After `admin.New` validates the real installed client, assembly binds that
concrete client once, before publishing the server. All three callbacks call
the real administrator client: workspace resolution, removal-journal read and
independent workspace read. The capability returns the helper's result or
error unchanged. It has no successful unbound path. Store readiness consults
the binding, so a nonnil unbound forwarding capability cannot enable Clean.

`TestCompletedLaunchObservation` completes actual SQLite launch effects, proves
there is no remaining stage claim, and checks running and ended observation
requests. It also refuses unclaimed stop and release. The ownership control
rejects changed handles, life, containment, process generation, stale run,
foreign launch, cleaned run and changed current launch ownership.
`TestUncompletedObservationStillClaims` refuses an unclaimed in-flight launch
and then accepts an actual retained Stop claim. `TestCleanWithoutNativePort`
uses the real store and dispatch gate; `TestCleanupNativeUnbound` uses the real
store and private forwarding capability. Neither installs a fake native port.

The installed lifecycle harness already waits for successful launch operation
completion before its real CLI running check. Clean now also reads the
root-owned native enrollment and actual helper cleanup journal, verifies the
original operation, run, intent and claim, and independently measures the
enrolled filesystem and Git branch namespaces. Dirty work must remain with
the original directory identity; clean removal must leave both namespaces
absent. Exact inputs, command outputs and hashes are retained. The stand-in
agent writes a workspace transcript, so retained dirty work is an allowed,
measured outcome, never a reason to force removal.

The supervisor can run the two installed build cells from the merged checkout
on separate fresh authorized disposable Ubuntu 24.04 machines, one machine at
a time. Collect the first machine before starting the second: the installed
release path is immutable and these two artifacts have different hashes.

```sh
python3 -I -B scripts/v2-serve/native_cleanup_control.py \
  --source "$PWD" --evidence /opt/lb-v2-serve2-r42-missing --mode missing
python3 -I -B scripts/v2-serve/native_cleanup_control.py \
  --source "$PWD" --evidence /opt/lb-v2-serve2-r42-candidate --mode candidate
```

Each cell preserves the source Git metadata. The missing cell changes only the
protected disposable build copy's `CleanupNative: cleanup` to
`CleanupNative: nil`, retains exact before/after bytes and builds the actual
installed artifact. It must pass the real start/running/stop/quiescent/abandon/
archive prerequisites and stop at `lane.claudock.clean`, with the exact
`not_implemented`, owner `lb-v2-admin`, message
`installed protected cleanup native ports is not implemented`. An earlier refusal cannot pass the
control. Its installed report remains failed; the wrapper credits only the
specific negative control. The candidate cell requires all installed rows and
both drivers' native cleanup journal/namespace evidence. Any unexpected result
stops the cell; retain the machine and failure evidence for review. No test
machine was provisioned or runtime cell executed in this authoring run.

Seven service mutation controls and one integration readiness control nominate
the deciding tests and failures. Run those red/candidate pairs on Linux before
crediting the new tests. No control overlay was vetted or executed on Mac.
The fixture provenance remains `presence=simulated` and
`human_approval=not_proven`; it does not authenticate to an AI service.

Static follow-up for serve2b: the starting tree's
`lifecycle/revocation.go` asks for `RevocationEndpoint`, but no concrete store
method with that name is present. Its revoked `IdentityBindings` write also
meets `store/authority.go`'s `record.Revoked` refusal for new identity binding
stamping. These are source-trace findings for the lifecycle owner, not observed
runtime failures. This candidate changes neither lifecycle, the read-view
checks nor the planner authentication files.
