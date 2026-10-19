# Primary signal provenance and creator lifetime: run 35

Green33 on 2b1e4ce4 passes the former option refusal, then reports failed
readiness with EOF, SIGKILL, no bootstrap report and bwrap_stderr=other.
The retained log has 526 lines, 72,598 bytes and digest prefix a0a985a7c6fefd20.
It has no cgroup event counters, limit readbacks, helper-kill record or creator
task observation. That evidence does not identify the SIGKILL sender. No
installed OOM, parent-task-death or seccomp attribution is claimed here.

## Findings and narrow repairs

The production gate's nativeGateAttributes does not set Go Pdeathsig. The
separate availability probe does set it, but that is not the failing gate
constructor. The gate still passes bwrap --die-with-parent. Linux parent-death
notification is tied to the creating task: the helper process remaining alive
is insufficient if its creating OS thread terminates. Previously the launch
thread was unlocked after Start and namespace restoration. The candidate now
retains that dedicated locked thread through actual primary exit.

The lifetime owner is created before Start and is mandatory for production
gate creation. Namespace entry, UID/GID/group dropping, atomic cgroup placement
and namespace restoration retain their existing order. A successful launch
restores the original network namespace, reports Start, then keeps its thread
locked until an actual primary pidfd event or terminal Wait. Observation
errors do not close that lifetime. A failed restoration still refuses; if
created-child death cannot be measured, the thread stays quarantined rather
than returning an altered namespace to the executor pool. The existing native
kill and wait routes remain. Bwrap stays unprivileged and die-with-parent is
retained, so whole-helper death still applies that policy.

The readiness collector previously called Close before collecting the final
status. Close could send SIGKILL to a still-exiting bwrap after its readiness
descriptor had closed, replacing the natural setup status. The candidate
records facts on refusal and immediately before stop. For an already-failed
EOF, it allows at most 100 ms for natural termination, then follows the same
mandatory stop path if still live. This does not extend the readiness deadline
or admit a later packet. Close skips a signal only for measured termination;
a live or unavailable lifetime still takes the explicit pidfd stop route.
The actual send result is recorded separately from the actual terminal Wait.

The configured isolation probe budget remains 256 MiB, 64 tasks, five wall/CPU
seconds and bounded disk. resources_linux.go and isolationBudget are unchanged.
No OOM or task-exhaustion measurement supports resizing it yet. The kernel's
read-back values are now reported as ranges, including below_64MiB or
at_least_256MiB, and below_16/16_to_63/at_least_64 tasks. Unlimited or missing
readback is named explicitly; it is never silently replaced with the request.

The native bootstrap seccomp filter is unchanged. Its KILL_PROCESS actions
guard architecture/x32 mismatches; ordinary denied syscalls return errno and
clone3 returns ENOSYS. The isolation filter retains its architecture kill
guards too. A seccomp kill action normally terminates with SIGSYS, not the
observed SIGKILL. No specific missing syscall has been measured and no filter
allowance, unit policy, capability or namespace restriction is relaxed.

## Facts emitted by the failing gate

The gate reads memory.events, pids.events, memory.max and pids.max through the
same pinned cgroup directory used for creation. It verifies a cgroup-v2
filesystem and directory, uses fixed no-follow leaf names and bounds reads.
Ordinary files, malformed/duplicate counters, unavailable reads and unknown
fields do not become observed zeroes. The before sample precedes Start; the
after sample follows failure collection while the same directory is pinned.

| Field | Actual source and closed result |
| --- | --- |
| oom_before / oom_after / oom_delta | memory.events oom; zero/positive/unavailable and increased / unchanged / decreased / unavailable. |
| oom_kill_before / oom_kill_after / oom_kill_delta | memory.events oom_kill, with the same validity and delta rules. An increase is scoped cgroup evidence, not unique proof of which actor won a concurrent signal race. |
| pids_max_event_before / after / delta | pids.events max; missing reads remain unavailable. A task-limit event by itself does not prove a SIGKILL cause. |
| memory_max / pids_max | Kernel readback before and after as fixed ranges, unlimited or unavailable. No raw settings object is printed. |
| on_refusal / before_stop primary | Actual terminal Wait, or native pidfd poll; live/exited/waited/unavailable. |
| helper_kill | Actual pidfd_send_signal result or measured reason no signal was needed; sent, already_ended, not_needed_waited, not_needed_exited, a fixed failed errno category, or not_requested. Sent does not alone prove unique causality. |
| spawn_thread | Retained creator ownership plus actual helper task presence; locked_present, released, missing or unavailable. No TID is printed. |
| spawn_pdeathsig | The actual Go spawn attribute: none, SIGKILL, other or unavailable. This does not claim to remotely read bwrap's later prctl setting. |
| bwrap_die_with_parent | Requested/not_requested from the actual in-memory argv before its delimiter; no argv is printed. |
| primary_seccomp / primary_nnp | Bounded actual process status read between two live checks on the same pidfd; fixed mode/set/unset categories or unavailable. No capability bitmap, process ID or arbitrary status line is emitted. |

The original failed readiness case, actual wait, bootstrap reason, bounded
stderr category and final stop marker remain in the refusal. No diagnostic
field can continue into credentials, namespace acceptance or release.

## Stderr operation families

The diagnostic prefix bound, freeze behavior, owned sink and exact forwarding
remain unchanged. Seventeen operation families extend the original closed
vocabulary. Unknown input remains other and never becomes raw output.

| Family | Recognized setup message forms |
| --- | --- |
| namespace_setup_failed | Namespace creation errors outside the existing permission-denied category. |
| userns_policy_failed | disable/assert-userns prerequisite or disable-policy failures. |
| mount_source_unavailable | Can't find/resolve source path, or stat a source. |
| bind_mount_failed | Can't/failed to bind mount. |
| destination_create_failed | Directory/file creation failures. |
| mount_propagation_failed | Make root slave/remount failures. |
| root_switch_failed | pivot_root failures. |
| cwd_failed | chdir failures. |
| capability_setup_failed | capset or capability setup failure. |
| parent_death_setup_failed | Parent-death prctl setup failure. |
| no_new_privileges_failed | NNP prctl setup failure. |
| child_sync_failed | Child/eventfd synchronization failure. |
| seccomp_setup_failed | Seccomp setup/load/prctl failure. |
| process_create_failed | Fork/clone setup failure. |
| allocation_failed | Bwrap allocation failure. |
| runtime_memory_failed | Bootstrap runtime memory-startup failure. |
| runtime_thread_failed | Bootstrap runtime OS-thread creation failure. |

These parser fixtures are source-defined examples of operation forms, not
retained output from the installed 0.9.0 failure. Green34 must supply that
observation. The existing mount_failed category also accepts Failed to mount.

## Regressions and controls

No runtime canary or control ran on the authoring Mac. Eight new regression
functions and 33 new controls are compiled/vetted, with Linux reached-red and
candidate execution still required. The catalog has 417 IDs. All 384 prior
IDs remain; native-spawn-success and native-spawn-route are re-anchored to the
shared real Start/error path without changing their test or deciding assertion.
The remaining 382 rows and all runner ownership roots/allowlists are unchanged.

| Regression | Deciding controls and failure |
| --- | --- |
| TestNativeCreatorLifetime starts a real child with Go's pre-exec parent-death signal and the actual child prctl, checks its nonce/real pidfd/task presence after Start returns, then observes actual Wait and creator release. A nil Wait cannot release it. | creator-held releases ownership early; creator-thread-exit forces a locked Goexit and actual kernel parent-death behavior. Both must fail the live-child assertion. creator-wait-release omits terminal-Wait release and must fail actual creator collection. This is a real mechanism canary, not installed green33 attribution. |
| TestNativeCreatorRefusals checks nil/empty owners before a child can start and a real missing executable's typed private refusal. Unexpected test children are independently waited. | creator-owner-required admits the invalid owner and must fail the no-child assertion. |
| TestNativeReadinessCauseFacts/setup closes the real readiness socket after emitting a private mount-source message, then exits naturally after a short teardown. The natural exit 1 and no helper kill must remain visible. | cause-eof-collection removes the bounded collection interval and must replace that exit with helper SIGKILL. cause-facts-required removes the on-refusal field and must fail provenance. The Linux pair must reach the intended timed assertion; a wrong failure is not a kill. |
| TestNativeReadinessCauseFacts/deadline keeps an actual child live until the real helper stop, then requires its SIGKILL wait plus the actual sent record. | cause-helper-kill omits the syscall; cause-helper-label mislabels its real successful result. Both must fail signal/provenance. Fixture cleanup independently stops the exact child if a control disables production stop; failure is retained. |
| TestNativeEventFacts uses varied counter bytes, duplicate/overflow/invalid inputs and independent before/after expectations. | event-value-source fabricates zero, event-duplicate-refusal admits a duplicate, event-delta-known admits unknown input and event-counter-known reports unknown as zero. Each has a distinct assertion. These are parser checks, not synthetic kernel receipts. |
| TestNativeCgroupSource supplies ordinary files with plausible counter names and requires unavailable facts. | event-kernel-source removes filesystem identity and must fail ordinary-file rejection. |
| TestNativeLimitRanges checks memory/task boundaries, unlimited and invalid bytes. | limit-memory-class and limit-pids-class misclassify real input bytes and must fail their range assertions. No limit writer is weakened. |
| TestNativeProcessSecurity checks differing, duplicate, missing and private status inputs. | status-filter-source substitutes none for an actual parsed filter and must fail its input/privacy assertion. |
| TestSetupCategories covers all seventeen new operation families with private randomized suffixes. | Each setup-* control removes only its own category and must fail that named subtest's closed-operation assertion. Raw stderr and a build error are never a passing control result. |

Green34 must get past step 42 or name its next failure precisely. Retain all
new ordinary/faults reached-red/candidate pairs and the actual failing gate's
counter/limit, helper-signal, creator, security-mode and stderr categories.
Do not attribute an installed sender from source inspection or parser data.
Keep the original bounds and restrictions unless the new measurements prove
the particular cause. Full native installed qualification remains required.
Presence is simulated and human_approval=not_proven; no authenticated AI-service
result is claimed.
