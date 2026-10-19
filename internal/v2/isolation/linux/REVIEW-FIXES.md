# Draft.4 cross-review disposition

The complete gemini cross read was FIXES-NEEDED. This d4fix1 source starts at
6870b302. The supervisor reported the preceding wip4 source passing both
restriction cells and both builds, 396 PASS with no failure or skip. That
measurement does not cover the changes below. No runtime test ran on Mac.

| Review item | Source change and regression control | Remaining evidence |
| --- | --- | --- |
| P0 production route | Deferred by the supervisor. CONTRACT-GAPS lists each Service method's missing fix-9 authority, descriptor plan, fixed unprivileged entry and completion inputs. No speculative wiring was added. | Reviewed fix-9 contract and actual installed service/helper launch. |
| P0 wave-0 package | Removed by laneboss in the supplied base; no replacement or import is introduced here. | Supervisor publication review of the composed tree. |
| P1 red cleanup | main always invokes cleanup. The case records ownership before start, stops through the CLI, terminates remaining exact PID identities in its exclusive leased UID through pidfds, independently rechecks processes/cgroup, then collects through the CLI. Unknown starts/failed collection retain unknown state; no fabricated receipt or blind clean retry is used. | All public red artifacts must show actual zero survivors and real collection. The component control creates and kills a real detached child but intentionally reports missing service/cgroup evidence as unknown. |
| P1 mount admission | Mount and parent IDs are parsed. A post-pin snapshot must select the active same-target entry, match the descriptor's STATX_MNT_ID and reject aliases or descendants for data, runtime and helper inputs. | TestKernelMountAdmission creates a real tmpfs and bind overmount in a private namespace, reads random bytes through it and records both actual mount IDs. The mount identity/alias mutations must reach its failing assertion. |
| P1 path/Git admission | Source openat2 never pre-resolves symlinks and explicitly rejects a final O_PATH symlink. Main workspace must be a directory. Git administration indirections are rejected before file-type handling. | TestPinRejectsSourceLinks and TestGitAdminIndirections create actual final/ancestor links, common-directory and alternate-store pointers and internal Git-admin symlinks. Restore following/indirection admission and require the named failure. |
| P2 deterministic/UDP observations | Ordered denial checks retain every successful denial; mutation matching includes all recorded successes. Each cell resets reachability and refuses stale output. Outside TCP/UDP listeners count real connections/packets/bytes; a receive timeout cannot erase a successful UDP send. Only measured network attempts with outside zero may time out. TypeError follows the normal failure/finally path. | run_tests.py has a real datagram/no-echo control and a real double-fork cleanup control; the existing eight public red IDs and full cell matrix remain required. |
| P2 frozen invariants | Ready injection binds ordered names, grants, versions and credential slots; names/paths and expiry are checked. Disk/spend/paid-profile bounds and network enums/zero offline leases are checked. Observations require prompt and exclusive signed exit/signal facts. Abort requires prepared state, nil termination and the original generation. Mutable host checks run fresh and survive helper-probe composition. | New contract review tests and the added catalog entries; actual installed failure/recovery and mutable-host tests remain part of Linux acceptance. |

The catalog contains 32 component pairs and preserves the original 19. Its
test2json reader retains child-subtest output so a reached child assertion is
not lost. The catalog's syscall/protocol scopes do not establish installed
production readiness. A setup failure, timeout, unavailable fixture or unrelated
assertion remains an incomplete pair. Each pair must retain the red failure
before the unchanged candidate pass on disposable Linux.
