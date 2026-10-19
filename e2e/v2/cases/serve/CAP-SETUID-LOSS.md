# CAP_SETUID loss: measured cause and regression contract

Green29 on 4d73e6ea now confirms that fix: the startup CAP_SETUID effective,
permitted and bounding observations are present and the gate child spawns.
The next blocker is closed bootstrap readiness, not the old capability loss.
Run 31 extends startup to root real/effective/saved UIDs and an exact
template-derived permitted set. See [the readiness handoff](BOOTSTRAP-READINESS.md)
for the current failure, controls and green30 contract. The run-30 account
below records the original fix regression boundary and its earlier forecast.

Run 30 locks in the supervisor's fix, commit 4d73e6e.
The cause is the helper's measured systemd property combination with explicit
User=root and NoNewPrivileges=yes. The helper template now omits User= and uses
the system manager's default root identity. This run does not change that unit
or the supervisor's empty-User observation fix.

## Measured scope

The disposable box lb-v2-capbisect1 ran systemd 255.4-1ubuntu8.17 on kernel
7.0.0-1014-aws. The suite is retained at
~/.local / state / laneboss-top / runs / v2-capbisect-suite.sh; its exact log is under
~/.local / state / laneboss-top / evidence / lb-v2-capbisect1-verify-evidence / 
as verify-2d9b035f-20261017-025756.log. Run 30 retains those exact input/log
bytes, hashes and 42 parsed fixed-name probe verdicts in its private evidence.
Raw capability bitmaps, runtime arguments and settings are not published.

| Transient-unit probe | Process permitted result |
| --- | --- |
| Full helper property set, including User=root and NoNewPrivileges=yes | CAP_SETUID absent; CAP_SETGID and CAP_SYS_ADMIN present. |
| Full set with only User removed | CAP_SETUID present. |
| Full set with only NoNewPrivileges removed | CAP_SETUID present. |
| Full set with any other single property removed | CAP_SETUID absent. |
| User=root baseline, or any individual property with User=root | CAP_SETUID present. |

This identifies the property interaction in that tested full set on that
systemd build/kernel. It is not a universal rule for every systemd version,
kernel or pair of properties in isolation. The earlier green27 launch-thread
absence and spawn EPERM are no longer an unexplained capability-loss origin.
The bisect does not independently trace which child setup syscall first failed.

The supported fix removes only the explicit User directive. Group=root,
NoNewPrivileges=yes, RestrictSUIDSGID=yes, the declared bounding set and empty
ambient set remain. The installed-policy report maps empty effective User to
User.root=default, root/0 to yes, and other values to no. Installation must
still retain and compare actual fragment, combined unit/drop-ins, selected
effective properties and systemd version.

## Startup refusal

runPlatformHelper calls helperBeforeAccounts before any service/pool account
verification. It reads the fixed /proc/self/status once, retains the existing
helper.before_accounts CAP_SETUID observation, and refuses if the process
permitted set lacks CAP_SETUID, CAP_SETGID or both. The single administrator
prerequisite_missing error names the missing capability names and directs the
operator to the installed laneboss-helper systemd unit and its
User/NoNewPrivileges policy. An unreadable or malformed status also refuses
with a typed prerequisite diagnostic; logging alone cannot let startup pass.

The existing bounded reader still requires unique, complete CapEff/CapPrm/
CapBnd fields and closes its descriptor. Its parser now also extracts the
CAP_SETGID permitted bit. The existing CAP_SETUID observation format stays
compatible with journal collection. Unknown raw fields and private values do
not escape. This process/leader checkpoint does not replace the failure-time
calling-thread observation or the actual native credential-drop proof.

No production capability is added or restored. UID/GID and empty-group drops,
UseCgroupFD placement, namespace restoration, mounts, native lifetime ownership,
Landlock/seccomp and the complete independent confinement proof remain required.

## Regressions and deciding controls

The ordinary mutation catalog keeps all 321 preceding IDs and adds eight, for
329. Every new row edits one actual source anchor and names the exact deciding
assertion. All controls require reached-red followed by candidate pass on
Linux in ordinary and laneboss_faults builds. Static inspection of an anchor
does not establish its runtime kill.

| Regression / control | What must make the named check fail |
| --- | --- |
| TestHelperCapabilities / helper-user-nnp | Reinsert User=root before Group=root in the actual repository template. The deciding assertion is helper unit combines User= with NoNewPrivileges=yes. The test reads that file through helperUnitFixture in the nearest module, from either package or copied source-root cwd. A missing file or synthetic fixture is not this red. |
| TestHelperCapabilities / helper-nnp-required | Change the actual NoNewPrivileges directive to no. The hardening assertion must fail. |
| TestHelperCapabilities / helper-suid-required | Change the actual RestrictSUIDSGID directive to no. The same hardening assertion must fail. |
| TestHelperCapabilities / existing helper-drop-setuid and helper-drop-setgid | Omit either required bounding capability. The credential-drop assertion must fail; the existing namespace/stop and unused-capability assertions remain. |
| TestHelperBeforeAccounts/setuid / helper-startup-setuid | Disable the actual missing-permitted-UID guard. Parsed input has GID permitted and UID absent, with UID present in the other sets; the typed missing-capability assertion must fail. |
| TestHelperBeforeAccounts/setgid / helper-startup-setgid | Disable the actual missing-permitted-GID guard. Parsed input has UID permitted and GID absent, with GID present in the other sets; the typed missing-capability assertion must fail. |
| TestHelperBeforeAccounts/present / helper-startup-gid-source | Invert extraction of the GID permitted bit. Both permitted bits are present while their effective/bounding bits are absent; startup must incorrectly refuse and reach the positive assertion. |
| TestHelperBeforeAccounts/both | The one error must name both missing capabilities. Removing either missing-bit guard also invalidates this case; the catalog's focused guard controls isolate the UID and GID decisions individually. |
| TestHelperBeforeAccounts/unavailable / helper-startup-unavailable | Disable the status-error guard. Random malformed input must no longer produce the required unavailable-input diagnostic, reaching its typed/privacy assertion. |
| TestProcessSetUIDNative / helper-process-gid-native | Invert the GID permitted-bit extraction. The parser must disagree with independent leader capget and reach its GID assertion. Existing independent UID parser/native controls remain. |
| HelperPolicyControls.test_user_root_default_and_explicit | Actual empty, root, 0 and random other User inputs must yield default, yes, yes and no, with no private-value leak. For the deciding red, change only the empty-User default verdict in provision.py from default to yes; the empty subtest must fail User.root ignored the effective User field. |

Run the three Python methods with python3 -m unittest discover -s
scripts/v2-serve -p helper_policy_test.py on the authorized Linux machine.
The two earlier field/privacy and malformed-input controls remain documented:
substitute CAP_SETGID for the CAP_SETUID membership predicate to fail the
absent-UID assertion; remove the duplicate-property guard to fail the expected
ValueError assertion. None of these Python tests or controls ran on this Mac.

TestProcessSetUID still checks independent effective/permitted/bounding UID
combinations and malformed inputs, and now checks GID permission too.
TestInstalledProcessThreadCaps remains a separate required installed root
canary, including its thread-self-path and constant-reader controls. Preserve
the real kernel bit-loss canaries, locked-thread retirement and complete
TestInstalledIsolationProof; startup and unit component regressions do not
substitute for those native observations.

## Verification and next installed result

The run-30 candidate passed all 16 static vet configurations with the shared
Go cache, local Go 1.26.5, readonly modules and downloads disabled: admin and all
production/test importers for Linux amd64/arm64 default, faults,
partial/authenticator, combined, integration and integration/faults; Darwin
amd64/arm64 default and partial/authenticator. Python compilation covers every
serve script. Formatting and diff checks passed. Exact input/source bytes,
commands, outputs and exits are retained outside the checkout.

No runtime test, mutant/control overlay, installed service, provisioning or
model request ran on this Mac. Runtime red/candidate qualification remains
the supervisor's Linux responsibility. Green29 was already running on the
fix revision when this brief arrived; this lane does not poll or start
another run.

The next installed candidate must pass helper.before_accounts, retain the
actual installed default-root policy and progress past lane.claudock.start.
If another gate fails, report that actual first failure with its owner/code
and retained observations; do not predict or fabricate a higher PASS count.
A missing permitted bit must instead stop helper startup with the new typed
unit diagnostic. Software presence remains simulated,
human_approval=not_proven, with no authenticated AI-service test.
