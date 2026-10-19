"""Named deliberate faults for disposable Linux copies, never production flags."""

BASE = "internal/v2/secrets/"
NATIVE = BASE + "native/store.go"
RECOVERY = BASE + "native/recovery.go"
WIRE = BASE + "wire/wire.go"
BROKER = BASE + "broker.go"
SERVICE = BASE + "service.go"
STAGING = BASE + "staging.go"
CONTRACT = BASE + "contract_stubs.go"
CLI = "internal/v2/cli/commands_secrets.go"
PACKAGE = "./internal/v2/secrets"


def edit(path, function, before, after):
    return {"path": path, "function": function, "before": before, "after": after}


def mutation(name, rule, scope, package, tests, edits):
    return {"id": name, "rule": rule, "scope": scope, "package": package,
            "tests": tests, "edits": edits, "available": True}


CATALOG = [
    mutation("record-aad", "tampered stored AAD refuses", "backend", PACKAGE + "/native",
             ["TestEncryptedRoundTrip", "TestRecordTamper"], [
        edit(NATIVE, "func seal(", "plain, aad(*r))", "plain, nil)"),
        edit(NATIVE, "func open(", "r.Ciphertext, aad(r))", "r.Ciphertext, nil)"),
    ]),
    mutation("record-tag", "tampered ciphertext refuses", "backend", PACKAGE + "/native",
             ["TestRecordTamper"], [
        edit(NATIVE, "func open(",
             'return nil, wire.Error(api.CodeIntegrity, "encrypted secret authentication failed")',
             "return plain, nil"),
    ]),
    mutation("record-nonce", "new nonce for every stored version", "backend", PACKAGE + "/native",
             ["TestImmutableAndRevoke"], [
        edit(NATIVE, "func seal(", "r.Ciphertext = aead.Seal(",
             "clear(r.Nonce)\n\tr.Ciphertext = aead.Seal("),
    ]),
    mutation("plain-record", "secret values stay out of persisted metadata", "backend", PACKAGE + "/native",
             ["TestEncryptedRoundTrip"], [
        edit(NATIVE, "func (s *Service) storeLocked(",
             'return s.directory.Write(string(info.SourceHandle)+".json", data)',
             'if err := s.directory.Write("fault-value.tmp", material.Bytes); err != nil {\n'
             '\t\t\treturn err\n\t\t}\n'
             '\t\treturn s.directory.Write(string(info.SourceHandle)+".json", data)'),
    ]),
    mutation("key-fallback", "restart requires protected unlock", "backend", PACKAGE + "/native",
             ["TestRestartRecovery"], [
        edit(NATIVE, "func (s *Service) storeLocked(",
             'return s.directory.Write(string(info.SourceHandle)+".json", data)',
             'if err := s.directory.Write("fault-key.tmp", s.keys[info.KeyID]); err != nil {\n'
             '\t\t\treturn err\n\t\t}\n'
             '\t\treturn s.directory.Write(string(info.SourceHandle)+".json", data)'),
        edit(NATIVE, "func New(",
             "return &Service{deps: deps, directory: directory, keys: make(map[api.ID][]byte)}, nil",
             "service := &Service{deps: deps, directory: directory, keys: make(map[api.ID][]byte)}\n"
             '\tkey, readErr := directory.Read("fault-key.tmp", 32)\n'
             "\tif readErr == nil {\n\t\tservice.keys[deps.KeyHandle] = key\n\t}\n"
             "\treturn service, nil"),
    ]),
    mutation("recovery-aad", "recovery binds config and key ID", "backend", PACKAGE + "/native",
             ["TestRecoveryTamper"], [
        edit(RECOVERY, "func (s *Service) SealRecovery(", "s.keys[id], recoveryAAD(r))", "s.keys[id], nil)"),
        edit(RECOVERY, "func (s *Service) Recover(", "r.Ciphertext, recoveryAAD(r))", "r.Ciphertext, nil)"),
    ]),
    mutation("source-version", "only exact enrolled source and version fetches", "backend", PACKAGE + "/native",
             ["TestGrantMismatch"], [
        edit(NATIVE, "func (s *Service) Fetch(",
             "if r.Info.Name != grant.Name || r.Info.Version != grant.Version {",
             "if false && (r.Info.Name != grant.Name || r.Info.Version != grant.Version) {"),
    ]),
    mutation("version-reuse", "secret source versions are immutable", "backend", PACKAGE + "/native",
             ["TestImmutableAndRevoke"], [
        edit(NATIVE, "func (s *Service) storeLocked(",
             'return wire.Error(api.CodeConflict, "secret source and versions are immutable")', "return nil"),
    ]),
    mutation("revoke-ignore", "revoked sources cannot fetch", "backend", PACKAGE + "/native",
             ["TestImmutableAndRevoke"], [
        edit(NATIVE, "func (s *Service) Fetch(", "if r.Info.Revoked {", "if false && r.Info.Revoked {"),
    ]),
    mutation("private-mode", "encrypted records require private mode", "backend", PACKAGE + "/native",
             ["TestUnsafeFilesRefuse/public"], [
        edit(BASE + "private/files.go", "func owned(", "info.Mode().Perm() == mode", "info.Mode().Perm() == info.Mode().Perm()"),
    ]),
    mutation("private-links", "record hardlinks refuse", "backend", PACKAGE + "/native",
             ["TestUnsafeFilesRefuse/hardlink"], [
        edit(BASE + "private/files.go", "func (d *Directory) open(", "if !ok || stat.Nlink != 1 {", "if !ok || false && stat.Nlink != 1 {"),
    ]),
    mutation("stage-aad", "sealed upload authenticates exact AAD", "crypto", PACKAGE,
             ["TestSealedUpload"], [
        edit(STAGING, "func SealStage(", "material.Bytes, aad)", "material.Bytes, nil)"),
        edit(STAGING, "func openStage(", "request.Ciphertext, aad)", "request.Ciphertext, nil)"),
    ]),
    mutation("stage-salt", "sealed upload uses SHA-256 of AAD as salt", "crypto", PACKAGE,
             ["TestSealedUpload"], [
        edit(STAGING, "func stageCipher(", "salt := sha256.Sum256(aad)", "salt := sha256.Sum256(nil)"),
    ]),
    mutation("reserved-env", "reserved launcher variables refuse", "preflight", PACKAGE + "/wire",
             ["TestTargetBlacklist"], [
        edit(WIRE, "func EnvTarget(", '\tupper := strings.ToUpper(value)',
             '\tif value != "" { return true }\n\tupper := strings.ToUpper(value)'),
    ]),
    mutation("file-traversal", "file delivery cannot escape its runtime root", "preflight", PACKAGE + "/wire",
             ["TestTargetBlacklist"], [
        edit(WIRE, "func FileTarget(", "if len(value) == 0 ||", "if value != \"\" { return true }\n\tif len(value) == 0 ||"),
    ]),
    mutation("secret-subset", "undelegated task source refuses", "preflight", PACKAGE,
             ["TestGrantSelection"], [
        edit(BROKER, "func (s *Service) Inject(", "if !found {", "if false && !found {"),
    ]),
    mutation("profile-subset", "task source cannot choose another login", "preflight", PACKAGE,
             ["TestProfileSelection"], [
        edit(BROKER, "func (s *Service) Acquire(", "if !found {", "if false && !found {"),
    ]),
    mutation("profile-expiry", "expired login grants refuse", "preflight", PACKAGE,
             ["TestProfileExpiryAndDriver"], [
        edit(BROKER, "func validateProfile(", "if !future(grant.ExpiresAt, now) {", "if false && !future(grant.ExpiresAt, now) {"),
    ]),
    mutation("stale-grants", "revoked grant sets refuse", "preflight", PACKAGE,
             ["TestGrantSelection"], [
        edit(BROKER, "func (s *Service) currentGrants(", "grants.Revoked ||", "false && grants.Revoked ||"),
        edit(BROKER, "func (s *Service) currentGrants(", "current.Revoked ||", "false && current.Revoked ||"),
    ]),
    mutation("cleanup-running", "running containment cannot release a slot", "preflight", PACKAGE,
             ["TestCleanupNeedsQuiescence"], [
        edit(BROKER, "func quiescent(", 'observation.State != "exited" ||', 'false && observation.State != "exited" ||'),
    ]),
    mutation("cleanup-survivors", "surviving processes block release", "preflight", PACKAGE,
             ["TestCleanupNeedsQuiescence"], [
        edit(BROKER, "func quiescent(", "*observation.Survivors != 0 ||", "false && *observation.Survivors != 0 ||"),
    ]),
    mutation("human-proof", "secret mutation needs a human operation proof", "preflight", PACKAGE,
             ["TestMutationStopsBeforeProof"], [
        edit(SERVICE, "func (s *Service) human(", "if proof && scope.Request.Proof == nil {", "if false && proof && scope.Request.Proof == nil {"),
    ]),
    mutation("stage-principal", "sealed stages cannot cross human principals", "preflight", PACKAGE,
             ["TestKeyScopeAndExpiry"], [
        edit(SERVICE, "func (s *Service) SecretStage(", "if !ok || key.actor != scope.Actor.ID {", "if !ok || false && key.actor != scope.Actor.ID {"),
    ]),
    mutation("stage-expiry", "expired upload keys refuse", "preflight", PACKAGE,
             ["TestKeyScopeAndExpiry"], [
        edit(SERVICE, "func (s *Service) expireKeys(", "if !now.Before(key.expires) {", "if false && !now.Before(key.expires) {"),
    ]),
    mutation("json-case", "unknown case-alias JSON keys refuse", "wire", PACKAGE + "/wire",
             ["TestExactJSONKeys"], [
        edit(WIRE, "func required(", "if !known[name] {", "if false && !known[name] {"),
    ]),
    mutation("typed-nil", "missing protected key channels fail typed", "backend", PACKAGE + "/native",
             ["TestTypedNilKeyInputs"], [
        edit(NATIVE, "func (s *Service) Unlock(", "wire.Nil(protected)", "protected == nil"),
    ]),
    mutation("directory-mode", "directory privacy is rechecked before use", "backend", PACKAGE + "/native",
             ["TestDirectoryModeDrift"], [
        edit(BASE + "private/files.go", "func (d *Directory) privacy(",
             "!owned(directory, 0700)", "false && !owned(directory, 0700)"),
    ]),
    mutation("lock-identity", "lock pathname retains its opened identity", "backend", PACKAGE + "/native",
             ["TestLockIdentityDrift"], [
        edit(BASE + "private/files.go", "func (d *Directory) privacy(",
             "if !os.SameFile(opened, current) {", "if false && !os.SameFile(opened, current) {"),
    ]),
    mutation("read-peer", "read connector must remain alive", "preflight", PACKAGE,
             ["TestReadConnectionGuards/closed"], [
        edit(SERVICE, "func (s *Service) transport(",
             "if err := peer.Alive(ctx); err != nil {", "if err := peer.Alive(ctx); false && err != nil {"),
    ]),
    mutation("read-writer", "every frame writer is verified", "preflight", PACKAGE,
             ["TestReadConnectionGuards/writer"], [
        edit(SERVICE, "func (s *Service) transport(",
             "if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {",
             "if err := scope.Frame.Verify(ctx, scope.Connection); false && err != nil {"),
    ]),
    mutation("read-endpoint", "read authority matches the current endpoint", "preflight", PACKAGE,
             ["TestReadConnectionGuards/endpoint"], [
        edit(SERVICE, "func (s *Service) readAuthority(",
             "authority.EndpointGeneration != scope.EndpointGeneration ||",
             "false && authority.EndpointGeneration != scope.EndpointGeneration ||"),
    ]),
    mutation("read-idle", "idle read expiry refuses", "preflight", PACKAGE,
             ["TestReadConnectionGuards/idle"], [
        edit(SERVICE, "func (s *Service) readAuthority(",
             "!future(authority.IdleExpiresAt, now)", "false && !future(authority.IdleExpiresAt, now)"),
    ]),
    mutation("stage-connection", "upload keys stay on their issuing connection", "preflight", PACKAGE,
             ["TestStageReadSession"], [
        edit(SERVICE, "func (s *Service) SecretStage(",
             "key.connection != scope.Connection.ID()", "false && key.connection != scope.Connection.ID()"),
    ]),
    mutation("stage-session", "upload keys stay in their issuing read session", "preflight", PACKAGE,
             ["TestStageReadSession"], [
        edit(SERVICE, "func (s *Service) SecretStage(",
             "key.session != authority.SessionID", "false && key.session != authority.SessionID"),
    ]),
    mutation("key-read-expiry", "upload key lifetime is bounded by read authority", "preflight", PACKAGE,
             ["TestKeyReadExpiryBound"], [
        edit(SERVICE, "func (s *Service) SecretKey(", "if limit.Before(expires) {", "if false && limit.Before(expires) {"),
    ]),
    mutation("eligibility-session", "continuation retains the actual session and history", "preflight", PACKAGE,
             ["TestEligibilityCurrentState/session", "TestEligibilityCurrentState/history"], [
        edit(CONTRACT, "func (s *Service) Eligibility(",
             "lane.Session != request.Session", "false && lane.Session != request.Session"),
    ]),
    mutation("eligibility-model", "continuation retains the actual model", "preflight", PACKAGE,
             ["TestEligibilityCurrentState/model"], [
        edit(CONTRACT, "func (s *Service) Eligibility(",
             "lane.Model != request.Model", "false && lane.Model != request.Model"),
    ]),
    mutation("eligibility-exclusion", "excluded login cannot become eligible", "preflight", PACKAGE,
             ["TestEligibilityCurrentState/excluded"], [
        edit(CONTRACT, "func (s *Service) Eligibility(", "if excluded == to.ProfileID {", "if false && excluded == to.ProfileID {"),
    ]),
    mutation("eligibility-paid", "continuation cannot introduce paid fallback", "preflight", PACKAGE,
             ["TestEligibilityCurrentState/paid"], [
        edit(CONTRACT, "func (s *Service) Eligibility(", "if to.Paid && !from.Paid {", "if false && to.Paid && !from.Paid {"),
    ]),
    mutation("worker-lease", "worker credential lease must match the protected record", "preflight", PACKAGE,
             ["TestWorkerLeaseAndSubset/lease", "TestWorkerLeaseAndSubset/generation", "TestWorkerLeaseAndSubset/runtime"], [
        edit(CONTRACT, "func (s *Service) InjectWorker(", "if stored != lease {", "if false && stored != lease {"),
    ]),
    mutation("worker-subset", "worker sources stay within exact current grants", "preflight", PACKAGE,
             ["TestWorkerLeaseAndSubset/source", "TestWorkerLeaseAndSubset/target", "TestWorkerLeaseAndSubset/version"], [
        edit(CONTRACT, "func (s *Service) InjectWorker(", "if !found {", "if false && !found {"),
    ]),
    mutation("cli-semantic", "feature input rejects wildcard secret names", "preflight", PACKAGE,
             ["TestCLISemanticRefusal"], [
        edit(BASE + "validation.go", "func ValidateImportInput(", "if !wire.Name(input.Name) ||", "if false && !wire.Name(input.Name) ||"),
    ]),
    mutation("key-check-enrollment", "first unlock persists an empty sealed key check", "d4fix1", PACKAGE + "/native",
             ["TestEmptyKeyEnrollment"], [
        edit("internal/v2/secrets/native/store.go", "func (s *Service) Unlock(", "if err := s.checkKey(id, key); err != nil {", "if err := error(nil); err != nil {"),
    ]),
    mutation("key-check-auth", "wrong key fails on an otherwise empty enrolled store", "d4fix1", PACKAGE + "/native",
             ["TestEmptyKeyEnrollment"], [
        edit("internal/v2/secrets/native/store.go", "func (s *Service) Unlock(", "if err := s.checkKey(id, key); err != nil {", "if err := s.checkKey(id, key); false && err != nil {"),
    ]),
    mutation("native-clock", "grant expiry uses the injected clock", "d4fix1", PACKAGE + "/native",
             ["TestNativeClock"], [
        edit("internal/v2/secrets/native/store.go", "func (s *Service) Fetch(", "s.deps.Clock.Now().Before(expiry)", "time.Now().Before(expiry)"),
    ]),
    mutation("native-clock-required", "native construction requires its clock", "d4fix1", PACKAGE + "/native",
             ["TestNativeRequiresClock"], [
        edit("internal/v2/secrets/native/store.go", "func New(", "if wire.Nil(deps.Clock) {", "if false && wire.Nil(deps.Clock) {"),
    ]),
    mutation("parent-mode", "an unprotected parent refuses before directory creation", "d4fix1", PACKAGE + "/private",
             ["TestProtectedParent"], [
        edit("internal/v2/secrets/private/files.go", "func Open(", "parentInfo.Mode().Perm()&0022 != 0", "false && parentInfo.Mode().Perm()&0022 != 0"),
    ]),
    mutation("lock-wait", "contended locks wait until context deadline", "d4fix1", PACKAGE + "/private",
             ["TestContextLock"], [
        edit("internal/v2/secrets/private/files.go", "func (d *Directory) Lock(", "timer := time.NewTimer(10 * time.Millisecond)", "if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {\n\t\t\treturn wire.Error(api.CodeConflict, \"deliberate immediate contention\")\n\t\t}\n\t\ttimer := time.NewTimer(10 * time.Millisecond)"),
    ]),
    mutation("read-idle-bound", "remaining idle authority cannot exceed the published bound", "d4fix1", PACKAGE,
             ["TestReadWindowContract/idle-over"], [
        edit("internal/v2/secrets/service.go", "func (s *Service) readAuthority(", "idle.After(now.Add(readIdleLimit))", "false && idle.After(now.Add(readIdleLimit))"),
    ]),
    mutation("read-absolute-bound", "remaining absolute authority cannot exceed the published bound", "d4fix1", PACKAGE,
             ["TestReadWindowContract/absolute-over"], [
        edit("internal/v2/secrets/service.go", "func (s *Service) readAuthority(", "expires.After(now.Add(readAbsoluteLimit))", "false && expires.After(now.Add(readAbsoluteLimit))"),
    ]),
    mutation("read-connection", "read authority belongs to the actual connection", "d4fix1", PACKAGE,
             ["TestReadConnectionGuards/connection"], [
        edit("internal/v2/secrets/service.go", "func (s *Service) readAuthority(", "authority.ConnectionID != scope.Connection.ID()", "false && authority.ConnectionID != scope.Connection.ID()"),
    ]),
    mutation("read-retained", "retained dispatcher authority must match current connection facts", "d4fix1", PACKAGE,
             ["TestReadConnectionGuards/retained"], [
        edit("internal/v2/secrets/service.go", "func (s *Service) readAuthority(", "(scope.ReadAuthority != nil && *scope.ReadAuthority != authority)", "(false && scope.ReadAuthority != nil && *scope.ReadAuthority != authority)"),
    ]),
    mutation("proof-intent", "mutation proof binds the exact request digest", "d4fix1", PACKAGE,
             ["TestProofPreflight/digest"], [
        edit("internal/v2/secrets/service.go", "func (s *Service) human(", "p.RequestSHA256 != scope.Request.RequestSHA256", "false && p.RequestSHA256 != scope.Request.RequestSHA256"),
    ]),
    mutation("proof-id", "mutation proof has an opaque valid ID", "d4fix1", PACKAGE,
             ["TestProofPreflight/id"], [
        edit("internal/v2/secrets/service.go", "func (s *Service) human(", "!wire.ID(string(p.ID))", "false && !wire.ID(string(p.ID))"),
    ]),
    mutation("proof-expiry", "expired mutation proof refuses before dependencies", "d4fix1", PACKAGE,
             ["TestProofPreflight/expired"], [
        edit("internal/v2/secrets/service.go", "func (s *Service) human(", "!future(p.ExpiresAt, s.deps.Clock.Now())", "false && !future(p.ExpiresAt, s.deps.Clock.Now())"),
    ]),
    mutation("read-proof", "human reads cannot carry mutation proofs", "d4fix1", PACKAGE,
             ["TestReadsRejectProof/secret.key"], [
        edit("internal/v2/secrets/service.go", "func (s *Service) human(", "if scope.Request.Proof != nil {", "if false && scope.Request.Proof != nil {"),
    ]),
    mutation("cli-validator-registration", "common file input requires the owning validator registration", "d4fix1", PACKAGE,
             ["TestCLIValidators/secret.stage/invalid"], [
        edit("internal/v2/cli/commands_secrets.go", "func init()", "\t\t{\"secret.stage\", lbV2SecretsInputCheck(secrets.ValidateStageInput)},\n", ""),
    ]),
    mutation("cli-proof-intent", "ergonomic CLI proof binds its operation or human.session intent", "d4fix1", PACKAGE,
             ["TestCLIProofIntent"], [
        edit("internal/v2/cli/commands_secrets.go", "func lbV2SecretsRPC[", "proof.RequestSHA256 != expected", "false && proof.RequestSHA256 != expected"),
    ]),
    mutation("stage-clock", "sealed upload expiry uses the caller clock", "d4fix1", PACKAGE,
             ["TestStageInjectedClock"], [
        edit("internal/v2/secrets/staging.go", "func SealStage(", "if len(clocks) == 1 {", "if false && len(clocks) == 1 {"),
    ]),
    mutation("installed-config", "missing installed configuration is a prerequisite failure", "d4fix1", PACKAGE,
             ["TestInstalledInputs"], [
        edit("internal/v2/secrets/service.go", "func New(", "wire.Error(api.CodePrerequisite, \"secrets requires its installed configuration\")", "wire.Error(api.CodeInvalid, \"secrets requires its installed configuration\")"),
    ]),
    mutation("installed-service-scope", "fixed internal service lookup scope is derived from installed config", "d4fix1", PACKAGE,
             ["TestInstalledInputs"], [
        edit("internal/v2/secrets/service.go", "func New(", "if deps.ServiceScope.Config == \"\" {", "if false && deps.ServiceScope.Config == \"\" {"),
    ]),
    mutation("stage-import-principal", "stage consumption retains its submitting principal", "d4fix1", PACKAGE,
             ["TestImportSessionBinding/principal"], [
        edit("internal/v2/secrets/mutations.go", "func (s *Service) claimStage(", "stage.key.actor != scope.Actor.ID", "false && stage.key.actor != scope.Actor.ID"),
    ]),
    mutation("stage-import-connection", "stage consumption retains the actual submitting connection", "d4fix1", PACKAGE,
             ["TestImportSessionBinding/connection"], [
        edit("internal/v2/secrets/mutations.go", "func (s *Service) claimStage(", "stage.key.connection != scope.Connection.ID()", "false && stage.key.connection != scope.Connection.ID()"),
    ]),
    mutation("stage-import-session", "stage consumption retains its human read session", "d4fix1", PACKAGE,
             ["TestImportSessionBinding/session"], [
        edit("internal/v2/secrets/mutations.go", "func (s *Service) claimStage(", "stage.key.session != authority.SessionID", "false && stage.key.session != authority.SessionID"),
    ]),
    mutation("stage-import-endpoint", "stage consumption retains its endpoint generation", "d4fix1", PACKAGE,
             ["TestImportSessionBinding/endpoint"], [
        edit("internal/v2/secrets/mutations.go", "func (s *Service) claimStage(", "stage.key.endpoint != scope.EndpointGeneration", "false && stage.key.endpoint != scope.EndpointGeneration"),
    ]),
    mutation("stage-import-expiry", "expired in-memory stages cannot be consumed", "d4fix1", PACKAGE,
             ["TestImportSessionBinding/expiry"], [
        edit("internal/v2/secrets/service.go", "func (s *Service) expireKeys(", "if !now.Before(stage.key.expires) {", "if false && !now.Before(stage.key.expires) {"),
    ]),
    mutation("stage-claim", "one staged ciphertext is bound to one exact mutation request", "d4fix1", PACKAGE,
             ["TestStageIntentAndClaim"], [
        edit("internal/v2/secrets/mutations.go", "func (s *Service) claimStage(", "if stage.claimed != (api.RequestKey{}) && stage.claimed != requestKey(scope) {", "if false && stage.claimed != (api.RequestKey{}) && stage.claimed != requestKey(scope) {"),
    ]),
    mutation("stage-intent", "stage metadata matches the requested secret name and version", "d4fix1", PACKAGE,
             ["TestStageIntentAndClaim"], [
        edit("internal/v2/secrets/mutations.go", "func (s *Service) claimStage(", "stage.request.Name != name", "false && stage.request.Name != name"),
    ]),
    mutation("mutation-proof-use", "proof use is in the event and reply transaction", "d4fix1", PACKAGE,
             ["TestSecretLifecycle"], [
        edit("internal/v2/secrets/mutations.go", "func (s *Service) commitSecret(", "Guards: []api.TransactionGuard{{Proof: &api.ProofUse{Proof: *scope.Request.Proof, Target: target}}}", "Guards: nil"),
    ]),
    mutation("mutation-check-proof", "proof verification precedes protected backend work", "d4fix1", PACKAGE,
             ["TestProofBeforeBackend","TestMutationIntentRetry"], [
        edit("internal/v2/secrets/mutations.go", "func (s *Service) checkProof(", "\tif err != nil {\n\t\treturn target, err\n\t}\n\tif verified.Ref", "\tif err != nil {\n\t\treturn target, nil\n\t}\n\tif verified.Ref"),
    ]),
    mutation("backend-store-required", "a successful event requires a real prior protected write", "d4fix1", PACKAGE,
             ["TestSecretLifecycle","TestBackendFailureDoesNotCommit"], [
        edit("internal/v2/secrets/mutations.go", "func (s *Service) importSecret(", "stored, err = protected.Store(ctx, api.SecretInfo{Name: name, Version: stage.request.Version, SourceHandle: source}, material)", "stored, err = api.SecretInfo{Name: name, Version: stage.request.Version, SourceHandle: source, KeyID: \"fault-key\"}, error(nil)"),
    ]),
    mutation("import-reconcile", "restart retry reconciles the existing authenticated source", "d4fix1", PACKAGE,
             ["TestImportCrashRetry"], [
        edit("internal/v2/secrets/mutations.go", "func (s *Service) importSecret(", "if stored.SourceHandle == \"\" {", "if true {"),
    ]),
    mutation("pending-source", "unrelated operations cannot bypass an uncommitted backend source", "d4fix1", PACKAGE,
             ["TestImportCrashRetry"], [
        edit("internal/v2/secrets/mutations.go", "func reconcile(", "if !committed && info.SourceHandle != own || info.Revoked && !revoked && (!revoking || info.SourceHandle != current.SourceHandle) {", "if false && (!committed && info.SourceHandle != own || info.Revoked && !revoked && (!revoking || info.SourceHandle != current.SourceHandle)) {"),
    ]),
    mutation("import-replay", "completed receipt replays before another proof check", "d4fix1", PACKAGE,
             ["TestSecretLifecycle"], [
        edit("internal/v2/secrets/mutations.go", "func (s *Service) importSecret(", "\n\tif receipt.Reply != nil {", "\n\tif false && receipt.Reply != nil {"),
    ]),
    mutation("rotate-cas", "two rotations cannot advance the same expected version", "d4fix1", PACKAGE,
             ["TestConcurrentRotations"], [
        edit("internal/v2/secrets/mutations.go", "func (s *Service) importSecret(", "expected != \"\" && (!exists || current.Version != expected || current.Revoked)", "false && expected != \"\" && (!exists || current.Version != expected || current.Revoked)"),
    ]),
    mutation("revoke-operation", "only the original operation reconciles an interrupted tombstone", "d4fix1", PACKAGE,
             ["TestRevokeCrashRetry"], [
        edit("internal/v2/secrets/native/store.go", "func (s *Service) revokeLocked(", "if operation != \"\" && r.RevocationID != operation {", "if false && operation != \"\" && r.RevocationID != operation {"),
    ]),
    mutation("revoke-operation-aad", "the tombstone operation ID is authenticated", "d4fix1", PACKAGE + "/native",
             ["TestRevocationOperationAAD"], [
        edit("internal/v2/secrets/native/store.go", "func aad(", "if r.RevocationID != \"\" {", "if false && r.RevocationID != \"\" {"),
    ]),
    mutation("mutation-scope-end", "a retained protected backend view cannot write after unlock", "d4fix1", PACKAGE + "/native",
             ["TestMutationScopeEnd"], [
        edit("internal/v2/secrets/native/mutation.go", "func (v *mutationView) Store(", "if !v.active {", "if false && !v.active {"),
    ]),
    mutation("stage-import-tag", "tampered ciphertext fails before Store or proof consumption", "d4fix1", PACKAGE,
             ["TestStageTamperAtImport"], [
        edit("internal/v2/secrets/staging.go", "func openStage(", "return result, wire.Error(api.CodeIntegrity, \"sealed-upload authentication failed\")", "return api.SecretMaterial{Bytes: []byte(\"deliberate fault\")}, nil"),
    ]),
    mutation("commit-reference", "interrupted transaction retains a retryable operation reference", "d4fix1", PACKAGE,
             ["TestImportCrashRetry"], [
        edit("internal/v2/secrets/mutations.go", "func commitFailure(", "copy.Retryable = true", "copy.Retryable = false"),
    ]),
    mutation("backend-retry-rewrite", "exact backend retry preserves the original ciphertext bytes", "d4fix1", PACKAGE + "/native",
             ["TestImmutableAndRevoke"], [
        edit("internal/v2/secrets/native/store.go", "func (s *Service) storeLocked(", "if equal {\n\t\t\t\t\treturn nil\n\t\t\t\t}", "if equal {\n\t\t\t\t\tif err := seal(s.keys[r.Info.KeyID], &r, material.Bytes); err != nil { return err }\n\t\t\t\t\tdata, err := json.Marshal(r)\n\t\t\t\t\tif err != nil { return err }\n\t\t\t\t\treturn s.directory.Write(name, data)\n\t\t\t\t}"),
    ]),
]


# Draft.4 fix 9 controls are prepared, not measured until Linux red/green.
CATALOG.extend([
    mutation("fix9-acquire", "reserved-life acquisition uses the real slot implementation", "d4fix9", "./internal/v2/secrets",
             ["TestReservedCredentialLifecycle"], [
        edit("internal/v2/secrets/broker.go", "func (s *Service) Acquire(", "return s.acquireProfile(ctx, target, grant, current)", "return api.CredentialSlot{}, api.NotImplemented(\"lb-v2-secrets\", \"deliberate acquire predecessor\")"),
    ]),
    mutation("fix9-inject", "reserved-life injection uses the real slot implementation", "d4fix9", "./internal/v2/secrets",
             ["TestReservedCredentialLifecycle"], [
        edit("internal/v2/secrets/broker.go", "func (s *Service) Inject(", "return s.prepareInjection(ctx, target, grants, current)", "return api.Injection{}, api.NotImplemented(\"lb-v2-secrets\", \"deliberate injection predecessor\")"),
    ]),
    mutation("fix9-worker", "fixed worker injection prepares actual protected material", "d4fix9", "./internal/v2/secrets",
             ["TestFixedWorkerCredentialLifecycle"], [
        edit("internal/v2/secrets/contract_stubs.go", "func (s *Service) InjectWorker(", "return s.prepareWorkerInjection(ctx, lease, grants, current)", "return api.Injection{}, api.NotImplemented(\"lb-v2-secrets\", \"deliberate worker predecessor\")"),
    ]),
    mutation("fix9-release", "profile release imports measured canonical refresh", "d4fix9", "./internal/v2/secrets",
             ["TestFileLoginRefresh"], [
        edit("internal/v2/secrets/broker.go", "func (s *Service) Release(", "return s.releaseCredential(ctx, slot, observation)", "return api.NotImplemented(\"lb-v2-secrets\", \"deliberate release predecessor\")"),
    ]),
    mutation("fix9-revoke", "injection cleanup calls its real measured implementation", "d4fix9", "./internal/v2/secrets",
             ["TestReservedCredentialLifecycle"], [
        edit("internal/v2/secrets/broker.go", "func (s *Service) RevokeInjection(", "return s.releaseInjection(ctx, injection, observation)", "return api.NotImplemented(\"lb-v2-secrets\", \"deliberate cleanup predecessor\")"),
    ]),
    mutation("fix9-room", "Room consumes protected producer evidence", "d4fix9", "./internal/v2/secrets",
             ["TestProfileRoomEvidence"], [
        edit("internal/v2/secrets/broker.go", "func (s *Service) Room(", "return s.roomForProfile(ctx, grant, profile)", "_ = profile\n\treturn api.Room{}, api.NotImplemented(\"lb-v2-secrets\", \"deliberate room predecessor\")"),
    ]),
    mutation("fix9-eligibility", "Eligibility produces a bound protected assessment", "d4fix9", "./internal/v2/secrets",
             ["TestProtectedProfileEligibility"], [
        edit("internal/v2/secrets/contract_stubs.go", "func (s *Service) Eligibility(", "return s.profileEligibility(ctx, request, *from, *to)", "return api.ProfileEligibility{}, api.NotImplemented(\"lb-v2-secrets\", \"deliberate eligibility predecessor\")"),
    ]),
    mutation("fix9-prepared-agent", "nonexecuting agent material equals selected source bytes", "d4fix9", "./internal/v2/secrets",
             ["TestPreparedAgentMaterial"], [
        edit("internal/v2/secrets/prepared_material.go", "func (s *Service) PreparedSlotMaterial(", "material.Bytes = append([]byte(nil), latest.Material...)", "material.Bytes = []byte{}"),
    ]),
    mutation("fix9-prepared-worker", "nonexecuting worker material equals selected source bytes", "d4fix9", "./internal/v2/secrets",
             ["TestFixedWorkerCredentialLifecycle"], [
        edit("internal/v2/secrets/worker_credentials.go", "func (s *Service) PrepareWorkerMaterial(", "material.Bytes = append([]byte(nil), current.Material...)", "material.Bytes = []byte{}"),
    ]),
    mutation("fix9-plan-claim", "expired planning claims cannot allocate a slot", "d4fix9", "./internal/v2/secrets",
             ["TestReservationGuards/claim"], [
        edit("internal/v2/secrets/launch_binding.go", "func (s *Service) livePlanClaim(", "!future(record.ClaimExpiresAt, s.deps.Clock.Now()) ||", "false && !future(record.ClaimExpiresAt, s.deps.Clock.Now()) ||"),
    ]),
    mutation("fix9-plan-epoch", "the planning cause matches the reserved cancellation epoch", "d4fix9", "./internal/v2/secrets",
             ["TestReservationGuards/epoch"], [
        edit("internal/v2/secrets/launch_binding.go", "func (s *Service) reservedPlan(", "effect.Context.CancellationEpoch != r.CancellationEpoch ||", "false && effect.Context.CancellationEpoch != r.CancellationEpoch ||"),
    ]),
    mutation("fix9-plan-foreign", "the reserved planning record belongs to the installed configuration", "d4fix9", "./internal/v2/secrets",
             ["TestReservationGuards/foreign"], [
        edit("internal/v2/secrets/launch_binding.go", "func (s *Service) reservedPlan(", "r.Config != s.deps.Config ||", "false && r.Config != s.deps.Config ||"),
    ]),
    mutation("fix9-plan-inputs", "both initial and final grants match the exact sourced reservation", "d4fix9", "./internal/v2/secrets",
             ["TestReservationGuards/resolved"], [
        edit("internal/v2/secrets/launch_binding.go", "func (s *Service) credentialLaunch(", "if !reflect.DeepEqual(launch.record.Inputs.Grants, current) {", "if false && !reflect.DeepEqual(launch.record.Inputs.Grants, current) {"),
        edit("internal/v2/secrets/launch_binding.go", "func (s *Service) recheckCredentialLaunch(", "!reflect.DeepEqual(grants, record.Inputs.Grants) ||", "false && !reflect.DeepEqual(grants, record.Inputs.Grants) ||"),
    ]),
    mutation("fix9-plan-policy", "current policy is rechecked before and after protected preparation", "d4fix9", "./internal/v2/secrets",
             ["TestReservationGuards/policy"], [
        edit("internal/v2/secrets/broker.go", "func (s *Service) currentGrants(", "policy.Generation != current.PolicyGeneration ||", "false && policy.Generation != current.PolicyGeneration ||"),
        edit("internal/v2/secrets/launch_binding.go", "func (s *Service) recheckCredentialLaunch(", "policy.Generation != record.Reservation.PolicyGeneration ||", "false && policy.Generation != record.Reservation.PolicyGeneration ||"),
    ]),
    mutation("fix9-plan-original", "the retained original request digest agrees with the reservation", "d4fix9", "./internal/v2/secrets",
             ["TestReservationGuards/request"], [
        edit("internal/v2/secrets/launch_binding.go", "func (s *Service) launchOriginal(", "request.RequestSHA256 != r.RequestSHA256 ||", "false && request.RequestSHA256 != r.RequestSHA256 ||"),
        edit("internal/v2/secrets/launch_binding.go", "func (s *Service) launchOriginal(", "digest != r.RequestSHA256 ||", "false && digest != r.RequestSHA256 ||"),
    ]),
    mutation("fix9-profile-runtime", "the acquired profile supports the selected enrolled executable", "d4fix9", "./internal/v2/secrets",
             ["TestReservationGuards/executable"], [
        edit("internal/v2/secrets/credential_slots.go", "func (s *Service) acquireProfile(", "profile.Runtime != launch.record.Inputs.Sources.Runtime.Executable ||", "false && profile.Runtime != launch.record.Inputs.Sources.Runtime.Executable ||"),
    ]),
    mutation("fix9-private-slot", "a retained home ID cannot become a credential slot", "d4fix9", "./internal/v2/secrets",
             ["TestReservationGuards/history"], [
        edit("internal/v2/secrets/credential_slots.go", "func slotIsPrivate(", "slot.ID != home.Home.ID &&", "true &&"),
    ]),
    mutation("fix9-profile-retry", "changed original input cannot replay a retained slot", "d4fix9", "./internal/v2/secrets",
             ["TestCredentialChangedRetryAndRestart"], [
        edit("internal/v2/secrets/credential_slots.go", "func (s *Service) acquireProfile(", "retained.Fingerprint != fingerprint ||", "false && retained.Fingerprint != fingerprint ||"),
    ]),
    mutation("fix9-injection-retry", "a changed task selection cannot reuse an injection reservation", "d4fix9", "./internal/v2/secrets",
             ["TestInjectionSelectionReplay"], [
        edit("internal/v2/secrets/credential_slots.go", "func (s *Service) prepareInjection(", "if marker.Fingerprint != selection {", "if false && marker.Fingerprint != selection {"),
    ]),
    mutation("fix9-release-identity", "cleanup validates the actual committed identity tuple", "d4fix9", "./internal/v2/secrets",
             ["TestReleaseGuards/identity"], [
        edit("internal/v2/secrets/credential_release.go", "func (s *Service) slotBinding(", "if err := api.ValidateLaunchBindingPlan(binding, plan); err != nil {", "if err := api.ValidateLaunchBindingPlan(binding, plan); false && err != nil {"),
    ]),
    mutation("fix9-release-comparison", "the caller observation agrees with the independent helper measurement", "d4fix9", "./internal/v2/secrets",
             ["TestReleaseGuards/disagreement"], [
        edit("internal/v2/secrets/credential_release.go", "func (s *Service) measuredRelease(", "if actual.Handle != claim.Handle || actual.State != claim.State || !reflect.DeepEqual(actual.ExitCode, claim.ExitCode) || !reflect.DeepEqual(actual.Signal, claim.Signal) || !reflect.DeepEqual(actual.Survivors, claim.Survivors) {", "if false && (actual.Handle != claim.Handle || actual.State != claim.State || !reflect.DeepEqual(actual.ExitCode, claim.ExitCode) || !reflect.DeepEqual(actual.Signal, claim.Signal) || !reflect.DeepEqual(actual.Survivors, claim.Survivors)) {"),
    ]),
    mutation("fix9-release-commit", "an uncommitted helper receipt cannot erase credentials", "d4fix9", "./internal/v2/secrets",
             ["TestReleaseGuards/record"], [
        edit("internal/v2/secrets/credential_release.go", "func (s *Service) measuredRelease", "return wire.Error(api.CodeIntegrity, \"credential cleanup has no committed helper-measured release receipt\")", "return nil"),
    ]),
    mutation("fix9-release-selection", "cleanup preserves the full retained injection selection", "d4fix9", "./internal/v2/secrets",
             ["TestInjectionCleanupSelection"], [
        edit("internal/v2/secrets/credential_release.go", "func (s *Service) releaseInjection(", "if !reflect.DeepEqual(expected, injection) {", "if false && !reflect.DeepEqual(expected, injection) {"),
    ]),
    mutation("fix9-refresh-import", "measured refresh writes the actual canonical returned bytes", "d4fix9", "./internal/v2/secrets", ["TestFileLoginRefresh"], [
        edit("internal/v2/secrets/credential_release.go", "func (s *Service) releaseSlotLocked(", "owner.Material = append([]byte(nil), current.Returned...)", "owner.Material = []byte{}"),
    ]),
    mutation("fix9-refresh-serialize", "an expired unreleased canonical login owner still excludes aliases", "d4fix9", "./internal/v2/secrets",
             ["TestCanonicalLoginRefreshWait"], [
        edit("internal/v2/secrets/credential_slots.go", "func (s *Service) acquireProfile", "if owner.SlotID != \"\" && owner.SlotID != id {", "if false && owner.SlotID != \"\" && owner.SlotID != id {"),
    ]),
    mutation("fix9-refresh-latest", "a later alias receives the latest canonical refresh", "d4fix9", "./internal/v2/secrets",
             ["TestCanonicalLoginRefreshWait"], [
        edit("internal/v2/secrets/credential_slots.go", "func (s *Service) acquireProfile", "if len(canonical) > 0 {", "if false && len(canonical) > 0 {"),
    ]),
    mutation("fix9-refresh-identity", "a returned refresh cannot change non-refresh identity fields", "d4fix9", "./internal/v2/secrets",
             ["TestRefreshFieldGuards/identity"], [
        edit("internal/v2/secrets/credential_release.go", "func validateRefresh(", "if !bytes.Equal(one, two) {", "if false && !bytes.Equal(one, two) {"),
    ]),
    mutation("fix9-refresh-unknown", "a returned refresh cannot add unsupported fields", "d4fix9", "./internal/v2/secrets",
             ["TestRefreshFieldGuards/unknown"], [
        edit("internal/v2/secrets/credential_release.go", "func validateRefresh(", "if _, ok := before[key]; !ok {", "if _, ok := before[key]; false && !ok {"),
    ]),
    mutation("fix9-refresh-expiry", "returned expiry is a supported future UTC timestamp", "d4fix9", "./internal/v2/secrets",
             ["TestRefreshFieldGuards/expiry"], [
        edit("internal/v2/secrets/credential_release.go", "func validateRefresh", "if err != nil || !strings.HasSuffix(text, \"Z\") || !now.Before(expires) {", "if false && (err != nil || !strings.HasSuffix(text, \"Z\") || !now.Before(expires)) {"),
    ]),
    mutation("fix9-refresh-owner", "only the original canonical owner may return refresh material", "d4fix9", "./internal/v2/secrets",
             ["TestRefreshFieldGuards/owner"], [
        edit("internal/v2/secrets/credential_release.go", "func (s *Service) ReturnSlot(", "if owner.ID != current.LoginID || owner.SlotID != current.ID {", "if false && (owner.ID != current.LoginID || owner.SlotID != current.ID) {"),
    ]),
    mutation("fix9-refresh-generation", "returning a refresh rechecks enrollment generation", "d4fix9", "./internal/v2/secrets",
             ["TestRefreshFieldGuards/generation"], [
        edit("internal/v2/secrets/credential_release.go", "func (s *Service) ReturnSlot(", "if profile.Generation != current.ProfileGeneration || profile.LoginID != current.LoginID {", "if false && (profile.Generation != current.ProfileGeneration || profile.LoginID != current.LoginID) {"),
    ]),
    mutation("fix9-room-available", "Room reports actual available and unavailable producer results", "d4fix9", "./internal/v2/secrets",
             ["TestProfileRoomEvidence"], [
        edit("internal/v2/secrets/profiles.go", "func (s *Service) roomForProfile(", "Available: observation.Available,", "Available: true,"),
    ]),
    mutation("fix9-room-generation", "room evidence pins the protected enrollment generation", "d4fix9", "./internal/v2/secrets",
             ["TestProtectedRoomGuards/generation"], [
        edit("internal/v2/secrets/profiles.go", "func (s *Service) profileObservation(", "observation.Generation != profile.Generation ||", "false && observation.Generation != profile.Generation ||"),
    ]),
    mutation("fix9-room-login", "room evidence pins the canonical login", "d4fix9", "./internal/v2/secrets",
             ["TestProtectedRoomGuards/login"], [
        edit("internal/v2/secrets/profiles.go", "func (s *Service) profileObservation(", "observation.LoginID != profile.LoginID ||", "false && observation.LoginID != profile.LoginID ||"),
    ]),
    mutation("fix9-room-window", "room evidence has at most a five minute observation window", "d4fix9", "./internal/v2/secrets",
             ["TestProtectedRoomGuards/window"], [
        edit("internal/v2/secrets/profiles.go", "func (s *Service) profileObservation", "expires.After(checked.Add(5*time.Minute))", "false && expires.After(checked.Add(5*time.Minute))"),
    ]),
    mutation("fix9-room-zone", "room checked-at uses the exact UTC representation", "d4fix9", "./internal/v2/secrets",
             ["TestProtectedRoomGuards/zone"], [
        edit("internal/v2/secrets/profiles.go", "func (s *Service) profileObservation", "!strings.HasSuffix(string(observation.CheckedAt), \"Z\") ||", "false && !strings.HasSuffix(string(observation.CheckedAt), \"Z\") ||"),
    ]),
    mutation("fix9-room-producer", "the protected evidence producer completed successfully", "d4fix9", "./internal/v2/secrets",
             ["TestProtectedRoomGuards/producer"], [
        edit("internal/v2/secrets/profiles.go", "func (s *Service) profileObservation", "operation.Status != \"succeeded\" ||", "false && operation.Status != \"succeeded\" ||"),
    ]),
    mutation("fix9-evidence-origin", "room evidence has protected service origin", "d4fix9", "./internal/v2/secrets",
             ["TestEligibilityGuards/evidence-origin"], [
        edit("internal/v2/secrets/launch_binding.go", "func (s *Service) protectedObject", "meta.Origin != \"service\" ||", "false && meta.Origin != \"service\" ||"),
    ]),
    mutation("fix9-evidence-hash", "protected object hash verification precedes semantic decoding", "d4fix9", "./internal/v2/secrets",
             ["TestProtectedRoomGuards/hash"], [
        edit("internal/v2/secrets/launch_binding.go", "func (s *Service) protectedObject", "api.Digest(hex.EncodeToString(sum[:])) != ref.SHA256", "false && api.Digest(hex.EncodeToString(sum[:])) != ref.SHA256"),
    ]),
    mutation("fix9-worker-claim", "worker credential preparation requires its live current claim", "d4fix9", "./internal/v2/secrets",
             ["TestWorkerGuards/claim"], [
        edit("internal/v2/secrets/worker_credentials.go", "func (s *Service) workerSelection", "!future(current.ClaimExpiresAt, s.deps.Clock.Now()) ||", "false && !future(current.ClaimExpiresAt, s.deps.Clock.Now()) ||"),
    ]),
    mutation("fix9-worker-target", "worker cause targets the exact leased run", "d4fix9", "./internal/v2/secrets",
             ["TestWorkerGuards/foreign"], [
        edit("internal/v2/secrets/worker_credentials.go", "func (s *Service) workerSelection", "e.Context.Target != lease.Target ||", "false && e.Context.Target != lease.Target ||"),
    ]),
    mutation("fix9-worker-runtime", "the fixed worker executable matches protected runtime bytes", "d4fix9", "./internal/v2/secrets",
             ["TestWorkerGuards/manifest"], [
        edit("internal/v2/secrets/worker_credentials.go", "func (s *Service) workerSelection", "manifest.Bootstrap != plan.Executable", "false && manifest.Bootstrap != plan.Executable"),
    ]),
    mutation("fix9-worker-executable", "worker staging rejects caller-selected executable paths", "d4fix9", "./internal/v2/secrets",
             ["TestWorkerGuards/executable"], [
        edit("internal/v2/secrets/worker_credentials.go", "func (s *Service) workerSelection", "!wire.ID(string(plan.Executable.ID)) ||", "false && !wire.ID(string(plan.Executable.ID)) ||"),
        edit("internal/v2/secrets/worker_credentials.go", "func (s *Service) workerSelection", "manifest.Bootstrap != plan.Executable", "false && manifest.Bootstrap != plan.Executable"),
    ]),
    mutation("fix9-worker-plan-retry", "worker slot identity pins the complete fixed job input", "d4fix9", "./internal/v2/secrets",
             ["TestWorkerGuards/changed-retry"], [
        edit("internal/v2/secrets/worker_credentials.go", "func (s *Service) prepareWorkerInjection", "}{lease, *effect.Effect.Worker, manifest, grants, requested})", "}{lease, api.WorkerPlan{}, manifest, grants, requested})"),
    ]),
    mutation("fix9-worker-subset-retry", "worker retry preserves both requested input and prepared result", "d4fix9", "./internal/v2/secrets",
             ["TestWorkerGuards/changed-subset"], [
        edit("internal/v2/secrets/worker_credentials.go", "func (s *Service) prepareWorkerInjection", "if marker.Fingerprint != selection {", "if false && marker.Fingerprint != selection {"),
        edit("internal/v2/secrets/worker_credentials.go", "func (s *Service) prepareWorkerInjection", "if !reflect.DeepEqual(*marker.Injection, result) {", "if false && !reflect.DeepEqual(*marker.Injection, result) {"),
    ]),
    mutation("fix9-worker-spec-selection", "the final worker spec preserves the exact prepared injection", "d4fix9", "./internal/v2/secrets", ["TestFixedWorkerMaterialGuards/selection"], [
        edit("internal/v2/secrets/worker_credentials.go", "func (s *Service) retainedWorkerSpecJournal", "if marker.Injection == nil || !reflect.DeepEqual(*marker.Injection, spec.Injection) {", "if false && (marker.Injection == nil || !reflect.DeepEqual(*marker.Injection, spec.Injection)) {"),
    ]),
    mutation("fix9-worker-resolver", "worker material calls the actual post-spec helper resolver", "d4fix9", "./internal/v2/secrets", ["TestFixedWorkerMaterialGuards/runtime"], [
        edit("internal/v2/secrets/worker_credentials.go", "func (s *Service) retainedWorkerSpecJournal", "if !resolve {", "if true {"),
    ]),
    mutation("fix9-worker-spec-retry", "material delivery cannot change its retained final handoff", "d4fix9", "./internal/v2/secrets",
             ["TestFixedWorkerDeliveryReplay"], [
        edit("internal/v2/secrets/worker_credentials.go", "func (s *Service) PrepareWorkerMaterial", "current.Handoff != nil && !reflect.DeepEqual(*current.Handoff, handoff)", "false && current.Handoff != nil && !reflect.DeepEqual(*current.Handoff, handoff)"),
    ]),
    mutation("fix9-eligibility-model", "profile compatibility uses the destination enrolled model", "d4fix9", "./internal/v2/secrets",
             ["TestProtectedProfileEligibility"], [
        edit("internal/v2/secrets/profiles.go", "func (s *Service) profileEligibility", "slices.Contains(after.Models, request.Model) &&", "true &&"),
    ]),
    mutation("fix9-eligibility-vendor", "profile compatibility uses the destination pinned vendor version", "d4fix9", "./internal/v2/secrets",
             ["TestEligibilityGuards/vendor"], [
        edit("internal/v2/secrets/profiles.go", "func (s *Service) profileEligibility", "slices.Contains(after.VendorVersions, request.Session.VendorVersion) &&", "true &&"),
    ]),
    mutation("fix9-eligibility-runtime", "profile compatibility uses the exact enrolled runtime", "d4fix9", "./internal/v2/secrets",
             ["TestEligibilityGuards/runtime"], [
        edit("internal/v2/secrets/profiles.go", "func (s *Service) profileEligibility", "before.Runtime == after.Runtime", "true"),
    ]),
    mutation("fix9-eligibility-binding", "eligibility validates the committed private history binding", "d4fix9", "./internal/v2/secrets",
             ["TestEligibilityGuards/identity"], [
        edit("internal/v2/secrets/profiles.go", "func (s *Service) profileEligibility", "if err := api.ValidateLaunchBindingPlan(binding, *record.Plan); err != nil {", "if err := api.ValidateLaunchBindingPlan(binding, *record.Plan); false && err != nil {"),
    ]),
    mutation("fix9-continuation-epoch", "the durable continuation and submitted swap share the reservation epoch", "d4fix9", "./internal/v2/secrets",
             ["TestContinuationCredentialGuards/epoch"], [
        edit("internal/v2/secrets/" "continuation_credentials.go", "func (s *Service) continuationOriginal", "intent.CancellationEpoch != r.CancellationEpoch ||", "false && intent.CancellationEpoch != r.CancellationEpoch ||"),
        edit("internal/v2/secrets/" "continuation_credentials.go", "func (s *Service) continuationOriginal", "swap.CancellationEpoch != intent.CancellationEpoch ||", "false && swap.CancellationEpoch != intent.CancellationEpoch ||"),
    ]),
    mutation("fix9-continuation-claim", "continuation acquisition rechecks a currently claimed intent", "d4fix9", "./internal/v2/secrets",
             ["TestContinuationCredentialGuards/claim"], [
        edit("internal/v2/secrets/" "continuation_credentials.go", "func (s *Service) continuationOriginal", "intent.Status != \"claimed\" ||", "false && intent.Status != \"claimed\" ||"),
        edit("internal/v2/secrets/launch_binding.go", "func (s *Service) recheckCredentialLaunch", "current.Status != \"claimed\" ||", "false && current.Status != \"claimed\" ||"),
    ]),
    mutation("fix9-broker-aad", "broker ciphertext authenticates the complete documented AAD", "d4fix9", "./internal/v2/secrets/native",
             ["TestEncryptedBrokerJournal"], [
        edit("internal/v2/secrets/native/broker.go", "func (v *brokerView) Read(", "r.Ciphertext, brokerAAD(r))", "r.Ciphertext, nil)"),
        edit("internal/v2/secrets/native/broker.go", "func (v *brokerView) Write(", "plain, brokerAAD(r))", "plain, nil)"),
    ]),
    mutation("fix9-broker-id", "broker AAD prevents id transplantation", "d4fix9", "./internal/v2/secrets/native",
             ["TestBrokerAADTransplant/id"], [
        edit("internal/v2/secrets/native/broker.go", "func brokerAAD(", "return []byte(", "r.ID = \"\"\n\treturn []byte("),
    ]),
    mutation("fix9-broker-kind", "broker AAD prevents kind transplantation", "d4fix9", "./internal/v2/secrets/native",
             ["TestBrokerAADTransplant/kind"], [
        edit("internal/v2/secrets/native/broker.go", "func brokerAAD(", "return []byte(", "r.Kind = \"\"\n\treturn []byte("),
    ]),
    mutation("fix9-broker-key", "broker AAD prevents key transplantation", "d4fix9", "./internal/v2/secrets/native",
             ["TestBrokerAADTransplant/key"], [
        edit("internal/v2/secrets/native/broker.go", "func brokerAAD(", "return []byte(", "r.KeyID = \"\"\n\treturn []byte("),
    ]),
    mutation("fix9-broker-lifetime", "journal writes cannot escape their locked callback", "d4fix9", "./internal/v2/secrets/native",
             ["TestBrokerViewLifetime"], [
        edit("internal/v2/secrets/native/broker.go", "func (v *brokerView) Write(", "if !v.active {", "if false && !v.active {"),
    ]),
    mutation("fix9-broker-cancel", "cancelled journal callbacks cannot write", "d4fix9", "./internal/v2/secrets/native",
             ["TestBrokerViewLifetime"], [
        edit("internal/v2/secrets/native/broker.go", "func (v *brokerView) Write(", "if err := wire.Context(v.ctx); err != nil {", "if err := wire.Context(v.ctx); false && err != nil {"),
    ]),
    mutation("fix9-broker-revoked", "a bound slot rechecks actual source revocation", "d4fix9", "./internal/v2/secrets",
             ["TestBoundMaterialSourceRevocation"], [
        edit("internal/v2/secrets/native/broker.go", "func (v *brokerView) Fetch(", "if r.Info.Revoked {", "if false && r.Info.Revoked {"),
    ]),
    mutation("fix9-broker-nonce", "every encrypted journal write has a fresh nonce", "d4fix9", "./internal/v2/secrets/native",
             ["TestBrokerNonceFresh"], [
        edit("internal/v2/secrets/native/broker.go", "func (v *brokerView) Write(", "r.Ciphertext = aead.Seal(", "clear(r.Nonce)\n\tr.Ciphertext = aead.Seal("),
    ]),
    mutation("fix9-broker-private", "ordinary metadata scans still enforce broker-file privacy", "d4fix9", "./internal/v2/secrets/native",
             ["TestBrokerPrivateEnumeration"], [
        edit("internal/v2/secrets/private/files.go", "func (d *Directory) Names(", "if brokerFileName(name) {", "if brokerFileName(name) { continue }\n\t\tif false && brokerFileName(name) {"),
    ]),
    mutation("fix9-material-expiry", "prepared profile bytes require an unexpired issued slot", "d4fix9", "./internal/v2/secrets",
             ["TestPreparedAgentMaterialGuards/expiry"], [
        edit("internal/v2/secrets/prepared_material.go", "func (s *Service) PreparedSlotMaterial", "!future(slot.Credential.ExpiresAt, s.deps.Clock.Now()) ||", "false && !future(slot.Credential.ExpiresAt, s.deps.Clock.Now()) ||"),
        edit(BASE + "projection_state.go", "func (s *Service) deliveryPolicy(", "|| !future(slot.Credential.ExpiresAt, s.deps.Clock.Now())", "|| false && !future(slot.Credential.ExpiresAt, s.deps.Clock.Now())"),
    ]),
    mutation("fix9-material-binding", "restart material lookup cannot ignore a missing retained binding", "d4fix9", "./internal/v2/secrets", ["TestCredentialChangedRetryAndRestart"], [
        edit("internal/v2/secrets/credential_release.go", "func (s *Service) SlotMaterial", "_, retainedPlan, err := s.slotBinding(ctx, slot)\n\tif err != nil {", "_, retainedPlan, err := s.slotBinding(ctx, slot)\n\tif false && err != nil {"),
    ]),
    mutation("fix9-profile-selected", "Acquire cannot choose another delegated profile over the retained selection", "d4fix9", "./internal/v2/secrets",
             ["TestContinuationCredentialSelection"], [
        edit("internal/v2/secrets/credential_slots.go", "func (s *Service) acquireProfile", "if launch.profile != grant.ID {", "if false && launch.profile != grant.ID {"),
    ]),
    mutation("fix9-storage-life", "the helper-owned home belongs to the exact reserved life", "d4fix9", "./internal/v2/secrets",
             ["TestReservationGuards/storage"], [
        edit("internal/v2/secrets/launch_binding.go", "func (s *Service) launchAllocation", "storage.Home.LifeID != r.Target.LifeID ||", "false && storage.Home.LifeID != r.Target.LifeID ||"),
    ]),
    mutation("fix9-room-future", "room evidence cannot claim an observation after the injected current time", "d4fix9", "./internal/v2/secrets",
             ["TestProtectedRoomGuards/future"], [
        edit("internal/v2/secrets/profiles.go", "func (s *Service) profileObservation", "checked.After(s.deps.Clock.Now()) ||", "false && checked.After(s.deps.Clock.Now()) ||"),
    ]),
    mutation("fix9-cleanup-replay", "a released slot still rejects a changed process generation on replay", "d4fix9", "./internal/v2/secrets", ["TestCleanupReplayBinding"], [
        edit("internal/v2/secrets/credential_release.go", "func (s *Service) releaseCredential", "if err := s.measuredRelease(ctx, slot, observation); err != nil {", "if slot.Released { return nil }\n\tif err := s.measuredRelease(ctx, slot, observation); err != nil {"),
    ]),
    mutation("fix9-object-chunks", "protected object reads retain all API-bounded chunks", "d4fix9", "./internal/v2/secrets",
             ["TestProtectedObjectChunks"], [
        edit("internal/v2/secrets/launch_binding.go", "func (s *Service) protectedObject", "for int64(len(data)) < ref.Bytes {", "for int64(len(data)) < ref.Bytes && len(data) == 0 {"),
    ]),
    mutation("fix9-object-offset", "each protected chunk has its exact contiguous offset", "d4fix9", "./internal/v2/secrets",
             ["TestProtectedObjectChunkGuards/offset"], [
        edit("internal/v2/secrets/launch_binding.go", "func (s *Service) protectedObject", "chunk.Offset != offset ||", "false && chunk.Offset != offset ||"),
    ]),
    mutation("fix9-object-part-hash", "each protected chunk authenticates its actual returned bytes", "d4fix9", "./internal/v2/secrets",
             ["TestProtectedObjectChunkGuards/hash"], [
        edit("internal/v2/secrets/launch_binding.go", "func (s *Service) protectedObject", "chunk.SHA256 != api.Digest(hex.EncodeToString(part[:]))", "false && chunk.SHA256 != api.Digest(hex.EncodeToString(part[:]))"),
    ]),
])
CATALOG.extend([
    mutation("fix10-level", "reserved child level comes from the retained reservation", "d4fix10", PACKAGE,
             ["TestReservedAuthorityPins/level"], [
        edit(BASE + "launch_binding.go", "func validateReservedSelection(", "level != r.Level ||", "false && level != r.Level ||"),
    ]),
    mutation("fix10-role", "reserved child role comes from the retained reservation", "d4fix10", PACKAGE,
             ["TestReservedAuthorityPins/role"], [
        edit(BASE + "launch_binding.go", "func validateReservedSelection(", "role != r.Role ||", "false && role != r.Role ||"),
    ]),
    mutation("fix10-driver", "reserved child driver comes from the retained reservation", "d4fix10", PACKAGE,
             ["TestReservedAuthorityPins/driver"], [
        edit(BASE + "launch_binding.go", "func validateReservedSelection(", "driver != r.Driver ||", "false && driver != r.Driver ||"),
    ]),
    mutation("fix10-ticket", "root launch preserves the actually consumed ticket", "d4fix10", PACKAGE,
             ["TestReservedAuthorityPins/ticket"], [
        edit(BASE + "launch_binding.go", "func validateReservedSelection(", 'r.Authority.Kind == "ticket" && ticket != r.Authority.ID', 'false && r.Authority.Kind == "ticket" && ticket != r.Authority.ID'),
    ]),
    mutation("fix10-proof", "retained human launch preserves the consumed operation proof", "d4fix10", PACKAGE,
             ["TestRetainedConsumedProof/missing", "TestRetainedConsumedProof/foreign"], [
        edit(BASE + "launch_binding.go", "func (s *Service) launchOriginal(", 'if r.Authority.Kind == "proof" &&', 'if false && r.Authority.Kind == "proof" &&'),
    ]),
    mutation("fix10-capture-current", "prepared credentials require the current approved capture refusal policy", "d4fix10", PACKAGE,
             ["TestCaptureCurrentPolicy/disabled", "TestCaptureCurrentPolicy/approval"], [
        edit(BASE + "prepared_material.go", "func (s *Service) PreparedSlotMaterial(", "if err := api.ValidateCapturePolicy(launch.record.Plan.Capture, policy); err != nil {", "if err := api.ValidateCapturePolicy(launch.record.Plan.Capture, policy); false && err != nil {"),
    ]),
    mutation("fix10-worker-kind", "retained worker material rejects an agent-kind binding", "d4fix10", PACKAGE,
             ["TestPreparedWorkerBindingKind"], [
        edit(BASE + "worker_credentials.go", "func (s *Service) workerSlotBinding(", 'binding.Record.Kind != "worker" ||', 'false && binding.Record.Kind != "worker" ||'),
    ]),
    mutation("f11-usage-percent", "outside from-profile usage must actually be exhausted", "d4fix11", PACKAGE,
             ["TestOutsideUsageGuards/percent"], [
        edit(BASE + "usage_source.go", "func parseUsageRows(", "used >= 100 &&", "used >= 0 &&"),
        edit(BASE + "usage_source.go", "func (s *Service) ReadUsageWindow(", "if err := api.ValidateUsageWindow(evidence, request, producer, s.deps.Clock.Now()); err != nil {", "if err := api.ValidateUsageWindow(evidence, request, producer, s.deps.Clock.Now()); false && err != nil {"),
    ]),
    mutation("f11-usage-fresh", "outside observation is fresh successful and after the measured exit", "d4fix11", PACKAGE,
             ["TestOutsideUsageGuards/stale", "TestOutsideUsageGuards/pre-exit", "TestOutsideUsageGuards/future"], [
        edit(BASE + "usage_source.go", "func (s *Service) ReadUsageWindow(", "if err := api.ValidateUsageWindow(evidence, request, producer, s.deps.Clock.Now()); err != nil {", "if err := api.ValidateUsageWindow(evidence, request, producer, s.deps.Clock.Now()); false && err != nil {"),
    ]),
    mutation("f11-usage-profile", "outside usage measures the causing from-profile", "d4fix11", PACKAGE,
             ["TestOutsideUsageGuards/profile"], [
        edit(BASE + "usage_source.go", "func (s *Service) usageProfile(", "if record.Plan.Runner.Slot.ProfileGrantID != request.ProfileGrantID || record.Plan.Runner.Slot.ProfileID != request.ProfileID {", "if false && (record.Plan.Runner.Slot.ProfileGrantID != request.ProfileGrantID || record.Plan.Runner.Slot.ProfileID != request.ProfileID) {"),
    ]),
    mutation("f11-usage-producer", "outside producer is compared with the actual native connection facts", "d4fix11", PACKAGE,
             ["TestOutsideUsageGuards/producer"], [
        edit(BASE + "usage_jobs.go", "func (s *Service) mappedWorker(", "if err := api.ValidateWorkerPrincipal(principal, binding, facts, operation, s.deps.Clock.Now()); err != nil {", "if err := api.ValidateWorkerPrincipal(principal, binding, facts, operation, s.deps.Clock.Now()); false && err != nil {"),
    ]),
    mutation("f11-usage-source", "outside source uses the exact ordered five-column TSV", "d4fix11", PACKAGE,
             ["TestOutsideUsageGuards/header"], [
        edit(BASE + "usage_source.go", "func parseUsageRows(", 'strings.Join(rows[0], "\\t") != "PROFILE\\tPLAN\\tWINDOW\\tUSED_PERCENT\\tRESETS_UTC"', 'false && strings.Join(rows[0], "\\t") != "PROFILE\\tPLAN\\tWINDOW\\tUSED_PERCENT\\tRESETS_UTC"'),
        edit(BASE + "usage_source.go", "func (s *Service) ReadUsageWindow(", "if err := api.ValidateUsageSource(evidence, output.Raw, profile.Usage.VendorProfile); err != nil {", "if err := api.ValidateUsageSource(evidence, output.Raw, profile.Usage.VendorProfile); false && err != nil {"),
    ]),
    mutation("f11-usage-known-reset", "unknown reset rows cannot be selected as exhaustion", "d4fix11", PACKAGE,
             ["TestUsageTSVAllRows"], [
        edit(BASE + "usage_source.go", "func parseUsageRows(", "!unknown && reset.After(now)", "reset.Equal(reset)"),
    ]),
    mutation("f11-usage-all-rows", "every vendor TSV row requires finite nonnegative usage", "d4fix11", PACKAGE,
             ["TestUsageTSVAllRows"], [
        edit(BASE + "usage_source.go", "func parseUsageRows(", "math.IsInf(used, 0) ||", "false && math.IsInf(used, 0) ||"),
    ]),
    mutation("f11-usage-grants", "outside worker cannot borrow lane workspace capabilities", "d4fix11", PACKAGE,
             ["TestOutsideUsageGuards/grants"], [
        edit(BASE + "usage_source.go", "func (s *Service) usageGrants(", "len(current.Data)+len(current.Resources)+len(current.Profiles)+len(current.Channels) != 0 ||", "false && len(current.Data)+len(current.Resources)+len(current.Profiles)+len(current.Channels) != 0 ||"),
    ]),
    mutation("f11-worker-mapping", "credential delivery authenticates lease peer claim and closed operation", "d4fix11", PACKAGE,
             ["TestMappedCredentialGuards/lease", "TestMappedCredentialGuards/peer", "TestMappedCredentialGuards/claim", "TestMappedCredentialGuards/permission"], [
        edit(BASE + "usage_jobs.go", "func (s *Service) mappedWorker(", "if err := api.ValidateWorkerPrincipal(principal, binding, facts, operation, s.deps.Clock.Now()); err != nil {", "if err := api.ValidateWorkerPrincipal(principal, binding, facts, operation, s.deps.Clock.Now()); false && err != nil {"),
    ]),
    mutation("f11-worker-material", "mapped credential delivery returns actual selected protected bytes", "d4fix11", PACKAGE,
             ["TestMappedCredentialWorker"], [
        edit(BASE + "usage_jobs.go", "func (s *Service) MappedWorkerMaterial(", "return material, nil", 'return api.SecretMaterial{}, api.NotImplemented("lb-v2-secrets", "deliberate mapped material predecessor")'),
    ]),
    mutation("f11-usage-command", "the native query uses the exact fresh fixed argv", "d4fix11", PACKAGE,
             ["TestUsageCommand"], [
        edit(BASE + "usage_command.go", "func RunUsageCommand(", 'exec.CommandContext(bounded, "/proc/self/fd/3", "usage", "--max-age", "0")', 'exec.CommandContext(bounded, "/proc/self/fd/3", "usage", "--max-age", "1")'),
    ]),
    mutation("f11-usage-command-pin", "the native query hashes the held executable against enrollment", "d4fix11", PACKAGE,
             ["TestUsageCommandGuards/pin"], [
        edit(BASE + "usage_command.go", "func RunUsageCommand(", "api.Digest(hex.EncodeToString(hash.Sum(nil))) != selected.Request.Executable.SHA256", "false && api.Digest(hex.EncodeToString(hash.Sum(nil))) != selected.Request.Executable.SHA256"),
    ]),
    mutation("f11-usage-command-home", "the native query uses a private worker home handle", "d4fix11", PACKAGE,
             ["TestUsageCommandGuards/home"], [
        edit(BASE + "usage_command.go", "func RunUsageCommand(", "homeInfo.Mode().Perm() != 0700", "false && homeInfo.Mode().Perm() != 0700"),
    ]),
    mutation("f11-usage-command-generation", "the native query rechecks its actual kernel lifetime", "d4fix11", PACKAGE,
             ["TestUsageCommandGuards/generation"], [
        edit(BASE + "usage_process_linux.go", "func verifyUsageProcess(", "fields[19] != p.Peer.ProcessGeneration ||", "false && fields[19] != p.Peer.ProcessGeneration ||"),
    ]),
    mutation("f11-usage-producer-path", "the owned outside evidence source returns its retained measured result", "d4fix11", PACKAGE,
             ["TestOutsideUsageWindow"], [
        edit(BASE + "usage_source.go", "func (s *Service) ReadUsageWindow(", "return evidence, nil", 'return api.UsageWindowEvidence{}, api.NotImplemented("lb-v2-secrets", "deliberate outside usage predecessor")'),
    ]),
    mutation("f11-usage-seals", "hashed executable bytes cannot change before exec", "d4fix11", PACKAGE,
             ["TestUsageExecutableSnapshot"], [
        edit(BASE + "usage_process_linux.go", "func snapshotUsageExecutable(", "unix.F_SEAL_GROW|unix.F_SEAL_WRITE", "unix.F_SEAL_GROW"),
    ]),
    mutation("f11-usage-output", "outside output is complete and bounded even when exit races the pipe", "d4fix11", PACKAGE,
             ["TestUsageCommandGuards/overflow", "TestUsageCommandGuards/stderr-overflow"], [
        edit(BASE + "usage_command.go", "func (b *usageBuffer) Write(", "if len(data) > b.limit-len(b.data) {", "if false && len(data) > b.limit-len(b.data) {"),
    ]),
    mutation("f11-usage-cancel", "cancellation of an actual started query returns typed cancelled", "d4fix11", PACKAGE,
             ["TestUsageCommandCancellation"], [
        edit(BASE + "usage_command.go", "func RunUsageCommand(", "if bounded.Err() != nil {", "if false && bounded.Err() != nil {"),
    ]),
    mutation("f11-usage-executable-mode", "the installed query executable cannot be group or other writable", "d4fix11", PACKAGE,
             ["TestUsageCommandGuards/writable-exe", "TestUsageCommandGuards/owner-write"], [
        edit(BASE + "usage_command.go", "func RunUsageCommand(", "info.Mode().Perm()&0222 != 0 ||", "false && info.Mode().Perm()&0222 != 0 ||"),
    ]),
])

CATALOG.extend([
    mutation("f12-required-id", "production construction requires the broker-channel identity", "d4fix12", PACKAGE,
             ["TestProjectionDeps"], [
        edit(SERVICE, "func New(", "if wire.Nil(deps.ProjectionIdentity) {", "if false && wire.Nil(deps.ProjectionIdentity) {"),
    ]),
    mutation("f12-producer", "the broker supplies real selected descriptor exports", "d4fix12", PACKAGE, ["TestProjectionFlow", "TestHeadlessProjection"], [
        edit("internal/v2/secrets/projection.go", "func (s *Service) transferCredentials(", "return api.CredentialTransfer{Authority: f.transfer.Authority, Files: append([]*os.File(nil), f.transfer.Files...)}, nil", "return api.CredentialTransfer{}, api.NotImplemented(\"lb-v2-secrets\", \"deliberate projection predecessor\")"),
    ]),
    mutation("f12-source", "projection inventory comes from current protected source state", "d4fix12", PACKAGE, ["TestProjectionGuards/source"], [
        edit("internal/v2/secrets/projection.go", "func (s *Service) transferLocked(", "if !reflect.DeepEqual(sources, a.Sources) {", "if false && !reflect.DeepEqual(sources, a.Sources) {"),
        edit("internal/v2/secrets/projection.go", "func (s *Service) transferLocked(", "if !reflect.DeepEqual(versions, a.Sources) {", "if false && !reflect.DeepEqual(versions, a.Sources) {"),
    ]),
    mutation("f12-held-observe", "acknowledgement agrees with the independent helper observer", "d4fix12", PACKAGE, ["TestProjectionGuards/ack"], [
        edit("internal/v2/secrets/projection.go", "func (s *Service) acknowledgeLocked(", "if !reflect.DeepEqual(actual, receipt) {", "if false && !reflect.DeepEqual(actual, receipt) {"),
    ]),
    mutation("f12-held-shape", "acknowledgement validates complete held descriptor counts", "d4fix12", PACKAGE, ["TestProjectionGuards/holding"], [
        edit("internal/v2/secrets/projection.go", "func (s *Service) acknowledgeLocked(", "if err := api.ValidateCredentialProjectionReceipt(f.transfer, f.facts, receipt, s.deps.Clock.Now()); err != nil {", "if err := api.ValidateCredentialProjectionReceipt(f.transfer, f.facts, receipt, s.deps.Clock.Now()); false && err != nil {"),
    ]),
    mutation("f12-held-durable", "helper acknowledgement is durably read back before originals close", "d4fix12", PACKAGE, ["TestProjectionGuards/durable"], [
        edit("internal/v2/secrets/projection.go", "func (s *Service) acknowledgeLocked(", "if read.State != \"held\" ||", "if false && read.State != \"held\" ||"),
        edit("internal/v2/secrets/projection.go", "func (s *Service) acknowledgeLocked(", "read.Generation != receipt.Generation || read.Receipt == nil || !reflect.DeepEqual(*read.Receipt, receipt) || !reflect.DeepEqual(read, committed)", "false && (read.Generation != receipt.Generation || read.Receipt == nil || !reflect.DeepEqual(read.Receipt, &receipt) || !reflect.DeepEqual(read, committed))"),
    ]),
    mutation("f12-gate-policy", "opening checks the actual current approved policy head", "d4fix12", PACKAGE, ["TestProjectionGuards/policy"], [
        edit("internal/v2/secrets/projection.go", "func (s *Service) projectionPolicy(", "policy.Generation != r.Handoff.Spec.PolicyGeneration ||", "false && policy.Generation != r.Handoff.Spec.PolicyGeneration ||"),
        edit("internal/v2/secrets/projection.go", "func (s *Service) projectionSlots(", "policy.Generation != r.Handoff.Spec.PolicyGeneration ||", "false && policy.Generation != r.Handoff.Spec.PolicyGeneration ||"),
    ]),
    mutation("f12-gate-claim", "a gate requires the current claimed open effect", "d4fix12", PACKAGE,
             ["TestProjectionGuards/claim"], [
        edit(BASE + "projection_guard.go", "func (s *Service) checkProjectionGate(", "claim.State != api.EffectClaimed ||", "false && claim.State != api.EffectClaimed ||"),
    ]),
    mutation("f12-withdraw-admit", "pending withdrawal closes admission before draining an existing guard", "d4fix12", PACKAGE,
             ["TestProjectionDrain"], [
        edit(BASE + "projection.go", "func (s *Service) BeginCredentialWithdrawal(", "f.fence()", "f.mu.Lock(); f.mu.Unlock()"),
    ]),
    mutation("f12-withdraw-zero", "nonzero helper collection cannot erase retained broker credentials", "d4fix12", PACKAGE,
             ["TestWithdrawalZeros"], [
        edit(BASE + "projection.go", "func (s *Service) FinishCredentialWithdrawal(", "if err := api.ValidateCredentialWithdrawalHelper(validationRecord, actual); err != nil {", "if err := api.ValidateCredentialWithdrawalHelper(validationRecord, actual); false && err != nil {"),
    ]),
    mutation("f12-refresh-native", "reverse refresh validates its actual root-owned quiescent descriptor", "d4fix12", PACKAGE,
             ["TestRefreshOwnerReject"], [
        edit(BASE + "projection.go", "func (s *Service) AcceptCredentialRefresh(", "if err := api.ValidateCredentialRefresh(record, refresh, s.deps.Clock.Now()); err != nil {", "if err := api.ValidateCredentialRefresh(record, refresh, s.deps.Clock.Now()); false && err != nil {"),
    ]),
    mutation("f12-rights", "the private native sender transfers an actual descriptor", "d4fix12", PACKAGE,
             ["TestProjectionSCM"], [
        edit(BASE + "projection_channel_linux.go", "func sendProjectionPacket(", "rights = unix.UnixRights(fds...)", "rights = nil"),
    ]),
    mutation("f12-seal", "export bytes cannot be rewritten through an opened alias", "d4fix12", PACKAGE,
             ["TestProjectionSCM"], [
        edit(BASE + "projection_linux.go", "func exportCredential(", "unix.F_SEAL_WRITE|unix.F_SEAL_GROW", "unix.F_SEAL_GROW"),
        edit(BASE + "projection_linux.go", "func credentialFact(", "required := unix.F_SEAL_WRITE |", "required :="),
    ]),
    mutation("f12-early-release", "ordinary release cannot bypass durable projection withdrawal", "d4fix12", PACKAGE,
             ["TestProjectionEarlyRelease"], [
        edit(BASE + "projection.go", "func (s *Service) projectionReleasedLocked(", 'if !journal.Released || record.State != "withdrawn" || record.Generation < 2 || record.Withdrawal == nil {', 'if false && (!journal.Released || record.State != "withdrawn" || record.Generation < 2 || record.Withdrawal == nil) {'),
        edit(BASE + "projection.go", "func (s *Service) projectionReleasedLocked(", 'return api.ValidateCredentialWithdrawal(api.CredentialProjectionRecord{Authority: record.Authority, Generation: record.Generation - 1, State: "withdrawing", Receipt: record.Receipt, Fence: record.Fence}, *record.Withdrawal)', "return nil"),
    ]),
    mutation("f12-worker-policy", "worker bytes require the exact current policy generation", "d4fix12", PACKAGE,
             ["TestWorkerPolicyDelivery/prepared", "TestWorkerPolicyDelivery/bound", "TestWorkerPolicyDelivery/copy"], [
        edit(BASE + "worker_credentials.go", "func (s *Service) currentWorkerGrants(", "current.PolicyGeneration != policy.Generation", "current.PolicyGeneration > policy.Generation"),
        edit(BASE + "projection_state.go", "func (s *Service) deliveryPolicy(", "slot.PolicyGeneration != policy.Generation ||", "false && slot.PolicyGeneration != policy.Generation ||"),
    ]),
    mutation("f12-release-race", "the tombstone transaction must reject a projection bound after measurement", "d4fix12", PACKAGE, ["TestReleaseBindRace/profile", "TestReleaseBindRace/worker"], [
        edit("internal/v2/secrets/credential_release.go", "func (s *Service) releaseSlotLocked(", "if err := s.releaseProjectionLocked(ctx, journal, slot, current); err != nil {", "if err := s.releaseProjectionLocked(ctx, journal, slot, current); false && err != nil {"),
    ]),
    mutation("f12-effect-state", "planning consumes only the shared claimed effect state", "d4fix12", PACKAGE,
             ["TestPlanClaimState"], [
        edit(BASE + "launch_binding.go", "func (s *Service) livePlanClaim(", "record.State != api.EffectClaimed ||", 'record.State != "running" ||'),
    ]),
    mutation("f12-stage-cap", "one actor cannot exhaust the shared encrypted-stage pool", "d4fix12", PACKAGE,
             ["TestActorStageCap"], [
        edit(SERVICE, "func (s *Service) SecretStage(", "if actorStages >= 8 {", "if false && actorStages >= 8 {"),
    ]),
    mutation("f12-history-bound", "metadata replay has a bounded total work window", "d4fix12", PACKAGE,
             ["TestHistoryWalkBound"], [
        edit(BASE + "mutations.go", "func (s *Service) heads(", "if walked > 65536 || payloadBytes > 8<<20 {", "if false && (walked > 65536 || payloadBytes > 8<<20) {"),
    ]),
    mutation("f12-retry-source", "metadata retries revalidate the actual revoked source", "d4fix12", PACKAGE,
             ["TestRetrySourceRevocation/acquire", "TestRetrySourceRevocation/inject"], [
        edit(BASE + "native/broker.go", "func (v *brokerView) Fetch(", "if r.Info.Revoked {", "if false && r.Info.Revoked {"),
    ]),
    mutation("f12-retained-policy", "retained credential selections survive an approved live policy refresh", "d4fix12", PACKAGE,
             ["TestRetainedPolicyAdvance"], [
        edit(BROKER, "func (s *Service) currentGrants(", "if !retained && policy.Generation != current.PolicyGeneration ||", "if policy.Generation != current.PolicyGeneration ||"),
    ]),
    mutation("f12-journal-generation", "broker envelope generation is authenticated with its payload", "d4fix12", PACKAGE + "/native",
             ["TestBrokerAADTransplant/generation"], [
        edit(BASE + "native/broker.go", "func brokerAAD(", "strconv.FormatUint(uint64(r.Generation), 10)", "strconv.FormatUint(0, 10)"),
    ]),
])

CATALOG.extend([
    mutation("r6-quarantine", "exposed canonical logins remain quarantined with closed originals", "d4fix12", "./internal/v2/secrets",
             ["TestExposureQuarantine/cancelled","TestExposureQuarantine/rotation"], [
        edit("internal/v2/secrets/projection_state.go", "func (s *Service) quarantineProjection(", "owner.Quarantined = true", "owner.Quarantined = false"),
        edit(BASE + "projection_state.go", "func (s *Service) quarantineProjection(", "!read.Quarantined ||", "false && !read.Quarantined ||"),
    ]),
    mutation("r6-worker", "native worker projection retains its cleanup binding and selection", "d4fix12", "./internal/v2/secrets",
             ["TestWorkerProjection/binding","TestWorkerProjection/marker"], [
        edit("internal/v2/secrets/projection_state.go", "func bindProjectionSlot(", "if slot.Kind == \"worker\" {", "if false && slot.Kind == \"worker\" {"),
        edit("internal/v2/secrets/projection.go", "func (s *Service) projectionSlots(", "if err := s.retainedWorkerSpecJournal(ctx, r.Handoff, found, false, j); err != nil {", "if err := s.retainedWorkerSpecJournal(ctx, r.Handoff, found, false, j); false && err != nil {"),
    ]),
    mutation("r6-completion", "store completion succeeds before canonical material is released", "d4fix12", "./internal/v2/secrets",
             ["TestWithdrawalCommit"], [
        edit("internal/v2/secrets/projection.go", "func (s *Service) FinishCredentialWithdrawal(", "record, err = s.completeWithdrawal(ctx, record, actual)\n\t\t\tif err != nil {", "record, err = s.completeWithdrawal(ctx, record, actual)\n\t\t\tif false && err != nil {"),
    ]),
    mutation("r6-fence", "native failure fences persist in the failure transaction", "d4fix12", "./internal/v2/secrets",
             ["TestDurableFence/exchange","TestDurableFence/guard"], [
        edit("internal/v2/secrets/projection_state.go", "func (s *Service) fenceProjectionLocked(", "p.Fenced = true", "p.Fenced = false"),
    ]),
    mutation("r6-policy", "delivery and transfer read the current policy inside their lock", "d4fix12", "./internal/v2/secrets",
             ["TestLiveSlotPolicy","TestLockedPolicyRead"], [
        edit("internal/v2/secrets/projection_state.go", "func (s *Service) deliveryPolicy(", "slot.PolicyGeneration != policy.Generation ||", "false && slot.PolicyGeneration != policy.Generation ||"),
        edit("internal/v2/secrets/projection.go", "func (s *Service) projectionPolicy(", "policy.Generation != r.Handoff.Spec.PolicyGeneration ||", "false && policy.Generation != r.Handoff.Spec.PolicyGeneration ||"),
        edit("internal/v2/secrets/projection.go", "func (s *Service) projectionSlots(", "policy.Generation != r.Handoff.Spec.PolicyGeneration ||", "false && policy.Generation != r.Handoff.Spec.PolicyGeneration ||"),
    ]),
    mutation("r6-partial", "an interrupted durable bind cannot be retried", "d4fix12", "./internal/v2/secrets",
             ["TestPartialBind/profile","TestPartialBind/task","TestPartialBind/worker"], [
        edit("internal/v2/secrets/journal_stage.go", "func (s *Service) withPreparedBind(", "if prior.Injection == nil {", "if false && prior.Injection == nil {"),
    ]),
    mutation("r6-ack", "acknowledgement replay validates shape and transfer identity", "d4fix12", "./internal/v2/secrets",
             ["TestAckReplayShape","TestTransferAckID"], [
        edit("internal/v2/secrets/projection.go", "func (s *Service) acknowledgeLocked(", "if err := api.ValidateCredentialProjectionReceipt(f.transfer, f.facts, receipt, s.deps.Clock.Now()); err != nil {", "if err := api.ValidateCredentialProjectionReceipt(f.transfer, f.facts, receipt, s.deps.Clock.Now()); false && err != nil {"),
        edit("internal/v2/secrets/projection_state.go", "func validateTransferReceiptID(", "if receipt.ProjectionID != transfer.Authority.ID {", "if false && receipt.ProjectionID != transfer.Authority.ID {"),
    ]),
    mutation("r6-release-group", "all injection slots validate before any profile lease is released", "d4fix12", "./internal/v2/secrets",
             ["TestInjectionReleaseGroup"], [
        edit("internal/v2/secrets/credential_release.go", "func (s *Service) releaseInjection(", "s.releaseSlotLocked(ctx, staged, slot)", "s.releaseSlotLocked(ctx, j, slot)"),
    ]),
])

# Fable follow-up. Live measurements have nonzero owned controls.
CATALOG.extend([
    mutation("r7-broker-count", "open originals cannot be replaced by a closed flag", "d4fix12", "./internal/v2/secrets", ["TestLiveWithdrawal/original"], [
        edit("internal/v2/secrets/projres.go", "func (f *projectionFlight) brokerDescriptorCount(", "count++", "count += 0"),
    ]),
    mutation("r7-lease-count", "kernel locks outlive duplicated owning descriptors", "d4fix12", "./internal/v2/secrets", ["TestLiveWithdrawal/lease"], [
        edit("internal/v2/secrets/projres.go", "func (f *projectionFlight) refreshLeaseCount(", "if held {", "if false && held {"),
    ]),
    mutation("r7-lease-missing", "unknown original live lease inventory refuses", "d4fix12", "./internal/v2/secrets", ["TestLiveWithdrawal/missing"], [
        edit("internal/v2/secrets/projres.go", "func (f *projectionFlight) refreshLeaseCount(", "if !found {", "if false && !found {"),
    ]),
    mutation("r7-kernel-probe", "refresh exclusion has an independent kernel probe", "d4fix12", "./internal/v2/secrets/private", ["TestRefreshKernel"], [
        edit("internal/v2/secrets/private/refresh.go", "func (l *RefreshLease) probe(", "return true, nil", "return false, nil"),
    ]),
    mutation("r7-withdraw-lock", "withdrawal decisions use one canonical transaction", "d4fix12", "./internal/v2/secrets", ["TestWithdrawalLock/begin","TestWithdrawalLock/finish"], [
        edit("internal/v2/secrets/projection.go", "func (s *Service) BeginCredentialWithdrawal(", "defer f.leave()", "defer f.leave()\n\tif _, _, err := s.projectionLookup(ctx, request.ProjectionID); err != nil { return result, err }"),
        edit("internal/v2/secrets/projection.go", "func (s *Service) FinishCredentialWithdrawal(", "defer f.leave()", "defer f.leave()\n\tif _, _, err := s.projectionLookup(ctx, id); err != nil { return result, err }"),
    ]),
    mutation("r7-writable", "facts observe real write-access aliases", "d4fix12", "./internal/v2/secrets", ["TestWritableAliases"], [
        edit("internal/v2/secrets/projection_linux.go", "func credentialWritableHandles(", "count++", "count += 0"),
    ]),
    mutation("r7-clear", "refused selected slots clear both owned byte slices", "d4fix12", "./internal/v2/secrets", ["TestSlotClearing/profile","TestSlotClearing/validator","TestSlotClearing/login","TestSlotClearing/owner"], [
        edit("internal/v2/secrets/projection.go", "func (s *Service) projectionSlots(", "if !selected {", "if false && !selected {"),
    ]),
    mutation("r7-policy", "credential paths select the approved policy head", "d4fix12", "./internal/v2/secrets", ["TestCurrentPolicy/agent","TestCurrentPolicy/worker","TestCurrentPolicy/delivery"], [
        edit("internal/v2/secrets/broker.go", "func (s *Service) currentGrants(", "s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ServiceScope)", "s.deps.Store.Policy(ctx, s.deps.ServiceScope)"),
        edit("internal/v2/secrets/worker_credentials.go", "func (s *Service) currentWorkerGrants(", "s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ServiceScope)", "s.deps.Store.Policy(ctx, s.deps.ServiceScope)"),
        edit("internal/v2/secrets/projection_state.go", "func (s *Service) deliveryPolicy(", "s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ServiceScope)", "s.deps.Store.Policy(ctx, s.deps.ServiceScope)"),
    ]),
    mutation("r7-ticker", "periodic gate checks revalidate live authority", "d4fix12", "./internal/v2/secrets", ["TestGateTicker/policy","TestGateTicker/claim","TestGateTicker/grants","TestGateTicker/epoch"], [
        edit("internal/v2/secrets/projection_guard.go", "func (s *Service) lockCredentialProjection(", "if _, err := s.checkProjectionGate(bounded, j, f, request); err != nil {", "if err := s.projectionPeer(bounded, f.peer, record.Authority); err != nil {"),
    ]),
    mutation("r7-quarantine-retry", "quarantined slots cannot replay acquisition", "d4fix12", "./internal/v2/secrets", ["TestExposureQuarantine/cancelled","TestExposureQuarantine/rotation"], [
        edit("internal/v2/secrets/credential_slots.go", "func (s *Service) acquireProfile(", "if owner.Quarantined || owner.PendingRelease != \"\" || owner.SlotID != retained.ID {", "if false && (owner.Quarantined || owner.PendingRelease != \"\" || owner.SlotID != retained.ID) {"),
    ]),
    mutation("r7-refresh-live", "a retired kernel lease cannot authorize another use", "d4fix12", "./internal/v2/secrets", ["TestLiveWithdrawal/lease"], [
        edit("internal/v2/secrets/projres.go", "func (f *projectionFlight) checkRefreshLease(", "return live.lease.Check()", "_ = live.lease.Check(); return nil"),
    ]),
])

# Round 8 prepared-copy gates and the public guard refusal interface.
CATALOG.extend([
    mutation("r8-prepared", "prepared profile and task copies recheck live canonical delivery authority", "d4fix12", "./internal/v2/secrets", ["TestPreparedPolicy/profile/quarantine","TestPreparedPolicy/profile/pending","TestPreparedPolicy/profile/excluded","TestPreparedPolicy/task/quarantine","TestPreparedPolicy/task/pending","TestPreparedPolicy/task/excluded"], [
        edit("internal/v2/secrets/prepared_material.go", "func (s *Service) PreparedSlotMaterial(", "if err := s.deliveryPolicy(ctx, j, latest); err != nil {", "if err := s.deliveryPolicy(ctx, j, latest); false && err != nil {"),
        edit("internal/v2/secrets/prepared_material.go", "func (s *Service) PreparedSlotMaterial(", "if err := s.deliveryPolicy(ctx, j, selected); err != nil {", "if err := s.deliveryPolicy(ctx, j, selected); false && err != nil {"),
    ]),
    mutation("r8-worker", "first and retry worker copies require the final approved policy", "d4fix12", "./internal/v2/secrets", ["TestPreparedWorkerPolicy/first","TestPreparedWorkerPolicy/retry"], [
        edit("internal/v2/secrets/worker_credentials.go", "func (s *Service) PrepareWorkerMaterial(", "if err := s.deliveryPolicy(ctx, j, current); err != nil {", "if err := s.deliveryPolicy(ctx, j, current); false && err != nil {"),
    ]),
    mutation("r8-policy-source", "locked delivery selects the approved head over historical scope policy", "d4fix12", "./internal/v2/secrets", ["TestCurrentPolicy/delivery"], [
        edit("internal/v2/secrets/projection_state.go", "func (s *Service) deliveryPolicy(", "s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ServiceScope)", "s.deps.Store.Policy(ctx, s.deps.ServiceScope)"),
    ]),
    mutation("r8-guard", "a gate refusal returns a nil interface and keeps its actual error", "d4fix12", "./internal/v2/secrets", ["TestGuardRefusal/policy","TestGuardRefusal/claim"], [
        edit("internal/v2/secrets/projection_guard.go", "func (s *Service) LockCredentialProjection(", "return nil, err", "return guard, err"),
    ]),
])

# A missing production capability is an unavailable mutation, never a killed
# red or a passed live boundary. These names reserve exact acceptance targets.
for name, rule, target, dependency, fault in [
    ("human-stage", "human staging/import", "SECRET-INJECT", "installed identity/service and protected launch delivery",
     "Remove verified session/proof binding on sealed import."),
    ("inject-env", "delegated env bytes compare", "SECRET-INJECT", "protected runtime projection",
     "Remove selected environment slot materialization before release."),
    ("inject-file", "delegated read-only file bytes compare", "SECRET-INJECT", "protected runtime projection",
     "Remove the selected read-only file projection before release."),
    ("inherit-env", "broad environment inheritance fails", "SECRET-INJECT", "launcher credential projection",
     "Replace the fixed launch environment with broad host inheritance."),
    ("emit-values", "events and archives exclude values", "SECRET-INJECT", "committed injection and archive path",
     "Append actual injected bytes to event or archive output."),
    ("registry-mount", "other login and broad registry stay hidden", "CREDENTIAL-BOUND", "enrollment and selected-profile slots",
     "Widen the selected slot mount to the shared login registry."),
    ("refresh-race", "one refresh owner for concurrent logins", "CREDENTIAL-BOUND", "canonical login identity and persistent leases",
     "Remove canonical-login refresh lease exclusion."),
    ("cleanup-early", "physical slot cleanup waits for quiescence", "CREDENTIAL-BOUND", "slot-to-launch binding and cleanup",
     "Remove authoritative zero-survivor gating around slot removal."),
    ("subset-launch", "wider grant cannot launch", "SECRET-INJECT", "production lifecycle with protected injection",
     "Remove parent-subset validation before releasing the launch gate."),
]:
    CATALOG.append({"id": name, "rule": rule, "scope": "live-e2e", "available": False,
                    "tests": [target], "dependency": dependency, "fault": fault, "edits": []})

MUTATIONS = {row["id"]: row for row in CATALOG}

# Test names alone are insufficient: an unrelated setup error in the same test
# is not a killed mutation. Match the actual assertion diagnostic as well.
NATIVE_CODE = "expected error code "
STAGE_CODE = "expected stage error code "
FAILURE_TEXT = {
    "record-aad": ["stored ciphertext failed independent decryption", NATIVE_CODE + "integrity"],
    "record-tag": [NATIVE_CODE + "integrity"],
    "record-nonce": ["record versions reused an encryption nonce"],
    "plain-record": ["plaintext synthetic value or key leaked to disk"],
    "key-fallback": [NATIVE_CODE + "prerequisite_missing"],
    "recovery-aad": [NATIVE_CODE + "integrity"],
    "source-version": [NATIVE_CODE + "forbidden"],
    "version-reuse": [NATIVE_CODE + "conflict"],
    "revoke-ignore": [NATIVE_CODE + "forbidden"],
    "private-mode": [NATIVE_CODE + "integrity"],
    "private-links": [NATIVE_CODE + "integrity"],
    "stage-aad": ["sealed upload failed independent decryption"],
    "stage-salt": ["sealed upload failed independent decryption"],
    "reserved-env": ["reserved or invalid environment target was accepted"],
    "file-traversal": ["escaping or ambiguous file target was accepted"],
    "secret-subset": [STAGE_CODE + "forbidden"],
    "profile-subset": [STAGE_CODE + "forbidden"],
    "profile-expiry": [STAGE_CODE + "forbidden"],
    "stale-grants": [STAGE_CODE + "forbidden"],
    "cleanup-running": [STAGE_CODE + "containment_unknown"],
    "cleanup-survivors": [STAGE_CODE + "containment_unknown"],
    "human-proof": [STAGE_CODE + "unauthenticated"],
    "stage-principal": [STAGE_CODE + "not_found"],
    "stage-expiry": [STAGE_CODE + "not_found"],
    "json-case": ["case-alias request field was accepted"],
    "typed-nil": ["missing key channel panicked instead of returning a typed error"],
    "directory-mode": [NATIVE_CODE + "integrity"],
    "lock-identity": [NATIVE_CODE + "integrity"],
    "read-peer": [STAGE_CODE + "unauthenticated"],
    "read-writer": [STAGE_CODE + "unauthenticated"],
    "read-endpoint": [STAGE_CODE + "unauthenticated"],
    "read-idle": [STAGE_CODE + "unauthenticated"],
    "stage-connection": [STAGE_CODE + "not_found"],
    "stage-session": [STAGE_CODE + "not_found"],
    "key-read-expiry": ["upload key outlived its current read authority"],
    "eligibility-session": [STAGE_CODE + "conflict", STAGE_CODE + "conflict"],
    "eligibility-model": [STAGE_CODE + "conflict"],
    "eligibility-exclusion": [STAGE_CODE + "forbidden"],
    "eligibility-paid": [STAGE_CODE + "forbidden"],
    "worker-lease": [STAGE_CODE + "conflict", STAGE_CODE + "conflict", STAGE_CODE + "conflict"],
    "worker-subset": [STAGE_CODE + "forbidden", STAGE_CODE + "forbidden", STAGE_CODE + "forbidden"],
    "cli-semantic": ["invalid secret input was not refused before transport"],
    "key-check-enrollment": ["empty store did not persist sealed key enrollment"],
    "key-check-auth": ["expected error code integrity"],
    "native-clock": ["native injected clock did not allow live grant"],
    "native-clock-required": ["expected error code prerequisite_missing"],
    "parent-mode": ["expected private error code prerequisite_missing"],
    "lock-wait": ["expected private error code deadline_exceeded"],
    "read-idle-bound": ["expected stage error code unauthenticated"],
    "read-absolute-bound": ["expected stage error code unauthenticated"],
    "read-connection": ["expected stage error code unauthenticated"],
    "read-retained": ["expected stage error code unauthenticated"],
    "proof-intent": ["expected stage error code forbidden"],
    "proof-id": ["expected stage error code forbidden"],
    "proof-expiry": ["expected stage error code forbidden"],
    "read-proof": ["expected stage error code invalid_request"],
    "cli-validator-registration": ["catalog secret input bypassed semantic validation"],
    "cli-proof-intent": ["secret CLI accepted a proof for another intent"],
    "stage-clock": ["sealed upload ignored the injected clock"],
    "installed-config": ["expected stage error code prerequisite_missing"],
    "installed-service-scope": ["installed secret service lookup scope was not derived"],
    "stage-import-principal": ["expected stage error code not_found"],
    "stage-import-connection": ["expected stage error code not_found"],
    "stage-import-session": ["expected stage error code not_found"],
    "stage-import-endpoint": ["expected stage error code not_found"],
    "stage-import-expiry": ["expected stage error code not_found"],
    "stage-claim": ["expected stage error code conflict"],
    "stage-intent": ["expected stage error code forbidden"],
    "mutation-proof-use": ["secret import did not commit its source"],
    "mutation-check-proof": ["unverified proof reached protected backend work","expected stage error code forbidden"],
    "backend-store-required": ["secret import did not commit its source","expected stage error code unavailable"],
    "import-reconcile": ["interrupted import did not reconcile its original request"],
    "pending-source": ["expected stage error code conflict"],
    "import-replay": ["completed import retry performed another backend write proof check or commit"],
    "rotate-cas": ["concurrent rotations advanced the same expected version twice"],
    "revoke-operation": ["expected stage error code conflict"],
    "revoke-operation-aad": ["expected error code integrity"],
    "mutation-scope-end": ["expected error code forbidden"],
    "stage-import-tag": ["expected stage error code integrity"],
    "commit-reference": ["interrupted commit omitted its retryable operation reference"],
    "backend-retry-rewrite": ["exact backend retry rewrote ciphertext"],
}
FAILURE_TEXT.update({
    "f12-required-id": [STAGE_CODE + "prerequisite_missing"],
    "f12-producer": ["projection did not export its actual ordered private descriptors", "headless projection did not retain its fixed selected token destination"],
    "f12-source": [STAGE_CODE + "conflict"],
    "f12-held-observe": [STAGE_CODE + "integrity"],
    "f12-held-shape": [STAGE_CODE + "invalid_request"],
    "f12-held-durable": [STAGE_CODE + "integrity"],
    "f12-gate-policy": [STAGE_CODE + "conflict"],
    "f12-gate-claim": [STAGE_CODE + "conflict"],
    "f12-withdraw-admit": [STAGE_CODE + "conflict"],
    "f12-withdraw-zero": ["nonzero withdrawal retired its canonical refresh lease"],
    "f12-refresh-native": [STAGE_CODE + "invalid_request"],
    "f12-rights": ["native canary descriptor control count changed"],
    "f12-seal": ["credential transfer retained a writable alias"],
    "f12-early-release": [STAGE_CODE + "conflict"],
    "f12-worker-policy": ["stale worker generation returned material"] * 3,
    "f12-release-race": ["late projection binding was released"] * 2,
    "f12-effect-state": [STAGE_CODE + "conflict"],
    "f12-stage-cap": [STAGE_CODE + "budget_exhausted"],
    "f12-history-bound": [STAGE_CODE + "budget_exhausted"],
    "f12-retry-source": [STAGE_CODE + "forbidden", STAGE_CODE + "forbidden"],
    "f12-retained-policy": ["retained credential selection rejected an approved live policy advance"],
    "f12-journal-generation": ["expected error code integrity"],
    "fix10-level": [STAGE_CODE + "forbidden"],
    "fix10-role": [STAGE_CODE + "forbidden"],
    "fix10-driver": [STAGE_CODE + "forbidden"],
    "fix10-ticket": [STAGE_CODE + "forbidden"],
    "fix10-proof": [STAGE_CODE + "forbidden", STAGE_CODE + "forbidden"],
    "fix10-capture-current": [STAGE_CODE + "invalid_request", STAGE_CODE + "invalid_request"],
    "fix10-worker-kind": [STAGE_CODE + "forbidden"],
    "f11-usage-percent": [STAGE_CODE + "unavailable"],
    "f11-usage-fresh": [STAGE_CODE + "invalid_request", STAGE_CODE + "invalid_request", STAGE_CODE + "invalid_request"],
    "f11-usage-profile": [STAGE_CODE + "forbidden"],
    "f11-usage-producer": [STAGE_CODE + "invalid_request"],
    "f11-usage-source": [STAGE_CODE + "invalid_request"],
    "f11-usage-known-reset": ["TSV parser did not select the actual known exhausted row"],
    "f11-usage-all-rows": [STAGE_CODE + "invalid_request"],
    "f11-usage-grants": [STAGE_CODE + "forbidden"],
    "f11-worker-mapping": [STAGE_CODE + "invalid_request"] * 4,
    "f11-worker-material": ["native mapped worker did not receive its exact selected material"],
    "f11-usage-command": ["native usage command lost its exact argv private home environment or actual stdout"],
    "f11-usage-command-pin": [STAGE_CODE + "integrity"],
    "f11-usage-command-home": [STAGE_CODE + "integrity"],
    "f11-usage-command-generation": [STAGE_CODE + "containment_unknown"],
    "f11-usage-producer-path": ["outside usage did not retain its actual exhausted from-profile window"],
    "f11-usage-seals": ["usage executable snapshot remained writable after pinning"],
    "f11-usage-output": [STAGE_CODE + "unavailable", STAGE_CODE + "unavailable"],
    "f11-usage-cancel": [STAGE_CODE + "cancelled"],
    "f11-usage-executable-mode": [STAGE_CODE + "integrity", STAGE_CODE + "integrity"],
    "fix9-acquire": ["reserved-life profile acquisition did not prepare a real slot"],
    "fix9-inject": ["reserved-life injection did not retain its exact selected slots"],
    "fix9-worker": ["claimed fixed worker did not prepare its selected real credential"],
    "fix9-release": ["measured file-login release did not import supported refresh"],
    "fix9-revoke": ["measured injection cleanup did not release actual slots"],
    "fix9-room": ["profile room did not use actual protected evidence"],
    "fix9-eligibility": ["compatible enrolled profiles did not retain exact eligibility and evidence"],
    "fix9-prepared-agent": ["nonexecuting retained agent spec did not receive its exact selected material"],
    "fix9-prepared-worker": ["retained fixed worker spec did not receive the exact selected bytes"],
    "fix9-plan-claim": ["expected stage error code conflict"],
    "fix9-plan-epoch": ["expected stage error code forbidden"],
    "fix9-plan-foreign": ["expected stage error code forbidden"],
    "fix9-plan-inputs": ["expected stage error code conflict"],
    "fix9-plan-policy": ["expected stage error code conflict"],
    "fix9-plan-original": ["expected stage error code integrity"],
    "fix9-profile-runtime": ["expected stage error code forbidden"],
    "fix9-private-slot": ["expected stage error code forbidden"],
    "fix9-profile-retry": ["expected stage error code conflict"],
    "fix9-injection-retry": ["expected stage error code conflict"],
    "fix9-release-identity": ["expected stage error code invalid_request"],
    "fix9-release-comparison": ["expected stage error code containment_unknown"],
    "fix9-release-commit": ["expected stage error code integrity"],
    "fix9-release-selection": ["expected stage error code forbidden"],
    "fix9-refresh-import": ["refresh import did not preserve actual returned bytes"],
    "fix9-refresh-serialize": ["competing alias changed the unreleased canonical login owner"],
    "fix9-refresh-latest": ["canonical alias copied stale pre-refresh credential bytes"],
    "fix9-refresh-identity": ["expected stage error code forbidden"],
    "fix9-refresh-unknown": ["expected stage error code forbidden"],
    "fix9-refresh-expiry": ["expected stage error code forbidden"],
    "fix9-refresh-owner": ["expected stage error code conflict"],
    "fix9-refresh-generation": ["expected stage error code conflict"],
    "fix9-room-available": ["profile room ignored a measured unavailable result"],
    "fix9-room-generation": ["expected stage error code forbidden"],
    "fix9-room-login": ["expected stage error code forbidden"],
    "fix9-room-window": ["expected stage error code integrity"],
    "fix9-room-zone": ["expected stage error code integrity"],
    "fix9-room-producer": ["expected stage error code prerequisite_missing"],
    "fix9-evidence-origin": ["expected stage error code forbidden"],
    "fix9-evidence-hash": ["expected stage error code integrity"],
    "fix9-worker-claim": ["expected stage error code conflict"],
    "fix9-worker-target": ["expected stage error code conflict"],
    "fix9-worker-runtime": ["expected stage error code forbidden"],
    "fix9-worker-executable": ["expected stage error code forbidden"],
    "fix9-worker-plan-retry": ["expected stage error code conflict"],
    "fix9-worker-subset-retry": ["expected stage error code conflict"],
    "fix9-worker-spec-selection": ["expected stage error code forbidden"],
    "fix9-worker-resolver": ["expected stage error code not_implemented"],
    "fix9-worker-spec-retry": ["expected stage error code conflict"],
    "fix9-eligibility-model": ["profile compatibility ignored changed model enrollment"],
    "fix9-eligibility-vendor": ["profile eligibility accepted incompatible retained runtime or vendor"],
    "fix9-eligibility-runtime": ["profile eligibility accepted incompatible retained runtime or vendor"],
    "fix9-eligibility-binding": ["expected stage error code invalid_request"],
    "fix9-continuation-epoch": ["expected stage error code conflict"],
    "fix9-continuation-claim": ["expected stage error code conflict"],
    "fix9-broker-aad": ["broker ciphertext failed independent AAD authentication"],
    "fix9-broker-id": ["expected error code integrity"],
    "fix9-broker-kind": ["expected error code integrity"],
    "fix9-broker-key": ["expected error code integrity"],
    "fix9-broker-lifetime": ["expected error code forbidden"],
    "fix9-broker-cancel": ["expected error code cancelled"],
    "fix9-broker-revoked": ["expected stage error code forbidden"],
    "fix9-broker-nonce": ["broker writes reused an encryption nonce"],
    "fix9-broker-private": ["expected error code integrity"],
    "fix9-material-expiry": ["expected stage error code forbidden"],
    "fix9-material-binding": ["expected stage error code not_found"],
    "fix9-profile-selected": ["expected stage error code forbidden"],
    "fix9-storage-life": ["expected stage error code forbidden"],
    "fix9-room-future": ["expected stage error code integrity"],
    "fix9-cleanup-replay": ["expected stage error code containment_unknown"],
    "fix9-object-chunks": ["protected object reader did not retain every bounded chunk"],
    "fix9-object-offset": ["expected stage error code integrity"],
    "fix9-object-part-hash": ["expected stage error code integrity"],
})
FAILURE_TEXT.update({
    "r6-quarantine": ["exposure did not quarantine its retained canonical owner","exposure did not quarantine its retained canonical owner"],
    "r6-worker": ["native worker lost its retained cleanup binding","native worker bypassed its selection marker"],
    "r6-completion": ["failed completion released canonical material"],
    "r6-fence": ["native failure was fenced only in memory","native failure was fenced only in memory"],
    "r6-policy": ["stale live slot delivered credential material","expected stage error code conflict"],
    "r6-partial": ["partial credential bind was retried","partial credential bind was retried","partial credential bind was retried"],
    "r6-ack": ["held replay bypassed receipt validation","receipt selected another native transfer"],
    "r6-release-group": ["injection failure freed a profile lease"],
})
FAILURE_TEXT.update({
    "r7-broker-count": ["open broker descriptor was reported absent"],
    "r7-lease-count": ["live refresh lease was not measured before withdrawal"],
    "r7-lease-missing": ["missing live refresh inventory completed withdrawal"],
    "r7-kernel-probe": ["kernel refresh lease was reported absent"],
    "r7-withdraw-lock": ["withdrawal decision crossed journal locks","withdrawal decision crossed journal locks"],
    "r7-writable": ["write-access alias was reported absent"],
    "r7-clear": ["refused projection retained a selected secret buffer","refused projection retained a selected secret buffer","refused projection retained a selected secret buffer","refused projection retained a selected secret buffer"],
    "r7-policy": ["agent credentials used historical policy","worker credentials used historical policy","agent credentials used historical policy"],
    "r7-ticker": ["gate ticker retained stale authority","gate ticker retained stale authority","gate ticker retained stale authority","gate ticker retained stale authority"],
    "r7-quarantine-retry": ["quarantined login did not refuse acquisition immediately","quarantined login did not refuse acquisition immediately"],
    "r7-refresh-live": ["retired refresh lease remained usable"],
})
FAILURE_TEXT.update({
    "r8-prepared": ["prepared material ignored live delivery policy","prepared material ignored live delivery policy","prepared material ignored live delivery policy","prepared material ignored live delivery policy","prepared material ignored live delivery policy","prepared material ignored live delivery policy"],
    "r8-worker": ["prepared worker ignored final delivery policy","prepared worker ignored final delivery policy"],
    "r8-policy-source": ["agent credentials used historical policy"],
    "r8-guard": ["refused projection returned a nonnil guard","refused projection returned a nonnil guard"],
})
for row in CATALOG:
    if row["available"]:
        row["failure_text"] = dict(zip(row["tests"], FAILURE_TEXT[row["id"]], strict=True))
