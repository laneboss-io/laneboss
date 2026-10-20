package api

import (
	"reflect"
	"slices"
	"strings"
)

// This is a transaction projection/event catalog, not a command/tool allowlist.
// Unlisted public fields/events/effects refuse. Store-generated receipt, proof
// use and operation events are appended by the store after checking the guards.
// Current ACLs, proof/ticket/approval facts and effect causality remain store
// checks under its commit lock; this structural check cannot grant authority.
type publicWrites struct {
	fields, events, effects, guards string
	session                         bool
	deferred                        InternalKind
}

var publicWriteCatalog = map[Method]publicWrites{
	"blob.begin":         {fields: "UploadBegins", session: true},
	"blob.chunk":         {fields: "UploadChunks", session: true},
	"blob.commit":        {fields: "UploadCommits Objects", events: "blob.committed", session: true},
	"human.challenge":    {fields: "Challenges", events: "human.challenge"},
	"human.confirm":      {fields: "Challenges Counters Proofs Objects", events: "human.confirmed"},
	"human.session":      {fields: "ReadSessions", events: "human.session"},
	"human.enroll":       {fields: "HumanChanges", events: "human.enrollment"},
	"ticket.issue":       {fields: "Tickets", events: "ticket.issued"},
	"grants.root":        {fields: "Grants", events: "grants.issued"},
	"grants.enroll":      {fields: "Objects", events: "blob.committed"},
	"grants.revoke":      {fields: "Grants Lanes Continuations Endpoints", events: "grants.revoked lane.stopping watchdog.cancelled identity.revoked", effects: "Stop"},
	"grants.test-child":  {fields: "WorkerLeases", effects: "Worker"},
	"lane.start":         {fields: "Lanes Grants Turns WorkerLeases", events: "lane.created grants.issued", effects: "HelperAllocate Worker Launch PlanLaunch"},
	"lane.adopt":         {fields: "Lanes Grants Turns WorkerLeases", events: "lane.adopted grants.issued", effects: "HelperAllocate Worker Launch PlanLaunch"},
	"lane.resume":        {fields: "Lanes Turns Continuations WorkerLeases", events: "lane.turn watchdog.cancelled", effects: "HelperAllocate Worker Launch PlanLaunch"},
	"lane.turn":          {fields: "Lanes Turns Continuations WorkerLeases", events: "lane.turn watchdog.cancelled", effects: "HelperAllocate Worker Launch Deliver PlanLaunch"},
	"lane.stop":          {fields: "Lanes Continuations", events: "lane.stopping watchdog.cancelled", effects: "Stop"},
	"lane.mark":          {fields: "Lanes Continuations", events: "lane.state watchdog.cancelled", effects: "Stop"},
	"lane.review":        {events: "lane.reviewed"},
	"lane.clean":         {fields: "Lanes Continuations", events: "watchdog.cancelled", effects: "Clean"},
	"lane.archive":       {fields: "WorkerLeases", effects: "Worker"},
	"lane.check":         {fields: "Lanes", events: "run.observed lane.lost lane.ended lane.state", effects: "HelperRelease"},
	"lane.loop":          {fields: "Lanes", events: "lane.loop"},
	"lane.input":         {fields: "WorkerLeases", effects: "Worker"},
	"mail.send":          {fields: "Mail WorkerLeases", events: "mail.queued", effects: "Deliver Channel"},
	"report.submit":      {fields: "Mail WorkerLeases", events: "report.submitted mail.queued", effects: "Deliver Channel"},
	"policy.evaluate":    {events: "policy.evaluated", session: true},
	"guidance.select":    {session: true},
	"judge.ask":          {session: true},
	"org.bootstrap":      {effects: "Bootstrap"},
	"org.change.propose": {fields: "Changes WorkerLeases", events: "org.change.proposed", effects: "Worker"},
	"org.change.approve": {fields: "Approvals", events: "org.change.approved"},
	"org.change.apply":   {effects: "ApplyChange", deferred: InternalOrgPublish},
	"secret.stage":       {session: true},
	"secret.import":      {events: "secret.imported"},
	"secret.rotate":      {events: "secret.rotated"},
	"secret.revoke":      {events: "secret.revoked"},
	"records.append":     {events: "record.appended"},
	"decisions.mutate":   {fields: "Decisions", events: "decision.changed"},
	"records.import":     {fields: "WorkerLeases", effects: "Worker"},
	"store.rebuild":      {effects: "Rebuild"},
	"box.launch":         {fields: "WorkerLeases", events: "box.changed", effects: "Worker"},
	"box.run":            {fields: "WorkerLeases", events: "box.changed", effects: "Worker"},
	"box.harvest":        {fields: "WorkerLeases", events: "box.changed", effects: "Worker"},
	"box.end":            {fields: "WorkerLeases", events: "box.changed", effects: "Worker"},
	"migration.apply":    {fields: "Deployments", effects: "Migration"},
	"upgrade.apply":      {fields: "Deployments", effects: "Upgrade"},
}

// Internal provenance remains a store check against the bound component and
// current claim. This catalog also rejects out-of-domain writes structurally.
// Completion of org/bootstrap/judge work uses its specific original kind;
// effect_complete is only the common measured outcome and never policy ingress.
var internalWriteCatalog = map[InternalKind]publicWrites{
	InternalPolicyRefresh:    {fields: "Lanes", events: "lane.policy", guards: "Cancellation"},
	InternalLaunchPlan:       {fields: "LaunchPlans Grants Objects WorkerLeases", events: "launch.planned grants.issued capture.bound capture.refused", effects: "PlanLaunch HelperAllocate Worker", guards: "Cancellation"},
	InternalHelperAllocate:   {events: "helper.allocated", effects: "HelperAllocate", guards: "Cancellation"},
	InternalHelperRegister:   {guards: "Cancellation"},
	InternalHelperPrepare:    {fields: "IdentityBindings Endpoints LaunchPlans Lanes Turns", events: "launch.prepared identity.bound lane.created lane.adopted", effects: "HelperPrepare", guards: "Cancellation"},
	InternalHelperOpen:       {fields: "Lanes Endpoints Turns IdentityBindings WorkerLeases LaunchPlans", events: "lane.started lane.resumed lane.turn runner.session prompt.observed identity.bound data.materialized secret.injected credential.leased", guards: "Cancellation"},
	InternalHelperStop:       {fields: "Lanes Endpoints Continuations", events: "run.observed lane.ended lane.lost lane.stopping identity.revoked credential.released watchdog.cancelled", guards: "Cancellation"},
	InternalHelperAbort:      {fields: "Endpoints IdentityBindings LaunchPlans", events: "launch.failed identity.revoked", effects: "HelperAbort", guards: "Cancellation"},
	InternalHelperRelease:    {events: "helper.released credential.released", effects: "HelperRelease", guards: "Cancellation"},
	InternalEffectComplete:   {fields: "Lanes Endpoints IdentityBindings Turns Continuations Mail Deliveries WorkerLeases Objects Deployments", events: "operation.accepted operation.completed operation.failed worker.completed worker.failed launch.prepared launch.failed lane.started lane.resumed lane.ended lane.lost lane.cleaned archive.verified helper.allocated helper.released data.materialized credential.leased credential.released secret.injected blob.committed channel.delivered channel.failed mail.delivered mail.returned box.changed", guards: "Cancellation"},
	InternalMailDeliver:      {fields: "Mail Deliveries Turns WorkerLeases", events: "mail.delivered mail.returned channel.delivered channel.failed prompt.observed lane.turn secret.injected", effects: "Deliver Channel", guards: "Cancellation"},
	InternalGuidanceComplete: {fields: "Guidance Turns", events: "guidance.selected", guards: "Cancellation"},
	InternalGuidanceRecover:  {fields: "Guidance Turns", events: "guidance.selected", guards: "Cancellation"},
	InternalProfileContinue:  {fields: "Lanes Turns Continuations WorkerLeases Endpoints IdentityBindings", events: "watchdog.limit watchdog.waiting watchdog.swapped", effects: "Swap", guards: "Cancellation"},
	InternalProfileCancel:    {fields: "Lanes Continuations Endpoints", events: "watchdog.cancelled lane.stopping identity.revoked", effects: "Stop", guards: "Cancellation"},
	InternalOrgPublish:       {fields: "Applications Changes OrgSnapshots Policy Grants Channels Decisions Objects WorkerLeases", events: "org.change.applied record.appended decision.changed blob.committed", effects: "ApplyChange Worker", guards: "Cancellation"},
	InternalOrgBootstrap:     {fields: "OrgSnapshots Policy Grants Channels Decisions Objects WorkerLeases", events: "org.bootstrapped record.appended decision.changed blob.committed", effects: "Bootstrap Worker", guards: "Cancellation"},
	InternalUpgradeApply:     {fields: "Deployments Objects WorkerLeases Endpoints", events: "upgrade.applied worker.completed worker.failed blob.committed", effects: "Upgrade Worker", guards: "Cancellation"},
	InternalMigrationApply:   {fields: "Deployments Objects WorkerLeases", events: "migration.completed record.appended worker.completed worker.failed blob.committed", effects: "Migration Rebuild Worker", guards: "Cancellation"},
	InternalCaptureAppend:    {fields: "Objects", events: "capture.appended capture.gap capture.closed runner.session prompt.observed", guards: "Cancellation"},
	InternalObjectRetain:     {fields: "Objects WorkerLeases", events: "blob.committed worker.completed worker.failed", effects: "Worker", guards: "Cancellation"},
	InternalJudgeEvaluate:    {fields: "JudgeAudits Objects", events: "judge.completed blob.committed", guards: "Cancellation"},
	InternalLifecycleEffect:  {fields: "Lanes Grants Turns Endpoints IdentityBindings Continuations WorkerLeases", events: "lane.created lane.adopted launch.prepared launch.failed lane.started lane.resumed lane.turn prompt.observed lane.stopping lane.ended lane.lost lane.state lane.cleaned lane.reviewed lane.loop run.observed grants.issued grants.revoked identity.bound identity.revoked data.materialized secret.injected credential.leased credential.released runner.session watchdog.cancelled archive.verified", effects: "Launch Stop Clean Worker HelperAllocate HelperPrepare HelperRelease HelperAbort", guards: "Cancellation"},
	InternalChannelReceive:   {fields: "Mail Deliveries WorkerLeases Objects", events: "record.appended mail.queued report.submitted channel.delivered channel.failed worker.completed worker.failed blob.committed", effects: "Worker", guards: "Cancellation"},
	InternalAdminEnroll:      {fields: "Enrollments Objects", events: "blob.committed", guards: "Proof Approval"},
}

func validPublicWrites(transaction Transaction) bool {
	if transaction.Reply != nil && transaction.Reply.Error != nil {
		return reflect.ValueOf(transaction.Writes).IsZero() && len(transaction.Events)+len(transaction.Effects)+len(transaction.Guards) == 0
	}
	spec := Methods[transaction.Scope.Request.Method]
	row, exists := publicWriteCatalog[transaction.Scope.Request.Method]
	if spec.Mutation && !exists {
		return false
	}
	if !validDeferredMutation(transaction, row) {
		return false
	}
	if transaction.Scope.Request.Method == "human.confirm" && !validAssertionEvidence(transaction) {
		return false
	}
	if transaction.Scope.ReadAuthority != nil && !boundReadAuthority(transaction.Scope) {
		return false
	}
	if (spec.Access == "human-read" || transaction.Scope.Actor.Kind == "human" && row.session) && !boundReadAuthority(transaction.Scope) {
		return false
	}
	if spec.Access == "human-endpoint" && (transaction.Scope.Actor.Kind != "human" || transaction.Scope.Actor.ID == "" || transaction.Scope.EndpointGeneration == 0) {
		return false
	}
	proof, ticket, approval := false, false, false
	for _, guard := range transaction.Guards {
		if (guard.Proof != nil || guard.Ticket != nil) && transaction.Scope.Actor.Kind != "human" {
			return false
		}
		proof, ticket, approval = proof || guard.Proof != nil, ticket || guard.Ticket != nil, approval || guard.Approval != nil
		if use := guard.Ticket; use != nil && (use.PrincipalID != transaction.Scope.Actor.ID || use.Config != transaction.Scope.Config || use.EndpointGeneration == 0 || use.EndpointGeneration != transaction.Scope.EndpointGeneration) {
			return false
		}
	}
	if row.session && (proof || ticket || approval) {
		return false
	}
	for _, lease := range transaction.Writes.UploadBegins {
		if lease.ACL.Config != transaction.Scope.Config || lease.ACL.Owner != transaction.Scope.Actor {
			return false
		}
	}
	if transaction.Scope.Request.Method == "blob.commit" {
		for _, object := range transaction.Writes.Objects {
			if object.ACL.Config != transaction.Scope.Config || object.ACL.Owner != transaction.Scope.Actor {
				return false
			}
		}
	}
	if transaction.Scope.Actor.Kind == "human" && spec.Access == "spawn" && !ticket {
		return false
	}
	if transaction.Scope.Request.Method == "org.change.apply" && !approval {
		return false
	}
	if spec.Mutation && (spec.Access == "human-proof" || transaction.Scope.Actor.Kind == "human" && !row.session && spec.Access != "human-endpoint" && spec.Access != "spawn") {
		if !proof {
			return false
		}
	}
	for _, issued := range transaction.Writes.Tickets {
		if issued.PrincipalID != transaction.Scope.Actor.ID || issued.Config != transaction.Scope.Config || issued.EndpointGeneration == 0 || issued.EndpointGeneration != transaction.Scope.EndpointGeneration {
			return false
		}
	}
	return validWriteRow(transaction, row, false)
}

// HumanSessionMethod identifies fixed RPC staging/preview semantics, not a
// command/tool permission list. Lanes retain their normal authenticated ACLs.
func HumanSessionMethod(method Method) bool { return publicWriteCatalog[method].session }

func validInternalWrites(transaction Transaction) bool {
	row, exists := internalWriteCatalog[transaction.Internal.Kind]
	return exists && validWriteRow(transaction, row, true)
}

func validWriteRow(transaction Transaction, row publicWrites, internal bool) bool {
	writes := reflect.ValueOf(transaction.Writes)
	for index := 0; index < writes.NumField(); index++ {
		field := writes.Field(index)
		if !field.IsZero() && !slices.Contains(strings.Fields(row.fields), writes.Type().Field(index).Name) {
			return false
		}
	}
	for _, event := range transaction.Events {
		if !slices.Contains(strings.Fields(row.events), string(event.Kind)) {
			return false
		}
	}
	for _, effect := range transaction.Effects {
		value := reflect.ValueOf(effect)
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			name := value.Type().Field(index).Name
			if field.Kind() == reflect.Pointer && !field.IsNil() && name != "Context" && !slices.Contains(strings.Fields(row.effects), name) {
				return false
			}
		}
	}
	if internal {
		for _, guard := range transaction.Guards {
			value := reflect.ValueOf(guard)
			for index := 0; index < value.NumField(); index++ {
				if !value.Field(index).IsNil() && !slices.Contains(strings.Fields(row.guards), value.Type().Field(index).Name) {
					return false
				}
			}
		}
	}
	return true
}
