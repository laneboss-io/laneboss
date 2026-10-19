package store

import (
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// Consumer enforcement of final draft.4 (74354cd) while the supervisor's
// contract merge is pending. The API checks the same closed rows after merge.
type emitterRow struct{ fields, events, effects, guards string }

var emitterCatalog = map[api.InternalKind]emitterRow{
	api.InternalPolicyRefresh:    {fields: "Lanes", events: "lane.policy", guards: "Cancellation"},
	api.InternalLaunchPlan:       {fields: "LaunchPlans Grants Objects WorkerLeases", events: "launch.planned grants.issued capture.bound capture.refused", effects: "PlanLaunch HelperAllocate Worker", guards: "Cancellation"},
	api.InternalHelperAllocate:   {events: "helper.allocated", effects: "HelperAllocate", guards: "Cancellation"},
	api.InternalHelperRegister:   {guards: "Cancellation"},
	api.InternalHelperPrepare:    {fields: "IdentityBindings Endpoints LaunchPlans Lanes Turns", events: "launch.prepared identity.bound lane.created lane.adopted", effects: "HelperPrepare", guards: "Cancellation"},
	api.InternalHelperOpen:       {fields: "Lanes Endpoints Turns IdentityBindings WorkerLeases LaunchPlans", events: "lane.started lane.resumed lane.turn runner.session prompt.observed identity.bound data.materialized secret.injected credential.leased", guards: "Cancellation"},
	api.InternalHelperStop:       {fields: "Lanes Endpoints Continuations", events: "run.observed lane.ended lane.lost lane.stopping identity.revoked credential.released watchdog.cancelled", guards: "Cancellation"},
	api.InternalHelperAbort:      {fields: "Endpoints IdentityBindings LaunchPlans", events: "launch.failed identity.revoked", effects: "HelperAbort", guards: "Cancellation"},
	api.InternalHelperRelease:    {events: "helper.released credential.released", effects: "HelperRelease", guards: "Cancellation"},
	api.InternalEffectComplete:   {fields: "Lanes Endpoints IdentityBindings Turns Continuations Mail Deliveries WorkerLeases Objects Deployments", events: "operation.accepted operation.completed operation.failed worker.completed worker.failed launch.prepared launch.failed lane.started lane.resumed lane.ended lane.lost lane.cleaned archive.verified helper.allocated helper.released data.materialized credential.leased credential.released secret.injected blob.committed channel.delivered channel.failed mail.delivered mail.returned box.changed", guards: "Cancellation"},
	api.InternalMailDeliver:      {fields: "Mail Deliveries Turns WorkerLeases", events: "mail.delivered mail.returned channel.delivered channel.failed prompt.observed lane.turn secret.injected", effects: "Deliver Channel", guards: "Cancellation"},
	api.InternalGuidanceComplete: {fields: "Guidance Turns", events: "guidance.selected", guards: "Cancellation"},
	api.InternalGuidanceRecover:  {fields: "Guidance Turns", events: "guidance.selected", guards: "Cancellation"},
	api.InternalProfileContinue:  {fields: "Lanes Turns Continuations WorkerLeases Endpoints IdentityBindings", events: "watchdog.limit watchdog.waiting watchdog.swapped", effects: "Swap", guards: "Cancellation"},
	api.InternalProfileCancel:    {fields: "Lanes Continuations Endpoints", events: "watchdog.cancelled lane.stopping identity.revoked", effects: "Stop", guards: "Cancellation"},
	api.InternalOrgPublish:       {fields: "Applications Changes OrgSnapshots Policy Grants Channels Decisions Objects WorkerLeases", events: "org.change.applied record.appended decision.changed blob.committed", effects: "ApplyChange Worker", guards: "Approval Cancellation"},
	api.InternalOrgBootstrap:     {fields: "OrgSnapshots Policy Grants Channels Decisions Objects WorkerLeases", events: "org.bootstrapped record.appended decision.changed blob.committed", effects: "Bootstrap Worker", guards: "Cancellation"},
	api.InternalUpgradeApply:     {fields: "Deployments Objects WorkerLeases Endpoints", events: "upgrade.applied worker.completed worker.failed blob.committed", effects: "Upgrade Worker", guards: "Approval Cancellation"},
	api.InternalMigrationApply:   {fields: "Deployments Objects WorkerLeases", events: "migration.completed record.appended worker.completed worker.failed blob.committed", effects: "Migration Rebuild Worker", guards: "Approval Cancellation"},
	api.InternalCaptureAppend:    {fields: "Objects", events: "capture.appended capture.gap capture.closed runner.session prompt.observed", guards: "Cancellation"},
	api.InternalObjectRetain:     {fields: "Objects WorkerLeases", events: "blob.committed worker.completed worker.failed", effects: "Worker", guards: "Cancellation"},
	api.InternalJudgeEvaluate:    {fields: "JudgeAudits Objects", events: "judge.completed blob.committed", guards: "Cancellation"},
	api.InternalLifecycleEffect:  {fields: "Lanes Grants Turns Endpoints IdentityBindings Continuations WorkerLeases", events: "lane.created lane.adopted launch.prepared launch.failed lane.started lane.resumed lane.turn prompt.observed lane.stopping lane.ended lane.lost lane.state lane.cleaned lane.reviewed lane.loop run.observed grants.issued grants.revoked identity.bound identity.revoked data.materialized secret.injected credential.leased credential.released runner.session watchdog.cancelled archive.verified", effects: "Launch Stop Clean Worker HelperAllocate HelperPrepare HelperRelease HelperAbort", guards: "Cancellation"},
	api.InternalChannelReceive:   {fields: "Mail Deliveries WorkerLeases Objects", events: "record.appended mail.queued report.submitted channel.delivered channel.failed worker.completed worker.failed blob.committed", effects: "Worker", guards: "Cancellation"},
	api.InternalAdminEnroll:      {fields: "Enrollments Objects", events: "blob.committed", guards: "Proof Approval"},
}

func validEmitter(input api.Transaction) bool {
	row, exists := emitterCatalog[input.Internal.Kind]
	if !exists {
		return false
	}
	writes := reflect.ValueOf(input.Writes)
	for index := 0; index < writes.NumField(); index++ {
		if !writes.Field(index).IsZero() && !containsWord(row.fields, writes.Type().Field(index).Name) {
			return false
		}
	}
	for _, event := range input.Events {
		if !containsWord(row.events, string(event.Kind)) {
			return false
		}
	}
	for _, effect := range input.Effects {
		value := reflect.ValueOf(effect)
		for index := 0; index < value.NumField(); index++ {
			field, name := value.Field(index), value.Type().Field(index).Name
			if field.Kind() == reflect.Pointer && !field.IsNil() && name != "Context" && !containsWord(row.effects, name) {
				return false
			}
		}
	}
	for _, guard := range input.Guards {
		value := reflect.ValueOf(guard)
		for index := 0; index < value.NumField(); index++ {
			if !value.Field(index).IsNil() && !containsWord(row.guards, value.Type().Field(index).Name) {
				return false
			}
		}
	}
	return true
}
