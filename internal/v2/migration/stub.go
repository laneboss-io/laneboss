// Package migration is owned by lb-v2-migration.
package migration

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
)

type Dependencies struct {
	Store  api.StateStore
	Human  api.HumanVerifier
	Worker api.DataWorker
}

type planState struct {
	plan    api.MigrationPlan
	request api.MigrationPlanRequest
	bundle  *VerifiedBundle
	config  string
}

type Service struct {
	deps    Dependencies
	mu      sync.Mutex
	applyMu sync.Mutex
	plans   map[api.ID]*planState
}

func (s *Service) lookupPlan(id api.ID) (*planState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, exists := s.plans[id]
	if !exists || state == nil {
		return nil, false
	}
	copy := *state
	return &copy, true
}

func New(deps Dependencies) (*Service, error) {
	if err := api.RequireDependencies("lb-v2-migration", deps.Store, deps.Human, deps.Worker); err != nil {
		return nil, err
	}
	return &Service{deps: deps, plans: make(map[api.ID]*planState)}, nil
}

var _ api.MigrationAPI = (*Service)(nil)
var _ api.Module = (*Service)(nil)

func (s *Service) Register(registry api.Registrar) error {
	if err := api.RequireDependencies("lb-v2-migration", s, registry); err != nil {
		return err
	}
	if err := registry.Register("migration.plan", s.handlePlan); err != nil {
		return err
	}
	return registry.Register("migration.apply", s.handleApply)
}

func (s *Service) handlePlan(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
	var request api.MigrationPlanRequest
	if err := api.DecodeObject(raw, &request); err != nil {
		return nil, err
	}
	result, err := s.MigrationPlan(ctx, scope, request)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

func (s *Service) handleApply(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
	var request api.MigrationApplyRequest
	if err := api.DecodeObject(raw, &request); err != nil {
		return nil, err
	}
	result, err := s.MigrationApply(ctx, scope, request)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

// MigrationPlan inspects retained inputs without a state-changing transaction.
// The cache is an optimization only; apply receipts live in the StateStore.
func (s *Service) MigrationPlan(ctx context.Context, scope api.Scope, request api.MigrationPlanRequest) (api.MigrationPlan, error) {
	var zero api.MigrationPlan
	if err := validateScopeForPlan(scope); err != nil {
		return zero, err
	}
	bundle, err := inspectAndVerifyBundle(ctx, s.deps.Store, scope, request)
	if err != nil {
		return zero, err
	}
	delivered, pending, returned := 0, 0, 0
	for _, mail := range bundle.Mail {
		if mail.Delivered {
			delivered++
		} else if mail.Returned {
			returned++
		} else {
			pending++
		}
	}
	changes := []string{
		fmt.Sprintf("import:events:%d", len(bundle.Events)),
		fmt.Sprintf("import:decisions:%d", len(bundle.Decisions)),
		fmt.Sprintf("import:vectors:%d", len(bundle.Vectors)),
		fmt.Sprintf("import:egress:%d", len(bundle.Egress)),
		fmt.Sprintf("import:mail:delivered=%d,pending=%d,returned=%d", delivered, pending, returned),
		fmt.Sprintf("import:archives:%d", len(bundle.Archives)),
		"archives:receipts imported; tar and manifest bytes remain in the frozen source",
		fmt.Sprintf("import:owner_queue:%d", len(bundle.OwnerQueue)),
	}
	for _, reason := range bundle.Incompatibilities0 {
		changes = append(changes, "rollback:0.5.0:unavailable:"+reason)
	}
	if bundle.Adversarial != nil {
		changes = append(changes, fmt.Sprintf("preserve:adversarial_additions:%d", len(bundle.Adversarial.IDs)))
	}
	for _, unfinished := range bundle.Unfinished {
		changes = append(changes, fmt.Sprintf("prepare:relaunch:%s", unfinished.Lane))
	}
	relaunch := bundle.RequiresRelaunch
	if relaunch == nil {
		relaunch = []api.ID{}
	}
	planID := DeterministicID("migplan-", scope.Config, request.SourceVersion, string(request.SourceManifest.ID), string(request.SourceManifest.SHA256))
	plan := api.MigrationPlan{ID: planID, SourceVersion: request.SourceVersion,
		SourceManifest: request.SourceManifest, TargetSchema: api.SchemaVersion,
		Changes: changes, Problems: migrationPlanProblems(bundle, s.deps.Store), RequiresRelaunch: relaunch}
	s.mu.Lock()
	s.plans[planID] = &planState{plan: plan, request: request, bundle: bundle, config: scope.Config}
	s.mu.Unlock()
	return plan, nil
}

func mapLegacyEventCollection(event LegacyEventRecord) string {
	switch event.Kind {
	case "lane.refusal", "lane.workaround_suspected", "lane.refusal_reviewed":
		return "refusals"
	case "report.sent":
		return "reports"
	case "archive.verified", "archive.completed":
		return "archives"
	case "tool.submitted":
		return "tools"
	case "store.record":
		switch event.Payload["kind"] {
		case "decision", "owner-word":
			return "decisions"
		case "lane-report":
			return "reports"
		case "ledger-row":
			return "ledger"
		case "receipt":
			return "archives"
		}
	}
	return "observations"
}

func validateScopeForPlan(scope api.Scope) error {
	if !ValidConfigName(scope.Config) {
		return invalidErr("scope.config is required and must be a valid configuration name")
	}
	if scope.Actor.Kind != "human" && scope.Actor.Kind != "service" {
		return forbiddenErr("migration.plan requires human-read authority")
	}
	if !ValidID(scope.Actor.ID) {
		return forbiddenErr("scope.actor.id is required")
	}
	return nil
}

func validateScopeForApply(scope api.Scope) error {
	if !ValidConfigName(scope.Config) {
		return invalidErr("scope.config is required and must be a valid configuration name")
	}
	if scope.Actor.Kind != "human" || !ValidID(scope.Actor.ID) {
		return forbiddenErr("migration.apply requires human-proof authority on the human administration endpoint")
	}
	return nil
}
