package records

import (
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) RecordsImport(ctx context.Context, scope api.Scope, request api.TransferRequest) (api.Operation, error) {
	if err := mutationScope(ctx, scope, "records.import"); err != nil {
		return api.Operation{}, err
	}
	if err := ValidateImportInput(request); err != nil {
		return api.Operation{}, err
	}
	if !collection(request.Collection) || !manifestRef(request.Manifest) {
		return api.Operation{}, invalid("import requires a collection and committed manifest")
	}
	if scope.Actor.Kind != "human" && request.Collection != "observations" && request.Collection != "reports" {
		return api.Operation{}, &api.Error{Code: api.CodeForbidden, Message: "record imports require verified human authority", Instead: "Submit inert input up the report line; use approved D6 for canonical resources or migration for history."}
	}
	if s.deps.Records == nil {
		return api.Operation{}, api.NotImplemented("lb-v2-integrate", "confined records import")
	}
	return s.deps.Records.Import(ctx, scope, request)
}

func (s *Service) RecordsExport(ctx context.Context, scope api.Scope, request api.RecordQuery) (api.BlobRef, error) {
	if err := authorizeScope(ctx, scope); err != nil {
		return api.BlobRef{}, err
	}
	if err := ValidateQueryInput(request); err != nil {
		return api.BlobRef{}, err
	}
	if s.deps.Records == nil {
		return api.BlobRef{}, api.NotImplemented("lb-v2-integrate", "confined records export")
	}
	result, err := s.deps.Records.Export(ctx, scope, request)
	if err != nil {
		return api.BlobRef{}, err
	}
	if !manifestRef(result) && !(validID(result.ID) && validDigest(result.SHA256) && result.Bytes > 0 && result.Bytes <= api.MaxObjectBytes && result.Class == "archive") {
		return api.BlobRef{}, integrity("export worker returned an invalid object")
	}
	return result, nil
}

func (s *Service) BoxLaunch(ctx context.Context, scope api.Scope, request api.BoxLaunchRequest) (api.Box, error) {
	if err := mutationScope(ctx, scope, "box.launch"); err != nil {
		return api.Box{}, err
	}
	if err := ValidateBoxLaunchInput(request); err != nil {
		return api.Box{}, err
	}
	if request.Provider != "aws" && request.Provider != "gcp" || !validID(request.ResourceGrantID) || len(request.Purpose) < 4 || len(request.Purpose) > 128 || request.Purpose[:3] != "lb-" || !manifestRef(request.Spec) {
		return api.Box{}, invalid("box launch requires a named provider/grant, lb- purpose and committed spec")
	}
	if scope.Actor.Kind != "lane" {
		return api.Box{}, &api.Error{Code: api.CodeForbidden, Message: "box launch requires a delegated lane resource grant", Instead: "Approve root resource grants and launch a separately bound test lane."}
	}
	lane, err := s.deps.Store.Lane(ctx, scope, api.LifeRef{LifeID: scope.Actor.LifeID})
	if err != nil {
		return api.Box{}, err
	}
	grants, err := s.deps.Store.Grants(ctx, lane.GrantSetID)
	if err != nil {
		return api.Box{}, err
	}
	if grants.LifeID != lane.LifeID || grants.ID != lane.GrantSetID || grants.Revoked || expired(grants.ExpiresAt, s.deps.Clock.Now()) {
		return api.Box{}, &api.Error{Code: api.CodeForbidden, Message: "resource delegation is absent, expired or revoked", Instead: "Use a current explicitly delegated resource grant."}
	}
	var selected *api.ResourceGrant
	for index := range grants.Resources {
		if grants.Resources[index].ID == request.ResourceGrantID {
			selected = &grants.Resources[index]
			break
		}
	}
	if selected == nil || selected.Provider != request.Provider || selected.MaxActive == 0 || selected.TotalBudgetMicros <= 0 || expired(selected.ExpiresAt, s.deps.Clock.Now()) {
		return api.Box{}, &api.Error{Code: api.CodeForbidden, Message: "requested provider is outside the delegated resource grant", Instead: "Use the granted provider, region, image and cost ceiling."}
	}
	if request.Budget.SpendMicros <= 0 || request.Budget.SpendMicros > selected.TotalBudgetMicros || request.Budget.SpendMicros > lane.BudgetRemaining.SpendMicros || request.Budget.WallMS <= 0 {
		return api.Box{}, &api.Error{Code: api.CodeBudget, Message: "box budget exceeds the remaining delegated ceiling", Instead: "Use a bounded budget within the current grant and lane's remaining budget."}
	}
	if s.deps.Resources == nil {
		return api.Box{}, api.NotImplemented("lb-v2-integrate", "confined cloud provisioning")
	}
	// The confined broker resolves the spec, revalidates all ancestor grants and
	// reserves the one-active-machine lease and cost in a durable transaction.
	box, err := s.deps.Resources.Launch(ctx, scope, request)
	if err != nil {
		return api.Box{}, err
	}
	if !validID(box.ID) || box.Provider != request.Provider || box.ResourceGrantID != request.ResourceGrantID || box.Generation == 0 {
		return api.Box{}, integrity("resource worker returned an unrelated box")
	}
	return box, nil
}

func (s *Service) BoxRun(ctx context.Context, scope api.Scope, request api.BoxRunRequest) (api.Operation, error) {
	if err := mutationScope(ctx, scope, "box.run"); err != nil {
		return api.Operation{}, err
	}
	if err := ValidateBoxRunInput(request); err != nil {
		return api.Operation{}, err
	}
	if !validID(request.BoxID) || request.ExpectedGeneration == 0 || !manifestRef(request.Source) || !manifestRef(request.Plan) {
		return api.Operation{}, invalid("box run requires current box generation and committed source/plan manifests")
	}
	if s.deps.Resources == nil {
		return api.Operation{}, api.NotImplemented("lb-v2-integrate", "confined cloud run")
	}
	return s.deps.Resources.Run(ctx, scope, request)
}

func (s *Service) BoxHarvest(ctx context.Context, scope api.Scope, request api.BoxControlRequest) (api.BlobRef, error) {
	if err := mutationScope(ctx, scope, "box.harvest"); err != nil {
		return api.BlobRef{}, err
	}
	if err := ValidateBoxHarvestInput(request); err != nil {
		return api.BlobRef{}, err
	}
	if !validID(request.BoxID) || request.ExpectedGeneration == 0 {
		return api.BlobRef{}, invalid("box harvest requires current box generation")
	}
	if s.deps.Resources == nil {
		return api.BlobRef{}, api.NotImplemented("lb-v2-integrate", "confined cloud harvest")
	}
	return s.deps.Resources.Harvest(ctx, scope, request)
}

func (s *Service) BoxEnd(ctx context.Context, scope api.Scope, request api.BoxControlRequest) (api.Operation, error) {
	if err := mutationScope(ctx, scope, "box.end"); err != nil {
		return api.Operation{}, err
	}
	if err := ValidateBoxEndInput(request); err != nil {
		return api.Operation{}, err
	}
	if !validID(request.BoxID) || request.ExpectedGeneration == 0 {
		return api.Operation{}, invalid("box end requires current box generation")
	}
	if s.deps.Resources == nil {
		return api.Operation{}, api.NotImplemented("lb-v2-integrate", "confined cloud collection")
	}
	return s.deps.Resources.End(ctx, scope, request)
}

func (s *Service) BoxList(ctx context.Context, scope api.Scope, request api.ListRequest) (api.BoxPage, error) {
	if err := authorizeScope(ctx, scope); err != nil {
		return api.BoxPage{}, err
	}
	if err := ValidateBoxListInput(request); err != nil {
		return api.BoxPage{}, err
	}
	if request.Limit < 1 || request.Limit > 200 || len(request.Cursor) > 8192 || request.LifeID != "" && !validID(request.LifeID) {
		return api.BoxPage{}, invalid("invalid box page or life filter")
	}
	if s.deps.Resources == nil {
		return api.BoxPage{}, api.NotImplemented("lb-v2-integrate", "confined cloud inventory")
	}
	page, err := s.deps.Resources.List(ctx, scope, request)
	if err != nil {
		return api.BoxPage{}, err
	}
	if page.Boxes == nil || len(page.Boxes) > request.Limit {
		return api.BoxPage{}, integrity("resource worker returned invalid inventory")
	}
	return page, nil
}

func manifestRef(ref api.BlobRef) bool {
	return validID(ref.ID) && validDigest(ref.SHA256) && ref.Bytes > 0 && ref.Bytes <= api.MaxObjectBytes && ref.Class == "manifest"
}

func expired(value api.Timestamp, now time.Time) bool {
	expiry, err := time.Parse(time.RFC3339Nano, string(value))
	return err != nil || !now.Before(expiry)
}
