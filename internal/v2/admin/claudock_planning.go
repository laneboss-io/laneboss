package admin

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

// These private helper operations accept opaque allocation selectors and the
// exact service-retained runner request. They never accept a physical path.
type ClaudockPlanningRequest struct {
	Claim         api.LaunchClaim
	LeaseID       api.ID
	Home          api.PrivateHomeBinding
	Request       api.RunnerRequest
	RequiredUmask uint32
	Plan          *claudock.HomePlanRequest `json:",omitempty"`
}

type claudockNativePlanning struct {
	Input       ClaudockPlanningRequest
	Reservation api.LaunchReservation
}

type claudockHomeJournal struct {
	ReservationID api.ID
	BindingSHA256 api.Digest
	Bootstrap     api.Digest
	BootID        string
	Umask         *uint32
	Findings      []claudock.Finding
}

func validateClaudockHomeJournal(record leaseRecord, binding installation) error {
	p := record.Claudock
	if p == nil {
		return nil
	}
	found := false
	for _, allocation := range record.LaunchAllocations {
		found = found || allocation.Reservation.ID == p.ReservationID && allocation.Reservation.Driver == api.DriverClaudock
	}
	if !found || !validDigest(p.BindingSHA256) || p.Bootstrap != binding.Artifact.SHA256 || p.BootID != record.BootID ||
		p.Umask == nil || *p.Umask != claudock.RequiredUmask || p.Findings == nil || len(p.Findings) > 100001 {
		return failure(api.CodeIntegrity, "credential home journal lost its measured native binding")
	}
	for _, finding := range p.Findings {
		if !dataRelative(finding.Path) || finding.Kind != "link" && finding.Kind != "hardlink" && finding.Kind != "special" && finding.Kind != "unreadable-or-bounded" && finding.Kind != "unreadable" {
			return failure(api.CodeIntegrity, "credential home journal has an invalid retained finding")
		}
	}
	return nil
}

func (s *Service) VerifyClaudockBootstrap(ctx context.Context, input ClaudockPlanningRequest) error {
	if input.Plan != nil {
		return failure(api.CodeInvalid, "bootstrap measurement cannot contain a home operation")
	}
	return s.claudockPlanningCall(ctx, "claudock_bootstrap", input)
}

func (s *Service) PlanClaudockHome(ctx context.Context, input ClaudockPlanningRequest) error {
	if input.Plan == nil || !reflect.DeepEqual(input.Plan.Request, input.Request) || input.Plan.Home != input.Home ||
		input.Plan.ReservationID != input.Claim.ReservationID || !validDigest(input.Plan.InputsSHA256) {
		return failure(api.CodeForbidden, "credential home operation differs from its retained runner")
	}
	return s.claudockPlanningCall(ctx, "claudock_home", input)
}

func (s *Service) claudockPlanningCall(ctx context.Context, method string, input ClaudockPlanningRequest) error {
	if input.RequiredUmask != claudock.RequiredUmask || input.Request.Target.LifeID != input.Home.LifeID || input.Request.Home != input.Home.Home {
		return failure(api.CodeForbidden, "credential planning home or umask differs")
	}
	authority, err := s.launchAuthority(ctx, input.Claim.ReservationID, "", nil, input.Claim)
	if err != nil {
		return err
	}
	r := authority.Record.Reservation
	if r.Driver != api.DriverClaudock || r.Target != input.Request.Target || input.Plan != nil && input.Plan.Start != (r.Mode == "start") {
		return failure(api.CodeForbidden, "credential planning selects another driver or reserved method")
	}
	id := api.ID(digestBytes([]byte("launch\x00" + string(r.ID) + "\x00input-runner")))
	meta, err := s.deps.Store.ObjectMetadata(ctx, authority.Scope, id)
	if err != nil {
		return err
	}
	if meta.Origin != "service" || meta.SourceOperationID != r.OperationID || meta.ACL.Config != s.deps.Config ||
		meta.ACL.LifeID != r.Target.LifeID || meta.ACL.Owner.Kind != "service" || meta.ACL.Generation == 0 || len(meta.ACL.Participants) != 0 ||
		meta.ACL.Audience != "service" && meta.ACL.Audience != "owner" {
		return failure(api.CodeForbidden, "credential runner input lacks protected service provenance")
	}
	data, err := s.readLaunchObject(ctx, authority.Scope, meta.Ref, r.OperationID, r.Target.LifeID, true)
	if err != nil {
		return err
	}
	var retained api.RunnerRequest
	if meta.Ref.Class != "manifest" || api.DecodeObject(data, &retained) != nil || !reflect.DeepEqual(retained, input.Request) {
		return failure(api.CodeIntegrity, "credential planning request differs from protected runner input")
	}
	storage, err := s.runtimeLaunchStorage(ctx, authority, input.LeaseID)
	if err != nil {
		return err
	}
	if storage.Home != input.Home {
		return failure(api.CodeForbidden, "credential worker home is outside its retained lane allocation")
	}
	var result api.Empty
	if err := s.call(ctx, method, claudockNativePlanning{Input: input, Reservation: r}, &result); err != nil {
		return err
	}
	return s.fenceLaunch(ctx, authority)
}
