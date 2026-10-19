package admin

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

type launchAllocation struct {
	Request     api.HelperLeaseRequest `json:"request"`
	Reservation api.LaunchReservation  `json:"reservation"`
	Inputs      api.LaunchInputs       `json:"inputs"`
	Policy      api.EffectivePolicy    `json:"policy"`
}

type storageIdentity struct {
	ID     api.ID `json:"id"`
	Device string `json:"device"`
	Inode  string `json:"inode"`
}

type launchStorageRecord struct {
	Workspace     *workspaceJournal `json:"workspace_native,omitempty"`
	OriginalModes []storageMode     `json:"original_modes,omitempty"`
	Withdrawing   bool              `json:"withdrawing,omitempty"`
	Withdrawn     bool              `json:"withdrawn,omitempty"`
	Binding       api.LaunchStorage `json:"binding"`
	Directories   []storageIdentity `json:"directories"`
	Ready         bool              `json:"ready"`
	Collecting    bool              `json:"collecting,omitempty"`
	Collected     bool              `json:"collected,omitempty"`
	Inventory     []storageInode    `json:"collection_inventory,omitempty"`
}

type storageMode struct {
	RootID        api.ID `json:"root_id"`
	Name, Kind    string
	Device, Inode uint64
	Mode          uint32
}

type storageInode struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type launchStorageQuery struct {
	Request     api.LaunchDataRequest `json:"request"`
	Reservation api.LaunchReservation `json:"reservation"`
}

func launchBudget(authority launchAuthority) (api.Budget, error) {
	if loop := authority.Record.Reservation.Loop; loop != nil {
		if err := api.ValidateLaunchReservation(authority.Record.Reservation); err != nil {
			return api.Budget{}, err
		}
		return loop.BudgetRemaining, nil
	}
	switch authority.Request.Method {
	case "lane.start":
		input, err := decodeLaunchRequest[api.StartRequest](authority.Request, "lane.start")
		return input.Budget, err
	case "lane.adopt":
		input, err := decodeLaunchRequest[api.AdoptRequest](authority.Request, "lane.adopt")
		return input.Budget, err
	case "lane.resume":
		input, err := decodeLaunchRequest[api.ResumeRequest](authority.Request, "lane.resume")
		return input.Budget, err
	case "lane.turn":
		input, err := decodeLaunchRequest[api.TurnRequest](authority.Request, "lane.turn")
		return input.Budget, err
	default:
		return api.Budget{}, failure(api.CodeIntegrity, "allocation has no retained budget input")
	}
}

func validateLaunchAllocation(allocation launchAllocation, config string) error {
	r, request, inputs := allocation.Reservation, allocation.Request, allocation.Inputs
	if err := validateAllocation(request, config); err != nil {
		return err
	}
	if err := api.ValidateLaunchReservation(r); err != nil {
		return err
	}
	if r.Config != config || r.ID != request.ReservationID || r.Target != request.Cause.Target ||
		r.Target.LifeID != request.LifeID || r.OperationID != request.Cause.CauseOperationID || r.RequestID != request.Cause.CauseRequestID ||
		r.RequestedBy != request.Cause.RequestedBy || r.CancellationEpoch != request.Cause.CancellationEpoch ||
		inputs.Sources.ReservationID != r.ID || inputs.Grants.ID != r.GrantSetID || inputs.Grants.LifeID != request.LifeID ||
		inputs.Grants.ParentLifeID != r.ParentLifeID || inputs.Grants.Revoked || inputs.Grants.PolicyGeneration != r.PolicyGeneration ||
		allocation.Policy.Generation != r.PolicyGeneration || request.RuntimeManifestID != inputs.Sources.Runtime.Manifest.ID ||
		request.Backend != inputs.Sources.Runtime.Backend {
		return failure(api.CodeForbidden, "helper allocation is foreign to its launch reservation")
	}
	return api.ValidateLaunchPlanRecord(api.LaunchPlanRecord{Reservation: r, Generation: 1, Phase: "sourced", Inputs: &inputs})
}

func (m *leaseManager) allocateLaunch(ctx context.Context, allocation launchAllocation) (_ api.HelperLease, resultErr error) {
	defer helperCheck(&resultErr, "launch_allocation")
	if err := validateLaunchAllocation(allocation, m.binding.Config); err != nil {
		return api.HelperLease{}, err
	}
	if err := validateAllocationEnrollment(ctx, m.binding, allocation); err != nil {
		return api.HelperLease{}, err
	}
	records, err := m.records()
	if err != nil {
		return api.HelperLease{}, err
	}
	for _, current := range records {
		if current.Request.LifeID != allocation.Reservation.Target.LifeID {
			continue
		}
		for _, prior := range current.LaunchAllocations {
			if prior.Reservation.ID == allocation.Reservation.ID && !reflect.DeepEqual(prior, allocation) {
				return api.HelperLease{}, failure(api.CodeIdempotencyConflict, "launch allocation replay changed before resource work")
			}
		}
		if current.Request.ReservationID != allocation.Reservation.ID {
			if len(current.LaunchAllocations) == 0 {
				return api.HelperLease{}, failure(api.CodeContainmentUnknown, "retained allocation lost its source journal")
			}
			prior := current.LaunchAllocations[len(current.LaunchAllocations)-1]
			if prior.Reservation.ID != allocation.Reservation.ID && (allocation.Reservation.PreviousLaunchID != prior.Reservation.LaunchID ||
				allocation.Reservation.Target.Run != prior.Reservation.Target.Run+1 || prior.Inputs.Sources.Project != allocation.Inputs.Sources.Project || prior.Inputs.Sources.Runtime != allocation.Inputs.Sources.Runtime) {
				return api.HelperLease{}, failure(api.CodeConflict, "allocation predecessor or protected sources changed")
			}
		}
	}
	lease, err := m.allocate(ctx, allocation.Request)
	if err != nil {
		return api.HelperLease{}, err
	}
	record, err := m.findActive(lease.ID, storageInitializing)
	if err != nil {
		return api.HelperLease{}, err
	}
	found := false
	for _, previous := range record.LaunchAllocations {
		if previous.Reservation.ID == allocation.Reservation.ID {
			if !reflect.DeepEqual(previous, allocation) {
				return api.HelperLease{}, failure(api.CodeIdempotencyConflict, "launch allocation replay changed its retained inputs")
			}
			found = true
		}
	}
	if !found {
		if len(record.LaunchAllocations) > 0 {
			previous := record.LaunchAllocations[len(record.LaunchAllocations)-1]
			if allocation.Reservation.PreviousLaunchID != previous.Reservation.LaunchID || allocation.Reservation.Target.Run != previous.Reservation.Target.Run+1 ||
				previous.Inputs.Sources.Project != allocation.Inputs.Sources.Project || previous.Inputs.Sources.Runtime != allocation.Inputs.Sources.Runtime {
				return api.HelperLease{}, failure(api.CodeConflict, "retained life allocation changed its predecessor or sources")
			}
			if err := m.resources.Quiescent(ctx, record); err != nil {
				return api.HelperLease{}, err
			}
		} else if allocation.Reservation.PreviousLaunchID != "" || record.Request.ReservationID != allocation.Reservation.ID {
			return api.HelperLease{}, failure(api.CodeContainmentUnknown, "retained life has no original storage allocation journal")
		}
		record.LaunchAllocations = append(record.LaunchAllocations, allocation)
		if record.Storage == nil {
			storage, err := newLaunchStorage(allocation, lease)
			if err != nil {
				return api.HelperLease{}, err
			}
			record.Storage = &storage
		}
		if err := m.save(record); err != nil {
			return api.HelperLease{}, err
		}
	}
	if record.Storage == nil {
		return api.HelperLease{}, failure(api.CodeIntegrity, "launch allocation has no journaled storage IDs")
	}
	if err := m.syncLaunchStorage(ctx, &record, true); err != nil {
		return api.HelperLease{}, err
	}
	if err := m.save(record); err != nil {
		return api.HelperLease{}, err
	}
	return lease, nil
}

func newLaunchStorage(allocation launchAllocation, lease api.HelperLease) (launchStorageRecord, error) {
	ids := make([]api.ID, 4)
	for index := range ids {
		value, err := randomID("storage-")
		if err != nil {
			return launchStorageRecord{}, err
		}
		ids[index] = value
	}
	vendor := ".codex"
	if allocation.Inputs.Sources.Runtime.Driver == api.DriverClaudock {
		vendor = ".claude"
	}
	binding := api.LaunchStorage{ReservationID: allocation.Reservation.ID, Target: allocation.Reservation.Target,
		LeaseID: lease.ID, WorkspaceID: ids[0], Home: api.PrivateHomeBinding{LifeID: allocation.Reservation.Target.LifeID,
			RootID: ids[1], Generation: lease.EndpointGeneration, Home: api.PrivateHome{ID: ids[2], WorkspaceID: ids[0], VendorDirectory: vendor, HistoryID: ids[3]}}}
	return launchStorageRecord{Binding: binding, Directories: []storageIdentity{{ID: ids[0]}, {ID: ids[1]}, {ID: ids[3]}}}, nil
}

func (s *Service) ResolveLaunchStorage(ctx context.Context, request api.LaunchDataRequest) (api.LaunchStorage, error) {
	if !validID(request.GrantSetID) || !validID(request.LeaseID) {
		return api.LaunchStorage{}, failure(api.CodeInvalid, "invalid launch storage selector")
	}
	authority, err := s.launchAuthority(ctx, request.ReservationID, request.GrantSetID, nil, request.Claim)
	if err != nil {
		return api.LaunchStorage{}, err
	}
	return s.launchStorageWithAuthority(ctx, request, authority)
}

func (s *Service) launchStorageWithAuthority(ctx context.Context, request api.LaunchDataRequest, authority launchAuthority) (api.LaunchStorage, error) {
	if !validID(request.LeaseID) || request.ReservationID != authority.Record.Reservation.ID || request.GrantSetID != authority.Grants.ID {
		return api.LaunchStorage{}, failure(api.CodeForbidden, "launch storage selector differs from its validated authority")
	}
	if authority.Record.Inputs == nil || !reflect.DeepEqual(authority.Record.Inputs.Grants, authority.Grants) {
		return api.LaunchStorage{}, failure(api.CodeConflict, "launch storage has no retained sourced inputs")
	}
	var result api.LaunchStorage
	if err := s.call(ctx, "resolve_storage", launchStorageQuery{Request: request, Reservation: authority.Record.Reservation}, &result); err != nil {
		return result, err
	}
	if err := validateLaunchStorage(result, authority.Record.Reservation, request.LeaseID); err != nil {
		return api.LaunchStorage{}, err
	}
	if authority.Record.Plan != nil && (result.WorkspaceID != authority.Record.Plan.Data.Workspace.ID || result.Home != authority.Record.Plan.Data.Home) {
		return api.LaunchStorage{}, failure(api.CodeIntegrity, "helper storage differs from the retained plan")
	}
	if err := s.fenceLaunch(ctx, authority); err != nil {
		return api.LaunchStorage{}, err
	}
	return result, nil
}

func validateLaunchStorage(storage api.LaunchStorage, reservation api.LaunchReservation, lease api.ID) error {
	home := storage.Home
	if storage.ReservationID != reservation.ID || storage.Target != reservation.Target || storage.LeaseID != lease ||
		!validID(storage.WorkspaceID) || home.LifeID != reservation.Target.LifeID || !validID(home.RootID) ||
		home.Generation == 0 || home.Generation > 1<<53-1 || !validID(home.Home.ID) || !validID(home.Home.HistoryID) ||
		home.Home.WorkspaceID != storage.WorkspaceID || home.Home.VendorDirectory == "" || filepath.IsAbs(home.Home.VendorDirectory) ||
		filepath.Clean(home.Home.VendorDirectory) != home.Home.VendorDirectory || home.Home.VendorDirectory == "." || home.Home.VendorDirectory == ".." ||
		strings.HasPrefix(home.Home.VendorDirectory, "../") || strings.ContainsRune(home.Home.VendorDirectory, 0) ||
		home.RootID == storage.WorkspaceID || home.RootID == home.Home.HistoryID || storage.WorkspaceID == home.Home.HistoryID {
		return failure(api.CodeIntegrity, "helper storage identities are missing, aliased or foreign")
	}
	return nil
}

func validateLaunchJournal(record leaseRecord) error {
	if err := validateWorkspaceJournal(record); err != nil {
		return err
	}
	seen := map[api.ID]bool{}
	for _, allocation := range record.LaunchAllocations {
		if err := validateLaunchAllocation(allocation, record.Request.Config); err != nil {
			return err
		}
		if seen[allocation.Reservation.ID] || allocation.Request.LifeID != record.Request.LifeID || !sameLeasePolicy(allocation.Request, record.Request) {
			return failure(api.CodeIntegrity, "helper launch allocation journal is duplicated or foreign")
		}
		seen[allocation.Reservation.ID] = true
	}
	if record.Storage != nil {
		if len(record.LaunchAllocations) == 0 || len(record.Storage.Directories) != 3 {
			return failure(api.CodeIntegrity, "storage journal has no retained allocation")
		}
		if err := validateLaunchStorage(record.Storage.Binding, record.LaunchAllocations[0].Reservation, record.Lease.ID); err != nil {
			return err
		}
		ids := []api.ID{record.Storage.Binding.WorkspaceID, record.Storage.Binding.Home.RootID, record.Storage.Binding.Home.Home.HistoryID}
		for index, item := range record.Storage.Directories {
			if item.ID != ids[index] || (item.Device == "") != (item.Inode == "") || record.Storage.Ready && item.Inode == "" {
				return failure(api.CodeIntegrity, "private storage journal lost an inode binding")
			}
		}
		if len(record.Storage.OriginalModes) > 4096 {
			return failure(api.CodeIntegrity, "retained original modes exceed the complete inventory bound")
		}
		directories, err := privateStorageDirectories(record)
		if err != nil {
			return err
		}
		modeNames := map[string]bool{}
		for _, mode := range record.Storage.OriginalModes {
			owned := false
			for _, item := range directories {
				owned = owned || mode.RootID == item.ID
			}
			key := string(mode.RootID) + "/" + mode.Name
			if !owned || !dataRelative(mode.Name) && mode.Name != ".git" || modeNames[key] || mode.Inode == 0 || mode.Mode&^uint32(0777) != 0 || mode.Kind != "directory" && mode.Kind != "file" && mode.Kind != "symlink" {
				return failure(api.CodeIntegrity, "retained original mode identity is foreign or malformed")
			}
			modeNames[key] = true
		}
	}
	bindings := map[api.ID]bool{}
	for _, capture := range record.Captures {
		pending := capture.Native != nil && capture.Native.Phase == "preparing"
		if capture.Native != nil {
			n := capture.Native
			if (n.ArchiveObservation == nil) != (n.SpoolIdentity == "") {
				return failure(api.CodeIntegrity, "capture archive lost its retained spool identity")
			}
			if n.ArchiveObservation != nil {
				handle := api.ProcessHandle{ID: capture.Binding.ProducerID, Target: capture.Binding.Target, ContainmentID: n.Lease.ContainmentID, Generation: capture.Binding.ProducerGeneration}
				if err := dataTerminal(*n.ArchiveObservation, handle); err != nil {
					return err
				}
			}
		}
		if err := api.ValidateCaptureBinding(capture.Binding); err != nil && !pending {
			return err
		}
		if pending {
			if !validID(capture.Native.BindingID) || capture.Binding.ID != capture.Native.BindingID || capture.Native.PID != 0 {
				return failure(api.CodeIntegrity, "invalid pending capture attempt")
			}
		} else if capture.Native != nil && (capture.Native.Phase != "registered" || capture.Native.PID <= 0 || capture.Native.BindingID != capture.Binding.ID || capture.Binding.Status != "registered") {
			return failure(api.CodeIntegrity, "invalid registered capture native identity")
		}
		if !seen[capture.Registration.Reservation.ID] || bindings[capture.Binding.ID] ||
			capture.Binding.HelperLeaseID != record.Lease.ID || capture.Binding.ReservationID != capture.Registration.Reservation.ID ||
			capture.Binding.Target != capture.Registration.Reservation.Target || capture.Native == nil && capture.Binding.Status != "refused" {
			return failure(api.CodeIntegrity, "capture journal has no matching owned allocation")
		}
		bindings[capture.Binding.ID] = true
	}
	return nil
}

func (m *leaseManager) resolveStorage(ctx context.Context, query launchStorageQuery) (api.LaunchStorage, error) {
	if err := api.ValidateLaunchReservation(query.Reservation); err != nil {
		return api.LaunchStorage{}, err
	}
	if query.Reservation.ID != query.Request.ReservationID || query.Reservation.GrantSetID != query.Request.GrantSetID {
		return api.LaunchStorage{}, failure(api.CodeForbidden, "storage query selects a foreign reservation")
	}
	record, err := m.findActive(query.Request.LeaseID, storageReady)
	if err != nil {
		return api.LaunchStorage{}, err
	}
	if record.BootID != m.bootID || record.Phase != "active" || record.Storage == nil || !record.Storage.Ready || record.Storage.Collecting || record.Storage.Collected {
		return api.LaunchStorage{}, failure(api.CodeContainmentUnknown, "storage allocation is absent, incomplete or from another boot")
	}
	found := false
	for _, allocation := range record.LaunchAllocations {
		found = found || reflect.DeepEqual(allocation.Reservation, query.Reservation)
	}
	if !found {
		return api.LaunchStorage{}, failure(api.CodeForbidden, "storage query is not a journaled launch allocation")
	}
	if err := m.syncLaunchStorage(ctx, &record, false); err != nil {
		return api.LaunchStorage{}, err
	}
	result := record.Storage.Binding
	result.ReservationID, result.Target = query.Reservation.ID, query.Reservation.Target
	if err := validateLaunchStorage(result, query.Reservation, record.Lease.ID); err != nil {
		return api.LaunchStorage{}, err
	}
	return result, nil
}
