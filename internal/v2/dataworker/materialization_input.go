package dataworker

import (
	"encoding/json"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// MaterializationInput is this fixed worker's private materialize_input body.
// The service retains it before launch; it contains no host paths or agent
// credentials. Output names an inert service-retained candidate tree manifest,
// whose bytes become evidence only after actual copy and outside read-back.
type MaterializationInput struct {
	Schema      string                  `json:"schema"`
	StageID     api.ID                  `json:"stage_id"`
	Reservation api.LaunchReservation   `json:"reservation"`
	Source      api.ProjectLaunchSource `json:"source"`
	Storage     api.StorageProjection   `json:"storage"`
	Grants      api.GrantSet            `json:"grants"`
	Output      api.BlobRef             `json:"output"`
	Budget      api.Budget              `json:"budget"`
}

// MaterializationGrants derives the one read-only source capability. IDs must
// already have been issued by the stage store; this function allocates none.
func MaterializationGrants(r api.LaunchReservation, inputs api.LaunchInputs, setID, dataID api.ID, expires api.Timestamp, now time.Time) (api.GrantSet, error) {
	if _, err := manifest.Expiry(expires, now); err != nil {
		return api.GrantSet{}, err
	}
	return materializationGrantShape(r, inputs, setID, dataID, expires)
}

// A retained launch-time job set is historical evidence, not fresh execution
// authority. Its original bounded expiry/hash stays intact during read-back.
func materializationGrantShape(r api.LaunchReservation, inputs api.LaunchInputs, setID, dataID api.ID, expires api.Timestamp) (api.GrantSet, error) {
	var zero api.GrantSet
	if err := api.ValidateLaunchPlanRecord(api.LaunchPlanRecord{Reservation: r, Generation: 1, Phase: "sourced", Inputs: &inputs}); err != nil {
		return zero, err
	}
	if !manifest.ValidID(setID) || setID == r.GrantSetID || !manifest.ValidID(dataID) || dataID == inputs.Sources.Project.GrantID {
		return zero, manifest.Invalid("materialization needs distinct store-issued job grant identities")
	}
	deadline, err := manifest.Time(expires)
	if err != nil {
		return zero, err
	}
	limit, err := manifest.Time(inputs.Grants.ExpiresAt)
	if err != nil {
		return zero, err
	}
	if deadline.After(limit) {
		return zero, lstate.Error(api.CodeForbidden, "materialization job outlives the agent grants")
	}
	source := inputs.Sources.Project
	found := false
	for _, grant := range inputs.Grants.Data {
		if grant.ID != source.GrantID {
			continue
		}
		member, err := manifest.Time(grant.ExpiresAt)
		if err != nil {
			return zero, err
		}
		if deadline.After(member) || grant.RelativePath != "." || grant.Delivery != "copy" {
			return zero, lstate.Error(api.CodeForbidden, "materialization source exceeds its project grant")
		}
		found = true
	}
	if !found {
		return zero, manifest.Invalid("materialization project has no original data grant")
	}
	g := api.GrantSet{ID: setID, LifeID: r.Target.LifeID, ParentLifeID: r.Target.LifeID, Generation: 1,
		PolicyGeneration: r.PolicyGeneration, ExpiresAt: expires, Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{},
		Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{},
		Data: []api.DataGrant{{ID: dataID, ParentGrantID: source.GrantID, SourceObjectID: source.Object.ID, SourceSHA256: source.Object.SHA256,
			RelativePath: ".", Destination: "/job/source", Access: "ro", Delivery: "bind_ro", HistoryScope: source.HistoryScope, ExpiresAt: expires}}}
	g.SHA256, err = manifest.HashValue(g)
	return g, err
}

// EncodeMaterializationInput is the service preparation helper, before the
// final WorkerLease.Input hash is assigned. Final stage validation is mandatory
// after retaining these bytes and before the service launches its child effect.
func EncodeMaterializationInput(stage api.LaunchDataStage, output api.BlobRef) ([]byte, error) {
	input := MaterializationInput{Schema: "laneboss.materialize-input.v2", StageID: stage.ID,
		Reservation: stage.Reservation, Source: stage.Inputs.Sources.Project, Storage: stage.Storage,
		Grants: stage.Grants, Output: output, Budget: stage.Plan.Budget}
	if err := validateMaterializationInput(input, stage); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	canonical, err := api.CanonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	if len(canonical) > api.MaxFrameBytes {
		return nil, manifest.Invalid("materialization input exceeds the worker bootstrap bound")
	}
	return canonical, nil
}

func validateMaterializationInput(input MaterializationInput, stage api.LaunchDataStage) error {
	if input.Schema != "laneboss.materialize-input.v2" || input.StageID != stage.ID ||
		!reflect.DeepEqual(input.Reservation, stage.Reservation) || input.Source != stage.Inputs.Sources.Project ||
		input.Storage != stage.Storage || !reflect.DeepEqual(input.Grants, stage.Grants) || input.Budget != stage.Plan.Budget {
		return lstate.Error(api.CodeIntegrity, "materialization input differs from its retained stage")
	}
	if err := manifest.Budget(input.Budget); err != nil {
		return err
	}
	if err := manifest.Blob(input.Output); err != nil {
		return err
	}
	if input.Output.Class != "manifest" || input.Output.Bytes == 0 || input.Output.ID == input.Source.Object.ID {
		return manifest.Invalid("materialization requires a distinct service-retained output manifest")
	}
	return nil
}
