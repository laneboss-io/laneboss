package records

import "laneboss.io/laneboss/internal/v2/api"

// These input-only checks are shared by service preflight and both CLI forms.
// Current object ACLs, content screening, authority and budget ceilings remain
// service/store checks; a locally valid reference is not a committed object.
func ValidateAppendInput(request api.RecordAppendRequest) error {
	if !collection(request.Collection) {
		return invalid("unknown record collection")
	}
	if len(request.RelatedIDs) > 200 {
		return invalid("too many related records")
	}
	for _, id := range request.RelatedIDs {
		if !validID(id) {
			return invalid("invalid record ID")
		}
	}
	return validateContentRef(request.Content)
}

func ValidateDecisionInput(request api.DecisionMutateRequest) error {
	switch request.Action {
	case "add", "supersede", "annotate", "feedback", "embed":
	default:
		return invalid("unknown decision action")
	}
	if request.Action == "add" {
		if request.RecordID != "" || request.ExpectedGeneration != 0 {
			return invalid("new decision requires an absent base")
		}
	} else if !validID(request.RecordID) || request.ExpectedGeneration == 0 || request.ExpectedGeneration >= 1<<53-1 {
		return invalid("decision change requires a canonical decision and base generation")
	}
	return validateContentRef(request.Content)
}

func validateContentRef(ref api.BlobRef) error {
	if !validID(ref.ID) || !validDigest(ref.SHA256) || ref.Bytes < 1 || ref.Bytes > api.MaxJudgeBytes || ref.Class != "record" && ref.Class != "report" {
		return invalid("record content must reference bounded committed text")
	}
	return nil
}

func ValidateImportInput(request api.TransferRequest) error {
	if !collection(request.Collection) || !manifestRef(request.Manifest) {
		return invalid("import requires a collection and committed manifest")
	}
	return nil
}

func ValidateBoxLaunchInput(request api.BoxLaunchRequest) error {
	if request.Provider != "aws" && request.Provider != "gcp" || !validID(request.ResourceGrantID) || len(request.Purpose) < 4 || len(request.Purpose) > 128 || request.Purpose[:3] != "lb-" || !manifestRef(request.Spec) {
		return invalid("box launch requires a named provider/grant, lb- purpose and committed spec")
	}
	return nil
}

func ValidateBoxRunInput(request api.BoxRunRequest) error {
	if !validID(request.BoxID) || request.ExpectedGeneration == 0 || !manifestRef(request.Source) || !manifestRef(request.Plan) {
		return invalid("box run requires current box generation and committed source/plan manifests")
	}
	return nil
}

func ValidateBoxHarvestInput(request api.BoxControlRequest) error {
	if !validID(request.BoxID) || request.ExpectedGeneration == 0 {
		return invalid("box harvest requires current box generation")
	}
	return nil
}

func ValidateBoxEndInput(request api.BoxControlRequest) error {
	if !validID(request.BoxID) || request.ExpectedGeneration == 0 {
		return invalid("box end requires current box generation")
	}
	return nil
}

func ValidateBoxListInput(request api.ListRequest) error {
	if request.Limit < 1 || request.Limit > 200 || len(request.Cursor) > 8192 || request.LifeID != "" && !validID(request.LifeID) {
		return invalid("invalid box page or life filter")
	}
	return nil
}
