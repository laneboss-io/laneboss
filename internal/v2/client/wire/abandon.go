package wire

import (
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

// Abandonment carries the required empty review field without claiming a
// reviewer, blob or coverage enum. First apply the complete shared strict DTO
// check. Only the exact empty review has this contextual shape; positive review
// data and every other state keep their ordinary enum and object rules.
func shapeAbandonedMark(value any) (bool, error) {
	object, ok := value.(map[string]any)
	if !ok || object["state"] != "abandoned" {
		return false, nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return true, Invalid("abandonment request cannot be encoded")
	}
	var request api.MarkRequest
	if err := api.DecodeObject(data, &request); err != nil {
		return true, err
	}
	review := request.Review
	empty := review.Evidence == nil && review.ID == "" && review.Reviewer == (api.Actor{}) &&
		review.Diff == (api.BlobRef{}) && len(review.Checks) == 0 && review.RecordInventory == (api.BlobRef{}) &&
		len(review.RefusalResolution) == 0 && review.Coverage == ""
	return empty, nil
}
