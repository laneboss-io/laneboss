package admin

import "laneboss.io/laneboss/internal/v2/api"

// BalanceTool belongs to the operator command. It is never installed as a
// service dependency and cannot accept a manually entered balance.
type BalanceTool struct {
	Command      string   `json:"command"`
	Selector     string   `json:"selector"`
	CredentialID api.ID   `json:"credential_id"`
	ProfileIDs   []api.ID `json:"profile_ids"`
	FloorMicros  int64    `json:"floor_micros"`
}
