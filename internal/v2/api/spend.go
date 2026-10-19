package api

import "context"

// VendorSpend is one stream-json result, never a token-price estimate.
type VendorSpend struct {
	SessionID           string `json:"session_id"`
	ResultID            string `json:"result_id"`
	CostMicros          int64  `json:"cost_micros"`
	InputTokens         int64  `json:"input_tokens"`
	OutputTokens        int64  `json:"output_tokens"`
	CacheReadTokens     int64  `json:"cache_read_tokens"`
	CacheCreationTokens int64  `json:"cache_creation_tokens"`
}

// SpendReading travels only over the native administrator channel. Output is
// the exact operator-side tool stdout; there is no balance-number input.
type SpendReading struct {
	ID           ID        `json:"id"`
	CredentialID ID        `json:"credential_id"`
	ProfileIDs   []ID      `json:"profile_ids"`
	FloorMicros  int64     `json:"floor_micros"`
	Selector     string    `json:"selector"`
	Output       []byte    `json:"output"`
	ObservedAt   Timestamp `json:"observed_at"`
}

type SpendBalance struct {
	CredentialID      ID         `json:"credential_id"`
	SeedMicros        int64      `json:"seed_micros"`
	SpentMicros       int64      `json:"spent_micros"`
	ReadingMicros     int64      `json:"reading_micros"`
	RemainingMicros   int64      `json:"remaining_micros"`
	FloorMicros       int64      `json:"floor_micros"`
	AnchorMicros      int64      `json:"anchor_micros"`
	AnchorSpentMicros int64      `json:"anchor_spent_micros"`
	Generation        Generation `json:"generation"`
	ObservedAt        Timestamp  `json:"observed_at"`
	NeedsReading      bool       `json:"needs_reading"`
	AwaitingSince     Timestamp  `json:"awaiting_since,omitempty"`
	AccountingError   *Error     `json:"accounting_error,omitempty"`
}

type SpendRecorded struct {
	Usage           VendorSpend `json:"usage"`
	CaptureID       ID          `json:"capture_id"`
	RemainingMicros int64       `json:"remaining_micros"`
}

type SpendJournal struct {
	EstimateMicros int64  `json:"estimate_micros"`
	ReadingMicros  int64  `json:"reading_micros"`
	FloorMicros    int64  `json:"floor_micros"`
	Line           string `json:"line"`
}

type CredentialSpendGuard interface {
	CheckCredentialSpend(context.Context, CredentialSlot) (SpendBalance, error)
}

type SpendStatusReader interface {
	LaneSpend(context.Context, Scope, LifeRef) (*SpendBalance, error)
}

type SpendReconciler interface {
	ReconcileSpend(context.Context, SpendReading) (SpendBalance, error)
}

func ValidateSpendCapture(plan LaunchPlan) error {
	if plan.Runner.Slot.Mode != "claude-api-key" {
		return nil
	}
	if plan.Runner.Driver == DriverClaudock && plan.Capture.Status == "registered" {
		for _, stream := range plan.Capture.Streams {
			if stream.Stream == "stdout" || stream.Stream == "vendor" || stream.Stream == "structured" {
				return nil
			}
		}
	}
	return &Error{Code: CodePrerequisite, Owner: "lb-v2-spend", Message: "API credential launch requires registered outside vendor cost capture",
		Instead: "Restore primary stream-json capture before launching on an API credential."}
}
